import { canonicalDigest, cloneJson } from "./canonical.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  compileOutcomeTransitions,
  validateOutcomeTransitionLedger
} from "./outcome-transitions.mjs";

export const OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION = 1;

export const OUTCOME_PLAN_AMENDMENT_LIMITS = Object.freeze({
  outcomes: 512,
  revisionEntries: 512,
  appendedRevisions: 32,
  transitionEntries: 512,
  transitionLedgerBytes: 2 * 1024 * 1024,
  definitionBytes: 64 * 1024,
  aggregateDefinitionBytes: 2 * 1024 * 1024,
  rationaleBytes: 4 * 1024
});

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const REVISION_STATUSES = new Set(["planned", "conditional"]);
const FROZEN_STATUSES = new Set(["active", "achieved", "retired"]);
const OUTCOME_DEFINITION_KEYS = [
  "acceptance",
  "allowedChangeKinds",
  "dependsOn",
  "id",
  "kind",
  "nonGoals",
  "outcome",
  "stage"
];
const ACCEPTANCE_DEFINITION_KEYS = [
  "activationCriterionRefs",
  "claimRefs",
  "criteria",
  "exitCriteria",
  "gapRefs"
];
const CRITERION_DEFINITION_KEYS = ["claimRefs", "gapRefs", "id", "statement"];
const DEFINITION_FIELD_PATHS = [
  "id",
  "stage",
  "outcome",
  "dependsOn",
  "kind",
  "allowedChangeKinds",
  "acceptance.activationCriterionRefs",
  "acceptance.criteria",
  "acceptance.exitCriteria",
  "acceptance.claimRefs",
  "acceptance.gapRefs",
  "nonGoals"
];
const REVISION_KEYS = [
  "amendmentChangeId",
  "changedFields",
  "currentDefinitionDigest",
  "governanceBaselineDigest",
  "id",
  "outcomeRef",
  "previousDefinition",
  "previousDefinitionDigest",
  "rationale",
  "requiredAuthorityRef"
];

export function compileOutcomePlanAmendment({
  change,
  governanceBaseline,
  currentModel,
  resolvedPackages = [],
  priorAcceptedPackages = null
} = {}) {
  const changeKind = readString(change?.changeKind) ?? "implementation";
  if (changeKind !== "plan-amendment") {
    const transitionCompilation = compileOutcomeTransitions({
      change,
      governanceBaseline,
      currentModel,
      resolvedPackages,
      priorAcceptedPackages
    });
    return finalizeCompilation({
      change,
      governanceBaseline,
      baselinePlan: governanceBaseline?.plan,
      currentPlan: currentModel?.plan,
      transitionCompilation,
      amendmentKind: "none",
      appendedRevisions: [],
      activationBindings: []
    });
  }

  assertGovernanceBaselineSeal(governanceBaseline);
  const baselinePlan = requirePlan(governanceBaseline?.plan, "frozen");
  const currentPlan = requirePlan(currentModel?.plan, "current");
  assertPlanAmendmentIdentity({ governanceBaseline, currentModel, baselinePlan, currentPlan });
  assertPlanAmendmentCannotSelfAuthorize(change);
  assertPlanLimits(baselinePlan, currentPlan);

  const baselineLedger = normalizeRevisionLedger(baselinePlan.outcomeRevisions, "frozen");
  const currentLedger = normalizeRevisionLedger(currentPlan.outcomeRevisions, "current");
  assertLedgerPrefix({
    baselineLedger,
    currentLedger,
    code: "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
    label: "Outcome Revision"
  });
  validateRevisionHistory({ plan: baselinePlan, ledger: baselineLedger, label: "frozen" });

  const baselineTransitions = normalizeOpaqueLedger(baselinePlan.outcomeTransitions, "frozen Outcome Transition");
  const currentTransitions = normalizeOpaqueLedger(currentPlan.outcomeTransitions, "current Outcome Transition");
  assertTransitionLedgerValid(baselinePlan, governanceBaseline?.knowledgeGaps, "frozen");
  assertTransitionLedgerValid(currentPlan, currentModel?.knowledgeGaps, "current");
  assertLedgerPrefix({
    baselineLedger: baselineTransitions,
    currentLedger: currentTransitions,
    code: "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
    label: "Outcome Transition"
  });

  const appendedRevisionEntries = currentLedger.slice(baselineLedger.length);
  const appendedTransitionEntries = currentTransitions.slice(baselineTransitions.length);
  const definitionDeltas = collectDefinitionDeltas(baselinePlan, currentPlan);
  const statusDeltas = collectStatusDeltas(baselinePlan, currentPlan);
  const revisionIntent = appendedRevisionEntries.length > 0 || definitionDeltas.length > 0;

  if (revisionIntent && (appendedTransitionEntries.length > 0 || statusDeltas.length > 0)) {
    throw amendmentError(
      "OUTCOME_REVISION_TRANSITION_MIXED",
      "An Amendment that contains an Outcome Revision intent cannot contain any Outcome status Transition.",
      {
        revisedOutcomeRefs: uniqueStrings([
          ...definitionDeltas.map((entry) => entry.outcomeRef),
          ...appendedRevisionEntries.map((entry) => entry.outcomeRef)
        ]).sort(),
        statusOutcomeRefs: uniqueStrings(statusDeltas.map((entry) => entry.outcomeRef)).sort(),
        appendedTransitionIds: appendedTransitionEntries.map((entry) => readString(entry?.id)).filter(Boolean).slice(0, 32)
      }
    );
  }

  if (revisionIntent) {
    assertKnowledgeGapProofContractsPreserved({ governanceBaseline, currentModel });
    if (readString(currentPlan.authority) !== readString(baselinePlan.authority)) {
      throw amendmentError(
        "OUTCOME_REVISION_AUTHORITY_MISMATCH",
        "An Outcome Revision must use the frozen Development Plan authority.",
        {
          expectedAuthorityRef: readString(baselinePlan.authority) ?? null,
          observedAuthorityRef: readString(currentPlan.authority) ?? null
        }
      );
    }
    const appendedRevisions = compileRevisions({
      change,
      governanceBaseline,
      baselinePlan,
      currentPlan,
      baselineLedger,
      currentLedger,
      appendedRevisionEntries,
      definitionDeltas
    });
    return finalizeCompilation({
      change,
      governanceBaseline,
      baselinePlan,
      currentPlan,
      transitionCompilation: null,
      amendmentKind: "revision",
      appendedRevisions,
      activationBindings: [],
      priorAcceptedPackages
    });
  }

  const transitionCompilation = compileOutcomeTransitions({
    change,
    governanceBaseline,
    currentModel,
    resolvedPackages,
    priorAcceptedPackages
  });
  const activationBindings = compileActivationBindings({
    baselinePlan,
    appendedTransitions: transitionCompilation.appendedTransitions
  });
  return finalizeCompilation({
    change,
    governanceBaseline,
    baselinePlan,
    currentPlan,
    transitionCompilation,
    amendmentKind: transitionCompilation.appendedTransitions.length > 0
      || transitionCompilation.unresolved.length > 0 ? "transition" : "none",
    appendedRevisions: [],
    activationBindings
  });
}

export function validateOutcomeRevisionLedger(plan, decisionAuthorities = new Set()) {
  try {
    const ledger = normalizeRevisionLedger(plan?.outcomeRevisions, "plan");
    validateRevisionHistory({ plan, ledger, label: "plan" });
    const knownAuthorities = decisionAuthorities instanceof Set
      ? decisionAuthorities
      : new Set(asArray(decisionAuthorities).map(readReference).filter(Boolean));
    for (const revision of ledger) {
      if (knownAuthorities.size > 0 && !knownAuthorities.has(revision.requiredAuthorityRef)) {
        throw amendmentError(
          "OUTCOME_REVISION_AUTHORITY_MISMATCH",
          `Outcome Revision ${revision.id} references an unknown Decision Authority.`,
          { revisionId: revision.id, observedAuthorityRef: revision.requiredAuthorityRef }
        );
      }
    }
    return { valid: true, errors: [] };
  } catch (error) {
    return {
      valid: false,
      errors: [{
        code: "plan.outcome-revision.invalid",
        location: ".legatura/plan.json#outcomeRevisions",
        message: error.message,
        details: { causeCode: error.code ?? null, ...(error.details ?? {}) }
      }]
    };
  }
}

function compileRevisions({
  change,
  governanceBaseline,
  baselinePlan,
  currentPlan,
  baselineLedger,
  currentLedger,
  appendedRevisionEntries,
  definitionDeltas
}) {
  if (appendedRevisionEntries.length > OUTCOME_PLAN_AMENDMENT_LIMITS.appendedRevisions) {
    throw limitError(
      "appended-revisions",
      OUTCOME_PLAN_AMENDMENT_LIMITS.appendedRevisions,
      appendedRevisionEntries.length
    );
  }
  const deltaByOutcome = new Map(definitionDeltas.map((entry) => [entry.outcomeRef, entry]));
  const revisionsByOutcome = new Map();
  for (const revision of appendedRevisionEntries) {
    const existing = revisionsByOutcome.get(revision.outcomeRef) ?? [];
    existing.push(revision);
    revisionsByOutcome.set(revision.outcomeRef, existing);
  }
  const duplicateOutcomeRefs = [...revisionsByOutcome]
    .filter(([, entries]) => entries.length > 1)
    .map(([outcomeRef]) => outcomeRef)
    .sort();
  if (duplicateOutcomeRefs.length > 0) {
    throw amendmentError(
      "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      "One Amendment can append at most one Revision for each Outcome.",
      { duplicateOutcomeRefs }
    );
  }

  for (const delta of definitionDeltas) {
    if (FROZEN_STATUSES.has(delta.baselineStatus) || !REVISION_STATUSES.has(delta.baselineStatus)) {
      throw amendmentError(
        "OUTCOME_REVISION_STATUS_FORBIDDEN",
        `Outcome ${delta.outcomeRef} cannot be revised from status ${delta.baselineStatus ?? "unknown"}.`,
        { outcomeRef: delta.outcomeRef, baselineStatus: delta.baselineStatus ?? null }
      );
    }
    if (!revisionsByOutcome.has(delta.outcomeRef)) {
      throw amendmentError(
        "OUTCOME_REVISION_REQUIRED",
        `Outcome ${delta.outcomeRef} changed without one appended Revision.`,
        { outcomeRef: delta.outcomeRef, changedFields: delta.changedFields }
      );
    }
  }

  const compiled = [];
  for (const revision of appendedRevisionEntries) {
    const delta = deltaByOutcome.get(revision.outcomeRef);
    if (!delta) {
      throw amendmentError(
        "OUTCOME_REVISION_NOOP",
        `Outcome Revision ${revision.id} does not bind a definition change.`,
        { revisionId: revision.id, outcomeRef: revision.outcomeRef }
      );
    }
    if (!REVISION_STATUSES.has(delta.baselineStatus)) {
      throw amendmentError(
        "OUTCOME_REVISION_STATUS_FORBIDDEN",
        `Outcome ${revision.outcomeRef} cannot be revised from status ${delta.baselineStatus ?? "unknown"}.`,
        { revisionId: revision.id, outcomeRef: revision.outcomeRef, baselineStatus: delta.baselineStatus ?? null }
      );
    }
    const priorCount = baselineLedger.filter((entry) => entry.outcomeRef === revision.outcomeRef).length;
    const expectedId = `${revision.outcomeRef}-R${priorCount + 1}`;
    if (revision.id !== expectedId) {
      throw amendmentError(
        "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
        `Outcome Revision ids must be consecutive for ${revision.outcomeRef}.`,
        { revisionId: revision.id, expectedRevisionId: expectedId, outcomeRef: revision.outcomeRef }
      );
    }
    if (canonicalDigest(revision.previousDefinition) !== delta.previousDefinitionDigest
      || revision.previousDefinitionDigest !== delta.previousDefinitionDigest) {
      throw amendmentError(
        "OUTCOME_REVISION_PRIOR_MISMATCH",
        `Outcome Revision ${revision.id} does not preserve the complete frozen definition.`,
        {
          revisionId: revision.id,
          expectedDigest: delta.previousDefinitionDigest,
          observedDigest: revision.previousDefinitionDigest
        }
      );
    }
    if (revision.currentDefinitionDigest !== delta.currentDefinitionDigest
      || canonicalDigest(revision.changedFields) !== canonicalDigest(delta.changedFields)) {
      throw amendmentError(
        "OUTCOME_REVISION_CURRENT_MISMATCH",
        `Outcome Revision ${revision.id} does not match the compiler-derived current definition.`,
        {
          revisionId: revision.id,
          expectedDigest: delta.currentDefinitionDigest,
          observedDigest: revision.currentDefinitionDigest,
          expectedChangedFields: delta.changedFields,
          observedChangedFields: revision.changedFields
        }
      );
    }
    const requiredAuthorityRef = readString(baselinePlan.authority) ?? null;
    if (revision.requiredAuthorityRef !== requiredAuthorityRef) {
      throw amendmentError(
        "OUTCOME_REVISION_AUTHORITY_MISMATCH",
        `Outcome Revision ${revision.id} does not name the frozen Development Plan authority.`,
        {
          revisionId: revision.id,
          expectedAuthorityRef: requiredAuthorityRef,
          observedAuthorityRef: revision.requiredAuthorityRef
        }
      );
    }
    if (revision.amendmentChangeId !== readString(change?.id)
      || revision.governanceBaselineDigest !== governanceBaseline.digest) {
      throw amendmentError(
        "OUTCOME_REVISION_BINDING_INVALID",
        `Outcome Revision ${revision.id} is not bound to this Change and its frozen Governance Baseline.`,
        {
          revisionId: revision.id,
          expectedChangeId: readString(change?.id) ?? null,
          observedChangeId: revision.amendmentChangeId,
          expectedGovernanceBaselineDigest: governanceBaseline.digest,
          observedGovernanceBaselineDigest: revision.governanceBaselineDigest
        }
      );
    }
    const normalized = cloneJson(revision);
    compiled.push({
      ...normalized,
      bindingDigest: canonicalDigest({
        schemaVersion: OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION,
        changeId: change?.id ?? null,
        governanceBaselineDigest: governanceBaseline.digest,
        baselinePlanDigest: canonicalDigest(baselinePlan),
        currentPlanDigest: canonicalDigest(currentPlan),
        revision: normalized
      })
    });
  }
  validateRevisionHistory({ plan: currentPlan, ledger: currentLedger, label: "current" });
  return compiled.sort(compareRevisions);
}

function collectDefinitionDeltas(baselinePlan, currentPlan) {
  const baselineOutcomes = indexOutcomes(baselinePlan?.outcomes, "frozen");
  const currentOutcomes = indexOutcomes(currentPlan?.outcomes, "current");
  const removedOutcomeRefs = [...baselineOutcomes.keys()].filter((outcomeRef) => !currentOutcomes.has(outcomeRef));
  if (removedOutcomeRefs.length > 0) {
    throw amendmentError(
      "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      "An Outcome Plan Amendment cannot remove frozen Outcomes.",
      { removedOutcomeRefs: removedOutcomeRefs.slice(0, 32).sort() }
    );
  }
  for (const [outcomeRef, outcome] of currentOutcomes) {
    if (baselineOutcomes.has(outcomeRef)) continue;
    if (!REVISION_STATUSES.has(readString(outcome?.status))) {
      throw amendmentError(
        "OUTCOME_REVISION_STATUS_FORBIDDEN",
        "A newly declared Outcome must begin planned or conditional.",
        { outcomeRef, observedStatus: readString(outcome?.status) ?? null }
      );
    }
  }
  let aggregateDefinitionBytes = 0;
  return [...baselineOutcomes].flatMap(([outcomeRef, baselineOutcome]) => {
    const currentOutcome = currentOutcomes.get(outcomeRef);
    const previousDefinition = normalizeOutcomeDefinition(
      baselineOutcome,
      `frozen Outcome ${outcomeRef}`,
      { allowLegacyIdReferences: true }
    );
    const currentDefinition = normalizeOutcomeDefinition(
      currentOutcome,
      `current Outcome ${outcomeRef}`,
      { allowLegacyIdReferences: true }
    );
    aggregateDefinitionBytes += jsonBytes(previousDefinition) + jsonBytes(currentDefinition);
    if (aggregateDefinitionBytes > OUTCOME_PLAN_AMENDMENT_LIMITS.aggregateDefinitionBytes) {
      throw limitError(
        "aggregate-outcome-definition-bytes",
        OUTCOME_PLAN_AMENDMENT_LIMITS.aggregateDefinitionBytes,
        aggregateDefinitionBytes
      );
    }
    const changedFields = deriveChangedFields(previousDefinition, currentDefinition);
    return changedFields.length === 0 ? [] : [{
      outcomeRef,
      baselineStatus: readString(baselineOutcome?.status) ?? null,
      currentStatus: readString(currentOutcome?.status) ?? null,
      previousDefinition,
      previousDefinitionDigest: canonicalDigest(previousDefinition),
      currentDefinitionDigest: canonicalDigest(currentDefinition),
      changedFields
    }];
  });
}

function collectStatusDeltas(baselinePlan, currentPlan) {
  const currentOutcomes = indexOutcomes(currentPlan?.outcomes, "current");
  return asArray(baselinePlan?.outcomes).flatMap((baselineOutcome) => {
    const outcomeRef = readString(baselineOutcome?.id);
    const currentOutcome = currentOutcomes.get(outcomeRef);
    const from = readString(baselineOutcome?.status) ?? null;
    const to = readString(currentOutcome?.status) ?? null;
    return currentOutcome && from !== to ? [{ outcomeRef, from, to }] : [];
  });
}

function compileActivationBindings({ baselinePlan, appendedTransitions }) {
  const baselineOutcomes = indexOutcomes(baselinePlan?.outcomes, "frozen");
  return asArray(appendedTransitions).flatMap((transition) => {
    if (transition?.to !== "active") return [];
    const outcomeRef = readString(transition?.outcomeRef);
    const outcome = baselineOutcomes.get(outcomeRef);
    if (!outcome) {
      throw amendmentError(
        "OUTCOME_ACTIVATION_DEFINITION_CHANGED",
        "Outcome activation requires an exact frozen-baseline definition.",
        { outcomeRef: outcomeRef ?? null, transitionId: readString(transition?.id) ?? null }
      );
    }
    return [{
      transitionId: readString(transition.id),
      outcomeRef,
      frozenDefinitionDigest: canonicalDigest(normalizeOutcomeDefinition(
        outcome,
        `frozen Outcome ${outcomeRef}`,
        { allowLegacyIdReferences: true }
      ))
    }];
  }).sort((left, right) => left.outcomeRef.localeCompare(right.outcomeRef)
    || left.transitionId.localeCompare(right.transitionId));
}

function validateRevisionHistory({ plan, ledger, label }) {
  const outcomes = indexOutcomes(plan?.outcomes, label);
  const seenIds = new Set();
  const byOutcome = new Map();
  for (const revision of ledger) {
    if (seenIds.has(revision.id)) {
      throw amendmentError(
        "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
        `Duplicate Outcome Revision id: ${revision.id}.`,
        { revisionId: revision.id }
      );
    }
    seenIds.add(revision.id);
    const outcome = outcomes.get(revision.outcomeRef);
    if (!outcome) {
      throw amendmentError(
        "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
        `Outcome Revision ${revision.id} references an unknown Outcome.`,
        { revisionId: revision.id, outcomeRef: revision.outcomeRef }
      );
    }
    const entries = byOutcome.get(revision.outcomeRef) ?? [];
    entries.push(revision);
    byOutcome.set(revision.outcomeRef, entries);
  }

  for (const [outcomeRef, revisions] of byOutcome) {
    const materializedDefinition = normalizeOutcomeDefinition(
      outcomes.get(outcomeRef),
      `${label} Outcome ${outcomeRef}`,
      { allowLegacyIdReferences: true }
    );
    for (let index = 0; index < revisions.length; index += 1) {
      const revision = revisions[index];
      const expectedId = `${outcomeRef}-R${index + 1}`;
      if (revision.id !== expectedId) {
        throw amendmentError(
          "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
          `Outcome Revision history for ${outcomeRef} must use consecutive ids.`,
          { revisionId: revision.id, expectedRevisionId: expectedId, outcomeRef }
        );
      }
      const previousDigest = canonicalDigest(revision.previousDefinition);
      if (revision.previousDefinitionDigest !== previousDigest) {
        throw amendmentError(
          "OUTCOME_REVISION_PRIOR_MISMATCH",
          `Outcome Revision ${revision.id} has a forged previous definition digest.`,
          { revisionId: revision.id, expectedDigest: previousDigest, observedDigest: revision.previousDefinitionDigest }
        );
      }
      const nextDefinition = revisions[index + 1]?.previousDefinition ?? materializedDefinition;
      const expectedCurrentDigest = canonicalDigest(nextDefinition);
      const expectedChangedFields = deriveChangedFields(revision.previousDefinition, nextDefinition);
      if (expectedChangedFields.length === 0) {
        throw amendmentError(
          "OUTCOME_REVISION_NOOP",
          `Outcome Revision ${revision.id} does not change the complete definition.`,
          { revisionId: revision.id, outcomeRef }
        );
      }
      if (revision.currentDefinitionDigest !== expectedCurrentDigest
        || canonicalDigest(revision.changedFields) !== canonicalDigest(expectedChangedFields)) {
        throw amendmentError(
          "OUTCOME_REVISION_CURRENT_MISMATCH",
          `Outcome Revision ${revision.id} does not bind the next complete definition.`,
          {
            revisionId: revision.id,
            expectedDigest: expectedCurrentDigest,
            observedDigest: revision.currentDefinitionDigest,
            expectedChangedFields,
            observedChangedFields: revision.changedFields
          }
        );
      }
    }
  }
}

function normalizeRevisionLedger(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw amendmentError(
      "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      `${label} outcomeRevisions must be an array.`
    );
  }
  if (value.length > OUTCOME_PLAN_AMENDMENT_LIMITS.revisionEntries) {
    throw limitError("revision-entries", OUTCOME_PLAN_AMENDMENT_LIMITS.revisionEntries, value.length);
  }
  let aggregateDefinitionBytes = 0;
  return value.map((entry, index) => {
    assertPlainObject(entry, "OUTCOME_REVISION_DEFINITION_INVALID", `${label} outcomeRevisions[${index}] must be an object.`);
    assertOnlyKeys(entry, REVISION_KEYS, `${label} outcomeRevisions[${index}]`);
    const id = requireString(entry.id, "Outcome Revision id");
    const outcomeRef = requireString(entry.outcomeRef, `Outcome Revision ${id} outcomeRef`);
    if (!new RegExp(`^${escapeRegExp(outcomeRef)}-R[1-9][0-9]*$`, "u").test(id)) {
      throw amendmentError(
        "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
        `Outcome Revision id must use the stable ${outcomeRef}-Rn form.`,
        { revisionId: id, outcomeRef }
      );
    }
    const previousDefinition = normalizeOutcomeDefinition(entry.previousDefinition, `${label} Outcome Revision ${id} previousDefinition`);
    if (canonicalDigest(previousDefinition) !== canonicalDigest(entry.previousDefinition)) {
      throw amendmentError(
        "OUTCOME_REVISION_DEFINITION_INVALID",
        `Outcome Revision ${id} previousDefinition must already be complete and canonical.`,
        { revisionId: id }
      );
    }
    const definitionBytes = jsonBytes(previousDefinition);
    if (definitionBytes > OUTCOME_PLAN_AMENDMENT_LIMITS.definitionBytes) {
      throw limitError("revision-definition-bytes", OUTCOME_PLAN_AMENDMENT_LIMITS.definitionBytes, definitionBytes, { revisionId: id });
    }
    aggregateDefinitionBytes += definitionBytes;
    if (aggregateDefinitionBytes > OUTCOME_PLAN_AMENDMENT_LIMITS.aggregateDefinitionBytes) {
      throw limitError(
        "aggregate-revision-definition-bytes",
        OUTCOME_PLAN_AMENDMENT_LIMITS.aggregateDefinitionBytes,
        aggregateDefinitionBytes
      );
    }
    const previousDefinitionDigest = requireDigest(entry.previousDefinitionDigest, `${id}.previousDefinitionDigest`);
    const currentDefinitionDigest = requireDigest(entry.currentDefinitionDigest, `${id}.currentDefinitionDigest`);
    const changedFields = normalizeStringList(entry.changedFields).sort();
    if (!Array.isArray(entry.changedFields)
      || canonicalDigest(changedFields) !== canonicalDigest(entry.changedFields)) {
      throw amendmentError(
        "OUTCOME_REVISION_DEFINITION_INVALID",
        `Outcome Revision ${id} changedFields must be a canonical unique list.`,
        { revisionId: id }
      );
    }
    const unknownChangedFields = changedFields.filter((field) => !DEFINITION_FIELD_PATHS.includes(field));
    if (unknownChangedFields.length > 0) {
      throw amendmentError(
        "OUTCOME_REVISION_DEFINITION_INVALID",
        `Outcome Revision ${id} names unsupported changed fields.`,
        { revisionId: id, unknownChangedFields }
      );
    }
    const rationale = requireString(entry.rationale, `${id}.rationale`);
    const rationaleBytes = Buffer.byteLength(rationale, "utf8");
    if (rationale.length < 12) {
      throw amendmentError(
        "OUTCOME_REVISION_DEFINITION_INVALID",
        `Outcome Revision ${id} requires a substantive rationale.`,
        { revisionId: id }
      );
    }
    if (rationaleBytes > OUTCOME_PLAN_AMENDMENT_LIMITS.rationaleBytes) {
      throw limitError("revision-rationale-bytes", OUTCOME_PLAN_AMENDMENT_LIMITS.rationaleBytes, rationaleBytes, { revisionId: id });
    }
    return {
      id,
      outcomeRef,
      amendmentChangeId: requireString(entry.amendmentChangeId, `${id}.amendmentChangeId`),
      governanceBaselineDigest: requireDigest(entry.governanceBaselineDigest, `${id}.governanceBaselineDigest`),
      previousDefinition,
      previousDefinitionDigest,
      currentDefinitionDigest,
      changedFields,
      rationale,
      requiredAuthorityRef: requireString(entry.requiredAuthorityRef, `${id}.requiredAuthorityRef`)
    };
  });
}

function normalizeOutcomeDefinition(outcome, label, { allowLegacyIdReferences = false } = {}) {
  assertPlainObject(outcome, "OUTCOME_REVISION_DEFINITION_INVALID", `${label} must be an Outcome object.`);
  const definitionSource = cloneJson(outcome);
  delete definitionSource.status;
  assertOnlyKeys(definitionSource, OUTCOME_DEFINITION_KEYS, label);
  const acceptance = definitionSource.acceptance;
  assertPlainObject(acceptance, "OUTCOME_REVISION_DEFINITION_INVALID", `${label}.acceptance must be an object.`);
  assertOnlyKeys(acceptance, ACCEPTANCE_DEFINITION_KEYS, `${label}.acceptance`);
  const criteria = asArray(acceptance.criteria).map((criterion, index) => {
    assertPlainObject(
      criterion,
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label}.acceptance.criteria[${index}] must be an object.`
    );
    assertOnlyKeys(criterion, CRITERION_DEFINITION_KEYS, `${label}.acceptance.criteria[${index}]`);
    return {
      id: requireString(criterion.id, `${label} Criterion id`),
      statement: requireString(criterion.statement, `${label} Criterion statement`),
      claimRefs: normalizeDefinitionReferenceList(
        criterion.claimRefs,
        `${label} Criterion claimRefs`
      ).sort(),
      gapRefs: normalizeDefinitionReferenceList(
        criterion.gapRefs,
        `${label} Criterion gapRefs`
      ).sort()
    };
  }).sort((left, right) => left.id.localeCompare(right.id));
  const duplicateCriterionIds = duplicates(criteria.map((criterion) => criterion.id));
  if (duplicateCriterionIds.length > 0) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} repeats Criterion ids.`,
      { duplicateCriterionIds }
    );
  }
  const normalized = {
    id: requireString(definitionSource.id, `${label}.id`),
    stage: requireString(definitionSource.stage, `${label}.stage`),
    outcome: requireString(definitionSource.outcome, `${label}.outcome`),
    dependsOn: normalizeDefinitionReferenceList(
      definitionSource.dependsOn,
      `${label}.dependsOn`,
      { allowLegacyIdReferences }
    ).sort(),
    kind: readString(definitionSource.kind) ?? null,
    allowedChangeKinds: normalizeDefinitionList(
      definitionSource.allowedChangeKinds,
      `${label}.allowedChangeKinds`
    ).sort(),
    acceptance: {
      activationCriterionRefs: normalizeDefinitionReferenceList(
        acceptance.activationCriterionRefs,
        `${label}.acceptance.activationCriterionRefs`,
        { allowLegacyIdReferences }
      ).sort(),
      criteria,
      exitCriteria: normalizeDefinitionList(
        acceptance.exitCriteria,
        `${label}.acceptance.exitCriteria`
      ).sort(),
      claimRefs: normalizeDefinitionReferenceList(
        acceptance.claimRefs,
        `${label}.acceptance.claimRefs`,
        { allowLegacyIdReferences }
      ).sort(),
      gapRefs: normalizeDefinitionReferenceList(
        acceptance.gapRefs,
        `${label}.acceptance.gapRefs`,
        { allowLegacyIdReferences }
      ).sort()
    },
    nonGoals: normalizeDefinitionList(definitionSource.nonGoals, `${label}.nonGoals`).sort()
  };
  const bytes = jsonBytes(normalized);
  if (bytes > OUTCOME_PLAN_AMENDMENT_LIMITS.definitionBytes) {
    throw limitError("outcome-definition-bytes", OUTCOME_PLAN_AMENDMENT_LIMITS.definitionBytes, bytes, { outcomeRef: normalized.id });
  }
  return normalized;
}

function deriveChangedFields(previousDefinition, currentDefinition) {
  return DEFINITION_FIELD_PATHS.filter((field) => (
    canonicalDigest(readPath(previousDefinition, field)) !== canonicalDigest(readPath(currentDefinition, field))
  )).sort();
}

function assertPlanAmendmentIdentity({ governanceBaseline, currentModel, baselinePlan, currentPlan }) {
  const baselineProjectId = readProjectId(governanceBaseline);
  const currentProjectId = readProjectId(currentModel);
  if (!baselineProjectId || currentProjectId !== baselineProjectId) {
    throw amendmentError(
      "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      "An Outcome Plan Amendment must preserve the frozen Project identity.",
      { baselineProjectId: baselineProjectId ?? null, currentProjectId: currentProjectId ?? null }
    );
  }
  if (readString(baselinePlan.id) !== readString(currentPlan.id)) {
    throw amendmentError(
      "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      "An Outcome Plan Amendment cannot replace the Development Plan identity.",
      { baselinePlanId: readString(baselinePlan.id) ?? null, currentPlanId: readString(currentPlan.id) ?? null }
    );
  }
}

function assertPlanAmendmentCannotSelfAuthorize(change) {
  if (change?.planRefs !== undefined && !Array.isArray(change.planRefs)) {
    throw amendmentError(
      "OUTCOME_PLAN_SELF_AUTHORIZATION_FORBIDDEN",
      "A Plan Amendment requires an empty planRefs list.",
      { problems: ["plan-refs-invalid"] }
    );
  }
  const planRefs = normalizeDefinitionList(change?.planRefs, "Plan Amendment planRefs");
  if (planRefs.length > 0) {
    throw amendmentError(
      "OUTCOME_PLAN_SELF_AUTHORIZATION_FORBIDDEN",
      "A Plan Amendment cannot reference the Development Plan that it changes.",
      { planRefs: planRefs.slice(0, 32) }
    );
  }
}

function assertPlanLimits(baselinePlan, currentPlan) {
  const observed = Math.max(asArray(baselinePlan?.outcomes).length, asArray(currentPlan?.outcomes).length);
  if (observed > OUTCOME_PLAN_AMENDMENT_LIMITS.outcomes) {
    throw limitError("outcomes", OUTCOME_PLAN_AMENDMENT_LIMITS.outcomes, observed);
  }
}

function assertGovernanceBaselineSeal(governanceBaseline) {
  assertPlainObject(
    governanceBaseline,
    "OUTCOME_PLAN_BASELINE_INVALID",
    "Outcome Plan Amendment compilation requires a sealed Governance Baseline."
  );
  const { digest, ...snapshot } = governanceBaseline;
  if (!DIGEST_PATTERN.test(readString(digest) ?? "") || canonicalDigest(snapshot) !== digest) {
    throw amendmentError(
      "OUTCOME_PLAN_BASELINE_INVALID",
      "The frozen Governance Baseline does not match its canonical digest.",
      { problems: ["governance-baseline-digest-mismatch"] }
    );
  }
}

function assertLedgerPrefix({ baselineLedger, currentLedger, code, label }) {
  if (currentLedger.length < baselineLedger.length) {
    throw amendmentError(code, `${label} history cannot be deleted.`, {
      baselineLength: baselineLedger.length,
      currentLength: currentLedger.length
    });
  }
  const mismatchIndex = baselineLedger.findIndex((entry, index) => (
    canonicalDigest(entry) !== canonicalDigest(currentLedger[index])
  ));
  if (mismatchIndex >= 0) {
    throw amendmentError(code, `${label} history cannot be reordered or rewritten.`, {
      mismatchIndex,
      baselineEntryId: readString(baselineLedger[mismatchIndex]?.id) ?? null,
      currentEntryId: readString(currentLedger[mismatchIndex]?.id) ?? null
    });
  }
}

function normalizeOpaqueLedger(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw amendmentError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      `${label} ledger must be an array.`
    );
  }
  if (value.length > OUTCOME_PLAN_AMENDMENT_LIMITS.transitionEntries) {
    throw limitError("transition-entries", OUTCOME_PLAN_AMENDMENT_LIMITS.transitionEntries, value.length);
  }
  const observedBytes = jsonBytes(value);
  if (observedBytes > OUTCOME_PLAN_AMENDMENT_LIMITS.transitionLedgerBytes) {
    throw limitError(
      "transition-ledger-bytes",
      OUTCOME_PLAN_AMENDMENT_LIMITS.transitionLedgerBytes,
      observedBytes
    );
  }
  return cloneJson(value);
}

function assertTransitionLedgerValid(plan, knowledgeGaps, label) {
  const validation = validateOutcomeTransitionLedger(plan, knowledgeGaps);
  if (validation.valid) return;
  throw amendmentError(
    "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
    `The ${label} Outcome Transition ledger is invalid.`,
    {
      errorCount: validation.errors.length,
      issueCodes: validation.errors.map((entry) => entry.code).slice(0, 32)
    }
  );
}

function indexOutcomes(value, label) {
  if (!Array.isArray(value)) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} Development Plan outcomes must be an array.`
    );
  }
  const index = new Map();
  for (const outcome of value) {
    const outcomeRef = readString(outcome?.id);
    if (!outcomeRef || index.has(outcomeRef)) {
      throw amendmentError(
        "OUTCOME_REVISION_DEFINITION_INVALID",
        `${label} Development Plan Outcomes require unique stable ids.`,
        { outcomeRef: outcomeRef ?? null }
      );
    }
    index.set(outcomeRef, outcome);
  }
  return index;
}

function finalizeCompilation({
  change,
  governanceBaseline,
  baselinePlan,
  currentPlan,
  transitionCompilation,
  amendmentKind,
  appendedRevisions,
  activationBindings,
  priorAcceptedPackages
}) {
  const mode = readString(governanceBaseline?.projectDocument?.changePolicy?.outcomeTransitionMode)
    ?? "declared";
  const appendedTransitions = cloneJson(transitionCompilation?.appendedTransitions ?? []);
  const unresolved = cloneJson(transitionCompilation?.unresolved ?? []);
  const status = amendmentKind === "revision"
    ? "complete"
    : transitionCompilation?.status ?? "not-applicable";
  const projection = {
    schemaVersion: OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION,
    mode,
    status,
    amendmentKind,
    priorAcceptedPackagesDigest: readString(transitionCompilation?.priorAcceptedPackagesDigest)
      ?? readString(priorAcceptedPackages?.digest)
      ?? readString(change?.priorAcceptedPackages?.digest)
      ?? null,
    baselinePlanDigest: baselinePlan ? canonicalDigest(baselinePlan) : null,
    currentPlanDigest: currentPlan ? canonicalDigest(currentPlan) : null,
    requiredAuthorityRef: readString(baselinePlan?.authority) ?? null,
    appendedRevisions: cloneJson(appendedRevisions),
    appendedTransitions,
    activationBindings: cloneJson(activationBindings),
    unresolved
  };
  return cloneJson({
    ...projection,
    digest: canonicalDigest({
      ...projection,
      changeId: readString(change?.id) ?? null,
      governanceBaselineDigest: readString(governanceBaseline?.digest) ?? null
    })
  });
}

function requirePlan(value, label) {
  assertPlainObject(
    value,
    "OUTCOME_REVISION_DEFINITION_INVALID",
    `Outcome Plan Amendment compilation requires a ${label} Development Plan.`
  );
  return value;
}

function requireDigest(value, label) {
  const digest = readString(value);
  if (!digest || !DIGEST_PATTERN.test(digest)) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} must be a canonical sha256 digest.`
    );
  }
  return digest;
}

function requireString(value, label) {
  const normalized = readString(value);
  if (!normalized) {
    throw amendmentError("OUTCOME_REVISION_DEFINITION_INVALID", `${label} must be substantive.`);
  }
  return normalized;
}

function assertOnlyKeys(value, allowed, label) {
  const unexpectedFields = Object.keys(value).filter((key) => !allowed.includes(key)).sort();
  if (unexpectedFields.length > 0) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} contains unsupported fields.`,
      { unexpectedFields: unexpectedFields.slice(0, 32) }
    );
  }
}

function assertPlainObject(value, code, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw amendmentError(code, message);
  }
}

function readProjectId(value) {
  return readString(value?.projectDocument?.project?.id)
    ?? readString(value?.project?.id);
}

function readReference(value) {
  if (typeof value === "string") return readString(value);
  return readString(value?.id) ?? readString(value?.authority);
}

function readPath(value, field) {
  return field.split(".").reduce((current, segment) => current?.[segment], value);
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeStringList(value) {
  return [...new Set(asArray(value).map(readString).filter(Boolean))];
}

function normalizeDefinitionList(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((entry) => !readString(entry))) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} must be a list of substantive strings.`
    );
  }
  return [...new Set(value.map((entry) => entry.trim()))];
}

function normalizeDefinitionReferenceList(value, label, { allowLegacyIdReferences = false } = {}) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} must be a list of stable references.`
    );
  }
  const references = value.map((entry) => readStableReference(entry, { allowLegacyIdReferences }));
  if (references.some((entry) => !entry)) {
    throw amendmentError(
      "OUTCOME_REVISION_DEFINITION_INVALID",
      `${label} contains an invalid stable reference.`
    );
  }
  return [...new Set(references)];
}

function readStableReference(value, { allowLegacyIdReferences }) {
  if (typeof value === "string") return readString(value);
  if (!allowLegacyIdReferences || !value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const fields = Object.keys(value);
  return fields.length === 1 && fields[0] === "id" ? readString(value.id) : undefined;
}

function uniqueStrings(value) {
  return [...new Set(value.filter(Boolean))];
}

function duplicates(value) {
  const seen = new Set();
  return [...new Set(value.filter((entry) => {
    if (seen.has(entry)) return true;
    seen.add(entry);
    return false;
  }))].sort();
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function jsonBytes(value) {
  return Buffer.byteLength(JSON.stringify(value), "utf8");
}

function compareRevisions(left, right) {
  return left.outcomeRef.localeCompare(right.outcomeRef) || left.id.localeCompare(right.id);
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function limitError(limitId, limit, observed, details = {}) {
  return amendmentError(
    "OUTCOME_PLAN_LIMIT_EXCEEDED",
    `Outcome Plan Amendment limit exceeded: ${limitId}.`,
    { limitId, limit, observed, ...details },
    413
  );
}

function amendmentError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details) error.details = cloneJson(details);
  return error;
}
