import { canonicalDigest, cloneJson } from "./canonical.mjs";
import { compileOutcomeAlignmentAgainstGovernance } from "./change-compiler.mjs";

export const OUTCOME_TRANSITION_SCHEMA_VERSION = 1;

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const DEFAULT_ALLOWED_ROUTES = new Set([
  "planned->active",
  "conditional->active",
  "active->achieved",
  "planned->retired",
  "conditional->retired",
  "active->retired"
]);

export function compileOutcomeTransitions({
  change,
  governanceBaseline,
  currentModel,
  resolvedPackages = [],
  priorAcceptedPackages = null
} = {}) {
  const baselinePlan = governanceBaseline?.plan;
  const currentPlan = currentModel?.plan;
  const mode = readString(governanceBaseline?.projectDocument?.changePolicy?.outcomeTransitionMode)
    ?? "declared";
  if ((readString(change?.changeKind) ?? "implementation") !== "plan-amendment") {
    return finalizeCompilation({
      mode,
      status: "not-applicable",
      change,
      governanceBaseline,
      baselinePlan,
      currentPlan,
      appendedTransitions: [],
      unresolved: []
    });
  }
  if (!baselinePlan || !currentPlan) {
    throw transitionError(
      "OUTCOME_TRANSITION_STATUS_UNBOUND",
      "A plan-amendment requires both frozen and current Development Plans before Transitions can compile."
    );
  }
  assertGovernanceBaselineSeal(governanceBaseline);
  const baselineProjectId = readProjectId(governanceBaseline);
  const currentProjectId = readProjectId(currentModel);
  if (!baselineProjectId || currentProjectId !== baselineProjectId) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      "A Transition amendment must preserve the frozen Project identity.",
      { baselineProjectId: baselineProjectId ?? null, currentProjectId: currentProjectId ?? null }
    );
  }
  if (readString(baselinePlan.id) !== readString(currentPlan.id)) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      "A Transition amendment cannot replace the frozen Development Plan identity.",
      { baselinePlanId: baselinePlan.id ?? null, currentPlanId: currentPlan.id ?? null }
    );
  }

  const baselineLedger = normalizeLedger(baselinePlan.outcomeTransitions, "frozen");
  const currentLedger = normalizeLedger(currentPlan.outcomeTransitions, "current");
  assertLedgerPrefix(baselineLedger, currentLedger);
  const appended = currentLedger.slice(baselineLedger.length);
  const statusDeltas = collectStatusDeltas(baselinePlan, currentPlan);
  assertExistingOutcomeSemanticsFrozen(baselinePlan, currentPlan);
  assertNewOutcomeStatuses(baselinePlan, currentPlan);
  const matched = matchTransitions(statusDeltas, appended);
  if (matched.unexpected.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_STATUS_UNBOUND",
      "Every appended Outcome Transition must bind exactly one frozen-to-current status delta.",
      { unexpectedTransitionIds: matched.unexpected.map((entry) => entry.id) }
    );
  }
  if (matched.duplicate.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_STATUS_UNBOUND",
      "Each Outcome status delta must have exactly one appended Transition.",
      { duplicateOutcomeRefs: matched.duplicate }
    );
  }

  const unresolved = matched.missing.map((delta) => ({
    outcomeRef: delta.outcomeRef,
    from: delta.from,
    to: delta.to,
    reason: "status-delta-has-no-appended-transition"
  }));
  if (unresolved.length > 0 && mode === "enforced") {
    throw transitionError(
      "OUTCOME_TRANSITION_STATUS_UNBOUND",
      "Enforced Outcome status changes require exactly one appended Transition.",
      { unresolved }
    );
  }

  const packageRecords = new Map();
  const duplicatePackageRecordIds = [];
  for (const record of asArray(resolvedPackages)) {
    const recordId = readString(record?.id);
    if (!recordId) continue;
    if (packageRecords.has(recordId)) duplicatePackageRecordIds.push(recordId);
    packageRecords.set(recordId, record);
  }
  if (duplicatePackageRecordIds.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      "Resolved Accepted Package records must be unique by Change id.",
      { duplicatePackageRecordIds: [...new Set(duplicatePackageRecordIds)].sort() }
    );
  }
  const priorCatalog = normalizePriorAcceptedPackages(priorAcceptedPackages);
  const priorRefs = priorCatalog.refs;
  const targetClaimIndex = new Map(asArray(governanceBaseline.contracts)
    .flatMap((contract) => asArray(contract?.claims))
    .map((claim) => [readString(claim?.id), claim])
    .filter(([id]) => Boolean(id)));
  const baselineGaps = indexKnowledgeGaps(governanceBaseline?.knowledgeGaps, "frozen");
  const currentGaps = indexKnowledgeGaps(currentModel?.knowledgeGaps, "current");
  const allowedRoutes = new Set(normalizeStringList(
    baselinePlan?.outcomeGovernance?.transition?.allowed
  ));
  if (allowedRoutes.size === 0) {
    for (const route of DEFAULT_ALLOWED_ROUTES) allowedRoutes.add(route);
  }

  const appendedTransitions = matched.bound.map(({ delta, transition }) => compileTransition({
    change,
    governanceBaseline,
    baselinePlan,
    baselineLedger,
    delta,
    transition,
    packageRecords,
    priorRefs,
    targetClaimIndex,
    baselineGaps,
    currentGaps,
    allowedRoutes
  })).sort(compareTransitions);

  return finalizeCompilation({
    mode,
    status: unresolved.length > 0 ? "unresolved" : appendedTransitions.length > 0 ? "complete" : "not-applicable",
    change,
    governanceBaseline,
    baselinePlan,
    currentPlan,
    appendedTransitions,
    unresolved,
    priorAcceptedPackagesDigest: priorCatalog.digest
  });
}

export function collectOutcomeTransitionPackageRefs({ baselinePlan, currentPlan } = {}) {
  const baselineLedger = normalizeLedger(baselinePlan?.outcomeTransitions, "frozen");
  const currentLedger = normalizeLedger(currentPlan?.outcomeTransitions, "current");
  assertLedgerPrefix(baselineLedger, currentLedger);
  return uniquePackageRefs(currentLedger.slice(baselineLedger.length)
    .flatMap((entry) => entry.packageRefs));
}

export function validateOutcomeTransitionLedger(plan) {
  const errors = [];
  let ledger;
  try {
    ledger = normalizeLedger(plan?.outcomeTransitions, "plan");
  } catch (error) {
    return {
      valid: false,
      errors: [{
        code: "plan.outcome-transition.invalid",
        location: ".legatura/plan.json#outcomeTransitions",
        message: error.message,
        details: { causeCode: error.code ?? null, ...error.details }
      }]
    };
  }
  const outcomes = new Map(asArray(plan?.outcomes)
    .map((outcome) => [readString(outcome?.id), outcome])
    .filter(([id]) => Boolean(id)));
  const seenIds = new Set();
  for (const entry of ledger) {
    const location = `.legatura/plan.json#${entry.id}`;
    if (seenIds.has(entry.id)) {
      errors.push(ledgerIssue("plan.outcome-transition.id.duplicate", location, `Duplicate Transition id: ${entry.id}.`));
    }
    seenIds.add(entry.id);
    const outcome = outcomes.get(entry.outcomeRef);
    if (!outcome) {
      errors.push(ledgerIssue("plan.outcome-transition.outcome.unknown", location, `Unknown Outcome: ${entry.outcomeRef}.`));
      continue;
    }
    if (!new RegExp(`^${escapeRegExp(entry.outcomeRef)}-T[1-9][0-9]*$`, "u").test(entry.id)) {
      errors.push(ledgerIssue(
        "plan.outcome-transition.id.invalid",
        location,
        `Transition id must use the stable ${entry.outcomeRef}-Tn form.`
      ));
    }
    const criteria = new Set(asArray(outcome?.acceptance?.criteria).map((criterion) => readString(criterion?.id)));
    const gaps = new Set(normalizeStringList(outcome?.acceptance?.gapRefs));
    for (const assessment of entry.criterionAssessments) {
      if (!criteria.has(assessment.criterionRef)) {
        errors.push(ledgerIssue(
          "plan.outcome-transition.criterion.unknown",
          location,
          `Transition references unknown Criterion ${assessment.criterionRef}.`
        ));
      }
    }
    for (const disposition of entry.gapDispositions) {
      if (!gaps.has(disposition.gapRef)) {
        errors.push(ledgerIssue(
          "plan.outcome-transition.gap.unknown",
          location,
          `Transition references undeclared Outcome Gap ${disposition.gapRef}.`
        ));
      }
    }
  }
  return { valid: errors.length === 0, errors };
}

export function inspectAcceptedPackageRecord(record) {
  const problems = [];
  const recordId = readString(record?.id);
  const recordState = readString(record?.state);
  const acceptanceDigest = readString(record?.acceptance?.digest);
  const packageContent = record?.acceptance?.package;
  if (!recordId) problems.push("record-id-missing");
  if (!DIGEST_PATTERN.test(acceptanceDigest ?? "")) problems.push("acceptance-digest-invalid");
  if (!packageContent || typeof packageContent !== "object" || Array.isArray(packageContent)) {
    problems.push("package-missing");
  } else {
    if (readString(packageContent.changeId) !== recordId) problems.push("package-change-id-mismatch");
    if (canonicalDigest(packageContent) !== acceptanceDigest) problems.push("package-digest-mismatch");
    const frozen = packageContent.governanceBaseline;
    if (!frozen?.digest) {
      problems.push("governance-baseline-missing");
    } else {
      const { digest, ...snapshot } = frozen;
      if (canonicalDigest(snapshot) !== digest) problems.push("governance-baseline-digest-mismatch");
    }
  }
  const acceptedEvents = asArray(record?.history).filter((event) => (
    event?.from === "EvidenceReady"
      && event?.to === "Accepted"
      && event?.digest === acceptanceDigest
  ));
  if (acceptedEvents.length === 0) problems.push("accepted-history-missing");
  if (acceptedEvents.length > 1) problems.push("accepted-history-ambiguous");
  const acceptedAt = readString(record?.acceptance?.acceptedAt);
  if (!acceptedAt) problems.push("accepted-at-missing");
  else if (!Number.isFinite(Date.parse(acceptedAt))) problems.push("accepted-at-invalid");
  if (acceptedEvents.some((event) => !Number.isFinite(Date.parse(event?.at)))) {
    problems.push("accepted-history-at-invalid");
  }
  if (acceptedEvents.length === 1 && acceptedEvents[0]?.at !== acceptedAt) {
    problems.push("accepted-at-history-mismatch");
  }
  const history = asArray(record?.history);
  if (history.length === 0 || readString(history.at(-1)?.to) !== recordState) {
    problems.push("record-state-history-mismatch");
  }
  return {
    valid: problems.length === 0,
    problems,
    reference: problems.length === 0 ? { changeId: recordId, acceptanceDigest } : null,
    acceptedAt: acceptedAt ?? null,
    package: packageContent ?? null
  };
}

function compileTransition({
  change,
  governanceBaseline,
  baselinePlan,
  baselineLedger,
  delta,
  transition,
  packageRecords,
  priorRefs,
  targetClaimIndex,
  baselineGaps,
  currentGaps,
  allowedRoutes
}) {
  const route = `${delta.from}->${delta.to}`;
  if (!allowedRoutes.has(route)) {
    throw transitionError(
      "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
      `Frozen transition policy does not allow ${route}.`,
      { outcomeRef: delta.outcomeRef, route }
    );
  }
  const { criteria, dependencyProofs } = requiredCriteria({ delta, baselinePlan, baselineLedger });
  const expectedCriterionRefs = criteria.map((criterion) => criterion.id).sort();
  const observedCriterionRefs = transition.criterionAssessments
    .map((assessment) => assessment.criterionRef).sort();
  const duplicateCriterionRefs = duplicates(observedCriterionRefs);
  const missingCriterionRefs = expectedCriterionRefs.filter((ref) => !observedCriterionRefs.includes(ref));
  const unexpectedCriterionRefs = observedCriterionRefs.filter((ref) => !expectedCriterionRefs.includes(ref));
  if (duplicateCriterionRefs.length > 0 || missingCriterionRefs.length > 0 || unexpectedCriterionRefs.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_CRITERIA_INCOMPLETE",
      "Transition Criterion proofs must exactly cover the Criteria derived from the frozen Outcome.",
      { outcomeRef: delta.outcomeRef, missingCriterionRefs, unexpectedCriterionRefs, duplicateCriterionRefs }
    );
  }

  const resolvedPool = transition.packageRefs.map((ref) => ({
    ref,
    inspection: resolvePackage({ ref, change, packageRecords, priorRefs, baselinePlan, governanceBaseline })
  }));
  const usedPackageKeys = new Set();

  const criterionProofs = criteria.map((criterion) => {
    const supplied = transition.criterionAssessments
      .find((assessment) => assessment.criterionRef === criterion.id);
    return compileCriterionProof({
      outcome: delta.baselineOutcome,
      criterion,
      supplied,
      resolvedPool,
      targetClaimIndex,
      usedPackageKeys
    });
  });
  const requiredGapRefs = [...new Set(criteria.flatMap((criterion) => normalizeStringList(criterion.gapRefs)))].sort();
  const observedGapRefs = transition.gapDispositions.map((entry) => entry.gapRef).sort();
  const missingGapRefs = requiredGapRefs.filter((ref) => !observedGapRefs.includes(ref));
  const unexpectedGapRefs = observedGapRefs.filter((ref) => !requiredGapRefs.includes(ref));
  const duplicateGapRefs = duplicates(observedGapRefs);
  if (missingGapRefs.length > 0 || unexpectedGapRefs.length > 0 || duplicateGapRefs.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      "Transition Gap dispositions must exactly cover the Gaps declared by its required Criteria.",
      { outcomeRef: delta.outcomeRef, missingGapRefs, unexpectedGapRefs, duplicateGapRefs }
    );
  }
  const gapDispositions = requiredGapRefs.map((gapRef) => compileGapDisposition({
    gapRef,
    supplied: transition.gapDispositions.find((entry) => entry.gapRef === gapRef),
    resolvedPool,
    baselineGaps,
    currentGaps,
    usedPackageKeys
  }));
  const unusedPackageRefs = transition.packageRefs
    .filter((ref) => !usedPackageKeys.has(packageRefKey(ref)));
  if (unusedPackageRefs.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      "Every Package selected for a Transition must prove a required Criterion or close a required Gap.",
      { outcomeRef: delta.outcomeRef, unusedPackageRefs }
    );
  }
  const compiled = {
    id: transition.id,
    outcomeRef: delta.outcomeRef,
    from: delta.from,
    to: delta.to,
    rationale: transition.rationale,
    requiredAuthorityRef: readString(baselinePlan.authority) ?? null,
    dependencyProofs,
    criterionProofs,
    gapDispositions
  };
  const bindingDigest = canonicalDigest({
    schemaVersion: OUTCOME_TRANSITION_SCHEMA_VERSION,
    changeId: change.id,
    governanceBaselineDigest: governanceBaseline.digest,
    transition: compiled
  });
  return { ...compiled, bindingDigest };
}

function compileCriterionProof({
  outcome,
  criterion,
  supplied,
  resolvedPool,
  targetClaimIndex,
  usedPackageKeys
}) {
  const assessment = supplied?.authorityAssessment;
  if (assessment?.conclusion !== "satisfied"
    || !readString(assessment?.rationale)
    || !isSubstantive(assessment?.residualUncertainty)) {
    throw transitionError(
      "OUTCOME_TRANSITION_ASSESSMENT_REQUIRED",
      `Criterion ${criterion.id} requires a substantive Plan-authority assessment.`,
      { outcomeRef: outcome.id, criterionRef: criterion.id }
    );
  }
  const requiredClaimRefs = normalizeStringList(criterion.claimRefs).sort();
  if (requiredClaimRefs.length > 0 && resolvedPool.length === 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      `Criterion ${criterion.id} has Claims but no prior Accepted Package proof.`,
      { outcomeRef: outcome.id, criterionRef: criterion.id, problems: ["package-proof-missing"] }
    );
  }
  if (requiredClaimRefs.length === 0 && normalizeStringList(criterion.gapRefs).length === 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      `Criterion ${criterion.id} declares no machine-checkable Claim or Gap proof source.`,
      { outcomeRef: outcome.id, criterionRef: criterion.id, problems: ["proof-source-missing"] }
    );
  }

  const observedClaimRefs = new Set();
  const packages = resolvedPool.flatMap(({ ref, inspection }) => {
    const packageContent = inspection.package;
    const exception = asArray(packageContent?.outcomeAlignment?.exceptions).some((entry) => (
      entry?.outcomeRef === outcome.id
    ));
    if (exception) {
      throw transitionError(
        "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
        `Accepted Package ${ref.changeId} contains a non-progress exception for ${outcome.id}.`,
        {
          outcomeRef: outcome.id,
          criterionRef: criterion.id,
          changeId: ref.changeId,
          problems: ["exception-proof-forbidden"]
        }
      );
    }
    const contributions = asArray(packageContent?.outcomeAlignment?.contributions).filter((entry) => (
      entry?.outcomeRef === outcome.id && entry?.criterionRef === criterion.id
    ));
    if (contributions.length > 1) {
      throw transitionError(
        "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
        `Accepted Package ${ref.changeId} contains ambiguous Contributions for ${criterion.id}.`,
        {
          outcomeRef: outcome.id,
          criterionRef: criterion.id,
          changeId: ref.changeId,
          problems: ["exact-contribution-ambiguous"]
        }
      );
    }
    if (contributions.length === 0) return [];
    const contribution = contributions[0];
    const contributionClaims = validateContributionBinding({
      packageContent,
      contribution,
      targetOutcome: outcome,
      targetCriterion: criterion,
      targetClaimIndex
    });
    contributionClaims.forEach((claim) => observedClaimRefs.add(claim.id));
    const evidenceBindings = deriveEvidenceBindings(packageContent, contributionClaims, {
      outcomeRef: outcome.id,
      criterionRef: criterion.id,
      changeId: ref.changeId
    });
    usedPackageKeys.add(packageRefKey(ref));
    return [{
      changeId: ref.changeId,
      acceptanceDigest: ref.acceptanceDigest,
      acceptedAt: inspection.acceptedAt,
      contributionId: contribution.contributionId,
      contributionBindingDigest: contribution.bindingDigest,
      claimRefs: contributionClaims.map((claim) => claim.id).sort(),
      evidenceBindings
    }];
  }).sort(comparePackageProofs);
  const missingClaimRefs = requiredClaimRefs.filter((ref) => !observedClaimRefs.has(ref));
  const unexpectedClaimRefs = [...observedClaimRefs].filter((ref) => !requiredClaimRefs.includes(ref)).sort();
  if (missingClaimRefs.length > 0 || unexpectedClaimRefs.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      `Accepted Package Contributions do not exactly cover Criterion ${criterion.id} Claims.`,
      { outcomeRef: outcome.id, criterionRef: criterion.id, missingClaimRefs, unexpectedClaimRefs }
    );
  }
  return {
    criterionRef: criterion.id,
    claimRefs: requiredClaimRefs,
    gapRefs: normalizeStringList(criterion.gapRefs).sort(),
    authorityAssessment: cloneJson(assessment),
    packages
  };
}

function compileGapDisposition({
  gapRef,
  supplied,
  resolvedPool,
  baselineGaps,
  currentGaps,
  usedPackageKeys
}) {
  const frozenGap = baselineGaps.get(gapRef);
  const gap = currentGaps.get(gapRef);
  if (!frozenGap || canonicalDigest(gapSemanticValue(frozenGap)) !== canonicalDigest(gapSemanticValue(gap))) {
    throw transitionError(
      "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      `Knowledge Gap ${gapRef} must preserve its frozen meaning while its closure is assessed.`,
      { gapRef, problems: [frozenGap ? "gap-semantic-mismatch" : "frozen-gap-missing"] }
    );
  }
  if (gap?.status !== "closed"
    || !readString(gap?.resolution)
    || !readString(gap?.reopenTrigger)
    || !readString(supplied?.rationale)) {
    throw transitionError(
      "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      `Knowledge Gap ${gapRef} is not durably closed with a substantive disposition.`,
      { gapRef }
    );
  }
  const declaredRefs = uniquePackageRefs(gap.closedBy ?? []);
  if (declaredRefs.length === 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      `Gap disposition ${gapRef} requires at least one Accepted Package in Knowledge Gap closedBy.`,
      { gapRef, declaredRefs }
    );
  }
  const packages = declaredRefs.map((ref) => {
    const selected = resolvedPool.find((entry) => packageRefKey(entry.ref) === packageRefKey(ref));
    if (!selected) {
      throw transitionError(
        "OUTCOME_TRANSITION_GAP_UNRESOLVED",
        `Gap disposition ${gapRef} closedBy Packages must be selected in the Transition Evidence pool.`,
        { gapRef, missingPackageRef: ref }
      );
    }
    usedPackageKeys.add(packageRefKey(ref));
    return { ...ref, acceptedAt: selected.inspection.acceptedAt };
  }).sort(comparePackageProofs);
  return {
    gapRef,
    rationale: supplied.rationale,
    resolution: gap.resolution,
    reopenTrigger: gap.reopenTrigger,
    packages
  };
}

function resolvePackage({ ref, change, packageRecords, priorRefs, baselinePlan, governanceBaseline }) {
  if (ref.changeId === change.id) {
    throw transitionError(
      "OUTCOME_TRANSITION_SELF_PROOF_FORBIDDEN",
      "A plan-amendment cannot cite itself as Outcome Transition proof.",
      { changeId: change.id }
    );
  }
  if (!priorRefs.has(packageRefKey(ref))) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      "Outcome Transition proof must already exist in the Candidate's frozen Accepted Package catalog.",
      { reference: ref }
    );
  }
  const record = packageRecords.get(ref.changeId);
  if (!record) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_FOUND",
      `Accepted Package record not found: ${ref.changeId}.`,
      { reference: ref }
    );
  }
  const inspection = inspectAcceptedPackageRecord(record);
  if (!inspection.valid
    || inspection.reference?.acceptanceDigest !== ref.acceptanceDigest) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      `Accepted Package ${ref.changeId} does not match its canonical seal and Accepted history.`,
      { reference: ref, problems: inspection.problems }
    );
  }
  const acceptedTime = Date.parse(inspection.acceptedAt);
  const changeTime = Date.parse(readString(change.createdAt) ?? "");
  if (!Number.isFinite(changeTime) || acceptedTime > changeTime) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      `Accepted Package ${ref.changeId} does not predate the Transition Candidate.`,
      {
        reference: ref,
        acceptedAt: inspection.acceptedAt,
        candidateCreatedAt: change.createdAt ?? null
      }
    );
  }
  const packageContent = inspection.package;
  if (baselinePlan && readString(packageContent?.governanceBaseline?.plan?.id) !== readString(baselinePlan.id)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      `Accepted Package ${ref.changeId} belongs to a different Development Plan.`,
      { reference: ref, problems: ["plan-identity-mismatch"] }
    );
  }
  const targetProjectId = readString(governanceBaseline?.projectDocument?.project?.id)
    ?? readString(governanceBaseline?.project?.id);
  const packageProjectId = readString(packageContent?.governanceBaseline?.projectDocument?.project?.id)
    ?? readString(packageContent?.governanceBaseline?.project?.id);
  if (targetProjectId && packageProjectId !== targetProjectId) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      `Accepted Package ${ref.changeId} belongs to a different Project.`,
      { reference: ref, problems: ["project-identity-mismatch"] }
    );
  }
  if (readString(change.repoPath) && readString(packageContent?.repoPath) !== readString(change.repoPath)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      `Accepted Package ${ref.changeId} belongs to a different repository.`,
      { reference: ref, problems: ["repository-identity-mismatch"] }
    );
  }
  return inspection;
}

function validateContributionBinding({
  packageContent,
  contribution,
  targetOutcome,
  targetCriterion,
  targetClaimIndex
}) {
  const packageBaseline = packageContent.governanceBaseline;
  const packageOutcome = asArray(packageBaseline?.plan?.outcomes)
    .find((outcome) => outcome?.id === targetOutcome.id);
  const packageCriterion = asArray(packageOutcome?.acceptance?.criteria)
    .find((criterion) => criterion?.id === targetCriterion.id);
  const problems = [];
  if (packageContent.changeKind !== "implementation") problems.push("package-kind-not-implementation");
  if (packageContent.outcomeAlignment?.status !== "complete") problems.push("outcome-alignment-incomplete");
  if (contribution.moduleRef !== packageContent.primaryModule) problems.push("contribution-module-mismatch");
  try {
    const derivedAlignment = compileOutcomeAlignmentAgainstGovernance({
      id: packageContent.changeId,
      primaryModule: packageContent.primaryModule,
      changeKind: packageContent.changeKind,
      planRefs: cloneJson(packageContent.planRefs),
      claims: cloneJson(packageContent.claims),
      compilerInput: {
        outcomeContributionHints: cloneJson(packageContent.outcomeContributionHints),
        outcomeExceptions: cloneJson(packageContent.outcomeExceptions)
      }
    }, packageBaseline);
    if (canonicalDigest(derivedAlignment) !== canonicalDigest(packageContent.outcomeAlignment)) {
      problems.push("outcome-alignment-rederivation-mismatch");
    }
  } catch {
    problems.push("outcome-alignment-rederivation-failed");
  }
  if (readString(packageOutcome?.outcome) !== readString(targetOutcome.outcome)) {
    problems.push("outcome-semantic-mismatch");
  }
  if (canonicalDigest(criterionSemanticValue(packageCriterion))
    !== canonicalDigest(criterionSemanticValue(targetCriterion))) {
    problems.push("criterion-semantic-mismatch");
  }
  const rawContributionClaimRefs = asArray(contribution.claimRefs).map(readString);
  if (rawContributionClaimRefs.some((claimRef) => !claimRef)) problems.push("contribution-claim-invalid");
  if (duplicates(rawContributionClaimRefs.filter(Boolean)).length > 0) {
    problems.push("contribution-claim-duplicate");
  }
  const contributionClaimRefs = rawContributionClaimRefs.filter(Boolean);
  const claims = contributionClaimRefs.map((claimRef) => {
    const packageClaim = asArray(packageContent.claims).find((claim) => claim?.id === claimRef);
    const targetClaim = targetClaimIndex.get(claimRef);
    if (!packageClaim || !targetClaim || packageClaim.statement !== targetClaim.statement) {
      problems.push(`claim-semantic-mismatch:${claimRef}`);
    }
    return packageClaim;
  }).filter(Boolean);
  const binding = {
    schemaVersion: 1,
    changeId: packageContent.changeId,
    governanceBaselineDigest: packageBaseline.digest,
    outcome: { id: packageOutcome?.id, statement: packageOutcome?.outcome },
    criterion: cloneJson(packageCriterion),
    moduleRef: contribution.moduleRef,
    claims: claims.map((claim) => ({ id: claim.id, statement: claim.statement }))
  };
  const observedDigest = canonicalDigest(binding);
  if (contribution.bindingDigest !== observedDigest) problems.push("contribution-binding-digest-mismatch");
  if (contribution.contributionId !== `oc-${observedDigest.slice("sha256:".length)}`) {
    problems.push("contribution-id-mismatch");
  }
  if (problems.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      `Contribution ${contribution.contributionId ?? "unknown"} cannot prove the frozen Criterion.`,
      {
        outcomeRef: targetOutcome.id,
        criterionRef: targetCriterion.id,
        changeId: packageContent.changeId,
        problems
      }
    );
  }
  return claims;
}

function deriveEvidenceBindings(packageContent, claims, context) {
  const evidence = asArray(packageContent.evidence);
  const duplicateEvidenceIds = duplicates(evidence.map((item) => readString(item?.id)).filter(Boolean));
  const allRunBindingIds = asArray(packageContent.gateRuns)
    .flatMap((run) => asArray(run?.evidenceBindings).map((binding) => readString(binding?.id)).filter(Boolean));
  const duplicateRunBindingIds = duplicates(allRunBindingIds);
  if (duplicateEvidenceIds.length > 0 || duplicateRunBindingIds.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      `Accepted Package ${context.changeId} contains ambiguous Evidence identities.`,
      { ...context, problems: ["evidence-identity-ambiguous"], duplicateEvidenceIds, duplicateRunBindingIds }
    );
  }
  const summaries = new Map();
  for (const claim of claims) {
    const matching = evidence.filter((item) => {
      if (!isPositiveObservation(item?.observation)) return false;
      if (!["builtin-oracle", "gate-command"].includes(readString(item?.provenance?.kind))) return false;
      if (!readString(item?.oracle?.kind) || !isSubstantive(item?.residualUncertainty)) return false;
      if (!evidenceBindsOnePassedRun(item, packageContent)) return false;
      return (item?.claim?.id === claim.id && item?.claim?.statement === claim.statement)
        || asArray(item?.directSupportBindings).some((binding) => (
          binding?.claimId === claim.id && binding?.claimStatement === claim.statement
        ));
    });
    if (matching.length === 0) {
      throw transitionError(
        "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
        `Accepted Package ${context.changeId} has no bound positive Evidence for Claim ${claim.id}.`,
        { ...context, claimRef: claim.id, problems: ["bound-evidence-missing"] }
      );
    }
    for (const item of matching) {
      const existing = summaries.get(item.id) ?? {
        evidenceId: item.id,
        evidenceDigest: canonicalDigest(item),
        claimRefs: [],
        oracleKind: readString(item?.oracle?.kind) ?? null,
        observationStatus: readString(item?.observation?.status) ?? null,
        residualUncertainty: cloneJson(item.residualUncertainty)
      };
      existing.claimRefs = [...new Set([...existing.claimRefs, claim.id])].sort();
      summaries.set(item.id, existing);
    }
  }
  return [...summaries.values()].sort((left, right) => left.evidenceId.localeCompare(right.evidenceId));
}

function evidenceBindsOnePassedRun(item, packageContent) {
  const itemId = readString(item?.id);
  const itemDigest = canonicalDigest(item);
  if (!itemId) return false;
  const matchingRuns = asArray(packageContent.gateRuns).filter((run) => (
    asArray(run?.evidenceBindings).some((binding) => (
      binding?.id === itemId && binding?.digest === itemDigest
    ))
  ));
  if (matchingRuns.length !== 1) return false;
  const run = matchingRuns[0];
  if (run.status !== "passed") return false;
  if (asArray(run.evidenceIds).filter((id) => id === itemId).length !== 1) return false;
  const provenance = item.provenance ?? {};
  if (provenance.changeId !== packageContent.changeId
    || provenance.verificationSubjectDigest !== run.verificationSubjectDigest
    || provenance.projectModelDigest !== run.projectModelDigest
    || provenance?.git?.contentDigest !== run.gitContentDigest) {
    return false;
  }
  if (provenance.kind === "builtin-oracle") {
    return run.kind === "builtin-oracle";
  }
  if (provenance.kind !== "gate-command" || provenance.gateId !== run.gateId) return false;
  const commandResults = asArray(run.commandResults).filter((result) => result?.evidenceId === itemId);
  return commandResults.length === 1
    && commandResults[0]?.id === provenance.commandId
    && commandResults[0]?.status === "passed"
    && commandResults[0]?.exitCode === 0
    && item?.observation?.exitCode === 0;
}

function requiredCriteria({ delta, baselinePlan, baselineLedger }) {
  if (delta.to === "achieved") {
    const criteria = asArray(delta.baselineOutcome?.acceptance?.criteria);
    if (criteria.length === 0) {
      throw transitionError(
        "OUTCOME_TRANSITION_CRITERIA_INCOMPLETE",
        `Outcome ${delta.outcomeRef} has no stable Criteria to prove.`,
        { outcomeRef: delta.outcomeRef, missingCriterionRefs: ["all"] }
      );
    }
    return { criteria, dependencyProofs: [] };
  }
  if (delta.to === "active") {
    const dependencyProofs = normalizeStringList(delta.baselineOutcome?.dependsOn).map((outcomeRef) => {
      const dependency = asArray(baselinePlan.outcomes).find((outcome) => outcome?.id === outcomeRef);
      if (dependency?.status !== "achieved") {
        throw transitionError(
          "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
          `Outcome ${delta.outcomeRef} dependency ${outcomeRef} was not achieved in the frozen Plan.`,
          { outcomeRef: delta.outcomeRef, dependencyRef: outcomeRef, observedStatus: dependency?.status ?? null }
        );
      }
      if (normalizeStringList(baselinePlan?.bootstrapBaseline?.outcomeRefs).includes(outcomeRef)) {
        return { outcomeRef, source: "bootstrap-baseline", head: baselinePlan.bootstrapBaseline.head };
      }
      const transition = [...baselineLedger].reverse().find((entry) => (
        entry.outcomeRef === outcomeRef && entry.to === "achieved"
      ));
      if (!transition) {
        throw transitionError(
          "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
          `Achieved dependency ${outcomeRef} has no bootstrap or append-only Transition fact.`,
          { outcomeRef: delta.outcomeRef, dependencyRef: outcomeRef }
        );
      }
      return { outcomeRef, source: "outcome-transition", transitionId: transition.id };
    });
    const activationRefs = normalizeStringList(delta.baselineOutcome?.acceptance?.activationCriterionRefs);
    if (delta.from === "conditional" && activationRefs.length === 0) {
      throw transitionError(
        "OUTCOME_TRANSITION_CRITERIA_INCOMPLETE",
        `Conditional Outcome ${delta.outcomeRef} requires predeclared activationCriterionRefs.`,
        { outcomeRef: delta.outcomeRef, missingCriterionRefs: ["activationCriterionRefs"] }
      );
    }
    const criteria = activationRefs.map((criterionRef) => {
      const criterion = asArray(delta.baselineOutcome?.acceptance?.criteria)
        .find((candidate) => candidate?.id === criterionRef);
      if (!criterion) {
        throw transitionError(
          "OUTCOME_TRANSITION_CRITERIA_INCOMPLETE",
          `Activation Criterion ${criterionRef} was not declared in the frozen Outcome.`,
          { outcomeRef: delta.outcomeRef, missingCriterionRefs: [criterionRef] }
        );
      }
      return criterion;
    });
    return { criteria, dependencyProofs };
  }
  return { criteria: [], dependencyProofs: [] };
}

function assertExistingOutcomeSemanticsFrozen(baselinePlan, currentPlan) {
  const currentOutcomes = new Map(asArray(currentPlan.outcomes)
    .map((outcome) => [readString(outcome?.id), outcome])
    .filter(([id]) => Boolean(id)));
  for (const baselineOutcome of asArray(baselinePlan.outcomes)) {
    const outcomeRef = readString(baselineOutcome?.id);
    const currentOutcome = currentOutcomes.get(outcomeRef);
    if (!currentOutcome) continue;
    assertOutcomeSemanticsFrozen({ outcomeRef, baselineOutcome, currentOutcome });
  }
}

function assertOutcomeSemanticsFrozen({ outcomeRef, baselineOutcome, currentOutcome }) {
  const comparisons = {
    outcome: [readString(baselineOutcome?.outcome), readString(currentOutcome?.outcome)],
    stage: [baselineOutcome?.stage, currentOutcome?.stage],
    dependsOn: [normalizeStringList(baselineOutcome?.dependsOn).sort(), normalizeStringList(currentOutcome?.dependsOn).sort()],
    kind: [baselineOutcome?.kind ?? null, currentOutcome?.kind ?? null],
    allowedChangeKinds: [
      normalizeStringList(baselineOutcome?.allowedChangeKinds).sort(),
      normalizeStringList(currentOutcome?.allowedChangeKinds).sort()
    ],
    activationCriterionRefs: [
      normalizeStringList(baselineOutcome?.acceptance?.activationCriterionRefs).sort(),
      normalizeStringList(currentOutcome?.acceptance?.activationCriterionRefs).sort()
    ],
    criteria: [
      asArray(baselineOutcome?.acceptance?.criteria).map(criterionSemanticValue).sort(compareCriterionValues),
      asArray(currentOutcome?.acceptance?.criteria).map(criterionSemanticValue).sort(compareCriterionValues)
    ],
    exitCriteria: [
      normalizeStringList(baselineOutcome?.acceptance?.exitCriteria).sort(),
      normalizeStringList(currentOutcome?.acceptance?.exitCriteria).sort()
    ],
    claimRefs: [
      normalizeStringList(baselineOutcome?.acceptance?.claimRefs).sort(),
      normalizeStringList(currentOutcome?.acceptance?.claimRefs).sort()
    ],
    gapRefs: [
      normalizeStringList(baselineOutcome?.acceptance?.gapRefs).sort(),
      normalizeStringList(currentOutcome?.acceptance?.gapRefs).sort()
    ]
  };
  const changedFields = Object.entries(comparisons)
    .filter(([, [before, after]]) => canonicalDigest(before) !== canonicalDigest(after))
    .map(([field]) => field);
  if (changedFields.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
      "A plan amendment cannot redefine frozen Outcome semantics while appending lifecycle history.",
      { outcomeRef, changedFields }
    );
  }
}

function collectStatusDeltas(baselinePlan, currentPlan) {
  const current = new Map(asArray(currentPlan.outcomes)
    .map((outcome) => [readString(outcome?.id), outcome])
    .filter(([id]) => Boolean(id)));
  const removedOutcomeIds = asArray(baselinePlan.outcomes)
    .map((outcome) => readString(outcome?.id))
    .filter((outcomeRef) => outcomeRef && !current.has(outcomeRef));
  if (removedOutcomeIds.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      "A Transition amendment cannot remove frozen Outcomes.",
      { removedOutcomeIds }
    );
  }
  return asArray(baselinePlan.outcomes).flatMap((baselineOutcome) => {
    const outcomeRef = readString(baselineOutcome?.id);
    const currentOutcome = current.get(outcomeRef);
    if (!currentOutcome || baselineOutcome.status === currentOutcome.status) return [];
    return [{
      outcomeRef,
      from: baselineOutcome.status,
      to: currentOutcome.status,
      baselineOutcome,
      currentOutcome
    }];
  });
}

function assertNewOutcomeStatuses(baselinePlan, currentPlan) {
  const baselineIds = new Set(asArray(baselinePlan.outcomes).map((outcome) => readString(outcome?.id)));
  const illegal = asArray(currentPlan.outcomes).filter((outcome) => (
    !baselineIds.has(readString(outcome?.id)) && !["planned", "conditional"].includes(outcome?.status)
  ));
  if (illegal.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
      "New Outcomes must begin planned or conditional; adding active or terminal state bypasses Transition history.",
      { outcomes: illegal.map((outcome) => ({ id: outcome.id, status: outcome.status })) }
    );
  }
}

function matchTransitions(deltas, appended) {
  const bound = [];
  const missing = [];
  const duplicate = [];
  for (const delta of deltas) {
    const matches = appended.filter((entry) => (
      entry.outcomeRef === delta.outcomeRef && entry.from === delta.from && entry.to === delta.to
    ));
    if (matches.length === 0) missing.push(delta);
    else if (matches.length > 1) duplicate.push(delta.outcomeRef);
    else bound.push({ delta, transition: matches[0] });
  }
  const unexpected = appended.filter((entry) => !deltas.some((delta) => (
    entry.outcomeRef === delta.outcomeRef && entry.from === delta.from && entry.to === delta.to
  )));
  return { bound, missing, duplicate, unexpected };
}

function assertLedgerPrefix(baselineLedger, currentLedger) {
  if (currentLedger.length < baselineLedger.length) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      "Outcome Transition history is append-only and cannot be removed.",
      { baselineLength: baselineLedger.length, currentLength: currentLedger.length }
    );
  }
  const changedIndexes = baselineLedger.flatMap((entry, index) => (
    canonicalDigest(entry) === canonicalDigest(currentLedger[index]) ? [] : [index]
  ));
  if (changedIndexes.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      "Outcome Transition history is an exact canonical prefix and cannot be edited or reordered.",
      { changedIndexes }
    );
  }
}

function normalizeLedger(value, label) {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
      `${label} outcomeTransitions must be an array.`
    );
  }
  const ledger = value.map((entry, index) => normalizeTransitionEntry(entry, `${label}[${index}]`));
  const duplicateIds = duplicates(ledger.map((entry) => entry.id));
  if (duplicateIds.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN",
      `${label} outcomeTransitions contains duplicate stable ids.`,
      { duplicateIds }
    );
  }
  return ledger;
}

function normalizeTransitionEntry(value, location) {
  assertObject(value, "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location} must be an object.`);
  assertOnlyKeys(value, [
    "id", "outcomeRef", "from", "to", "rationale", "packageRefs", "criterionAssessments", "gapDispositions"
  ], location);
  const id = readString(value.id);
  const outcomeRef = readString(value.outcomeRef);
  const from = readString(value.from);
  const to = readString(value.to);
  const rationale = readString(value.rationale);
  if (!id || !outcomeRef || !from || !to || !rationale) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
      `${location} requires id, outcomeRef, from, to, and rationale.`
    );
  }
  const packageRefs = uniquePackageRefs(value.packageRefs ?? []);
  if (value.criterionAssessments !== undefined && !Array.isArray(value.criterionAssessments)) {
    throw transitionError("OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location}.criterionAssessments must be an array.`);
  }
  if (value.gapDispositions !== undefined && !Array.isArray(value.gapDispositions)) {
    throw transitionError("OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location}.gapDispositions must be an array.`);
  }
  const criterionAssessments = asArray(value.criterionAssessments).map((assessment, index) => {
    const assessmentLocation = `${location}.criterionAssessments[${index}]`;
    assertObject(assessment, "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${assessmentLocation} must be an object.`);
    assertOnlyKeys(assessment, ["criterionRef", "authorityAssessment"], assessmentLocation);
    const criterionRef = readString(assessment.criterionRef);
    if (!criterionRef) {
      throw transitionError("OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location} Criterion assessment requires criterionRef.`);
    }
    assertObject(
      assessment.authorityAssessment,
      "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
      `${assessmentLocation}.authorityAssessment must be an object.`
    );
    assertOnlyKeys(
      assessment.authorityAssessment,
      ["conclusion", "rationale", "residualUncertainty"],
      `${assessmentLocation}.authorityAssessment`
    );
    return {
      criterionRef,
      authorityAssessment: cloneJson(assessment.authorityAssessment)
    };
  }).sort((left, right) => left.criterionRef.localeCompare(right.criterionRef));
  const gapDispositions = asArray(value.gapDispositions).map((disposition, index) => {
    assertObject(disposition, "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location}.gapDispositions[${index}] must be an object.`);
    assertOnlyKeys(disposition, ["gapRef", "rationale"], `${location}.gapDispositions[${index}]`);
    const gapRef = readString(disposition.gapRef);
    const gapRationale = readString(disposition.rationale);
    if (!gapRef || !gapRationale) {
      throw transitionError("OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", `${location} Gap disposition requires gapRef and rationale.`);
    }
    return { gapRef, rationale: gapRationale };
  }).sort((left, right) => left.gapRef.localeCompare(right.gapRef));
  return { id, outcomeRef, from, to, rationale, packageRefs, criterionAssessments, gapDispositions };
}

function normalizePriorAcceptedPackages(value) {
  assertObject(
    value,
    "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
    "priorAcceptedPackages must be a Candidate-frozen, content-addressed catalog."
  );
  assertOnlyKeys(value, ["schemaVersion", "entries", "digest"], "priorAcceptedPackages");
  if (value.schemaVersion !== 1 || !Array.isArray(value.entries)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      "The frozen Accepted Package catalog requires schemaVersion 1 and entries."
    );
  }
  const { digest, ...snapshot } = value;
  if (!readString(digest) || canonicalDigest(snapshot) !== digest) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      "The frozen Accepted Package catalog digest is invalid."
    );
  }
  const normalizedEntries = uniquePackageRefs(value.entries);
  if (canonicalDigest(normalizedEntries) !== canonicalDigest(value.entries)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      "The frozen Accepted Package catalog entries must already be unique and canonical."
    );
  }
  return { refs: new Set(normalizedEntries.map(packageRefKey)), digest: value.digest };
}

function uniquePackageRefs(value) {
  if (!Array.isArray(value)) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
      "Package references must be an array."
    );
  }
  const byKey = new Map();
  for (const item of value) {
    assertObject(item, "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID", "Each Package reference must be an object.");
    assertOnlyKeys(item, ["changeId", "acceptanceDigest"], "packageRef");
    const changeId = readString(item.changeId);
    const acceptanceDigest = readString(item.acceptanceDigest);
    if (!changeId || !DIGEST_PATTERN.test(acceptanceDigest ?? "")) {
      throw transitionError(
        "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
        "Package references require changeId and a canonical sha256 acceptanceDigest.",
        { reference: item }
      );
    }
    byKey.set(packageRefKey({ changeId, acceptanceDigest }), { changeId, acceptanceDigest });
  }
  return [...byKey.values()].sort(comparePackageProofs);
}

function finalizeCompilation({
  mode,
  status,
  change,
  governanceBaseline,
  baselinePlan,
  currentPlan,
  appendedTransitions,
  unresolved,
  priorAcceptedPackagesDigest
}) {
  const projection = {
    schemaVersion: OUTCOME_TRANSITION_SCHEMA_VERSION,
    mode,
    status,
    priorAcceptedPackagesDigest: readString(priorAcceptedPackagesDigest)
      ?? readString(change?.priorAcceptedPackages?.digest)
      ?? null,
    baselinePlanDigest: baselinePlan ? canonicalDigest(baselinePlan) : null,
    currentPlanDigest: currentPlan ? canonicalDigest(currentPlan) : null,
    requiredAuthorityRef: readString(baselinePlan?.authority) ?? null,
    appendedTransitions,
    unresolved
  };
  return cloneJson({ ...projection, digest: canonicalDigest({
    ...projection,
    changeId: change?.id ?? null,
    governanceBaselineDigest: governanceBaseline?.digest ?? null
  }) });
}

function criterionSemanticValue(criterion) {
  return {
    id: readString(criterion?.id) ?? null,
    statement: readString(criterion?.statement) ?? null,
    claimRefs: normalizeStringList(criterion?.claimRefs).sort(),
    gapRefs: normalizeStringList(criterion?.gapRefs).sort()
  };
}

function indexKnowledgeGaps(value, label) {
  const entries = asArray(value);
  const ids = entries.map((gap) => readString(gap?.id)).filter(Boolean);
  const duplicateIds = duplicates(ids);
  if (duplicateIds.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      `${label} Knowledge Gaps must have unique stable ids.`,
      { duplicateIds }
    );
  }
  return new Map(entries.map((gap) => [readString(gap?.id), gap]).filter(([id]) => Boolean(id)));
}

function gapSemanticValue(gap) {
  return {
    id: readString(gap?.id) ?? null,
    statement: readString(gap?.statement) ?? null,
    affects: normalizeStringList(gap?.affects).sort(),
    owner: readString(gap?.owner) ?? null,
    expansionTrigger: readString(gap?.expansionTrigger) ?? null
  };
}

function assertGovernanceBaselineSeal(governanceBaseline) {
  assertObject(
    governanceBaseline,
    "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
    "Outcome Transition compilation requires a sealed Governance Baseline."
  );
  const { digest, ...snapshot } = governanceBaseline;
  if (!DIGEST_PATTERN.test(readString(digest) ?? "") || canonicalDigest(snapshot) !== digest) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      "The frozen Governance Baseline does not match its canonical digest.",
      { problems: ["governance-baseline-digest-mismatch"] }
    );
  }
}

function readProjectId(value) {
  return readString(value?.projectDocument?.project?.id)
    ?? readString(value?.project?.id);
}

function isPositiveObservation(value) {
  const status = readString(value?.status)?.toLowerCase();
  return ["passed", "satisfied", "success"].includes(status);
}

function compareTransitions(left, right) {
  return left.outcomeRef.localeCompare(right.outcomeRef)
    || left.id.localeCompare(right.id);
}

function compareCriterionValues(left, right) {
  return (left.id ?? "").localeCompare(right.id ?? "");
}

function comparePackageProofs(left, right) {
  return left.changeId.localeCompare(right.changeId)
    || left.acceptanceDigest.localeCompare(right.acceptanceDigest);
}

function packageRefKey(ref) {
  return `${ref.changeId}\u0000${ref.acceptanceDigest}`;
}

function duplicates(values) {
  const seen = new Set();
  const duplicate = new Set();
  for (const value of values) {
    if (seen.has(value)) duplicate.add(value);
    seen.add(value);
  }
  return [...duplicate].sort();
}

function normalizeStringList(value) {
  return [...new Set(asArray(value).map(readString).filter(Boolean))];
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function isSubstantive(value) {
  if (typeof value === "string") return Boolean(value.trim());
  if (Array.isArray(value)) return value.some(isSubstantive);
  return Boolean(value && typeof value === "object" && Object.values(value).some(isSubstantive));
}

function assertObject(value, code, message) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw transitionError(code, message);
  }
}

function assertOnlyKeys(value, allowed, location) {
  const unexpected = Object.keys(value).filter((key) => !allowed.includes(key));
  if (unexpected.length > 0) {
    throw transitionError(
      "OUTCOME_TRANSITION_PACKAGE_REFERENCE_INVALID",
      `${location} contains unsupported fields.`,
      { unexpected }
    );
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function ledgerIssue(code, location, message, details) {
  return { code, location, message, ...(details ? { details } : {}) };
}

function transitionError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = 422;
  error.details = details;
  return error;
}
