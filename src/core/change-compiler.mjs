import { canonicalDigest, cloneJson } from "./canonical.mjs";

export const INTEGRITY_CHANGE_KINDS = Object.freeze([
  "regression-repair",
  "security-containment",
  "data-integrity-repair",
  "acceptance-integrity-repair",
  "entrypoint-restoration"
]);

export const CHANGE_KINDS = Object.freeze([
  "implementation",
  "plan-amendment",
  ...INTEGRITY_CHANGE_KINDS
]);

const INTEGRITY_FAILURE_PROVENANCE_KINDS = new Set([
  "builtin-oracle",
  "gate-command",
  "reported-incident",
  "external-incident"
]);

const INTEGRITY_EVIDENCE_FIELDS = [
  "claim",
  "oracle",
  "observation",
  "provenance",
  "applicability",
  "discriminatoryPower",
  "residualUncertainty"
];

const MAX_CHANGE_PLAN_REFS = 64;
const MAX_CHANGE_PLAN_REF_LENGTH = 256;

const COMPILED_CONTEXT_KEYS = new Set([
  "schemaVersion",
  "compiledFrom",
  "primaryModule",
  "module",
  "publicContracts",
  "dependencyContracts",
  "dependencies",
  "planOutcomes",
  "outcomeAlignment",
  "normativeSources",
  "knowledgeGaps",
  "scope",
  "contextExpansionPolicy",
  "assurance"
]);

const PROJECT_MODEL_CLAIM = {
  id: "project-model-self-consistent",
  statement: "The versioned Project Model is internally self-consistent for this Change."
};

export function validateIntegrityFailureEvidence(change, { requireDigest = false } = {}) {
  const changeKind = readString(change?.changeKind) ?? "implementation";
  if (!INTEGRITY_CHANGE_KINDS.includes(changeKind)) {
    return { required: false, valid: true, problems: [] };
  }
  const claimRef = readString(change.integrityTarget?.claimRef);
  const failureEvidenceRef = readString(change.integrityTarget?.failureEvidenceRef);
  const failureEvidence = asArray(change.evidence).find((item) => item?.id === failureEvidenceRef);
  const expectedClaim = asArray(change.claims).find((claim) => claim?.id === claimRef);
  const observedStatus = readString(failureEvidence?.observation?.status)?.toLowerCase() ?? null;
  const observedProvenanceKind = readString(failureEvidence?.provenance?.kind) ?? null;
  const missingFields = failureEvidence
    ? INTEGRITY_EVIDENCE_FIELDS.filter((field) => !isSubstantive(failureEvidence[field]))
    : [...INTEGRITY_EVIDENCE_FIELDS];
  const observedDigest = failureEvidence ? canonicalDigest(failureEvidence) : null;
  const expectedDigest = readString(change.integrityTarget?.failureEvidenceDigest) ?? null;
  const problems = [];
  if (!claimRef || !failureEvidenceRef) problems.push("target-reference-missing");
  if (!failureEvidence) problems.push("failure-evidence-missing");
  if (missingFields.length > 0) problems.push("failure-evidence-incomplete");
  if (!expectedClaim
    || failureEvidence?.claim?.id !== claimRef
    || failureEvidence?.claim?.statement !== expectedClaim?.statement) {
    problems.push("claim-mismatch");
  }
  if (observedStatus !== "failed") problems.push("observation-not-failed");
  if (!INTEGRITY_FAILURE_PROVENANCE_KINDS.has(observedProvenanceKind)) {
    problems.push("provenance-not-allowed");
  }
  if (requireDigest && (!expectedDigest || expectedDigest !== observedDigest)) {
    problems.push("failure-evidence-digest-mismatch");
  }
  return {
    required: true,
    valid: problems.length === 0,
    problems,
    claimRef: claimRef ?? null,
    failureEvidenceRef: failureEvidenceRef ?? null,
    expectedDigest,
    observedDigest,
    observedClaimRef: failureEvidence?.claim?.id ?? null,
    observedStatus,
    observedProvenanceKind,
    missingFields
  };
}

export function assertIntegrityFailureEvidenceCurrent(change) {
  const validation = validateIntegrityFailureEvidence(change, { requireDigest: true });
  if (!validation.valid) {
    throw compilerError(
      "CHANGE_INTEGRITY_FAILURE_EVIDENCE_INVALID",
      "The integrity channel requires the original complete failed Evidence for the protected Claim to remain present and content-exact.",
      validation
    );
  }
  return validation;
}

export function compileChangeAgainstGovernance(change, governanceBaseline) {
  const primaryModuleId = readString(change.primaryModule);
  if (!primaryModuleId) {
    throw compilerError(
      "CHANGE_PRIMARY_MODULE_REQUIRED",
      "A Change requires primaryModule before it can be compiled.",
      { knownModuleIds: governanceBaseline.modules.map((module) => module.id) }
    );
  }
  const primaryModule = governanceBaseline.modules.find((module) => module.id === primaryModuleId);
  if (!primaryModule) {
    throw compilerError(
      "CHANGE_MODULE_UNKNOWN",
      `Primary Module ${primaryModuleId} is not present in the frozen Governance Baseline.`,
      { primaryModule: primaryModuleId, governanceBaselineDigest: governanceBaseline.digest }
    );
  }

  const planOutcomes = selectDevelopmentOutcomes(change, governanceBaseline);
  const integrityTarget = compileIntegrityTarget(change);
  const assurance = assertAssuranceAllowsCompilation(change, primaryModule, governanceBaseline);
  const compilerInput = change.compilerInput ?? {};
  const outcomeAlignment = compileOutcomeAlignment({
    change,
    governanceBaseline,
    primaryModule,
    planOutcomes,
    hints: compilerInput.outcomeContributionHints,
    exceptions: compilerInput.outcomeExceptions
  });
  const contextCapsule = compileContextCapsule({
    governanceBaseline,
    primaryModule,
    planOutcomes,
    outcomeAlignment,
    assurance,
    supplied: compilerInput.contextCapsule
  });
  const impact = compileImpact({
    governanceBaseline,
    primaryModule,
    supplied: compilerInput.impact
  });
  const verificationObligations = compileVerificationObligations({
    claims: change.claims,
    primaryModule,
    governanceBaseline,
    supplied: compilerInput.verificationObligations
  });
  const verificationPlan = compileVerificationPlan({
    primaryModule,
    governanceBaseline,
    verificationObligations
  });
  const planRefs = planOutcomes.map((outcome) => outcome.id);

  return {
    ...change,
    planRefs,
    ...(outcomeAlignment ? { outcomeAlignmentSchemaVersion: 1 } : {}),
    integrityTarget,
    outcomeAlignment,
    contextCapsule,
    impact,
    verificationObligations,
    verificationPlan,
    compilation: {
      compiler: "legatura-core/change-compiler-v1",
      governanceBaselineDigest: governanceBaseline.digest,
      primaryModule: primaryModule.id,
      changeKind: change.changeKind,
      planRefs,
      outcomeAlignmentDigest: outcomeAlignment ? canonicalDigest(outcomeAlignment) : null,
      assuranceStatus: primaryModule.status
    }
  };
}

export function compileOutcomeAlignmentAgainstGovernance(change, governanceBaseline) {
  const primaryModuleId = readString(change?.primaryModule);
  const primaryModule = governanceBaseline?.modules?.find((module) => module.id === primaryModuleId);
  if (!primaryModule) {
    throw compilerError(
      "CHANGE_MODULE_UNKNOWN",
      `Primary Module ${primaryModuleId ?? "unknown"} is not present in the frozen Governance Baseline.`,
      { primaryModule: primaryModuleId ?? null, governanceBaselineDigest: governanceBaseline?.digest ?? null }
    );
  }
  const planOutcomes = selectDevelopmentOutcomes(change, governanceBaseline);
  const compilerInput = change.compilerInput ?? {};
  return compileOutcomeAlignment({
    change,
    governanceBaseline,
    primaryModule,
    planOutcomes,
    hints: compilerInput.outcomeContributionHints,
    exceptions: compilerInput.outcomeExceptions
  });
}

export function compileClaimGateRoutes(model, claimRef) {
  const exactClaimRef = readString(claimRef);
  if (!exactClaimRef) return [];
  const moduleRefs = normalizeStringList(
    asArray(model?.modules).map((module) => readModelReference(module))
  ).sort();
  const fullGateId = readString(model?.projectDocument?.changePolicy?.fullGate);
  return asArray(model?.gates).flatMap((gate) => {
    const commands = Array.isArray(gate?.commands)
      ? gate.commands
      : gate?.command ? [gate] : [];
    return commands
      .filter((command) => normalizeStringList(command?.claimRefs).includes(exactClaimRef))
      .map((command) => ({
        claimRef: exactClaimRef,
        gateId: readString(gate?.id) ?? null,
        commandId: readString(command?.id) ?? null,
        command: cloneJson(command?.command),
        timeoutMs: command?.timeoutMs ?? null,
        effectiveModuleRefs: moduleRefs.filter((moduleRef) => (
          gateSelectsModule(gate, moduleRef, fullGateId)
            && commandSelectsModule(command, moduleRef)
        )),
        oracle: cloneJson(command?.oracle),
        applicability: cloneJson(command?.applicability),
        discriminatoryPower: cloneJson(command?.discriminatoryPower),
        residualUncertainty: cloneJson(command?.residualUncertainty)
      }));
  }).sort((left, right) => (
    (left.gateId ?? "").localeCompare(right.gateId ?? "")
      || (left.commandId ?? "").localeCompare(right.commandId ?? "")
      || canonicalDigest(left).localeCompare(canonicalDigest(right))
  ));
}

function compileIntegrityTarget(change) {
  const changeKind = readString(change.changeKind) ?? "implementation";
  if (!INTEGRITY_CHANGE_KINDS.includes(changeKind)) return null;
  const failureEvidenceRef = readString(change.integrityTarget?.failureEvidenceRef);
  const failureEvidence = asArray(change.evidence).find((item) => item?.id === failureEvidenceRef);
  return {
    ...cloneJson(change.integrityTarget),
    failureEvidenceDigest: canonicalDigest(failureEvidence)
  };
}

function compileContextCapsule({
  governanceBaseline,
  primaryModule,
  planOutcomes,
  outcomeAlignment,
  assurance,
  supplied
}) {
  validateContextSupplement(supplied);
  const contractsById = new Map(governanceBaseline.contracts.map((contract) => [contract.id, contract]));
  const modulesById = new Map(governanceBaseline.modules.map((module) => [module.id, module]));
  const publicContractIds = unique(asArray(primaryModule.publicContracts).map(readReference).filter(Boolean));
  const publicContracts = publicContractIds.map((id) => contractsById.get(id)).filter(Boolean);
  const dependencies = asArray(primaryModule.dependencies).map((dependency) => {
    const moduleId = readReference(dependency, ["module", "moduleId", "target", "id"]);
    const interfaceRef = readReference(dependency, ["via", "contract", "contractId"]);
    return {
      module: moduleId,
      status: modulesById.get(moduleId)?.status ?? "unmodeled",
      interfaceRef: interfaceRef ?? null,
      access: readString(dependency?.access) ?? null
    };
  });
  const dependencyContractIds = unique(dependencies
    .map((dependency) => dependency.interfaceRef)
    .filter((id) => contractsById.has(id)));
  const dependencyContracts = dependencyContractIds.map((id) => contractsById.get(id));
  const selectedContracts = [...publicContracts, ...dependencyContracts];
  const normativeSourceIds = unique(selectedContracts
    .flatMap((contract) => asArray(contract.normativeSources).map(readReference).filter(Boolean)));
  const normativeSources = asArray(governanceBaseline.projectDocument?.normativeSources)
    .filter((source) => normativeSourceIds.includes(readReference(source)))
    .map(cloneJson);
  const projectedPlanOutcomes = projectOutcomeContext(planOutcomes, outcomeAlignment);
  const outcomeGapRefs = new Set(projectedPlanOutcomes
    .flatMap((outcome) => normalizeStringList(outcome?.acceptance?.gapRefs)));
  const relatedRefs = new Set([
    primaryModule.id,
    ...dependencies.map((dependency) => dependency.module),
    ...publicContractIds,
    ...dependencyContractIds
  ].filter(Boolean));
  const knowledgeGaps = governanceBaseline.knowledgeGaps
    .filter((gap) => outcomeGapRefs.has(readString(gap?.id))
      || asArray(gap.affects).map(readReference).some((ref) => relatedRefs.has(ref)))
    .map(cloneJson);
  for (const [index, statement] of asArray(primaryModule.modelGaps).entries()) {
    knowledgeGaps.push({
      id: `module-gap-${primaryModule.id}-${index + 1}`,
      affects: [primaryModule.id],
      statement,
      source: "Module.modelGaps"
    });
  }

  const modelDocumentPaths = relevantModelDocumentPaths(
    governanceBaseline.files,
    primaryModule.id,
    [...publicContractIds, ...dependencyContractIds]
  );
  const normativePaths = normativeSources.map((source) => readString(source.path)).filter(Boolean);
  const focusedTestPaths = asArray(primaryModule.focusedTests)
    .flatMap((test) => normalizePaths(typeof test === "string" ? test : test?.path ?? test?.paths));
  const generatedWrite = primaryModule.status === "opaque"
    ? { include: [], exclude: normalizePaths(primaryModule.paths?.include) }
    : {
        include: normalizePaths(primaryModule.paths?.include ?? primaryModule.paths),
        exclude: normalizePaths(primaryModule.paths?.exclude)
      };
  const generatedRead = {
    include: unique([
      ...normalizePaths(primaryModule.paths?.include ?? primaryModule.paths),
      ...modelDocumentPaths,
      ...normativePaths,
      ...focusedTestPaths
    ]),
    exclude: normalizePaths(primaryModule.paths?.exclude)
  };
  const suppliedScope = supplied?.scope ?? supplied?.allowedScope ?? {};
  const scope = {
    write: narrowScope(generatedWrite, suppliedScope.write ?? supplied?.allowedWriteScope, "write"),
    read: narrowScope(generatedRead, suppliedScope.read ?? supplied?.allowedReadScope, "read"),
    otherModuleImplementation: "contract-only; expansion must be recorded before reading implementation"
  };
  const extraContextRefs = normalizePaths(supplied?.additionalContextRefs);
  if (extraContextRefs.length > 0) {
    assertWithinScope(extraContextRefs, generatedRead.include, "additionalContextRefs");
    scope.read.include = unique([...scope.read.include, ...extraContextRefs]);
  }

  return {
    schemaVersion: 1,
    compiledFrom: {
      governanceBaselineDigest: governanceBaseline.digest,
      projectModelFiles: modelDocumentPaths
    },
    primaryModule: primaryModule.id,
    module: pickModuleContext(primaryModule),
    planOutcomes: projectedPlanOutcomes,
    outcomeAlignment: cloneJson(outcomeAlignment),
    publicContracts: publicContracts.map(pickContractContext),
    dependencyContracts: dependencyContracts.map(pickContractContext),
    dependencies,
    normativeSources,
    knowledgeGaps,
    scope,
    contextExpansionPolicy: {
      mode: readString(governanceBaseline.projectDocument?.changePolicy?.contextExpansion) ?? "recorded",
      requirement: "Record the requested paths, reason, expected knowledge, and resulting model disposition before using context outside read.include.",
      implementationBoundary: "Consume another Module through its Contract; do not load its implementation by default."
    },
    assurance,
    ...copySupplementalContext(supplied)
  };
}

function selectDevelopmentOutcomes(change, governanceBaseline) {
  const policy = governanceBaseline.projectDocument?.changePolicy ?? {};
  const changeKind = readString(change.changeKind) ?? "implementation";
  const planRefs = parseChangePlanRefs(change.planRefs);
  if (!CHANGE_KINDS.includes(changeKind)) {
    throw compilerError(
      "CHANGE_KIND_INVALID",
      `Unsupported Change kind: ${changeKind}.`,
      { changeKind, allowedChangeKinds: CHANGE_KINDS }
    );
  }
  if (changeKind === "plan-amendment") {
    if (planRefs.length > 0) {
      throw compilerError(
        "PLAN_AMENDMENT_PLAN_REF_FORBIDDEN",
        "A plan-amendment is authorized by governance authority and must not use the plan state it edits to authorize itself.",
        { planRefs }
      );
    }
    return [];
  }
  if (policy.requirePlanRefs === true && planRefs.length === 0) {
    throw compilerError(
      "CHANGE_PLAN_REF_REQUIRED",
      "This Governance Baseline requires at least one active Development Outcome before a Change can compile.",
      {
        planId: readString(governanceBaseline.plan?.id) ?? null,
        activeOutcomeIds: asArray(governanceBaseline.plan?.outcomes)
          .filter((outcome) => outcome?.status === "active")
          .map((outcome) => readString(outcome?.id))
          .filter(Boolean)
      }
    );
  }
  if (planRefs.length === 0) {
    if (INTEGRITY_CHANGE_KINDS.includes(changeKind)) {
      throw compilerError(
        "CHANGE_INTEGRITY_OUTCOME_REQUIRED",
        "An integrity repair must reference exactly one active integrity-maintenance Outcome.",
        { planRefs }
      );
    }
    return [];
  }

  const outcomesById = new Map(asArray(governanceBaseline.plan?.outcomes)
    .map((outcome) => [readString(outcome?.id), outcome])
    .filter(([id]) => Boolean(id)));
  const unknown = planRefs.filter((id) => !outcomesById.has(id));
  if (unknown.length > 0) {
    throw compilerError(
      "CHANGE_PLAN_REF_UNKNOWN",
      `Development Outcome references are not present in the frozen Governance Baseline: ${unknown.join(", ")}.`,
      { unknown, planId: readString(governanceBaseline.plan?.id) ?? null }
    );
  }

  const inactive = planRefs
    .map((id) => ({ id, outcome: outcomesById.get(id) }))
    .filter(({ outcome }) => outcome.status !== "active")
    .map(({ id, outcome }) => ({ id, status: outcome.status }));
  if (inactive.length > 0) {
    throw compilerError(
      "CHANGE_PLAN_REF_NOT_ACTIVE",
      "A planned, conditional, achieved, or retired Outcome cannot authorize implementation; activate it through an earlier normative amendment.",
      { inactive }
    );
  }

  const selected = planRefs.map((id) => ({
    ...cloneJson(outcomesById.get(id)),
    id
  }));
  const integrityOutcomes = selected.filter((outcome) => outcome.kind === "integrity-maintenance");
  if (changeKind === "implementation" && integrityOutcomes.length > 0) {
    throw compilerError(
      "CHANGE_INTEGRITY_CHANNEL_MISUSED",
      "An implementation Change cannot use an integrity-maintenance Outcome as a feature path.",
      { planRefs: integrityOutcomes.map((outcome) => outcome.id) }
    );
  }
  if (INTEGRITY_CHANGE_KINDS.includes(changeKind)) {
    if (integrityOutcomes.length !== selected.length || selected.length !== 1) {
      throw compilerError(
        "CHANGE_INTEGRITY_OUTCOME_REQUIRED",
        "An integrity repair must reference exactly one active integrity-maintenance Outcome.",
        { planRefs }
      );
    }
    const outcome = integrityOutcomes[0];
    if (!normalizeStringList(outcome.allowedChangeKinds).includes(changeKind)) {
      throw compilerError(
        "CHANGE_INTEGRITY_KIND_NOT_ALLOWED",
        `Outcome ${outcome.id} does not allow Change kind ${changeKind}.`,
        { outcomeId: outcome.id, changeKind, allowedChangeKinds: outcome.allowedChangeKinds ?? [] }
      );
    }
    const claimRef = readString(change.integrityTarget?.claimRef);
    const failureEvidenceRef = readString(change.integrityTarget?.failureEvidenceRef);
    if (!claimRef || !failureEvidenceRef) {
      throw compilerError(
        "CHANGE_INTEGRITY_TARGET_REQUIRED",
        "An integrity repair requires integrityTarget.claimRef and failureEvidenceRef.",
        { outcomeId: outcome.id }
      );
    }
    const protectedClaims = normalizeStringList(outcome.acceptance?.claimRefs);
    const changeClaims = new Set(asArray(change.claims).map((claim) => readString(claim?.id)).filter(Boolean));
    if (!protectedClaims.includes(claimRef) || !changeClaims.has(claimRef)) {
      throw compilerError(
        "CHANGE_INTEGRITY_CLAIM_INVALID",
        "The integrity target must be both protected by the maintenance Outcome and declared as a Claim on this Change.",
        { claimRef, protectedClaims }
      );
    }
    const failureValidation = validateIntegrityFailureEvidence(change);
    if (!failureValidation.valid) {
      throw compilerError(
        "CHANGE_INTEGRITY_FAILURE_EVIDENCE_INVALID",
        "The integrity channel requires complete failed Evidence for the protected Claim from an independent Oracle, Gate, or incident report.",
        failureValidation
      );
    }
  }

  return selected;
}

export function parseChangePlanRefs(value) {
  if (value === undefined) return [];
  if (typeof value === "string") {
    const planRef = value.trim();
    if (!planRef) {
      throw invalidPlanRefsError(value, [{
        receivedType: "string",
        reason: "blank-string"
      }]);
    }
    if (planRef.length > MAX_CHANGE_PLAN_REF_LENGTH) {
      throw invalidPlanRefsError(value, [{
        receivedType: "string",
        reason: "too-long",
        length: planRef.length,
        maxLength: MAX_CHANGE_PLAN_REF_LENGTH
      }]);
    }
    return [planRef];
  }
  if (!Array.isArray(value)) {
    const receivedType = inputType(value);
    throw invalidPlanRefsError(value, [{
      receivedType,
      reason: "non-string"
    }]);
  }
  if (value.length > MAX_CHANGE_PLAN_REFS) {
    throw invalidPlanRefsError(value, [{
      receivedType: "array",
      reason: "too-many-entries",
      count: value.length,
      maxCount: MAX_CHANGE_PLAN_REFS
    }]);
  }

  const invalidEntries = [];
  const planRefs = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      invalidEntries.push({
        index,
        receivedType: "missing",
        reason: "sparse-entry"
      });
      continue;
    }
    const entry = value[index];
    if (typeof entry !== "string") {
      invalidEntries.push({
        index,
        receivedType: inputType(entry),
        reason: "non-string"
      });
      continue;
    }
    const planRef = entry.trim();
    if (!planRef) {
      invalidEntries.push({
        index,
        receivedType: "string",
        reason: "blank-string"
      });
      continue;
    }
    if (planRef.length > MAX_CHANGE_PLAN_REF_LENGTH) {
      invalidEntries.push({
        index,
        receivedType: "string",
        reason: "too-long",
        length: planRef.length,
        maxLength: MAX_CHANGE_PLAN_REF_LENGTH
      });
      continue;
    }
    planRefs.push(planRef);
  }
  if (invalidEntries.length > 0) {
    throw invalidPlanRefsError(value, invalidEntries);
  }
  return unique(planRefs);
}

function invalidPlanRefsError(value, invalidEntries) {
  return compilerError(
    "CHANGE_PLAN_REF_INVALID",
    "Change planRefs must be absent, a non-empty string of at most 256 trimmed characters, or a dense list of at most 64 such strings.",
    {
      field: "planRefs",
      receivedType: inputType(value),
      invalidEntries
    }
  );
}

function inputType(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  return typeof value;
}

function compileOutcomeAlignment({
  change,
  governanceBaseline,
  primaryModule,
  planOutcomes,
  hints,
  exceptions
}) {
  const mode = readString(governanceBaseline.projectDocument?.changePolicy?.outcomeAlignmentMode);
  if (!mode) return null;
  if (!["declared", "enforced"].includes(mode)) {
    throw compilerError(
      "OUTCOME_ALIGNMENT_MODE_INVALID",
      `Unsupported Outcome alignment mode: ${mode}.`,
      { mode }
    );
  }

  const selectedOutcomeIds = new Set(planOutcomes.map((outcome) => outcome.id));
  const normalizedHints = normalizeOutcomeContributionHints(hints, selectedOutcomeIds);
  const normalizedExceptions = normalizeOutcomeExceptions(exceptions, selectedOutcomeIds);
  const changeKind = readString(change.changeKind) ?? "implementation";
  if (changeKind !== "implementation" || planOutcomes.length === 0) {
    if (normalizedHints.length > 0 || normalizedExceptions.length > 0) {
      throw compilerError(
        "OUTCOME_ALIGNMENT_INPUT_NOT_APPLICABLE",
        `Change kind ${changeKind} cannot carry Outcome contribution hints or exceptions.`,
        { changeKind }
      );
    }
    return {
      schemaVersion: 1,
      mode,
      status: "not-applicable",
      selectedOutcomeRefs: planOutcomes.map((outcome) => outcome.id),
      contributions: [],
      exceptions: [],
      unresolved: []
    };
  }

  const hintsByOutcome = new Map(normalizedHints.map((hint) => [hint.outcomeRef, hint]));
  const exceptionsByOutcome = new Map(normalizedExceptions.map((exception) => [exception.outcomeRef, exception]));
  const overlappingInputs = [...hintsByOutcome.keys()].filter((outcomeRef) => exceptionsByOutcome.has(outcomeRef));
  if (overlappingInputs.length > 0) {
    throw compilerError(
      "OUTCOME_ALIGNMENT_INPUT_CONFLICT",
      "An Outcome cannot use a Criterion hint and a non-progress exception in the same Change.",
      { outcomeRefs: overlappingInputs }
    );
  }

  const accessibleClaims = readAccessibleContractClaims(primaryModule, governanceBaseline);
  const globalClaims = new Map(governanceBaseline.contracts.flatMap((contract) => (
    asArray(contract.claims).map((claim) => [claim.id, claim])
  )));
  const exactAccessibleClaims = asArray(change.claims)
    .filter((claim) => accessibleClaims.get(claim?.id)?.statement === claim?.statement)
    .map(cloneJson);
  const contributions = [];
  const compiledExceptions = [];
  const unresolved = [];

  for (const outcome of planOutcomes) {
    const outcomeRef = outcome.id;
    const criteria = asArray(outcome.acceptance?.criteria);
    const hint = hintsByOutcome.get(outcomeRef);
    const exception = exceptionsByOutcome.get(outcomeRef);
    if (criteria.length === 0) {
      if (hint) {
        throw compilerError(
          "OUTCOME_CRITERION_UNKNOWN",
          `Outcome ${outcomeRef} has no stable Criteria for the supplied hint.`,
          { outcomeRef, criterionRefs: hint.criterionRefs }
        );
      }
      if (exception) {
        compiledExceptions.push(compileOutcomeException({
          change,
          governanceBaseline,
          primaryModule,
          outcome,
          exception,
          exactAccessibleClaims
        }));
      } else {
        unresolved.push(outcomeAlignmentProblem({
          outcomeRef,
          reason: "criteria-missing",
          exactAccessibleClaims,
          changeClaims: change.claims,
          accessibleClaims,
          globalClaims
        }));
      }
      continue;
    }

    const criteriaById = new Map(criteria.map((criterion) => [criterion.id, criterion]));
    if (hint) {
      const unknownCriterionRefs = hint.criterionRefs.filter((criterionRef) => !criteriaById.has(criterionRef));
      if (unknownCriterionRefs.length > 0) {
        throw compilerError(
          "OUTCOME_CRITERION_UNKNOWN",
          `Outcome ${outcomeRef} does not declare the hinted Criteria: ${unknownCriterionRefs.join(", ")}.`,
          { outcomeRef, unknownCriterionRefs }
        );
      }
    }

    const matchesByClaim = exactAccessibleClaims.map((claim) => ({
      claim,
      criterionRefs: criteria
        .filter((criterion) => normalizeStringList(criterion.claimRefs).includes(claim.id))
        .map((criterion) => criterion.id)
    }));
    const candidateCriterionRefs = new Set(matchesByClaim.flatMap((match) => match.criterionRefs));
    if (exception && candidateCriterionRefs.size > 0) {
      throw compilerError(
        "OUTCOME_EXCEPTION_CONTRIBUTION_AVAILABLE",
        `Outcome ${outcomeRef} has an exact Claim-to-Criterion match and cannot be replaced by a non-progress exception.`,
        { outcomeRef, candidateCriterionRefs: [...candidateCriterionRefs] }
      );
    }
    if (exception) {
      compiledExceptions.push(compileOutcomeException({
        change,
        governanceBaseline,
        primaryModule,
        outcome,
        exception,
        exactAccessibleClaims
      }));
      continue;
    }

    if (candidateCriterionRefs.size === 0) {
      if (hint) {
        throw compilerError(
          "OUTCOME_HINT_UNMATCHED",
          `Outcome ${outcomeRef} hint does not correspond to an exact accessible Change Claim.`,
          { outcomeRef, criterionRefs: hint.criterionRefs }
        );
      }
      unresolved.push(outcomeAlignmentProblem({
        outcomeRef,
        reason: "no-exact-match",
        exactAccessibleClaims,
        changeClaims: change.claims,
        accessibleClaims,
        globalClaims,
        criteria
      }));
      continue;
    }

    const ambiguousMatches = matchesByClaim.filter((match) => match.criterionRefs.length > 1);
    const ambiguousCriterionRefs = new Set(ambiguousMatches.flatMap((match) => match.criterionRefs));
    if (hint) {
      const unmatched = hint.criterionRefs.filter((criterionRef) => !candidateCriterionRefs.has(criterionRef));
      if (unmatched.length > 0) {
        throw compilerError(
          "OUTCOME_HINT_UNMATCHED",
          `Outcome ${outcomeRef} hint is not supported by exact accessible Claims.`,
          { outcomeRef, unmatched, candidateCriterionRefs: [...candidateCriterionRefs] }
        );
      }
      const unnecessary = hint.criterionRefs.filter((criterionRef) => !ambiguousCriterionRefs.has(criterionRef));
      if (unnecessary.length > 0) {
        throw compilerError(
          "OUTCOME_HINT_NOT_AMBIGUOUS",
          `Outcome ${outcomeRef} hint may only resolve an ambiguous Claim-to-Criterion match.`,
          { outcomeRef, unnecessary, ambiguousCriterionRefs: [...ambiguousCriterionRefs] }
        );
      }
    }

    const claimBindingsByCriterion = new Map();
    const assignClaim = (criterionRef, claim) => {
      const assigned = claimBindingsByCriterion.get(criterionRef) ?? [];
      assigned.push(claim);
      claimBindingsByCriterion.set(criterionRef, assigned);
    };
    for (const match of matchesByClaim.filter((entry) => entry.criterionRefs.length === 1)) {
      assignClaim(match.criterionRefs[0], match.claim);
    }
    const unresolvedAmbiguities = [];
    for (const match of ambiguousMatches) {
      const selected = match.criterionRefs.filter((criterionRef) => hint?.criterionRefs.includes(criterionRef));
      if (selected.length > 1) {
        throw compilerError(
          "OUTCOME_HINT_AMBIGUOUS",
          `Outcome ${outcomeRef} hint must select exactly one Criterion for Claim ${match.claim.id}.`,
          { outcomeRef, claimRef: match.claim.id, selectedCriterionRefs: selected }
        );
      }
      if (selected.length === 0) {
        unresolvedAmbiguities.push({
          claimRef: match.claim.id,
          candidateCriterionRefs: match.criterionRefs
        });
      } else {
        assignClaim(selected[0], match.claim);
      }
    }

    if (unresolvedAmbiguities.length > 0) {
      unresolved.push({
        outcomeRef,
        reason: "ambiguous",
        claimRefs: unresolvedAmbiguities.map((entry) => entry.claimRef),
        candidateCriterionRefs: unique(unresolvedAmbiguities.flatMap((entry) => entry.candidateCriterionRefs)),
        accessibleClaimRefs: exactAccessibleClaims.map((claim) => claim.id),
        inaccessibleClaimRefs: []
      });
    }

    for (const criterionRef of [...claimBindingsByCriterion.keys()].sort()) {
      const criterion = criteriaById.get(criterionRef);
      const claimBindings = claimBindingsByCriterion.get(criterionRef)
        .sort((left, right) => left.id.localeCompare(right.id));
      contributions.push(compileOutcomeContribution({
        change,
        governanceBaseline,
        primaryModule,
        outcome,
        criterion,
        claimBindings
      }));
    }
  }

  if (mode === "enforced" && unresolved.length > 0) {
    const codeByReason = {
      ambiguous: "OUTCOME_CRITERION_AMBIGUOUS",
      "criteria-missing": "OUTCOME_CRITERIA_REQUIRED",
      "no-exact-match": "OUTCOME_CONTRIBUTION_REQUIRED"
    };
    throw compilerError(
      codeByReason[unresolved[0].reason] ?? "OUTCOME_ALIGNMENT_UNRESOLVED",
      "Enforced Outcome alignment requires every selected Outcome to resolve to a Contribution or Plan-authorized exception request.",
      { unresolved }
    );
  }

  return {
    schemaVersion: 1,
    mode,
    status: unresolved.length > 0
      ? "unresolved"
      : compiledExceptions.length > 0 ? "pending-authority" : "complete",
    selectedOutcomeRefs: planOutcomes.map((outcome) => outcome.id),
    contributions: contributions.sort(compareOutcomeBindings),
    exceptions: compiledExceptions.sort(compareOutcomeBindings),
    unresolved
  };
}

function normalizeOutcomeContributionHints(value, selectedOutcomeIds) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw compilerError("OUTCOME_HINT_INVALID", "outcomeContributionHints must be a list.");
  }
  const seen = new Set();
  return value.map((hint) => {
    const outcomeRef = readString(hint?.outcomeRef);
    const rawCriterionRefs = hint?.criterionRefs;
    if (!outcomeRef || !Array.isArray(rawCriterionRefs) || rawCriterionRefs.length === 0
      || !rawCriterionRefs.every(readString)) {
      throw compilerError(
        "OUTCOME_HINT_INVALID",
        "Each Outcome contribution hint requires outcomeRef and non-empty criterionRefs."
      );
    }
    if (!selectedOutcomeIds.has(outcomeRef)) {
      throw compilerError(
        "OUTCOME_HINT_OUTCOME_UNSELECTED",
        `Outcome contribution hint references unselected Outcome ${outcomeRef}.`,
        { outcomeRef, selectedOutcomeRefs: [...selectedOutcomeIds] }
      );
    }
    if (seen.has(outcomeRef)) {
      throw compilerError("OUTCOME_HINT_DUPLICATE", `Outcome ${outcomeRef} has more than one contribution hint.`);
    }
    seen.add(outcomeRef);
    const criterionRefs = rawCriterionRefs.map((item) => item.trim());
    if (new Set(criterionRefs).size !== criterionRefs.length) {
      throw compilerError("OUTCOME_HINT_DUPLICATE_CRITERION", `Outcome ${outcomeRef} repeats a Criterion hint.`);
    }
    return { outcomeRef, criterionRefs };
  });
}

function normalizeOutcomeExceptions(value, selectedOutcomeIds) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw compilerError("OUTCOME_EXCEPTION_INVALID", "outcomeExceptions must be a list.");
  }
  const seen = new Set();
  return value.map((exception) => {
    const outcomeRef = readString(exception?.outcomeRef);
    const reason = readString(exception?.reason);
    if (!outcomeRef || !reason || !isSubstantive(exception?.residualUncertainty)) {
      throw compilerError(
        "OUTCOME_EXCEPTION_INVALID",
        "Each Outcome exception requires outcomeRef, reason, and residualUncertainty."
      );
    }
    if (!selectedOutcomeIds.has(outcomeRef)) {
      throw compilerError(
        "OUTCOME_EXCEPTION_OUTCOME_UNSELECTED",
        `Outcome exception references unselected Outcome ${outcomeRef}.`,
        { outcomeRef, selectedOutcomeRefs: [...selectedOutcomeIds] }
      );
    }
    if (seen.has(outcomeRef)) {
      throw compilerError("OUTCOME_EXCEPTION_DUPLICATE", `Outcome ${outcomeRef} has more than one exception.`);
    }
    seen.add(outcomeRef);
    return {
      outcomeRef,
      reason,
      residualUncertainty: cloneJson(exception.residualUncertainty)
    };
  });
}

function readAccessibleContractClaims(primaryModule, governanceBaseline) {
  const contractIds = new Set([
    ...asArray(primaryModule.publicContracts).map(readReference).filter(Boolean),
    ...asArray(primaryModule.dependencies)
      .map((dependency) => readReference(dependency, ["via", "contract", "contractId"]))
      .filter(Boolean)
  ]);
  return new Map(governanceBaseline.contracts
    .filter((contract) => contractIds.has(contract.id))
    .flatMap((contract) => asArray(contract.claims).map((claim) => [claim.id, claim])));
}

function outcomeAlignmentProblem({
  outcomeRef,
  reason,
  exactAccessibleClaims,
  changeClaims,
  accessibleClaims,
  globalClaims,
  criteria = []
}) {
  const criterionClaimRefs = new Set(criteria.flatMap((criterion) => normalizeStringList(criterion.claimRefs)));
  return {
    outcomeRef,
    reason,
    candidateCriterionRefs: [],
    accessibleClaimRefs: exactAccessibleClaims.map((claim) => claim.id),
    inaccessibleClaimRefs: asArray(changeClaims)
      .filter((claim) => criterionClaimRefs.has(claim?.id)
        && globalClaims.has(claim?.id)
        && !accessibleClaims.has(claim?.id))
      .map((claim) => claim.id)
  };
}

function compileOutcomeContribution({
  change,
  governanceBaseline,
  primaryModule,
  outcome,
  criterion,
  claimBindings
}) {
  const binding = {
    schemaVersion: 1,
    changeId: change.id,
    governanceBaselineDigest: governanceBaseline.digest,
    outcome: { id: outcome.id, statement: outcome.outcome },
    criterion: cloneJson(criterion),
    moduleRef: primaryModule.id,
    claims: claimBindings.map((claim) => ({ id: claim.id, statement: claim.statement }))
  };
  const bindingDigest = canonicalDigest(binding);
  return {
    contributionId: `oc-${bindingDigest.slice("sha256:".length)}`,
    outcomeRef: outcome.id,
    criterionRef: criterion.id,
    moduleRef: primaryModule.id,
    claimRefs: claimBindings.map((claim) => claim.id),
    bindingDigest
  };
}

function compileOutcomeException({
  change,
  governanceBaseline,
  primaryModule,
  outcome,
  exception,
  exactAccessibleClaims
}) {
  const requiredAuthorityRef = readReference(governanceBaseline.plan?.authority) ?? null;
  const claimRefs = exactAccessibleClaims.map((claim) => claim.id).sort();
  const binding = {
    schemaVersion: 1,
    changeId: change.id,
    governanceBaselineDigest: governanceBaseline.digest,
    outcome: { id: outcome.id, statement: outcome.outcome },
    moduleRef: primaryModule.id,
    claimRefs,
    reason: exception.reason,
    residualUncertainty: exception.residualUncertainty,
    requiredAuthorityRef,
    progress: "none",
    transitionUse: "forbidden"
  };
  const bindingDigest = canonicalDigest(binding);
  return {
    exceptionId: `oe-${bindingDigest.slice("sha256:".length)}`,
    outcomeRef: outcome.id,
    moduleRef: primaryModule.id,
    claimRefs,
    reason: exception.reason,
    residualUncertainty: cloneJson(exception.residualUncertainty),
    requiredAuthorityRef,
    progress: "none",
    transitionUse: "forbidden",
    bindingDigest
  };
}

function compareOutcomeBindings(left, right) {
  return left.outcomeRef.localeCompare(right.outcomeRef)
    || (left.criterionRef ?? "").localeCompare(right.criterionRef ?? "")
    || (left.contributionId ?? left.exceptionId).localeCompare(right.contributionId ?? right.exceptionId);
}

function projectOutcomeContext(planOutcomes, outcomeAlignment) {
  if (!outcomeAlignment || outcomeAlignment.status === "not-applicable") {
    return planOutcomes.map(cloneJson);
  }
  const criterionRefsByOutcome = new Map();
  for (const contribution of outcomeAlignment.contributions) {
    const refs = criterionRefsByOutcome.get(contribution.outcomeRef) ?? new Set();
    refs.add(contribution.criterionRef);
    criterionRefsByOutcome.set(contribution.outcomeRef, refs);
  }
  for (const problem of outcomeAlignment.unresolved) {
    const refs = criterionRefsByOutcome.get(problem.outcomeRef) ?? new Set();
    for (const criterionRef of normalizeStringList(problem.candidateCriterionRefs)) refs.add(criterionRef);
    criterionRefsByOutcome.set(problem.outcomeRef, refs);
  }
  return planOutcomes.map((outcome) => {
    const selectedRefs = criterionRefsByOutcome.get(outcome.id) ?? new Set();
    const criteria = asArray(outcome.acceptance?.criteria)
      .filter((criterion) => selectedRefs.has(criterion.id))
      .map(cloneJson);
    return cloneJson({
      ...outcome,
      acceptance: {
        ...outcome.acceptance,
        criteria,
        exitCriteria: criteria.map((criterion) => criterion.statement),
        claimRefs: unique(criteria.flatMap((criterion) => normalizeStringList(criterion.claimRefs))),
        gapRefs: unique(criteria.flatMap((criterion) => normalizeStringList(criterion.gapRefs)))
      }
    });
  });
}

function compileImpact({ governanceBaseline, primaryModule, supplied }) {
  const modulesById = new Map(governanceBaseline.modules.map((module) => [module.id, module]));
  const contractsById = new Map(governanceBaseline.contracts.map((contract) => [contract.id, contract]));
  const ownedContractIds = unique([
    ...asArray(primaryModule.publicContracts).map(readReference).filter(Boolean),
    ...governanceBaseline.contracts
      .filter((contract) => readReference(contract.owner, ["module", "moduleId", "id"]) === primaryModule.id)
      .map((contract) => contract.id)
  ]);
  const contractConsumers = unique(ownedContractIds.flatMap((contractId) => {
    const contract = contractsById.get(contractId);
    return asArray(contract?.consumers).map((consumer) => readReference(consumer, ["module", "moduleId", "id"])).filter(Boolean);
  }));
  const dependencyModules = unique(asArray(primaryModule.dependencies)
    .map((dependency) => readReference(dependency, ["module", "moduleId", "target", "id"]))
    .filter(Boolean));
  const reverseDependencies = unique(governanceBaseline.modules
    .filter((module) => asArray(module.dependencies)
      .some((dependency) => readReference(dependency, ["module", "moduleId", "target", "id"]) === primaryModule.id))
    .map((module) => module.id));
  const affectedModuleIds = unique([
    primaryModule.id,
    ...contractConsumers,
    ...dependencyModules,
    ...reverseDependencies,
    ...normalizeStringList(supplied?.additionalModules)
  ]);
  const affectedContractIds = unique([
    ...ownedContractIds,
    ...asArray(primaryModule.dependencies)
      .map((dependency) => readReference(dependency, ["via", "contract", "contractId"]))
      .filter((id) => contractsById.has(id)),
    ...normalizeStringList(supplied?.additionalContracts)
  ]);
  const byStatus = { governed: [], provisional: [], opaque: [], unmodeled: [] };
  for (const moduleId of affectedModuleIds) {
    const status = modulesById.get(moduleId)?.status ?? "unmodeled";
    byStatus[status].push(moduleId);
  }

  return {
    schemaVersion: 1,
    directModule: primaryModule.id,
    affectedModules: affectedModuleIds,
    affectedContracts: affectedContractIds,
    contractConsumers,
    dependencyModules,
    reverseDependencies,
    assuranceCrossings: {
      byStatus,
      crossesProvisional: byStatus.provisional.length > 0,
      crossesOpaque: byStatus.opaque.length > 0 || byStatus.unmodeled.length > 0
    },
    risks: unique([
      ...normalizeStringList(primaryModule.risks),
      ...normalizeStringList(supplied?.risks)
    ]),
    ...(supplied?.notes !== undefined ? { notes: cloneJson(supplied.notes) } : {}),
    ...(supplied?.annotations !== undefined ? { annotations: cloneJson(supplied.annotations) } : {})
  };
}

function compileVerificationObligations({ claims, primaryModule, governanceBaseline, supplied }) {
  const suppliedByClaim = new Map();
  for (const item of asArray(supplied)) {
    const claimId = readString(item?.claimId);
    if (claimId) suppliedByClaim.set(claimId, cloneJson(item));
  }
  const applicableGates = governanceBaseline.gates.filter((gate) => {
    const targets = normalizeStringList(gate.appliesTo);
    return targets.length === 0 || targets.includes(primaryModule.id);
  });
  const applicableGateIds = new Set(applicableGates.map((gate) => readString(gate?.id)).filter(Boolean));
  const authoritativeClaims = new Map(governanceBaseline.contracts.flatMap((contract) => (
    asArray(contract.claims).map((claim) => [claim.id, claim])
  )));

  return claims.map((claim) => {
    const authoritative = claim.id === PROJECT_MODEL_CLAIM.id
      ? PROJECT_MODEL_CLAIM
      : authoritativeClaims.get(claim.id);
    if (authoritative && authoritative.statement !== claim.statement) {
      throw compilerError(
        "CLAIM_SEMANTIC_MISMATCH",
        `Claim ${claim.id} reuses a governed identifier with a different statement.`,
        {
          claimId: claim.id,
          expectedStatement: authoritative.statement,
          observedStatement: claim.statement
        }
      );
    }
    const user = suppliedByClaim.get(claim.id) ?? {};
    const exactRoutes = compileAcceptanceClaimRoutes({
      governanceBaseline,
      claimId: claim.id,
      primaryModuleId: primaryModule.id,
      applicableGateIds
    });
    const exactGateIds = unique(exactRoutes.map((route) => route.gateId));
    const userGateRefs = normalizeStringList(user.gateClaimRefs ?? user.evidenceSourceRefs ?? user.supportedBy);
    const crossClaimRefs = userGateRefs.filter((ref) => ref !== claim.id);
    const sourceRoutes = compileAcceptanceSourceRoutes({
      governanceBaseline,
      claimIds: crossClaimRefs,
      primaryModuleId: primaryModule.id,
      applicableGateIds
    });
    let mapping;
    if (claim.id === "project-model-self-consistent") {
      mapping = { status: "mapped", kind: "builtin-oracle", sourceIds: ["project-model"] };
    } else if (exactGateIds.length > 0) {
      mapping = {
        status: "mapped",
        kind: "exact-contract-claim",
        gateIds: exactGateIds,
        routes: exactRoutes
      };
    } else if (crossClaimRefs.length > 0 && hasCrossMappingSemantics(user)) {
      mapping = {
        status: "pending-authority",
        kind: "cross-claim",
        sourceClaimIds: crossClaimRefs,
        sourceRoutes,
        requiredApproval: `approvedObligationIds must include ${readString(user.id) ?? `verify-${claim.id}`}`
      };
    } else {
      mapping = {
        status: "unmapped",
        kind: "unmapped",
        reason: crossClaimRefs.length > 0
          ? "Cross-Claim mappings require mappingRationale, applicability, and discriminatoryPower."
          : "No exact Contract Claim Gate mapping is declared; independent Evidence is required."
      };
    }

    return {
      ...user,
      id: readString(user.id) ?? `verify-${claim.id}`,
      claimId: claim.id,
      required: user.required !== false,
      gateClaimRefs: unique([
        ...userGateRefs,
        ...(exactGateIds.length > 0 ? [claim.id] : [])
      ]),
      exactGateIds,
      mapping
    };
  });
}

function compileAcceptanceClaimRoutes({
  governanceBaseline,
  claimId,
  primaryModuleId,
  applicableGateIds
}) {
  const routes = compileClaimGateRoutes(governanceBaseline, claimId)
    .filter((route) => applicableGateIds.has(route.gateId)
      && asArray(route.effectiveModuleRefs).includes(primaryModuleId))
    .map((route) => ({ gateId: route.gateId, commandId: route.commandId }));
  return uniqueGateCommandRoutes(routes);
}

function compileAcceptanceSourceRoutes({
  governanceBaseline,
  claimIds,
  primaryModuleId,
  applicableGateIds
}) {
  const routes = claimIds.flatMap((sourceClaimId) => compileAcceptanceClaimRoutes({
    governanceBaseline,
    claimId: sourceClaimId,
    primaryModuleId,
    applicableGateIds
  }).map((route) => ({ sourceClaimId, ...route })));
  const indexed = new Map();
  for (const route of routes) {
    const sourceClaimId = readString(route?.sourceClaimId);
    const gateId = readString(route?.gateId);
    const commandId = readString(route?.commandId);
    if (!sourceClaimId || !gateId || !commandId) continue;
    indexed.set(
      `${sourceClaimId}\u0000${gateId}\u0000${commandId}`,
      { sourceClaimId, gateId, commandId }
    );
  }
  return [...indexed.values()].sort((left, right) => (
    left.sourceClaimId.localeCompare(right.sourceClaimId)
      || left.gateId.localeCompare(right.gateId)
      || left.commandId.localeCompare(right.commandId)
  ));
}

function uniqueGateCommandRoutes(routes) {
  const indexed = new Map();
  for (const route of routes) {
    const gateId = readString(route?.gateId);
    const commandId = readString(route?.commandId);
    if (!gateId || !commandId) continue;
    indexed.set(`${gateId}\u0000${commandId}`, { gateId, commandId });
  }
  return [...indexed.values()].sort((left, right) => (
    left.gateId.localeCompare(right.gateId)
      || left.commandId.localeCompare(right.commandId)
  ));
}

function compileVerificationPlan({ primaryModule, governanceBaseline, verificationObligations }) {
  const policy = governanceBaseline.projectDocument?.changePolicy ?? {};
  const defaultGateId = readString(policy.defaultGate);
  const acceptanceGateIds = unique([
    "project-model",
    ...(defaultGateId
      ? [defaultGateId]
      : governanceBaseline.gates.filter((gate) => gate.required === true).map((gate) => gate.id))
  ]);
  const fullGateId = readString(policy.fullGate);
  const fullGateBefore = normalizeStringList(policy.fullGateBefore);
  return {
    schemaVersion: 1,
    primaryModule: primaryModule.id,
    defaultGateId: defaultGateId ?? null,
    acceptanceGateIds,
    integrationGateIds: fullGateId && fullGateBefore.map((value) => value.toLowerCase()).includes("integrated")
      ? [fullGateId]
      : [],
    obligations: verificationObligations.map((obligation) => ({
      id: obligation.id,
      claimId: obligation.claimId,
      required: obligation.required,
      mapping: cloneJson(obligation.mapping)
    }))
  };
}

function assertAssuranceAllowsCompilation(change, primaryModule, governanceBaseline) {
  if (primaryModule.status === "governed") {
    return { status: "governed", writeScopeMode: "module-paths" };
  }
  if (primaryModule.status === "provisional") {
    const expansion = change.modelExpansion;
    const rationale = readString(expansion?.rationale) ?? readString(expansion?.reason);
    const authorityPath = normalizeStringList(expansion?.authorityPath ?? expansion?.authorities ?? expansion?.authority);
    const declaredAuthorities = decisionAuthorityIds(governanceBaseline);
    if (!rationale || authorityPath.length === 0 || !authorityPath.some((id) => declaredAuthorities.includes(id))) {
      throw compilerError(
        "PROVISIONAL_MODULE_EXPANSION_REQUIRED",
        `Provisional Module ${primaryModule.id} requires modelExpansion with rationale and a declared authorityPath.`,
        { primaryModule: primaryModule.id, declaredAuthorities }
      );
    }
    return {
      status: "provisional",
      writeScopeMode: "module-paths-with-model-expansion",
      modelExpansion: cloneJson(expansion)
    };
  }
  if (primaryModule.status === "opaque") {
    const waiver = change.authorityDecision;
    const declaredAuthorities = decisionAuthorityIds(governanceBaseline);
    const validWaiver = waiver?.decisionType === "waiver"
      && ["approved", "accepted"].includes(waiver.status)
      && declaredAuthorities.includes(readString(waiver.authority))
      && readString(waiver.reason)
      && isSubstantive(waiver.expiresAt ?? waiver.expiresWhen)
      && Array.isArray(waiver.compensatingControls)
      && waiver.compensatingControls.length > 0
      && waiverScopeIncludesModule(waiver.scope, primaryModule.id);
    if (!validWaiver) {
      throw compilerError(
        "OPAQUE_MODULE_WAIVER_REQUIRED",
        `Opaque Module ${primaryModule.id} is outside automatic compilation; a scoped Authority waiver is required.`,
        { primaryModule: primaryModule.id, automaticWriteScope: [] }
      );
    }
    return {
      status: "opaque",
      writeScopeMode: "none",
      waiver: {
        authority: waiver.authority,
        expiresAt: waiver.expiresAt ?? waiver.expiresWhen,
        scope: cloneJson(waiver.scope)
      },
      restriction: "The waiver permits bounded handling but does not infer any opaque implementation write scope."
    };
  }
  throw compilerError("MODULE_ASSURANCE_STATUS_INVALID", `Unsupported Module status: ${primaryModule.status}.`);
}

function validateContextSupplement(value) {
  if (value === undefined || value === null) return;
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw compilerError("CONTEXT_CAPSULE_INPUT_INVALID", "contextCapsule supplement must be an object.");
  }
  const allowed = new Set([
    "scope",
    "allowedScope",
    "allowedReadScope",
    "allowedWriteScope",
    "additionalContextRefs",
    "notes",
    "workerInstructions",
    "annotations"
  ]);
  const forbidden = Object.keys(value).filter((key) => COMPILED_CONTEXT_KEYS.has(key) && !allowed.has(key));
  if (forbidden.length > 0) {
    throw compilerError(
      "COMPILED_CONTEXT_OVERRIDE_FORBIDDEN",
      `Project-owned Context Capsule fields cannot be overridden: ${forbidden.join(", ")}.`,
      { forbiddenFields: forbidden }
    );
  }
}

function copySupplementalContext(value) {
  if (!value || typeof value !== "object") return {};
  return {
    ...(value.notes !== undefined ? { notes: cloneJson(value.notes) } : {}),
    ...(value.workerInstructions !== undefined ? { workerInstructions: cloneJson(value.workerInstructions) } : {}),
    ...(value.annotations !== undefined ? { annotations: cloneJson(value.annotations) } : {})
  };
}

function narrowScope(generated, supplied, label) {
  if (supplied === undefined || supplied === null) return cloneJson(generated);
  const requested = Array.isArray(supplied) || typeof supplied === "string"
    ? { include: supplied }
    : supplied;
  if (!requested || typeof requested !== "object") {
    throw compilerError("CONTEXT_SCOPE_INVALID", `${label} scope must be a path list or scope object.`);
  }
  const include = requested.include === undefined
    ? generated.include
    : normalizePaths(requested.include);
  assertWithinScope(include, generated.include, `${label}.include`);
  const extraExcludes = normalizePaths(requested.exclude);
  assertWithinScope(extraExcludes, generated.include, `${label}.exclude`);
  return {
    include,
    exclude: unique([...generated.exclude, ...extraExcludes])
  };
}

function assertWithinScope(candidates, allowed, label) {
  const outside = candidates.filter((candidate) => !allowed.some((parent) => scopePatternWithin(candidate, parent)));
  if (outside.length > 0) {
    throw compilerError(
      "CONTEXT_SCOPE_EXPANSION_FORBIDDEN",
      `${label} may only narrow the Project Model scope.`,
      { outside, allowed }
    );
  }
}

function scopePatternWithin(candidate, parent) {
  if (!candidate || candidate.startsWith("/") || candidate.split("/").includes("..")) return false;
  if (candidate === parent || parent === "**" || parent === "**/*") return true;
  const candidateHasWildcard = /[?*[\]]/u.test(candidate);
  if (!candidateHasWildcard) return concretePathMatchesPattern(candidate, parent);

  // Pattern subset reasoning is intentionally conservative. A child glob is
  // only accepted beneath a literal recursive root; arbitrary shared prefixes
  // (for example src/*.js vs src/evil/**) do not establish containment.
  if (parent.endsWith("/**")) {
    const root = parent.slice(0, -3).replace(/\/$/u, "");
    return root.length === 0 || candidate.startsWith(`${root}/`);
  }
  return false;
}

function concretePathMatchesPattern(filePath, pattern) {
  let expression = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      expression += ".*";
      index += 1;
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/gu, "\\$&");
    }
  }
  return new RegExp(`^${expression}$`, "u").test(filePath);
}

function relevantModelDocumentPaths(files, moduleId, contractIds) {
  const desiredIds = new Set([moduleId, ...contractIds]);
  return unique(asArray(files).filter((file) => {
    if (file === ".legatura/project.json" || file === ".legatura/knowledge-gaps.json") return true;
    const id = file.split("/").at(-1)?.replace(/\.json$/u, "");
    return desiredIds.has(id);
  }));
}

function pickModuleContext(module) {
  return cloneJson({
    id: module.id,
    name: module.name,
    status: module.status,
    summary: module.summary,
    factAuthority: module.factAuthority ?? null,
    interface: module.interface ?? null,
    paths: module.paths,
    focusedTests: module.focusedTests ?? [],
    risks: module.risks ?? []
  });
}

function pickContractContext(contract) {
  return cloneJson({
    id: contract.id,
    name: contract.name,
    owner: contract.owner,
    maturity: contract.maturity,
    claims: contract.claims,
    consumers: contract.consumers ?? [],
    normativeSources: contract.normativeSources ?? [],
    residualUncertainty: contract.residualUncertainty ?? null
  });
}

function hasCrossMappingSemantics(obligation) {
  return Boolean(readString(obligation.mappingRationale)
    && isSubstantive(obligation.applicability)
    && isSubstantive(obligation.discriminatoryPower));
}

function gateSelectsModule(gate, moduleRef, fullGateId) {
  const appliesTo = normalizeGateScope(gate?.appliesTo);
  if (appliesTo.length === 0 || appliesTo.includes(moduleRef)) return true;
  return readString(gate?.id) === fullGateId
    && (appliesTo.includes("integration") || appliesTo.includes("release"));
}

function commandSelectsModule(command, moduleRef) {
  const appliesTo = normalizeGateScope(command?.appliesTo);
  return appliesTo.length === 0 || appliesTo.includes(moduleRef);
}

function normalizeGateScope(value) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.map(readString).filter(Boolean))];
}

function decisionAuthorityIds(governanceBaseline) {
  return unique(asArray(governanceBaseline.projectDocument?.authorities?.decision)
    .map((authority) => readReference(authority))
    .filter(Boolean));
}

function waiverScopeIncludesModule(scope, moduleId) {
  if (typeof scope === "string") return scope.trim() === moduleId;
  if (Array.isArray(scope)) return scope.map(readReference).includes(moduleId);
  if (!scope || typeof scope !== "object") return false;
  if (readReference(scope, ["module", "moduleId", "id"]) === moduleId) return true;
  return normalizeStringList(scope.modules).includes(moduleId);
}

function normalizePaths(value) {
  return normalizeStringList(value).map((item) => item.replace(/^\.\//u, ""));
}

function normalizeStringList(value) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? value : [value];
  return unique(values.filter(readString).map((item) => item.trim()));
}

function readReference(value, keys = ["id", "module", "moduleId", "contract", "contractId", "target"]) {
  if (typeof value === "string") return readString(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  for (const key of keys) {
    const candidate = readString(value[key]);
    if (candidate) return candidate;
  }
  return undefined;
}

function readModelReference(value, keys = ["id", "module", "moduleId", "target"]) {
  if (typeof value === "string") return readString(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  for (const key of keys) {
    const reference = readString(value[key]);
    if (reference) return reference;
  }
  return undefined;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function unique(values) {
  return [...new Set(values)];
}

function isSubstantive(value) {
  if (typeof value === "string") return Boolean(value.trim());
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object" && Object.keys(value).length > 0);
}

function compilerError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = 422;
  if (details !== undefined) error.details = details;
  return error;
}
