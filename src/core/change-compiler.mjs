import { Buffer } from "node:buffer";
import { types as utilTypes } from "node:util";

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

export const CLAIM_GATE_ROUTE_INDEX_LIMITS = Object.freeze({
  claimRefs: 4096,
  modules: 2048,
  contracts: 4096,
  modelClaims: 4096,
  refsPerModule: 256,
  visibilityRefs: 65536,
  gates: 2048,
  commands: 8192,
  refsPerCommand: 256,
  totalCommandClaimRefs: 65536,
  routeSelectionRows: 2048,
  refsPerRouteSelection: 256,
  routeSelectionClaimRefs: 65536,
  routes: 8192,
  routeBytes: 16384,
  totalRouteBytes: 2 * 1024 * 1024,
  depth: 64,
  textBytes: 4096,
  workUnits: 4194304
});

const COMPILED_CLAIM_GATE_ROUTE_INDEXES = new WeakMap();
const CLAIM_GATE_ROUTE_LIMIT_USAGES = new WeakMap();
let activeClaimGateRouteInputGuard = null;

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
  if (typeof claimRef !== "string") return [];
  const exactClaimRef = claimRef.trim();
  if (!exactClaimRef) return [];
  const index = compileClaimGateRouteIndex(model, { claimRefs: [exactClaimRef] });
  return projectCompiledClaimGateRouteIndex(index, {
    model,
    claimRefs: [exactClaimRef]
  }).routesByClaim.get(exactClaimRef);
}

export function compileClaimGateRouteIndex(model, options = {}) {
  const { claimRefs, limits } = normalizeClaimGateRouteIndexOptions(options);
  const budget = {
    commands: 0,
    contracts: 0,
    modelClaims: 0,
    visibilityRefs: 0,
    totalCommandClaimRefs: 0,
    routes: 0,
    totalRouteBytes: 0,
    workUnits: 0
  };
  const normalizedClaimRefs = normalizeRequestedClaimRefs(claimRefs, limits, budget);
  const routesByClaim = new Map(normalizedClaimRefs.map((claimRef) => [claimRef, []]));
  const acceptanceModuleRefsByClaim = new Map(
    normalizedClaimRefs.map((claimRef) => [claimRef, []])
  );
  for (const claimRef of normalizedClaimRefs) {
    const claimCoverageBytes = Buffer.byteLength(
      JSON.stringify([claimRef, []]),
      "utf8"
    );
    consumeClaimGateRouteAggregateBytes(
      budget,
      limits,
      (4 * claimCoverageBytes) + 32,
      `claimRefs.${claimRef}.acceptanceMetadata`
    );
  }
  const inputGuard = createClaimGateRouteInputGuard(model);
  const priorInputGuard = activeClaimGateRouteInputGuard;
  activeClaimGateRouteInputGuard = inputGuard;
  try {
    const moduleClaimVisibility = compileBoundedModuleClaimVisibility(model, limits, budget);
    if (normalizedClaimRefs.length > 0) {
      const selectedClaimRefs = new Set(normalizedClaimRefs);
      const moduleRefs = moduleClaimVisibility.moduleRefs;
      const gates = readRouteIndexArrayProperty(model, "gates", "model.gates");
      assertClaimGateRouteLimit("gates", gates.length, limits);
      const projectDocument = readOptionalRouteIndexDataProperty(
        model,
        "projectDocument",
        "model.projectDocument"
      );
      const changePolicy = readOptionalRouteIndexDataProperty(
        projectDocument,
        "changePolicy",
        "model.projectDocument.changePolicy"
      );
      const fullGateId = normalizeBoundedOptionalRouteText(
        readOptionalRouteIndexDataProperty(
          changePolicy,
          "fullGate",
          "model.projectDocument.changePolicy.fullGate"
        ),
        "model.projectDocument.changePolicy.fullGate",
        limits
      );

      for (let gateIndex = 0; gateIndex < gates.length; gateIndex += 1) {
        reserveClaimGateRouteWork(budget, limits, 1);
        const gateLocation = `model.gates.${gateIndex}`;
        const gate = readRouteIndexArrayValue(gates, gateIndex, gateLocation);
        let gateSemantics;
        const declaredCommands = readOptionalRouteIndexDataProperty(
          gate,
          "commands",
          `${gateLocation}.commands`
        );
        let commands;
        if (Array.isArray(declaredCommands)) {
          commands = assertRouteIndexArray(declaredCommands, `${gateLocation}.commands`);
        } else {
          const legacyCommand = readOptionalRouteIndexDataProperty(
            gate,
            "command",
            `${gateLocation}.command`
          );
          commands = legacyCommand ? [gate] : [];
        }
        budget.commands += commands.length;
        assertClaimGateRouteLimit("commands", budget.commands, limits);

        for (let commandIndex = 0; commandIndex < commands.length; commandIndex += 1) {
          reserveClaimGateRouteWork(budget, limits, 1);
          const command = readRouteIndexArrayValue(
            commands,
            commandIndex,
            `${gateLocation}.commands.${commandIndex}`
          );
          const location = `model.gates.${gateIndex}.commands.${commandIndex}`;
          const commandClaimRefs = normalizeBoundedCommandClaimRefs(
            readOptionalRouteIndexDataProperty(command, "claimRefs", `${location}.claimRefs`),
            `${location}.claimRefs`,
            limits,
            budget
          );
          const matchingClaimRefs = commandClaimRefs.filter((claimRef) => (
            selectedClaimRefs.has(claimRef)
          ));
          if (matchingClaimRefs.length === 0) continue;
          gateSemantics ??= compileBoundedGateSemantics(gate, gateLocation, limits, budget);
          const commandId = normalizeBoundedOptionalRouteText(
            readOptionalRouteIndexDataProperty(command, "id", `${location}.id`),
            `${location}.id`,
            limits
          ) ?? null;
          const commandScope = normalizeBoundedGateScope(
            readOptionalRouteIndexDataProperty(command, "appliesTo", `${location}.appliesTo`),
            `${location}.appliesTo`,
            limits,
            budget
          );
          reserveClaimGateRouteWork(budget, limits, moduleRefs.length);
          const effectiveModuleRefs = moduleRefs.filter((moduleRef) => (
            normalizedGateScopeSelectsModule(
              gateSemantics.scope,
              gateSemantics.selectorId,
              moduleRef,
              fullGateId
            )
              && normalizedCommandScopeSelectsModule(commandScope, moduleRef)
          ));
          reserveClaimGateRouteWork(budget, limits, moduleRefs.length);
          const acceptanceModuleRefs = moduleRefs.filter((moduleRef) => (
            normalizedAcceptanceGateScopeSelectsModule(gateSemantics.scope, moduleRef)
              && normalizedCommandScopeSelectsModule(commandScope, moduleRef)
          ));

          const routeTemplate = compileBoundedRouteTemplate({
            commandValues: readBoundedRouteCommandValues(command, location),
            commandId,
            effectiveModuleRefs,
            gateId: gateSemantics.id,
            limits,
            location,
            budget
          });
          for (const claimRef of matchingClaimRefs) {
            reserveClaimGateRouteWork(budget, limits, 1);
            reserveClaimGateRouteWork(budget, limits, acceptanceModuleRefs.length);
            budget.routes += 1;
            assertClaimGateRouteLimit("routes", budget.routes, limits);
            const route = cloneRouteForClaim(routeTemplate, claimRef);
            const routeBytes = Buffer.byteLength(JSON.stringify(route), "utf8");
            assertClaimGateRouteLimit("routeBytes", routeBytes, limits);
            budget.totalRouteBytes += routeBytes;
            assertClaimGateRouteLimit("totalRouteBytes", budget.totalRouteBytes, limits);
            const acceptanceMetadataBytes = Buffer.byteLength(
              JSON.stringify([claimRef, acceptanceModuleRefs]),
              "utf8"
            ) + 16;
            consumeClaimGateRouteAggregateBytes(
              budget,
              limits,
              acceptanceMetadataBytes,
              `${location}.acceptanceModuleRefs`
            );
            routesByClaim.get(claimRef).push({
              route,
              digest: canonicalDigest(route),
              acceptanceModuleRefs
            });
          }
        }
      }

      for (const claimRef of normalizedClaimRefs) {
        const compiled = routesByClaim.get(claimRef);
        compiled.sort((left, right) => {
          reserveClaimGateRouteWork(budget, limits, 1);
          return compareCompiledClaimGateRoutes(left, right);
        });
        acceptanceModuleRefsByClaim.set(
          claimRef,
          compiled.map((entry) => [...entry.acceptanceModuleRefs])
        );
        routesByClaim.set(claimRef, compiled.map((entry) => entry.route));
      }
    }
    return brandCompiledClaimGateRouteIndex({
      acceptanceModuleRefsByClaim,
      routesByClaim,
      model,
      claimRefs: normalizedClaimRefs,
      limits,
      inputGuard,
      moduleClaimVisibility
    });
  } finally {
    activeClaimGateRouteInputGuard = priorInputGuard;
  }
}

function compileBoundedGateSemantics(gate, location, limits, budget) {
  const selectorId = normalizeBoundedOptionalRouteText(
    readOptionalRouteIndexDataProperty(gate, "id", `${location}.id`),
    `${location}.id`,
    limits
  );
  return {
    id: selectorId ?? null,
    selectorId,
    scope: normalizeBoundedGateScope(
      readOptionalRouteIndexDataProperty(gate, "appliesTo", `${location}.appliesTo`),
      `${location}.appliesTo`,
      limits,
      budget
    )
  };
}

export function reuseCompiledClaimGateRouteIndex(index, options = {}) {
  return projectCompiledClaimGateRouteIndex(index, options).routesByClaim;
}

export function projectCompiledClaimGateRouteIndex(index, options = {}) {
  const priorInputGuard = activeClaimGateRouteInputGuard;
  activeClaimGateRouteInputGuard = null;
  try {
    return projectCompiledClaimGateRouteIndexWithoutGuardCapture(index, options);
  } finally {
    activeClaimGateRouteInputGuard = priorInputGuard;
  }
}

export function projectCompiledModuleClaimGateIndex(index, options = {}) {
  const priorInputGuard = activeClaimGateRouteInputGuard;
  activeClaimGateRouteInputGuard = null;
  try {
    return projectCompiledModuleClaimGateIndexWithoutGuardCapture(index, options);
  } finally {
    activeClaimGateRouteInputGuard = priorInputGuard;
  }
}

function projectCompiledModuleClaimGateIndexWithoutGuardCapture(index, options) {
  assertNotRouteIndexProxy(index, "index");
  const compiled = ((typeof index === "object" && index !== null)
    || typeof index === "function")
    ? COMPILED_CLAIM_GATE_ROUTE_INDEXES.get(index)
    : undefined;
  if (!compiled) throw invalidCompiledClaimGateRouteIndexError();

  const projection = normalizeCompiledModuleClaimGateProjectionOptions(options, compiled);
  if (projection.model !== compiled.model) {
    throw invalidCompiledClaimGateRouteIndexError({ reason: "model-identity-mismatch" });
  }
  assertCompiledClaimGateRouteProjectionLimits(compiled, projection.limits);
  assertClaimGateRouteInputGuardCurrent(compiled.inputGuard);
  assertCompiledClaimGateRouteProductDigestCurrent(compiled);

  const visibility = compiled.moduleClaimVisibility;
  const knownModules = new Set(visibility.moduleRefs);
  const visibilityByModule = new Map(visibility.visibilityByModule.map(([moduleRef, entries]) => [
    moduleRef,
    new Map(entries)
  ]));
  const claimsByContract = new Map(visibility.claimsByContract);
  const globalClaims = new Map(visibility.globalClaims);
  const requestedRouteClaims = new Map();
  const claimsByModule = new Map();
  const budget = {
    ...compiled.usage,
    workUnits: projection.workUnits,
    projectionBindings: 0,
    routeSelections: projection.routeSelectionRows
  };

  for (const moduleRef of projection.moduleRefs) {
    if (!knownModules.has(moduleRef)) throwUnknownModuleClaimProjectionReference(moduleRef);
    const claimOptions = new Map();
    const contractVisibility = visibilityByModule.get(moduleRef) ?? new Map();
    for (const [contractRef, visibilityKinds] of contractVisibility) {
      const contractClaims = claimsByContract.get(contractRef);
      if (!contractClaims) {
        throw invalidCompiledClaimGateRouteIndexError({
          reason: "module-visibility-content-invalid",
          moduleRef,
          contractRef
        });
      }
      for (const descriptor of contractClaims) {
        reserveClaimGateRouteWork(budget, projection.limits, 1);
        budget.projectionBindings += 1;
        const existing = claimOptions.get(descriptor.claimRef);
        if (existing && existing.contractRef !== contractRef) {
          throw invalidCompiledClaimGateRouteIndexError({
            reason: "claim-contract-identity-conflict",
            claimRef: descriptor.claimRef
          });
        }
        const projectedDescriptor = {
          claimRef: descriptor.claimRef,
          statement: descriptor.statement,
          contractRef,
          visibilityKinds: mergeVisibilityKinds(
            existing?.visibilityKinds ?? [],
            visibilityKinds
          )
        };
        const descriptorBytes = Buffer.byteLength(JSON.stringify(projectedDescriptor), "utf8");
        assertClaimGateRouteLimit("routeBytes", descriptorBytes, projection.limits);
        budget.totalRouteBytes += descriptorBytes;
        assertClaimGateRouteLimit(
          "totalRouteBytes",
          budget.totalRouteBytes,
          projection.limits
        );
        claimOptions.set(descriptor.claimRef, projectedDescriptor);
      }
    }
    const claims = [...claimOptions.values()].sort((left, right) => (
      left.claimRef.localeCompare(right.claimRef)
    ));
    claimsByModule.set(moduleRef, claims);
    requestedRouteClaims.set(moduleRef, new Set(claims.map((claim) => claim.claimRef)));
  }

  for (const [moduleRef, claimRefs] of projection.routeSelections) {
    if (!knownModules.has(moduleRef)) throwUnknownModuleClaimProjectionReference(moduleRef);
    if (!requestedRouteClaims.has(moduleRef)) requestedRouteClaims.set(moduleRef, new Set());
    for (const claimRef of claimRefs) {
      reserveClaimGateRouteWork(budget, projection.limits, 1);
      if (!globalClaims.has(claimRef)) {
        throw claimGateRouteIndexError(
          "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
          "Module Claim Gate route selections must reference a known Contract Claim.",
          { moduleRef, claimRef }
        );
      }
      requestedRouteClaims.get(moduleRef).add(claimRef);
    }
  }

  const requiredClaimRefs = [...new Set([...requestedRouteClaims.values()]
    .flatMap((claimRefs) => [...claimRefs]))].sort();
  const missingClaimRefs = requiredClaimRefs.filter((claimRef) => !compiled.claimRefSet.has(claimRef));
  if (missingClaimRefs.length > 0) {
    throw invalidCompiledClaimGateRouteIndexError({
      reason: "claim-coverage-incomplete",
      claimRefs: missingClaimRefs
    });
  }

  const authoritativeEntries = new Map(compiled.entries);
  const acceptanceEntries = new Map(compiled.acceptanceEntries);
  const routesByModule = new Map();
  for (const moduleRef of [...requestedRouteClaims.keys()].sort()) {
    const routesByClaim = new Map();
    for (const claimRef of [...requestedRouteClaims.get(moduleRef)].sort()) {
      reserveClaimGateRouteWork(budget, projection.limits, 1);
      const routes = authoritativeEntries.get(claimRef);
      const routeAcceptance = acceptanceEntries.get(claimRef);
      if (!Array.isArray(routes)
        || !Array.isArray(routeAcceptance)
        || routes.length !== routeAcceptance.length) {
        throw invalidCompiledClaimGateRouteIndexError({
          reason: "acceptance-route-metadata-conflict",
          claimRef
        });
      }
      const selectedRoutes = [];
      for (let routeIndex = 0; routeIndex < routes.length; routeIndex += 1) {
        reserveClaimGateRouteWork(budget, projection.limits, 1);
        const acceptedModuleRefs = routeAcceptance[routeIndex];
        if (!Array.isArray(acceptedModuleRefs)) {
          throw invalidCompiledClaimGateRouteIndexError({
            reason: "acceptance-route-metadata-conflict",
            claimRef
          });
        }
        if (!sortedReferenceListHas(
          acceptedModuleRefs,
          moduleRef,
          budget,
          projection.limits
        )) continue;
        budget.routes += 1;
        assertClaimGateRouteLimit("routes", budget.routes, projection.limits);
        const routeBytes = Buffer.byteLength(JSON.stringify(routes[routeIndex]), "utf8");
        assertClaimGateRouteLimit("routeBytes", routeBytes, projection.limits);
        budget.totalRouteBytes += routeBytes;
        assertClaimGateRouteLimit(
          "totalRouteBytes",
          budget.totalRouteBytes,
          projection.limits
        );
        selectedRoutes.push(structuredClone(routes[routeIndex]));
      }
      routesByClaim.set(claimRef, selectedRoutes);
    }
    routesByModule.set(moduleRef, routesByClaim);
  }

  const observation = Object.freeze({
    schemaVersion: 1,
    workUnits: budget.workUnits,
    routes: budget.routes,
    totalRouteBytes: budget.totalRouteBytes,
    modules: requestedRouteClaims.size,
    claimBindings: budget.projectionBindings,
    routeSelections: budget.routeSelections
  });
  return { claimsByModule, routesByModule, observation };
}

function normalizeCompiledModuleClaimGateProjectionOptions(options, compiled) {
  assertPlainRouteIndexObject(
    options,
    "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
    "Module Claim Gate projection options must be a plain object."
  );
  const allowedOptionKeys = new Set(["model", "moduleRefs", "routeSelections", "limits"]);
  for (const key in options) {
    if (!Object.hasOwn(options, key)) continue;
    if (!allowedOptionKeys.has(key)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Module Claim Gate projection options contain an unsupported field.",
        { field: key }
      );
    }
    assertRouteIndexDataProperty(options, key, "projection");
  }
  const model = Object.hasOwn(options, "model")
    ? readRouteIndexDataProperty(options, "model", "projection")
    : undefined;
  const rawLimits = Object.hasOwn(options, "limits")
    ? readRouteIndexDataProperty(options, "limits", "projection")
    : {};
  const limits = compileClaimGateRouteProjectionLimits(rawLimits, compiled.limits);
  const budget = { workUnits: compiled.usage.workUnits };
  const rawModuleRefs = Object.hasOwn(options, "moduleRefs")
    ? readRouteIndexDataProperty(options, "moduleRefs", "projection")
    : [];
  const moduleRefs = normalizeBoundedProjectionReferenceList(
    rawModuleRefs,
    "projection.moduleRefs",
    "modules",
    limits,
    budget
  );
  const rawRouteSelections = Object.hasOwn(options, "routeSelections")
    ? readRouteIndexDataProperty(options, "routeSelections", "projection")
    : [];
  if (!Array.isArray(rawRouteSelections)) throw invalidClaimGateRouteJsonError("projection.routeSelections");
  const routeSelections = assertRouteIndexArray(rawRouteSelections, "projection.routeSelections");
  assertClaimGateRouteLimit(
    "routeSelectionRows",
    routeSelections.length,
    limits,
    "projection.routeSelections"
  );
  assertPotentialClaimGateRouteWork(budget, limits, routeSelections.length);
  const selectionsByModule = new Map();
  let rawSelectionClaimRefs = 0;
  for (let index = 0; index < routeSelections.length; index += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    const location = `projection.routeSelections.${index}`;
    const selection = readRouteIndexArrayValue(routeSelections, index, location);
    assertPlainRouteIndexObject(
      selection,
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "Each Module Claim Gate route selection must be a plain object."
    );
    for (const key in selection) {
      if (!Object.hasOwn(selection, key)) continue;
      if (!new Set(["moduleRef", "claimRefs"]).has(key)) {
        throw claimGateRouteIndexError(
          "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
          "Module Claim Gate route selections contain an unsupported field.",
          { location, field: key }
        );
      }
      assertRouteIndexDataProperty(selection, key, location);
    }
    const moduleRef = normalizeBoundedRequiredModelText(
      readRouteIndexDataProperty(selection, "moduleRef", location),
      `${location}.moduleRef`,
      limits,
      "Module reference"
    );
    const rawClaimRefs = readRouteIndexDataProperty(selection, "claimRefs", location);
    if (!Array.isArray(rawClaimRefs)) throw invalidClaimGateRouteJsonError(`${location}.claimRefs`);
    const claimRefs = assertRouteIndexArray(rawClaimRefs, `${location}.claimRefs`);
    assertClaimGateRouteLimit(
      "refsPerRouteSelection",
      claimRefs.length,
      limits,
      `${location}.claimRefs`
    );
    rawSelectionClaimRefs += claimRefs.length;
    assertClaimGateRouteLimit(
      "routeSelectionClaimRefs",
      rawSelectionClaimRefs,
      limits,
      `${location}.claimRefs`
    );
    assertPotentialClaimGateRouteWork(budget, limits, claimRefs.length);
    if (!selectionsByModule.has(moduleRef)) selectionsByModule.set(moduleRef, new Set());
    for (let claimIndex = 0; claimIndex < claimRefs.length; claimIndex += 1) {
      reserveClaimGateRouteWork(budget, limits, 1);
      const claimRef = normalizeBoundedRequiredModelText(
        readRouteIndexArrayValue(
          claimRefs,
          claimIndex,
          `${location}.claimRefs.${claimIndex}`
        ),
        `${location}.claimRefs.${claimIndex}`,
        limits,
        "Claim reference"
      );
      selectionsByModule.get(moduleRef).add(claimRef);
    }
  }
  return {
    model,
    moduleRefs,
    routeSelectionRows: routeSelections.length,
    routeSelections: [...selectionsByModule.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([moduleRef, claimRefs]) => [moduleRef, [...claimRefs].sort()]),
    limits,
    workUnits: budget.workUnits
  };
}

function normalizeBoundedProjectionReferenceList(raw, location, dimension, limits, budget) {
  if (!Array.isArray(raw)) throw invalidClaimGateRouteJsonError(location);
  const values = assertRouteIndexArray(raw, location);
  assertClaimGateRouteLimit(dimension, values.length, limits, location);
  assertPotentialClaimGateRouteWork(budget, limits, values.length);
  const normalized = new Set();
  for (let index = 0; index < values.length; index += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    normalized.add(normalizeBoundedRequiredModelText(
      readRouteIndexArrayValue(values, index, `${location}.${index}`),
      `${location}.${index}`,
      limits,
      "Module reference"
    ));
  }
  return [...normalized].sort();
}

function mergeVisibilityKinds(left, right) {
  return [...new Set([...left, ...right])].sort(compareVisibilityKinds);
}

function sortedReferenceListHas(values, target, budget, limits) {
  const comparisons = values.length === 0
    ? 0
    : Math.ceil(Math.log2(values.length + 1));
  reserveClaimGateRouteWork(budget, limits, comparisons);
  let low = 0;
  let high = values.length - 1;
  while (low <= high) {
    const middle = low + Math.floor((high - low) / 2);
    const value = values[middle];
    if (value === target) return true;
    if (value < target) low = middle + 1;
    else high = middle - 1;
  }
  return false;
}

function throwUnknownModuleClaimProjectionReference(moduleRef) {
  throw claimGateRouteIndexError(
    "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
    "Module Claim Gate projection must reference a known Module.",
    { moduleRef }
  );
}

function projectCompiledClaimGateRouteIndexWithoutGuardCapture(index, options) {
  assertNotRouteIndexProxy(index, "index");
  const compiled = ((typeof index === "object" && index !== null)
    || typeof index === "function")
    ? COMPILED_CLAIM_GATE_ROUTE_INDEXES.get(index)
    : undefined;
  if (!compiled) {
    throw invalidCompiledClaimGateRouteIndexError();
  }

  const projection = normalizeCompiledClaimGateRouteProjectionOptions(options, compiled);
  if (projection.model !== compiled.model) {
    throw invalidCompiledClaimGateRouteIndexError({ reason: "model-identity-mismatch" });
  }
  const missingClaimRefs = projection.claimRefs.filter((claimRef) => (
    !compiled.claimRefSet.has(claimRef)
  ));
  if (missingClaimRefs.length > 0) {
    throw invalidCompiledClaimGateRouteIndexError({
      reason: "claim-coverage-incomplete",
      claimRefs: missingClaimRefs
    });
  }
  assertCompiledClaimGateRouteProjectionLimits(compiled, projection.limits);
  assertClaimGateRouteInputGuardCurrent(compiled.inputGuard);
  assertCompiledClaimGateRouteProductDigestCurrent(compiled);

  const authoritativeEntries = new Map(compiled.entries);
  const routesByClaim = new Map(projection.claimRefs.map((claimRef) => [
    claimRef,
    structuredClone(authoritativeEntries.get(claimRef))
  ]));
  return { routesByClaim, observation: compiled.observation };
}

function brandCompiledClaimGateRouteIndex({
  acceptanceModuleRefsByClaim,
  routesByClaim,
  model,
  claimRefs,
  limits,
  inputGuard,
  moduleClaimVisibility
}) {
  const token = Object.freeze(Object.create(null));
  const sealedInputGuard = sealClaimGateRouteInputGuard(inputGuard, limits);
  const usage = Object.freeze({ ...claimGateRouteLimitUsage(limits) });
  const entries = deepFreezeRouteProductValue(
    [...routesByClaim.entries()].map(([claimRef, routes]) => [
      claimRef,
      structuredClone(routes)
    ])
  );
  const acceptanceEntries = deepFreezeRouteProductValue(
    [...acceptanceModuleRefsByClaim.entries()].map(([claimRef, routeModuleRefs]) => [
      claimRef,
      structuredClone(routeModuleRefs)
    ])
  );
  const frozenModuleClaimVisibility = deepFreezeRouteProductValue(
    structuredClone(moduleClaimVisibility)
  );
  const observation = Object.freeze({
    schemaVersion: 1,
    workUnits: usage.workUnits,
    routes: usage.routes,
    totalRouteBytes: usage.totalRouteBytes
  });
  const compiled = {
    model,
    acceptanceEntries,
    claimRefs: Object.freeze([...claimRefs]),
    claimRefSet: new Set(claimRefs),
    entries,
    limits: Object.freeze({ ...limits }),
    usage,
    inputGuard: sealedInputGuard,
    moduleClaimVisibility: frozenModuleClaimVisibility,
    observation
  };
  compiled.productDigest = canonicalDigest({
    acceptanceEntries: compiled.acceptanceEntries,
    claimRefs: compiled.claimRefs,
    entries: compiled.entries,
    moduleClaimVisibility: compiled.moduleClaimVisibility,
    observation,
    routePolicyContentDigest: compiled.inputGuard.contentDigest
  });
  COMPILED_CLAIM_GATE_ROUTE_INDEXES.set(token, compiled);
  return token;
}

function normalizeCompiledClaimGateRouteProjectionOptions(options, compiled) {
  assertPlainRouteIndexObject(
    options,
    "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID",
    "Compiled Claim Gate route projection options must be a plain object."
  );
  const allowedOptionKeys = new Set(["model", "claimRefs", "limits"]);
  for (const key in options) {
    if (!Object.hasOwn(options, key)) continue;
    if (!allowedOptionKeys.has(key)) {
      throw invalidCompiledClaimGateRouteIndexError({
        reason: "unsupported-option",
        field: key
      });
    }
    assertRouteIndexDataProperty(
      options,
      key,
      "projection",
      "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID"
    );
  }
  const model = Object.hasOwn(options, "model")
    ? readRouteIndexDataProperty(
        options,
        "model",
        "projection",
        "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID"
      )
    : undefined;
  const rawClaimRefs = Object.hasOwn(options, "claimRefs")
    ? readRouteIndexDataProperty(
        options,
        "claimRefs",
        "projection",
        "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID"
      )
    : compiled.claimRefs;
  const rawLimits = Object.hasOwn(options, "limits")
    ? readRouteIndexDataProperty(
        options,
        "limits",
        "projection",
        "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID"
      )
    : {};
  const limits = compileClaimGateRouteProjectionLimits(rawLimits, compiled.limits);
  let claimRefs;
  try {
    claimRefs = normalizeRequestedClaimRefs(rawClaimRefs, limits, { workUnits: 0 });
  } catch (error) {
    if (error?.code === "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID") {
      throw invalidCompiledClaimGateRouteIndexError({ reason: "claim-coverage-invalid" });
    }
    throw error;
  }
  return { model, claimRefs, limits };
}

function compileClaimGateRouteProjectionLimits(supplied, compiledLimits) {
  assertPlainRouteIndexObject(
    supplied,
    "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
    "Compiled Claim Gate route projection limits must be a plain object."
  );
  const projected = { ...compiledLimits };
  for (const dimension in supplied) {
    if (!Object.hasOwn(supplied, dimension)) continue;
    if (!Object.hasOwn(CLAIM_GATE_ROUTE_INDEX_LIMITS, dimension)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
        "Compiled Claim Gate route projection limits contain an unsupported dimension.",
        { dimension }
      );
    }
    const requested = readRouteIndexDataProperty(
      supplied,
      dimension,
      "projection.limits",
      "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID"
    );
    const compiledLimit = compiledLimits[dimension];
    if (!Number.isSafeInteger(requested)
      || requested < 0
      || requested > compiledLimit) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
        "A projection limit must be a non-negative safe integer no greater than its compilation limit.",
        { dimension, compiledLimit, requested }
      );
    }
    projected[dimension] = requested;
  }
  return projected;
}

function assertCompiledClaimGateRouteProjectionLimits(compiled, limits) {
  for (const dimension of Object.keys(CLAIM_GATE_ROUTE_INDEX_LIMITS)) {
    assertClaimGateRouteLimit(dimension, compiled.usage[dimension], limits);
  }
}

function invalidCompiledClaimGateRouteIndexError(details) {
  return claimGateRouteIndexError(
    "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID",
    "A compiled Claim Gate route index must be compiler-produced for the same unchanged Model and cover every requested Claim.",
    details
  );
}

function assertCompiledClaimGateRouteProductDigestCurrent(compiled) {
  if (canonicalDigest({
    acceptanceEntries: compiled.acceptanceEntries,
    claimRefs: compiled.claimRefs,
    entries: compiled.entries,
    moduleClaimVisibility: compiled.moduleClaimVisibility,
    observation: compiled.observation,
    routePolicyContentDigest: compiled.inputGuard.contentDigest
  }) !== compiled.productDigest) {
    throw invalidCompiledClaimGateRouteIndexError({ reason: "product-content-drift" });
  }
}

function deepFreezeRouteProductValue(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const key of Object.keys(value)) deepFreezeRouteProductValue(value[key]);
  return Object.freeze(value);
}

function createClaimGateRouteInputGuard(model) {
  return {
    model,
    records: [],
    seen: new WeakMap(),
    objectIds: new WeakMap(),
    nextObjectId: 1
  };
}

function sealClaimGateRouteInputGuard(guard, limits) {
  const semanticRecords = [];
  for (const record of guard.records) {
    let semanticRecord;
    if (record.type === "descriptor") {
      semanticRecord = {
        type: record.type,
        location: record.location,
        key: record.key,
        present: record.present,
        ...(record.present ? { value: guardedValueIdentity(guard, record.value) } : {})
      };
    } else if (record.type === "prototype") {
      semanticRecord = {
        type: record.type,
        location: record.location,
        value: guardedValueIdentity(guard, record.value)
      };
    } else {
      semanticRecord = {
        type: record.type,
        location: record.location,
        value: record.value
      };
    }
    const recordBytes = Buffer.byteLength(JSON.stringify(semanticRecord), "utf8") + 1;
    const observedBytes = claimGateRouteLimitUsage(limits).totalRouteBytes + recordBytes;
    assertClaimGateRouteLimit(
      "totalRouteBytes",
      observedBytes,
      limits,
      record.location
    );
    semanticRecords.push(semanticRecord);
  }
  for (const record of guard.records) {
    if (record.type === "enumerable-keys") Object.freeze(record.value);
    Object.freeze(record);
  }
  return Object.freeze({
    model: guard.model,
    records: Object.freeze([...guard.records]),
    contentDigest: canonicalDigest(semanticRecords)
  });
}

function guardedValueIdentity(guard, value) {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    let id = guard.objectIds.get(value);
    if (!id) {
      id = guard.nextObjectId;
      guard.nextObjectId += 1;
      guard.objectIds.set(value, id);
    }
    return { kind: "object", id };
  }
  if (value === undefined) return { kind: "undefined" };
  if (typeof value === "number" && Object.is(value, -0)) return { kind: "number", value: "-0" };
  return { kind: typeof value, value };
}

function recordClaimGateRouteGuard(value, token, createRecord) {
  const guard = activeClaimGateRouteInputGuard;
  if (!guard || !value || typeof value !== "object") return;
  let tokens = guard.seen.get(value);
  if (!tokens) {
    tokens = new Set();
    guard.seen.set(value, tokens);
  }
  if (tokens.has(token)) return;
  tokens.add(token);
  guard.records.push(createRecord());
}

function recordClaimGateRoutePrototype(value, location) {
  recordClaimGateRouteGuard(value, "prototype", () => ({
    type: "prototype",
    object: value,
    location,
    value: Object.getPrototypeOf(value)
  }));
}

function recordClaimGateRouteArrayLength(value, location) {
  recordClaimGateRouteGuard(value, "array-length", () => ({
    type: "array-length",
    object: value,
    location,
    value: value.length
  }));
}

function recordClaimGateRouteEnumerableKeys(value, location, keys) {
  recordClaimGateRouteGuard(value, "enumerable-keys", () => ({
    type: "enumerable-keys",
    object: value,
    location,
    value: [...keys]
  }));
}

function guardedRouteIndexOwnDescriptor(value, key, location) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  recordClaimGateRouteGuard(value, `descriptor:${key}`, () => ({
    type: "descriptor",
    object: value,
    key,
    location,
    present: Boolean(descriptor),
    value: descriptor && "value" in descriptor ? descriptor.value : undefined,
    data: Boolean(descriptor && "value" in descriptor)
  }));
  return descriptor;
}

function assertClaimGateRouteInputGuardCurrent(guard) {
  for (const record of guard.records) {
    let current;
    if (record.type === "prototype") {
      current = Object.getPrototypeOf(record.object);
      if (current !== record.value) throwRouteInputDrift(record.location);
      continue;
    }
    if (record.type === "array-length") {
      if (record.object.length !== record.value) throwRouteInputDrift(record.location);
      continue;
    }
    if (record.type === "enumerable-keys") {
      let index = 0;
      for (const key in record.object) {
        if (!Object.hasOwn(record.object, key)) continue;
        if (key !== record.value[index]) throwRouteInputDrift(record.location);
        index += 1;
      }
      if (index !== record.value.length) throwRouteInputDrift(record.location);
      continue;
    }
    const descriptor = Object.getOwnPropertyDescriptor(record.object, record.key);
    if (Boolean(descriptor) !== record.present
      || (record.present && (!record.data
        || !("value" in descriptor)
        || !Object.is(descriptor.value, record.value)))) {
      throwRouteInputDrift(record.location);
    }
  }
}

function throwRouteInputDrift(location) {
  throw invalidCompiledClaimGateRouteIndexError({
    reason: "model-content-drift",
    location
  });
}

function readBoundedRouteCommandValues(command, location) {
  return {
    command: readOptionalRouteIndexDataProperty(command, "command", `${location}.command`),
    timeoutMs: readOptionalRouteIndexDataProperty(command, "timeoutMs", `${location}.timeoutMs`),
    oracle: readOptionalRouteIndexDataProperty(command, "oracle", `${location}.oracle`),
    applicability: readOptionalRouteIndexDataProperty(
      command,
      "applicability",
      `${location}.applicability`
    ),
    discriminatoryPower: readOptionalRouteIndexDataProperty(
      command,
      "discriminatoryPower",
      `${location}.discriminatoryPower`
    ),
    residualUncertainty: readOptionalRouteIndexDataProperty(
      command,
      "residualUncertainty",
      `${location}.residualUncertainty`
    )
  };
}

function readRouteIndexArrayProperty(value, key, location) {
  const observed = readOptionalRouteIndexDataProperty(value, key, location);
  if (!Array.isArray(observed)) return [];
  return assertRouteIndexArray(observed, location);
}

function assertRouteIndexArray(value, location) {
  assertNotRouteIndexProxy(value, location);
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw invalidClaimGateRouteJsonError(location);
  }
  recordClaimGateRoutePrototype(value, location);
  recordClaimGateRouteArrayLength(value, location);
  return value;
}

function readRouteIndexArrayValue(value, index, location) {
  assertRouteIndexArray(value, location.slice(0, location.lastIndexOf(".")) || location);
  const descriptor = guardedRouteIndexOwnDescriptor(value, String(index), location);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "Claim Gate route arrays must expose data values, not accessors.",
      { location }
    );
  }
  assertNotRouteIndexProxy(descriptor.value, location);
  return descriptor.value;
}

function readOptionalRouteIndexDataProperty(value, key, location) {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "object") return undefined;
  assertNotRouteIndexProxy(value, location);
  if (Array.isArray(value)) throw invalidClaimGateRouteJsonError(location);
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalidClaimGateRouteJsonError(location);
  }
  recordClaimGateRoutePrototype(value, location);
  const descriptor = guardedRouteIndexOwnDescriptor(value, key, location);
  if (!descriptor) return undefined;
  if (!("value" in descriptor)) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "Claim Gate route Model fields must expose data values, not accessors.",
      { location }
    );
  }
  assertNotRouteIndexProxy(descriptor.value, location);
  return descriptor.value;
}

function assertNotRouteIndexProxy(value, location) {
  if ((typeof value === "object" && value !== null) || typeof value === "function") {
    if (utilTypes.isProxy(value)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route inputs cannot contain Proxy values.",
        { location }
      );
    }
  }
}

function normalizeClaimGateRouteIndexOptions(options) {
  assertPlainRouteIndexObject(
    options,
    "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
    "Claim Gate route index options must be a plain object."
  );
  const allowedOptionKeys = new Set(["claimRefs", "limits"]);
  for (const key in options) {
    if (!Object.hasOwn(options, key)) continue;
    if (!allowedOptionKeys.has(key)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route index options contain an unsupported field.",
        { field: key }
      );
    }
    assertRouteIndexDataProperty(options, key, "options");
  }
  const rawClaimRefs = Object.hasOwn(options, "claimRefs")
    ? readRouteIndexDataProperty(options, "claimRefs", "options")
    : [];
  const rawLimits = Object.hasOwn(options, "limits")
    ? readRouteIndexDataProperty(options, "limits", "options")
    : {};
  return {
    claimRefs: rawClaimRefs === undefined ? [] : rawClaimRefs,
    limits: compileClaimGateRouteIndexLimits(rawLimits === undefined ? {} : rawLimits)
  };
}

function compileClaimGateRouteIndexLimits(supplied) {
  assertPlainRouteIndexObject(
    supplied,
    "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
    "Claim Gate route index limits must be a plain object."
  );
  const compiled = { ...CLAIM_GATE_ROUTE_INDEX_LIMITS };
  for (const dimension in supplied) {
    if (!Object.hasOwn(supplied, dimension)) continue;
    if (!Object.hasOwn(CLAIM_GATE_ROUTE_INDEX_LIMITS, dimension)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
        "Claim Gate route index limits contain an unsupported dimension.",
        { dimension }
      );
    }
    const requested = readRouteIndexDataProperty(
      supplied,
      dimension,
      "limits",
      "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID"
    );
    const hardLimit = CLAIM_GATE_ROUTE_INDEX_LIMITS[dimension];
    if (!Number.isSafeInteger(requested) || requested < 0 || requested > hardLimit) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_LIMIT_INVALID",
        "A Claim Gate route index limit must be a non-negative safe integer no greater than its hard limit.",
        { dimension, hardLimit, requested }
      );
    }
    compiled[dimension] = requested;
  }
  CLAIM_GATE_ROUTE_LIMIT_USAGES.set(
    compiled,
    Object.fromEntries(Object.keys(CLAIM_GATE_ROUTE_INDEX_LIMITS).map((dimension) => [dimension, 0]))
  );
  return compiled;
}

function normalizeRequestedClaimRefs(rawClaimRefs, limits, budget) {
  if (!Array.isArray(rawClaimRefs)) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "claimRefs must be a dense list of non-empty strings."
    );
  }
  assertRouteIndexArray(rawClaimRefs, "claimRefs");
  assertClaimGateRouteLimit("claimRefs", rawClaimRefs.length, limits);
  const normalized = new Set();
  for (let index = 0; index < rawClaimRefs.length; index += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    const descriptor = Object.getOwnPropertyDescriptor(rawClaimRefs, String(index));
    if (!descriptor || !("value" in descriptor)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "claimRefs must be a dense list of non-empty data strings.",
        { index }
      );
    }
    const claimRef = normalizeBoundedRequiredRouteText(
      descriptor.value,
      `claimRefs.${index}`,
      limits
    );
    normalized.add(claimRef);
  }
  return [...normalized].sort();
}

function compileRouteModuleRefs(modules, limits, budget) {
  assertClaimGateRouteLimit("modules", modules.length, limits);
  const moduleRefs = new Set();
  for (let index = 0; index < modules.length; index += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    const moduleRef = readBoundedModelReference(
      readRouteIndexArrayValue(modules, index, `model.modules.${index}`),
      `model.modules.${index}`,
      limits
    );
    if (!moduleRef || moduleRefs.has(moduleRef)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route Models require unique non-empty Module ids.",
        { location: `model.modules.${index}` }
      );
    }
    moduleRefs.add(moduleRef);
  }
  return [...moduleRefs].sort();
}

function compileBoundedModuleClaimVisibility(model, limits, budget) {
  const modules = readRouteIndexArrayProperty(model, "modules", "model.modules");
  const moduleRefs = compileRouteModuleRefs(modules, limits, budget);
  const modulesByRef = new Map();
  for (let index = 0; index < modules.length; index += 1) {
    const module = readRouteIndexArrayValue(modules, index, `model.modules.${index}`);
    const moduleRef = readBoundedModelReference(module, `model.modules.${index}`, limits);
    consumeClaimGateRouteAggregateBytes(
      budget,
      limits,
      (2 * Buffer.byteLength(JSON.stringify(moduleRef), "utf8")) + 16,
      `model.modules.${index}`
    );
    modulesByRef.set(moduleRef, { module, index });
  }

  const contracts = readRouteIndexArrayProperty(model, "contracts", "model.contracts");
  budget.contracts = contracts.length;
  assertClaimGateRouteLimit("contracts", budget.contracts, limits, "model.contracts");
  assertPotentialClaimGateRouteWork(budget, limits, contracts.length);
  const claimsByContract = new Map();
  const globalClaims = new Map();
  let totalClaims = 0;
  for (let contractIndex = 0; contractIndex < contracts.length; contractIndex += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    const contractLocation = `model.contracts.${contractIndex}`;
    const contract = readRouteIndexArrayValue(contracts, contractIndex, contractLocation);
    const contractRef = readBoundedModelReference(contract, contractLocation, limits);
    if (!contractRef || claimsByContract.has(contractRef)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route Models require unique non-empty Contract ids.",
        { location: contractLocation }
      );
    }
    consumeClaimGateRouteAggregateBytes(
      budget,
      limits,
      Buffer.byteLength(JSON.stringify(contractRef), "utf8") + 16,
      contractLocation
    );
    const claims = readRouteIndexArrayProperty(
      contract,
      "claims",
      `${contractLocation}.claims`
    );
    totalClaims += claims.length;
    budget.modelClaims = totalClaims;
    assertClaimGateRouteLimit(
      "modelClaims",
      budget.modelClaims,
      limits,
      `${contractLocation}.claims`
    );
    assertPotentialClaimGateRouteWork(budget, limits, claims.length);
    const descriptors = [];
    for (let claimIndex = 0; claimIndex < claims.length; claimIndex += 1) {
      reserveClaimGateRouteWork(budget, limits, 1);
      const claimLocation = `${contractLocation}.claims.${claimIndex}`;
      const claim = readRouteIndexArrayValue(claims, claimIndex, claimLocation);
      const claimRef = readBoundedModelReference(claim, claimLocation, limits);
      const statement = normalizeBoundedRequiredModelText(
        readOptionalRouteIndexDataProperty(claim, "statement", `${claimLocation}.statement`),
        `${claimLocation}.statement`,
        limits,
        "Claim statement"
      );
      if (!claimRef || globalClaims.has(claimRef)) {
        throw claimGateRouteIndexError(
          "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
          "Claim Gate route Models require globally unique non-empty Claim ids.",
          { location: claimLocation, claimRef: claimRef ?? null }
        );
      }
      const descriptor = { claimRef, statement, contractRef };
      const descriptorMetadataBytes = Buffer.byteLength(
        JSON.stringify([[claimRef, descriptor], descriptor]),
        "utf8"
      ) + 32;
      consumeClaimGateRouteAggregateBytes(
        budget,
        limits,
        descriptorMetadataBytes,
        claimLocation
      );
      descriptors.push(descriptor);
      globalClaims.set(claimRef, descriptor);
    }
    descriptors.sort((left, right) => left.claimRef.localeCompare(right.claimRef));
    claimsByContract.set(contractRef, descriptors);
  }

  const visibilityByModule = new Map();
  for (const moduleRef of moduleRefs) {
    const { module, index } = modulesByRef.get(moduleRef);
    const moduleLocation = `model.modules.${index}`;
    const visibleContracts = new Map();
    const publicContracts = readOptionalBoundedModelList(
      module,
      "publicContracts",
      `${moduleLocation}.publicContracts`,
      limits,
      budget
    );
    for (let contractIndex = 0; contractIndex < publicContracts.length; contractIndex += 1) {
      reserveClaimGateRouteWork(budget, limits, 1);
      const location = `${moduleLocation}.publicContracts.${contractIndex}`;
      const contractRef = readBoundedModelReference(
        readRouteIndexArrayValue(publicContracts, contractIndex, location),
        location,
        limits,
        ["id", "contract", "contractId"]
      );
      addBoundedContractVisibility(
        visibleContracts,
        claimsByContract,
        contractRef,
        "owned",
        location
      );
    }
    const dependencies = readOptionalBoundedModelList(
      module,
      "dependencies",
      `${moduleLocation}.dependencies`,
      limits,
      budget
    );
    for (let dependencyIndex = 0; dependencyIndex < dependencies.length; dependencyIndex += 1) {
      reserveClaimGateRouteWork(budget, limits, 1);
      const location = `${moduleLocation}.dependencies.${dependencyIndex}`;
      const dependency = readRouteIndexArrayValue(dependencies, dependencyIndex, location);
      const contractRef = readBoundedModelReference(
        dependency,
        location,
        limits,
        ["via", "contract", "contractId"]
      );
      addBoundedContractVisibility(
        visibleContracts,
        claimsByContract,
        contractRef,
        "dependency",
        location
      );
    }
    const visibilityEntries = [...visibleContracts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([contractRef, kinds]) => [
        contractRef,
        [...kinds].sort(compareVisibilityKinds)
      ]);
    for (const entry of visibilityEntries) {
      consumeClaimGateRouteAggregateBytes(
        budget,
        limits,
        Buffer.byteLength(JSON.stringify([moduleRef, entry]), "utf8") + 16,
        `${moduleLocation}.visibility`
      );
    }
    visibilityByModule.set(moduleRef, visibilityEntries);
  }

  return {
    moduleRefs,
    claimsByContract: [...claimsByContract.entries()].sort(([left], [right]) => (
      left.localeCompare(right)
    )),
    globalClaims: [...globalClaims.entries()].sort(([left], [right]) => left.localeCompare(right)),
    visibilityByModule: [...visibilityByModule.entries()]
  };
}

function readOptionalBoundedModelList(value, key, location, limits, budget) {
  const observed = readOptionalRouteIndexDataProperty(value, key, location);
  if (observed === undefined || observed === null) return [];
  if (!Array.isArray(observed)) throw invalidClaimGateRouteJsonError(location);
  const values = assertRouteIndexArray(observed, location);
  assertClaimGateRouteLimit("refsPerModule", values.length, limits, location);
  budget.visibilityRefs += values.length;
  assertClaimGateRouteLimit(
    "visibilityRefs",
    budget.visibilityRefs,
    limits,
    location
  );
  assertPotentialClaimGateRouteWork(budget, limits, values.length);
  return values;
}

function addBoundedContractVisibility(
  visibility,
  claimsByContract,
  contractRef,
  visibilityKind,
  location
) {
  if (!contractRef || !claimsByContract.has(contractRef)) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "Module Claim visibility must reference a known Contract.",
      { location, contractRef: contractRef ?? null }
    );
  }
  if (!visibility.has(contractRef)) visibility.set(contractRef, new Set());
  visibility.get(contractRef).add(visibilityKind);
}

function compareVisibilityKinds(left, right) {
  const rank = { owned: 0, dependency: 1 };
  return rank[left] - rank[right] || left.localeCompare(right);
}

function normalizeBoundedCommandClaimRefs(value, location, limits, budget) {
  const values = boundedRouteList(value, location, limits);
  budget.totalCommandClaimRefs += values.length;
  assertClaimGateRouteLimit("totalCommandClaimRefs", budget.totalCommandClaimRefs, limits);
  return normalizeBoundedRouteStringList(values, location, limits, budget);
}

function normalizeBoundedGateScope(value, location, limits, budget) {
  return new Set(normalizeBoundedRouteStringList(
    boundedRouteList(value, location, limits),
    location,
    limits,
    budget
  ));
}

function boundedRouteList(value, location, limits) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? assertRouteIndexArray(value, location) : [value];
  assertClaimGateRouteLimit("refsPerCommand", values.length, limits, location);
  return values;
}

function normalizeBoundedRouteStringList(values, location, limits, budget) {
  const normalized = new Set();
  for (let index = 0; index < values.length; index += 1) {
    reserveClaimGateRouteWork(budget, limits, 1);
    const descriptor = guardedRouteIndexOwnDescriptor(
      values,
      String(index),
      `${location}.${index}`
    );
    if (!descriptor) continue;
    if (!("value" in descriptor)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route lists must expose data values, not accessors.",
        { location: `${location}.${index}` }
      );
    }
    const item = normalizeBoundedOptionalRouteText(
      descriptor.value,
      `${location}.${index}`,
      limits
    );
    if (item) normalized.add(item);
  }
  return [...normalized];
}

function normalizedGateScopeSelectsModule(scope, gateId, moduleRef, fullGateId) {
  if (scope.size === 0 || scope.has(moduleRef)) return true;
  return gateId === fullGateId && (scope.has("integration") || scope.has("release"));
}

function normalizedAcceptanceGateScopeSelectsModule(scope, moduleRef) {
  return scope.size === 0 || scope.has(moduleRef);
}

function normalizedCommandScopeSelectsModule(scope, moduleRef) {
  return scope.size === 0 || scope.has(moduleRef);
}

function compileBoundedRouteTemplate({
  commandValues,
  commandId,
  effectiveModuleRefs,
  gateId,
  limits,
  location,
  budget
}) {
  const routeBudget = { bytes: 0 };
  const ancestors = new WeakSet();
  const clone = (value, field) => cloneBoundedRouteJson(value, {
    ancestors,
    budget,
    depth: 0,
    limits,
    location: `${location}.${field}`,
    routeBudget
  });
  return {
    gateId: clone(gateId, "gateId"),
    commandId: clone(commandId, "commandId"),
    command: clone(commandValues.command, "command"),
    timeoutMs: clone(commandValues.timeoutMs ?? null, "timeoutMs"),
    effectiveModuleRefs: clone(effectiveModuleRefs, "effectiveModuleRefs"),
    oracle: clone(commandValues.oracle, "oracle"),
    applicability: clone(commandValues.applicability, "applicability"),
    discriminatoryPower: clone(commandValues.discriminatoryPower, "discriminatoryPower"),
    residualUncertainty: clone(commandValues.residualUncertainty, "residualUncertainty")
  };
}

function cloneBoundedRouteJson(value, context) {
  const { ancestors, budget, depth, limits, location, routeBudget } = context;
  assertClaimGateRouteLimit("depth", depth, limits, location);
  reserveClaimGateRouteWork(budget, limits, 1);
  if (value === undefined) {
    consumeBoundedRouteBytes(routeBudget, limits, 4, location);
    return undefined;
  }
  if (value === null) {
    consumeBoundedRouteBytes(routeBudget, limits, 4, location);
    return null;
  }
  if (typeof value === "string") {
    assertBoundedRouteText(value, location, limits);
    consumeBoundedRouteBytes(
      routeBudget,
      limits,
      Buffer.byteLength(JSON.stringify(value), "utf8"),
      location
    );
    return value;
  }
  if (typeof value === "boolean") {
    consumeBoundedRouteBytes(routeBudget, limits, value ? 4 : 5, location);
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw invalidClaimGateRouteJsonError(location);
    }
    consumeBoundedRouteBytes(
      routeBudget,
      limits,
      Buffer.byteLength(JSON.stringify(value), "utf8"),
      location
    );
    return value;
  }
  if (!value || typeof value !== "object") throw invalidClaimGateRouteJsonError(location);
  assertNotRouteIndexProxy(value, location);
  if (ancestors.has(value)) throw invalidClaimGateRouteJsonError(location);
  recordClaimGateRoutePrototype(value, location);
  const toJsonDescriptor = guardedRouteIndexOwnDescriptor(value, "toJSON", `${location}.toJSON`);
  if (toJsonDescriptor
    && (!("value" in toJsonDescriptor) || typeof toJsonDescriptor.value === "function")) {
    throw invalidClaimGateRouteJsonError(`${location}.toJSON`);
  }

  if (Array.isArray(value)) {
    if (Object.getPrototypeOf(value) !== Array.prototype) {
      throw invalidClaimGateRouteJsonError(location);
    }
    const minimumBytes = 2 + Math.max(0, value.length - 1);
    recordClaimGateRouteArrayLength(value, location);
    consumeBoundedRouteBytes(routeBudget, limits, minimumBytes, location);
    assertPotentialClaimGateRouteWork(budget, limits, value.length);
    const result = new Array(value.length);
    ancestors.add(value);
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = guardedRouteIndexOwnDescriptor(
        value,
        String(index),
        `${location}.${index}`
      );
      if (!descriptor || !("value" in descriptor)) {
        ancestors.delete(value);
        throw invalidClaimGateRouteJsonError(`${location}.${index}`);
      }
      result[index] = cloneBoundedRouteJson(descriptor.value, {
        ...context,
        depth: depth + 1,
        location: `${location}.${index}`
      });
    }
    ancestors.delete(value);
    return result;
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalidClaimGateRouteJsonError(location);
  }
  consumeBoundedRouteBytes(routeBudget, limits, 2, location);
  const result = Object.create(null);
  const enumerableKeys = [];
  let propertyCount = 0;
  ancestors.add(value);
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    assertBoundedRouteText(key, `${location}.[key]`, limits);
    const keyLocation = `${location}.${key}`;
    const descriptor = guardedRouteIndexOwnDescriptor(value, key, keyLocation);
    if (!descriptor || !("value" in descriptor)) {
      ancestors.delete(value);
      throw invalidClaimGateRouteJsonError(keyLocation);
    }
    if (propertyCount > 0) consumeBoundedRouteBytes(routeBudget, limits, 1, location);
    consumeBoundedRouteBytes(
      routeBudget,
      limits,
      Buffer.byteLength(JSON.stringify(key), "utf8") + 1,
      keyLocation
    );
    enumerableKeys.push(key);
    Object.defineProperty(result, key, {
      configurable: true,
      enumerable: true,
      value: cloneBoundedRouteJson(descriptor.value, {
        ...context,
        depth: depth + 1,
        location: keyLocation
      }),
      writable: true
    });
    propertyCount += 1;
  }
  ancestors.delete(value);
  recordClaimGateRouteEnumerableKeys(value, location, enumerableKeys);
  return result;
}

function cloneRouteForClaim(template, claimRef) {
  return {
    claimRef,
    gateId: template.gateId,
    commandId: template.commandId,
    command: cloneJson(template.command),
    timeoutMs: cloneJson(template.timeoutMs),
    effectiveModuleRefs: cloneJson(template.effectiveModuleRefs),
    oracle: cloneJson(template.oracle),
    applicability: cloneJson(template.applicability),
    discriminatoryPower: cloneJson(template.discriminatoryPower),
    residualUncertainty: cloneJson(template.residualUncertainty)
  };
}

function compareCompiledClaimGateRoutes(left, right) {
  return (left.route.gateId ?? "").localeCompare(right.route.gateId ?? "")
    || (left.route.commandId ?? "").localeCompare(right.route.commandId ?? "")
    || left.digest.localeCompare(right.digest);
}

function readBoundedModelReference(
  value,
  location,
  limits,
  keys = ["id", "module", "moduleId", "target"]
) {
  if (typeof value === "string") {
    return normalizeBoundedOptionalRouteText(value, location, limits);
  }
  if (!value || typeof value !== "object") return undefined;
  assertNotRouteIndexProxy(value, location);
  if (Array.isArray(value)) return undefined;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalidClaimGateRouteJsonError(location);
  }
  recordClaimGateRoutePrototype(value, location);
  for (const key of keys) {
    const descriptor = guardedRouteIndexOwnDescriptor(value, key, `${location}.${key}`);
    if (!descriptor) continue;
    if (!("value" in descriptor)) {
      throw claimGateRouteIndexError(
        "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
        "Claim Gate route Model references must expose data values, not accessors.",
        { location: `${location}.${key}` }
      );
    }
    const reference = normalizeBoundedOptionalRouteText(
      descriptor.value,
      `${location}.${key}`,
      limits
    );
    if (reference) return reference;
  }
  return undefined;
}

function normalizeBoundedRequiredModelText(value, location, limits, label) {
  if (typeof value !== "string") {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      `${label} must be a non-empty string.`,
      { location }
    );
  }
  assertBoundedRouteText(value, location, limits);
  const normalized = value.trim();
  if (!normalized) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      `${label} must be a non-empty string.`,
      { location }
    );
  }
  return normalized;
}

function normalizeBoundedRequiredRouteText(value, location, limits) {
  if (typeof value !== "string") {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "claimRefs must contain only non-empty strings.",
      { location }
    );
  }
  assertBoundedRouteText(value, location, limits);
  const normalized = value.trim();
  if (!normalized) {
    throw claimGateRouteIndexError(
      "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
      "claimRefs must contain only non-empty strings.",
      { location }
    );
  }
  return normalized;
}

function normalizeBoundedOptionalRouteText(value, location, limits) {
  if (typeof value !== "string") return undefined;
  assertBoundedRouteText(value, location, limits);
  const normalized = value.trim();
  return normalized || undefined;
}

function assertBoundedRouteText(value, location, limits) {
  if (value.length > limits.textBytes) {
    assertClaimGateRouteLimit("textBytes", value.length, limits, location);
  }
  const observed = Buffer.byteLength(value, "utf8");
  assertClaimGateRouteLimit("textBytes", observed, limits, location);
}

function consumeBoundedRouteBytes(routeBudget, limits, bytes, location) {
  const observed = routeBudget.bytes + bytes;
  assertClaimGateRouteLimit("routeBytes", observed, limits, location);
  routeBudget.bytes = observed;
}

function consumeClaimGateRouteAggregateBytes(budget, limits, bytes, location) {
  const observed = budget.totalRouteBytes + bytes;
  assertClaimGateRouteLimit("totalRouteBytes", observed, limits, location);
  budget.totalRouteBytes = observed;
}

function reserveClaimGateRouteWork(budget, limits, units) {
  const observed = budget.workUnits + units;
  assertClaimGateRouteLimit("workUnits", observed, limits);
  budget.workUnits = observed;
}

function assertPotentialClaimGateRouteWork(budget, limits, units) {
  assertClaimGateRouteLimit("workUnits", budget.workUnits + units, limits);
}

function assertClaimGateRouteLimit(dimension, observed, limits, location) {
  const usage = CLAIM_GATE_ROUTE_LIMIT_USAGES.get(limits);
  if (usage) usage[dimension] = Math.max(usage[dimension], observed);
  const limit = limits[dimension];
  if (observed <= limit) return;
  throw claimGateRouteIndexError(
    "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED",
    "Claim Gate route index compilation exceeded a declared hard bound.",
    {
      dimension,
      limit,
      observed,
      ...(location ? { location } : {})
    },
    413
  );
}

function claimGateRouteLimitUsage(limits) {
  return CLAIM_GATE_ROUTE_LIMIT_USAGES.get(limits)
    ?? Object.fromEntries(Object.keys(CLAIM_GATE_ROUTE_INDEX_LIMITS).map((dimension) => [dimension, 0]));
}

function assertPlainRouteIndexObject(value, code, message) {
  assertNotRouteIndexProxy(value, "input");
  const prototype = value && typeof value === "object" && !Array.isArray(value)
    ? Object.getPrototypeOf(value)
    : undefined;
  if (!value || typeof value !== "object" || Array.isArray(value)
    || (prototype !== Object.prototype && prototype !== null)) {
    throw claimGateRouteIndexError(code, message);
  }
}

function assertRouteIndexDataProperty(
  value,
  key,
  location,
  code = "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID"
) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !("value" in descriptor)) {
    throw claimGateRouteIndexError(
      code,
      "Claim Gate route index inputs must expose data values, not accessors.",
      { location: `${location}.${key}` }
    );
  }
}

function readRouteIndexDataProperty(value, key, location, code) {
  assertRouteIndexDataProperty(value, key, location, code);
  return Object.getOwnPropertyDescriptor(value, key).value;
}

function invalidClaimGateRouteJsonError(location) {
  return claimGateRouteIndexError(
    "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID",
    "Claim Gate route values must contain only finite plain JSON data.",
    { location }
  );
}

function claimGateRouteIndexError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details !== undefined) error.details = details;
  return error;
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
