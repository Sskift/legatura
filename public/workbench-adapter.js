const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const WORKBENCH_COLLECTION_LIMIT = 65_536;

const WORKBENCH_SOURCE_KEYS = Object.freeze([
  "snapshotDigest",
  "projectModelDigest",
  "gitContentDigest",
  "changeStoreDigest",
]);

const WORKBENCH_CHANGE_KIND_IDS = Object.freeze([
  "implementation",
  "plan-amendment",
  "regression-repair",
  "security-containment",
  "data-integrity-repair",
  "acceptance-integrity-repair",
  "entrypoint-restoration",
]);

const WORKBENCH_DISABLED_REASON_CODES = Object.freeze([
  "PLAN_OUTCOME_UNAVAILABLE",
  "MODULE_NOT_GOVERNED",
  "CLAIM_ACCEPTANCE_ROUTE_MISSING",
  "CHANGE_CLAIM_REQUIRED",
  "CHANGE_NOT_COMPILED",
  "CHANGE_SCOPE_EXCEEDED",
  "AUTHORITY_OPTION_UNAVAILABLE",
  "CHANGE_NOT_EVIDENCE_READY",
  "CHANGE_SEALED",
  "GATE_NOT_APPLICABLE",
  "GATE_COMMAND_NOT_APPLICABLE",
]);

const WORKBENCH_INPUT_REASON_CODES = Object.freeze([
  "CHANGE_NOT_COMPILED",
  "CHANGE_SCOPE_EXCEEDED",
  "AUTHORITY_OPTION_UNAVAILABLE",
]);

const KNOWLEDGE_CLOSURE_MODES = Object.freeze(["no-new-knowledge", "entries"]);
const KNOWLEDGE_CLOSURE_ENTRY_KINDS = Object.freeze([
  "model-amendment",
  "model-gap",
  "ephemeral",
]);
const AUTHORITY_DECISION_TYPES = Object.freeze([
  "case-decision",
  "normative-amendment",
  "waiver",
]);
const AUTHORITY_REQUIRED_FIELDS = Object.freeze({
  "case-decision": Object.freeze(["decidedBy", "rationale"]),
  "normative-amendment": Object.freeze(["amendmentRefs", "decidedBy", "rationale"]),
  waiver: Object.freeze(["compensatingControls", "decidedBy", "expiresAt", "reason", "scope"]),
});
const ACCEPTANCE_BINDING_FIELDS = Object.freeze([
  "changeRef",
  "sourceSnapshotDigest",
  "governanceBaselineDigest",
  "verificationSubjectDigest",
]);

const PROFILE_DIMENSION_KEYS = Object.freeze([
  "outcomes",
  "criteria",
  "claims",
  "gates",
  "evidence",
  "residualUncertainty",
  "knowledgeGaps",
]);

const PROFILE_CONTEXT_KEYS = Object.freeze([
  "stages",
  "modules",
  "areas",
  "contracts",
  "changes",
  "routes",
]);

/**
 * Browser-side boundary adapters only validate and select canonical facts.
 * They deliberately do not derive governance eligibility or assurance.
 */
export function receiveArchitectureProfileViewModel(value) {
  requireRecord(value, "Architecture Profile");
  requireExactKeys(
    value,
    ["schemaVersion", "profileRef", "sourceRefs", "dimensions", "context", "relations", "viewModelDigest"],
    "Architecture Profile",
  );
  if (value.schemaVersion !== 1) throw invalidProjection("Architecture Profile schemaVersion");
  requireDigest(value.profileRef, "Architecture Profile profileRef");
  requireDigest(value.viewModelDigest, "Architecture Profile viewModelDigest");
  requireRecord(value.sourceRefs, "Architecture Profile sourceRefs");
  for (const digest of Object.values(value.sourceRefs)) {
    requireDigest(digest, "Architecture Profile sourceRef");
  }
  requireExactArrayRecord(value.dimensions, PROFILE_DIMENSION_KEYS, "Architecture Profile dimensions");
  requireExactArrayRecord(value.context, PROFILE_CONTEXT_KEYS, "Architecture Profile context");
  requireRecord(value.relations, "Architecture Profile relations");
  for (const relation of Object.values(value.relations)) {
    if (!Array.isArray(relation)) throw invalidProjection("Architecture Profile relation");
  }
  return deepFreeze(value);
}

export function receiveWorkbenchProjection(value) {
  requireRecord(value, "Workbench projection");
  requireExactKeys(
    value,
    ["schemaVersion", "source", "selection", "authoring", "changes", "projectionDigest"],
    "Workbench projection",
  );
  if (value.schemaVersion !== 2) throw invalidProjection("Workbench projection schemaVersion");
  requireDigest(value.projectionDigest, "Workbench projection digest");
  requireWorkbenchSource(value.source);
  requireRecord(value.selection, "Workbench selection");
  requireExactKeys(value.selection, ["changeRef"], "Workbench selection");
  if (value.selection.changeRef !== null
    && (typeof value.selection.changeRef !== "string" || value.selection.changeRef.length === 0)) {
    throw invalidProjection("Workbench selection changeRef");
  }
  requireWorkbenchAuthoring(value.authoring);
  if (!Array.isArray(value.changes)) throw invalidProjection("Workbench canonical collections");
  if (value.selection.changeRef === null && value.changes.length !== 0) {
    throw invalidProjection("Workbench authoring-only selection");
  }
  if (value.selection.changeRef !== null
    && (value.changes.length !== 1 || value.changes[0]?.id !== value.selection.changeRef)) {
    throw invalidProjection("Workbench selected Change projection");
  }
  if (value.selection.changeRef !== null) {
    requireWorkbenchSelectedChange(value.changes[0], value.source);
  }
  return deepFreeze(value);
}

export function architectureProfileDimension(profile, key) {
  if (!PROFILE_DIMENSION_KEYS.includes(key)) throw invalidProjection("Architecture Profile dimension key");
  const value = profile?.dimensions?.[key];
  return Array.isArray(value) ? value : [];
}

export function selectWorkbenchAuthoringModules(workbench) {
  const modules = workbench?.authoring?.modules;
  return Array.isArray(modules) ? modules : [];
}

export function selectWorkbenchPlanOutcomes(workbench) {
  const planOutcomes = workbench?.authoring?.planOutcomes;
  return Array.isArray(planOutcomes) ? planOutcomes : [];
}

export function selectWorkbenchChangeKinds(workbench) {
  const changeKinds = workbench?.authoring?.changeKinds;
  return Array.isArray(changeKinds) ? changeKinds : [];
}

export function selectWorkbenchChangeKindAuthoring(workbench, changeKind) {
  if (typeof changeKind !== "string" || !WORKBENCH_CHANGE_KIND_IDS.includes(changeKind)) {
    throw invalidProjection("Workbench Change kind");
  }
  const changeKinds = workbench?.authoring?.changeKinds;
  return Array.isArray(changeKinds)
    ? changeKinds.find((entry) => entry.id === changeKind) ?? null
    : null;
}

export function selectWorkbenchChange(workbench, changeId) {
  if (changeId === undefined || changeId === null || !Array.isArray(workbench?.changes)) return null;
  return workbench.changes.find((change) => String(change?.id) === String(changeId)) ?? null;
}

export function workbenchSourceMatchesChange(workbench, change) {
  const workbenchSnapshot = workbench?.source?.snapshotDigest;
  const changeSnapshot = change?.observation?.sourceSnapshotDigest;
  return typeof workbenchSnapshot === "string"
    && typeof changeSnapshot === "string"
    && workbenchSnapshot === changeSnapshot;
}

export function selectWorkbenchAction(workbench, change, kind) {
  if (!["compile", "gates", "accept"].includes(kind)) {
    throw invalidProjection("Workbench action kind");
  }
  if (!workbenchSourceMatchesChange(workbench, change)) return null;
  const action = selectWorkbenchChange(workbench, change.id)?.actions?.[kind];
  return action && typeof action === "object" ? action : null;
}

export function selectWorkbenchAcceptanceInputRequirements(workbench, change) {
  return selectWorkbenchAction(workbench, change, "accept")?.inputRequirements ?? null;
}

export function compileWorkbenchAcceptanceRequest(requirements, input) {
  requireRecord(requirements, "Workbench acceptance input requirements");
  requireRecord(input, "Workbench acceptance form input");
  requireExactKeys(
    input,
    [
      "confirmed",
      "decisionOptionIndex",
      "decidedBy",
      "decisionReason",
      "amendmentRefs",
      "expiresAt",
      "scope",
      "compensatingControls",
      "closureMode",
      "closureRationale",
      "knowledgeGapRefs",
      "ephemeralStatements",
    ],
    "Workbench acceptance form input",
  );
  if (requirements.available !== true || input.confirmed !== true) {
    throw invalidAcceptanceInput("The bound acceptance requirements are unavailable or unconfirmed.");
  }
  const option = requirements.authorityDecision.decisionOptions[input.decisionOptionIndex];
  if (!Number.isSafeInteger(input.decisionOptionIndex) || !option) {
    throw invalidAcceptanceInput("Select one Kernel-declared Authority Decision option.");
  }
  const decidedBy = acceptanceInputText(input.decidedBy);
  const decisionReason = acceptanceInputText(input.decisionReason);
  if (!decidedBy) throw invalidAcceptanceInput("The actual decision maker is required.");
  const requiredFields = new Set(option.requiredFields);
  const authorityDecision = {
    status: "approved",
    authority: option.authorityRef,
    decidedBy,
    decisionType: option.decisionType,
  };
  if (requiredFields.has("rationale")) authorityDecision.rationale = decisionReason;
  if (requiredFields.has("reason")) authorityDecision.reason = decisionReason;
  if (requiredFields.has("amendmentRefs")
    || requirements.authorityDecision.requiredAmendmentRefs.length > 0) {
    authorityDecision.amendmentRefs = requirements.authorityDecision.requiredAmendmentRefs.length > 0
      ? [...requirements.authorityDecision.requiredAmendmentRefs]
      : acceptanceInputStringArray(input.amendmentRefs, "amendmentRefs");
  }
  if (requirements.authorityDecision.requiredAdoptedChangePaths.length > 0) {
    authorityDecision.adoptedChangePaths = [
      ...requirements.authorityDecision.requiredAdoptedChangePaths,
    ];
  }
  if (requirements.authorityDecision.requiredApprovedObligationIds.length > 0) {
    authorityDecision.approvedObligationIds = [
      ...requirements.authorityDecision.requiredApprovedObligationIds,
    ];
  }
  if (requiredFields.has("expiresAt")) {
    authorityDecision.expiresAt = acceptanceInputText(input.expiresAt);
  }
  if (requiredFields.has("scope")) authorityDecision.scope = acceptanceInputText(input.scope);
  if (requiredFields.has("compensatingControls")) {
    authorityDecision.compensatingControls = acceptanceInputStringArray(
      input.compensatingControls,
      "compensatingControls",
    );
  }
  for (const field of option.requiredFields) {
    if (!isAcceptanceInputSubstantive(authorityDecision[field])) {
      throw invalidAcceptanceInput(`Kernel-required Authority field is missing: ${field}.`);
    }
  }

  const closureMode = acceptanceInputText(input.closureMode);
  const closureRationale = acceptanceInputText(input.closureRationale);
  if (!requirements.knowledgeClosure.allowedModes.includes(closureMode)) {
    throw invalidAcceptanceInput("Select one Kernel-declared Knowledge Closure mode.");
  }
  if (!closureRationale) throw invalidAcceptanceInput("Knowledge Closure rationale is required.");
  let knowledgeClosure;
  if (closureMode === "no-new-knowledge") {
    knowledgeClosure = {
      status: "complete",
      noNewKnowledge: true,
      rationale: closureRationale,
    };
  } else {
    const entries = [];
    if (requirements.knowledgeClosure.requiredModelAmendmentRefs.length > 0) {
      entries.push({
        kind: "model-amendment",
        refs: [...requirements.knowledgeClosure.requiredModelAmendmentRefs],
        rationale: closureRationale,
      });
    }
    const knowledgeGapRefs = acceptanceInputStringArray(input.knowledgeGapRefs, "knowledgeGapRefs");
    if (knowledgeGapRefs.some((gapRef) => (
      !requirements.knowledgeClosure.selectableKnowledgeGapRefs.includes(gapRef)
    ))) {
      throw invalidAcceptanceInput("Knowledge Gap input is not selectable in the bound requirements.");
    }
    if (knowledgeGapRefs.length > 0) {
      entries.push({ kind: "model-gap", refs: knowledgeGapRefs, rationale: closureRationale });
    }
    for (const statement of acceptanceInputStringArray(
      input.ephemeralStatements,
      "ephemeralStatements",
    )) {
      entries.push({ kind: "ephemeral", statement, rationale: closureRationale });
    }
    if (entries.length === 0) {
      throw invalidAcceptanceInput("Entries mode requires at least one declared knowledge entry.");
    }
    knowledgeClosure = { status: "complete", entries };
  }
  return {
    inputRequirementsConfirmation: {
      requirementsDigest: requirements.requirementsDigest,
      binding: {
        changeRef: requirements.binding.changeRef,
        sourceSnapshotDigest: requirements.binding.sourceSnapshotDigest,
        governanceBaselineDigest: requirements.binding.governanceBaselineDigest,
        verificationSubjectDigest: requirements.binding.verificationSubjectDigest,
      },
    },
    knowledgeClosure,
    authorityDecision,
  };
}

export async function refreshAfterMutation(loaders, {
  detailId = null,
  includeProject = false,
  preserveSelection = true,
} = {}) {
  requireRecord(loaders, "Workbench refresh loaders");
  const required = ["loadChanges", "loadWorkbench", "loadArchitectureProfile"];
  if (detailId !== null) required.push("loadChangeDetail");
  if (includeProject) required.push("loadProject");
  for (const name of required) {
    if (typeof loaders[name] !== "function") throw invalidProjection(`Workbench refresh ${name}`);
  }
  const operations = [];
  if (detailId !== null) operations.push(loaders.loadChangeDetail(detailId));
  operations.push(
    loaders.loadChanges({ preserveSelection }),
    loaders.loadWorkbench(),
    loaders.loadArchitectureProfile(),
  );
  if (includeProject) operations.push(loaders.loadProject());
  return Promise.allSettled(operations);
}

function requireExactArrayRecord(value, keys, label) {
  requireRecord(value, label);
  requireExactKeys(value, keys, label);
  for (const key of keys) {
    if (!Array.isArray(value[key])) throw invalidProjection(`${label}.${key}`);
  }
}

function requireWorkbenchSource(value) {
  requireRecord(value, "Workbench source");
  requireExactKeys(value, WORKBENCH_SOURCE_KEYS, "Workbench source");
  for (const field of WORKBENCH_SOURCE_KEYS) {
    requireDigest(value[field], `Workbench source.${field}`);
  }
}

function requireWorkbenchAuthoring(value) {
  requireRecord(value, "Workbench authoring");
  requireExactKeys(
    value,
    ["modules", "schemaVersion", "planOutcomes", "changeKinds"],
    "Workbench authoring",
  );
  if (value.schemaVersion !== 1) throw invalidProjection("Workbench authoring schemaVersion");
  if (!Array.isArray(value.modules)
    || !Array.isArray(value.planOutcomes)
    || !Array.isArray(value.changeKinds)) {
    throw invalidProjection("Workbench authoring collections");
  }
  requireBoundedArray(value.modules, "Workbench authoring Modules");
  requireBoundedArray(value.planOutcomes, "Workbench Plan Outcomes");
  requireBoundedArray(value.changeKinds, "Workbench Change kinds");
  requireWorkbenchAuthoringModules(value.modules);

  const outcomeRefs = new Set();
  for (const outcome of value.planOutcomes) {
    requireRecord(outcome, "Workbench Plan Outcome");
    requireExactKeys(outcome, ["outcomeRef", "statement"], "Workbench Plan Outcome");
    requireString(outcome.outcomeRef, "Workbench Plan Outcome ref");
    requireString(outcome.statement, "Workbench Plan Outcome statement");
    if (outcomeRefs.has(outcome.outcomeRef)) throw invalidProjection("Workbench Plan Outcome refs");
    outcomeRefs.add(outcome.outcomeRef);
  }

  if (value.changeKinds.length !== WORKBENCH_CHANGE_KIND_IDS.length) {
    throw invalidProjection("Workbench Change kind set");
  }
  value.changeKinds.forEach((changeKind, index) => {
    requireWorkbenchChangeKind(
      changeKind,
      WORKBENCH_CHANGE_KIND_IDS[index],
      outcomeRefs,
    );
  });
}

function requireWorkbenchAuthoringModules(modules) {
  const moduleRefs = new Set();
  for (const module of modules) {
    requireRecord(module, "Workbench authoring Module");
    requireExactKeys(
      module,
      ["id", "name", "governanceStatus", "selectable", "disabledReasonCodes", "claims"],
      "Workbench authoring Module",
    );
    requireString(module.id, "Workbench authoring Module id");
    requireString(module.name, "Workbench authoring Module name");
    if (moduleRefs.has(module.id)
      || !["governed", "provisional", "opaque"].includes(module.governanceStatus)
      || typeof module.selectable !== "boolean") {
      throw invalidProjection("Workbench authoring Module identity");
    }
    moduleRefs.add(module.id);
    requireClosedStringArray(
      module.disabledReasonCodes,
      WORKBENCH_DISABLED_REASON_CODES,
      "Workbench authoring Module disabled reasons",
    );
    if (module.selectable !== (module.disabledReasonCodes.length === 0)) {
      throw invalidProjection("Workbench authoring Module selectable state");
    }
    requireBoundedArray(module.claims, "Workbench authoring Claims");
    requireWorkbenchAuthoringClaims(module.claims);
  }
}

function requireWorkbenchAuthoringClaims(claims) {
  const claimRefs = new Set();
  for (const claim of claims) {
    requireRecord(claim, "Workbench authoring Claim");
    requireExactKeys(
      claim,
      [
        "id",
        "statement",
        "contractRef",
        "visibilityKinds",
        "selectable",
        "disabledReasonCodes",
        "acceptanceRoutes",
      ],
      "Workbench authoring Claim",
    );
    for (const [field, label] of [
      ["id", "id"],
      ["statement", "statement"],
      ["contractRef", "Contract ref"],
    ]) {
      requireString(claim[field], `Workbench authoring Claim ${label}`);
    }
    if (claimRefs.has(claim.id) || typeof claim.selectable !== "boolean") {
      throw invalidProjection("Workbench authoring Claim identity");
    }
    claimRefs.add(claim.id);
    requireUniqueClosedStringArray(
      claim.visibilityKinds,
      ["owned", "dependency"],
      "Workbench Claim visibility kinds",
      { nonempty: true },
    );
    requireClosedStringArray(
      claim.disabledReasonCodes,
      WORKBENCH_DISABLED_REASON_CODES,
      "Workbench authoring Claim disabled reasons",
    );
    if (claim.selectable !== (claim.disabledReasonCodes.length === 0)) {
      throw invalidProjection("Workbench authoring Claim selectable state");
    }
    requireBoundedArray(claim.acceptanceRoutes, "Workbench Claim acceptance routes");
    const routeRefs = new Set();
    for (const route of claim.acceptanceRoutes) {
      requireRecord(route, "Workbench Claim acceptance route");
      requireExactKeys(
        route,
        ["gateId", "commandId", "routeRef", "routeDigest"],
        "Workbench Claim acceptance route",
      );
      for (const field of ["gateId", "commandId", "routeRef"]) {
        requireString(route[field], `Workbench Claim acceptance route ${field}`);
      }
      requireDigest(route.routeDigest, "Workbench Claim acceptance route digest");
      const routeKey = `${route.gateId}\u0000${route.commandId}\u0000${route.routeRef}`;
      if (routeRefs.has(routeKey)) throw invalidProjection("Workbench Claim acceptance routes");
      routeRefs.add(routeKey);
    }
  }
}

function requireWorkbenchChangeKind(value, expectedId, outcomeRefs) {
  requireRecord(value, "Workbench Change kind");
  requireExactKeys(
    value,
    ["id", "selectable", "disabledReasonCodes", "planSelection", "integrityIncident"],
    "Workbench Change kind",
  );
  if (value.id !== expectedId || typeof value.selectable !== "boolean") {
    throw invalidProjection("Workbench Change kind identity");
  }
  requireClosedStringArray(
    value.disabledReasonCodes,
    ["PLAN_OUTCOME_UNAVAILABLE"],
    "Workbench Change kind disabled reasons",
  );
  if (value.selectable !== (value.disabledReasonCodes.length === 0)) {
    throw invalidProjection("Workbench Change kind selectable state");
  }

  requireRecord(value.planSelection, "Workbench Plan selection");
  requireExactKeys(
    value.planSelection,
    ["minRefs", "maxRefs", "selectableOutcomeRefs"],
    "Workbench Plan selection",
  );
  if (!Number.isSafeInteger(value.planSelection.minRefs)
    || value.planSelection.minRefs < 0
    || !Number.isSafeInteger(value.planSelection.maxRefs)
    || value.planSelection.maxRefs < value.planSelection.minRefs) {
    throw invalidProjection("Workbench Plan selection cardinality");
  }
  requireCanonicalStringArray(
    value.planSelection.selectableOutcomeRefs,
    "Workbench selectable Plan Outcomes",
  );
  if (value.planSelection.selectableOutcomeRefs.some((outcomeRef) => !outcomeRefs.has(outcomeRef))) {
    throw invalidProjection("Workbench selectable Plan Outcome reference");
  }

  requireRecord(value.integrityIncident, "Workbench integrity incident authoring");
  requireExactKeys(
    value.integrityIncident,
    ["required", "protectedClaimRefsByOutcome"],
    "Workbench integrity incident authoring",
  );
  if (typeof value.integrityIncident.required !== "boolean"
    || !Array.isArray(value.integrityIncident.protectedClaimRefsByOutcome)) {
    throw invalidProjection("Workbench integrity incident authoring");
  }
  const protectedOutcomeRefs = new Set();
  for (const protection of value.integrityIncident.protectedClaimRefsByOutcome) {
    requireRecord(protection, "Workbench protected Claim authoring");
    requireExactKeys(
      protection,
      ["outcomeRef", "claimRefs"],
      "Workbench protected Claim authoring",
    );
    requireString(protection.outcomeRef, "Workbench protected Claim Outcome ref");
    if (!outcomeRefs.has(protection.outcomeRef)
      || protectedOutcomeRefs.has(protection.outcomeRef)) {
      throw invalidProjection("Workbench protected Claim Outcome reference");
    }
    protectedOutcomeRefs.add(protection.outcomeRef);
    requireCanonicalStringArray(
      protection.claimRefs,
      "Workbench protected Claim refs",
    );
  }
}

function requireWorkbenchSelectedChange(value, source) {
  requireRecord(value, "Workbench selected Change");
  requireExactKeys(
    value,
    ["id", "state", "primaryModule", "governanceBaselineDigest", "actions"],
    "Workbench selected Change",
  );
  requireString(value.id, "Workbench selected Change id");
  requireString(value.state, "Workbench selected Change state");
  if (value.primaryModule !== null) {
    requireString(value.primaryModule, "Workbench selected Change primary Module");
  }
  requireDigest(
    value.governanceBaselineDigest,
    "Workbench selected Change Governance Baseline digest",
  );
  requireRecord(value.actions, "Workbench selected Change actions");
  requireExactKeys(value.actions, ["compile", "gates", "accept"], "Workbench selected Change actions");
  requireWorkbenchSimpleAction(value.actions.compile, "compile");
  requireBoundedArray(value.actions.gates, "Workbench Gate actions");
  const gateRefs = new Set();
  for (const gate of value.actions.gates) {
    requireWorkbenchGateAction(gate);
    if (gateRefs.has(gate.gateId)) throw invalidProjection("Workbench Gate action refs");
    gateRefs.add(gate.gateId);
  }

  const accept = value.actions.accept;
  requireRecord(accept, "Workbench accept action");
  requireExactKeys(
    accept,
    ["kind", "enabled", "disabledReasonCodes", "inputRequirements"],
    "Workbench accept action",
  );
  if (accept.kind !== "accept" || typeof accept.enabled !== "boolean") {
    throw invalidProjection("Workbench accept action identity");
  }
  requireClosedStringArray(
    accept.disabledReasonCodes,
    WORKBENCH_DISABLED_REASON_CODES,
    "Workbench accept action disabled reasons",
  );
  if (accept.enabled !== (accept.disabledReasonCodes.length === 0)) {
    throw invalidProjection("Workbench accept action enabled state");
  }
  requireWorkbenchAcceptanceInputRequirements(
    accept.inputRequirements,
    value,
    source,
  );
}

function requireWorkbenchSimpleAction(value, expectedKind) {
  requireRecord(value, `Workbench ${expectedKind} action`);
  requireExactKeys(
    value,
    ["kind", "enabled", "disabledReasonCodes"],
    `Workbench ${expectedKind} action`,
  );
  if (value.kind !== expectedKind || typeof value.enabled !== "boolean") {
    throw invalidProjection(`Workbench ${expectedKind} action identity`);
  }
  requireClosedStringArray(
    value.disabledReasonCodes,
    WORKBENCH_DISABLED_REASON_CODES,
    `Workbench ${expectedKind} action disabled reasons`,
  );
  if (value.enabled !== (value.disabledReasonCodes.length === 0)) {
    throw invalidProjection(`Workbench ${expectedKind} action enabled state`);
  }
}

function requireWorkbenchGateAction(value) {
  requireRecord(value, "Workbench Gate action");
  requireExactKeys(
    value,
    [
      "kind",
      "gateId",
      "name",
      "enabled",
      "disabledReasonCodes",
      "selectedCommandIds",
      "skippedCommandIds",
      "claimRouteAnnotations",
    ],
    "Workbench Gate action",
  );
  if (value.kind !== "gate" || typeof value.enabled !== "boolean") {
    throw invalidProjection("Workbench Gate action identity");
  }
  requireString(value.gateId, "Workbench Gate action id");
  requireString(value.name, "Workbench Gate action name");
  requireClosedStringArray(
    value.disabledReasonCodes,
    WORKBENCH_DISABLED_REASON_CODES,
    "Workbench Gate action disabled reasons",
  );
  if (value.enabled !== (value.disabledReasonCodes.length === 0)) {
    throw invalidProjection("Workbench Gate action enabled state");
  }
  requireCanonicalStringArray(
    value.selectedCommandIds,
    "Workbench selected Gate commands",
  );
  requireCanonicalStringArray(
    value.skippedCommandIds,
    "Workbench skipped Gate commands",
  );
  const selected = new Set(value.selectedCommandIds);
  if (value.skippedCommandIds.some((commandId) => selected.has(commandId))) {
    throw invalidProjection("Workbench Gate command partition");
  }
  requireBoundedArray(value.claimRouteAnnotations, "Workbench Gate route annotations");
  const annotationRefs = new Set();
  for (const annotation of value.claimRouteAnnotations) {
    requireRecord(annotation, "Workbench Gate route annotation");
    requireExactKeys(
      annotation,
      [
        "obligationRef",
        "targetClaimRef",
        "sourceClaimRef",
        "mappingKind",
        "gateId",
        "commandId",
        "routeDigest",
      ],
      "Workbench Gate route annotation",
    );
    for (const field of [
      "obligationRef",
      "targetClaimRef",
      "sourceClaimRef",
      "gateId",
      "commandId",
    ]) {
      requireString(annotation[field], `Workbench Gate route annotation ${field}`);
    }
    if (!["exact-contract-claim", "cross-claim"].includes(annotation.mappingKind)
      || annotation.gateId !== value.gateId) {
      throw invalidProjection("Workbench Gate route annotation identity");
    }
    requireDigest(annotation.routeDigest, "Workbench Gate route annotation digest");
    const annotationKey = [
      annotation.obligationRef,
      annotation.targetClaimRef,
      annotation.sourceClaimRef,
      annotation.gateId,
      annotation.commandId,
    ].join("\u0000");
    if (annotationRefs.has(annotationKey)) {
      throw invalidProjection("Workbench Gate route annotations");
    }
    annotationRefs.add(annotationKey);
  }
}

function requireWorkbenchAcceptanceInputRequirements(value, change, source) {
  requireRecord(value, "Workbench acceptance input requirements");
  requireExactKeys(
    value,
    [
      "schemaVersion",
      "binding",
      "available",
      "disabledReasonCodes",
      "knowledgeClosure",
      "authorityDecision",
      "confirmation",
      "requirementsDigest",
    ],
    "Workbench acceptance input requirements",
  );
  if (value.schemaVersion !== 1 || typeof value.available !== "boolean") {
    throw invalidProjection("Workbench acceptance input requirements identity");
  }
  requireDigest(value.requirementsDigest, "Workbench acceptance requirements digest");
  requireClosedStringArray(
    value.disabledReasonCodes,
    WORKBENCH_INPUT_REASON_CODES,
    "Workbench acceptance requirements disabled reasons",
  );
  if (value.available !== (value.disabledReasonCodes.length === 0)) {
    throw invalidProjection("Workbench acceptance requirements availability");
  }

  requireRecord(value.binding, "Workbench acceptance requirements binding");
  requireExactKeys(
    value.binding,
    ACCEPTANCE_BINDING_FIELDS,
    "Workbench acceptance requirements binding",
  );
  requireString(value.binding.changeRef, "Workbench acceptance requirements Change ref");
  requireDigest(
    value.binding.sourceSnapshotDigest,
    "Workbench acceptance requirements source digest",
  );
  requireDigest(
    value.binding.governanceBaselineDigest,
    "Workbench acceptance requirements Governance Baseline digest",
  );
  if (value.binding.verificationSubjectDigest !== null) {
    requireDigest(
      value.binding.verificationSubjectDigest,
      "Workbench acceptance requirements Verification Subject digest",
    );
  }
  if (value.binding.changeRef !== change.id
    || value.binding.sourceSnapshotDigest !== source.snapshotDigest
    || value.binding.governanceBaselineDigest !== change.governanceBaselineDigest) {
    throw invalidProjection("Workbench acceptance requirements source binding");
  }

  requireKnowledgeClosureRequirements(value.knowledgeClosure);
  requireAuthorityDecisionRequirements(value.authorityDecision);
  requireRecord(value.confirmation, "Workbench acceptance confirmation");
  requireExactKeys(
    value.confirmation,
    ["required", "bindingFields"],
    "Workbench acceptance confirmation",
  );
  if (value.confirmation.required !== true
    || !sameArray(value.confirmation.bindingFields, ACCEPTANCE_BINDING_FIELDS)) {
    throw invalidProjection("Workbench acceptance confirmation binding");
  }
}

function requireKnowledgeClosureRequirements(value) {
  requireRecord(value, "Workbench Knowledge Closure requirements");
  requireExactKeys(
    value,
    [
      "required",
      "allowedModes",
      "entryKinds",
      "requiredModelAmendmentRefs",
      "selectableKnowledgeGapRefs",
      "requiredEntryFields",
      "referenceOrStatementRequired",
    ],
    "Workbench Knowledge Closure requirements",
  );
  if (value.required !== true || value.referenceOrStatementRequired !== true) {
    throw invalidProjection("Workbench Knowledge Closure requirements");
  }
  requireClosedStringArray(
    value.allowedModes,
    KNOWLEDGE_CLOSURE_MODES,
    "Workbench Knowledge Closure modes",
  );
  if (value.allowedModes.length === 0) throw invalidProjection("Workbench Knowledge Closure modes");
  if (!sameArray(value.entryKinds, KNOWLEDGE_CLOSURE_ENTRY_KINDS)
    || !sameArray(value.requiredEntryFields, ["rationale"])) {
    throw invalidProjection("Workbench Knowledge Closure entry schema");
  }
  requireCanonicalStringArray(
    value.requiredModelAmendmentRefs,
    "Workbench required model amendment refs",
  );
  requireCanonicalStringArray(
    value.selectableKnowledgeGapRefs,
    "Workbench selectable Knowledge Gap refs",
  );
}

function requireAuthorityDecisionRequirements(value) {
  requireRecord(value, "Workbench Authority Decision requirements");
  requireExactKeys(
    value,
    [
      "required",
      "decisionOptions",
      "requiredAmendmentRefs",
      "requiredAdoptedChangePaths",
      "requiredApprovedObligationIds",
      "outOfScopePaths",
    ],
    "Workbench Authority Decision requirements",
  );
  if (value.required !== true || !Array.isArray(value.decisionOptions)) {
    throw invalidProjection("Workbench Authority Decision requirements");
  }
  let previousKey = null;
  for (const option of value.decisionOptions) {
    requireRecord(option, "Workbench Authority Decision option");
    requireExactKeys(
      option,
      ["authorityRef", "decisionType", "requiredFields"],
      "Workbench Authority Decision option",
    );
    requireString(option.authorityRef, "Workbench Authority Decision authority ref");
    if (!AUTHORITY_DECISION_TYPES.includes(option.decisionType)
      || !sameArray(option.requiredFields, AUTHORITY_REQUIRED_FIELDS[option.decisionType])) {
      throw invalidProjection("Workbench Authority Decision option schema");
    }
    const key = `${option.authorityRef}\u0000${option.decisionType}`;
    if (previousKey !== null && compareCodeUnits(previousKey, key) >= 0) {
      throw invalidProjection("Workbench Authority Decision option order");
    }
    previousKey = key;
  }
  for (const [field, label] of [
    ["requiredAmendmentRefs", "required amendment refs"],
    ["requiredAdoptedChangePaths", "required adopted Change paths"],
    ["requiredApprovedObligationIds", "required approved obligation ids"],
    ["outOfScopePaths", "out-of-scope paths"],
  ]) {
    requireCanonicalStringArray(value[field], `Workbench ${label}`);
  }
}

function requireClosedStringArray(value, allowed, label) {
  requireBoundedArray(value, label);
  let priorIndex = -1;
  for (const item of value) {
    const index = allowed.indexOf(item);
    if (index < 0 || index <= priorIndex) throw invalidProjection(label);
    priorIndex = index;
  }
}

function requireUniqueClosedStringArray(value, allowed, label, { nonempty = false } = {}) {
  requireBoundedArray(value, label);
  if (nonempty && value.length === 0) throw invalidProjection(label);
  const seen = new Set();
  for (const item of value) {
    if (!allowed.includes(item) || seen.has(item)) throw invalidProjection(label);
    seen.add(item);
  }
}

function requireCanonicalStringArray(value, label) {
  requireBoundedArray(value, label);
  let previous = null;
  for (const item of value) {
    requireString(item, label);
    if (previous !== null && compareCodeUnits(previous, item) >= 0) {
      throw invalidProjection(label);
    }
    previous = item;
  }
}

function requireBoundedArray(value, label) {
  if (!Array.isArray(value) || value.length > WORKBENCH_COLLECTION_LIMIT) {
    throw invalidProjection(label);
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    throw invalidProjection(label);
  }
}

function sameArray(value, expected) {
  return Array.isArray(value)
    && value.length === expected.length
    && value.every((item, index) => item === expected[index]);
}

function compareCodeUnits(left, right) {
  return left === right ? 0 : left < right ? -1 : 1;
}

function requireExactKeys(value, expected, label) {
  const observed = Object.keys(value).sort();
  const exact = [...expected].sort();
  if (observed.length !== exact.length || observed.some((key, index) => key !== exact[index])) {
    throw invalidProjection(`${label} shape`);
  }
}

function requireRecord(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidProjection(label);
  }
}

function requireDigest(value, label) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw invalidProjection(label);
  }
}

function invalidProjection(label) {
  const error = new Error(`${label} is not a canonical Kernel projection.`);
  error.code = "BROWSER_PROJECTION_INVALID";
  return error;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function acceptanceInputText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function acceptanceInputStringArray(value, label) {
  if (!Array.isArray(value)) throw invalidAcceptanceInput(`${label} must be an array.`);
  const result = value.map(acceptanceInputText);
  if (result.some((item) => !item) || new Set(result).size !== result.length) {
    throw invalidAcceptanceInput(`${label} must contain unique non-empty strings.`);
  }
  return result;
}

function isAcceptanceInputSubstantive(value) {
  return typeof value === "string"
    ? value.length > 0
    : Array.isArray(value) ? value.length > 0 : value !== null && value !== undefined;
}

function invalidAcceptanceInput(message) {
  const error = new Error(message);
  error.code = "BROWSER_ACCEPTANCE_INPUT_INVALID";
  return error;
}
