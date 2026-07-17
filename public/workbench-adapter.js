const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;

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
  return value;
}

export function receiveWorkbenchProjection(value) {
  requireRecord(value, "Workbench projection");
  requireExactKeys(
    value,
    ["schemaVersion", "source", "authoring", "changes", "projectionDigest"],
    "Workbench projection",
  );
  if (value.schemaVersion !== 1) throw invalidProjection("Workbench projection schemaVersion");
  requireDigest(value.projectionDigest, "Workbench projection digest");
  requireRecord(value.source, "Workbench source");
  for (const digest of Object.values(value.source)) {
    requireDigest(digest, "Workbench sourceRef");
  }
  requireRecord(value.authoring, "Workbench authoring");
  if (!Array.isArray(value.authoring.modules) || !Array.isArray(value.changes)) {
    throw invalidProjection("Workbench canonical collections");
  }
  return value;
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
