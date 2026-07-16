import { Buffer } from "node:buffer";

import { canonicalDigest, cloneJson } from "./canonical.mjs";
import { projectModelContentDigest, validateProjectModel } from "./project-model.mjs";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const EVIDENCE_CURRENCIES = new Set(["current", "stale", "invalid", "sealed-historical"]);
const EVIDENCE_ORIGINS = new Set(["current-record", "sealed-package"]);
const CONTRIBUTION_ORIGINS = new Set(["current-record", "sealed-package"]);
const CLAIM_ASSOCIATION_KINDS = new Set(["direct", "cross-claim", "builtin"]);
const FORBIDDEN_PROFILE_KEYS = new Set([
  "acceptedpackage",
  "body",
  "commandoutput",
  "coverage",
  "confidence",
  "evidencebody",
  "greenlight",
  "health",
  "observationbody",
  "overall",
  "output",
  "package",
  "percentage",
  "progress",
  "ready",
  "satisfied",
  "score",
  "sourcebody",
  "stderr",
  "stdout"
]);

export const ARCHITECTURE_PROFILE_LIMITS = Object.freeze({
  stages: 256,
  outcomes: 256,
  criteria: 2048,
  modules: 2048,
  areas: 2048,
  contracts: 4096,
  claims: 4096,
  gates: 2048,
  routes: 8192,
  gaps: 2048,
  changes: 2048,
  contributions: 16384,
  evidence: 32768,
  residuals: 32768,
  relations: 65536,
  refsPerFact: 256,
  depth: 64,
  textBytes: 4096,
  metadataBytes: 16384,
  modelBytes: 2 * 1024 * 1024,
  profileBytes: 2 * 1024 * 1024
});

export function compileArchitectureProfile(input = {}) {
  assertPlainObject(input, "input");
  assertPlainJsonContainer(input, "input", "input");
  assertAllowedKeys(input, ["model", "source", "changeFacts"], "input");
  const model = readJsonDataProperty(input, "model", "input.model");
  const sourceInput = readJsonDataProperty(input, "source", "input.source");
  assertPlainObject(model, "model");
  preflightJsonDocument(model, {
    location: "model",
    label: "Model",
    byteLimit: ARCHITECTURE_PROFILE_LIMITS.modelBytes
  });
  const changeFacts = Object.hasOwn(input, "changeFacts")
    ? readJsonDataProperty(input, "changeFacts", "input.changeFacts")
    : [];
  assertArray(changeFacts, "changeFacts");
  assertLimit("changes", changeFacts.length);
  preflightJsonDocument(changeFacts, {
    location: "changeFacts",
    label: "normalized Change facts",
    byteLimit: ARCHITECTURE_PROFILE_LIMITS.profileBytes
  });
  preflightJsonDocument(sourceInput, {
    location: "source",
    label: "source snapshot",
    byteLimit: ARCHITECTURE_PROFILE_LIMITS.metadataBytes
  });
  preflightArchitectureProfileModel(model);
  const validation = validateArchitectureProfileModel(model);
  const claimGateRouteIndex = validation.claimGateRouteIndex;
  if (!validation.valid) {
    throw profileError(
      "ARCHITECTURE_PROFILE_MODEL_INVALID",
      "Architecture Profile compilation requires a valid Project Model.",
      {
        errors: validation.errors.slice(0, 32).map((error) => ({
          code: readString(error?.code) ?? "project-model-invalid",
          location: boundedText(error?.location, "model.validation.location") ?? null
        })),
        errorCount: validation.errors.length
      }
    );
  }

  const source = compileSource(sourceInput, model);

  const graph = compileModelGraph(model, claimGateRouteIndex);
  compileChangeFacts(changeFacts, graph, source);

  for (const collection of Object.values(graph.entities)) sortFacts(collection);
  for (const collection of Object.values(graph.relations)) {
    sortFacts(collection);
  }
  assertLimit("relations", graph.budget.relations);
  assertLimit("contributions", graph.relations.contributions.length);
  assertLimit("evidence", graph.entities.evidence.length);
  assertLimit("residuals", graph.entities.residuals.length);

  const content = {
    schemaVersion: 1,
    source,
    entities: graph.entities,
    relations: graph.relations
  };
  assertProfileKeys(content);
  const profileBytes = Buffer.byteLength(JSON.stringify(content), "utf8");
  if (profileBytes > ARCHITECTURE_PROFILE_LIMITS.profileBytes) {
    throw boundsError("profileBytes", ARCHITECTURE_PROFILE_LIMITS.profileBytes, profileBytes);
  }
  return cloneJson({ ...content, profileDigest: canonicalDigest(content) });
}

function preflightJsonDocument(value, { location: rootLocation, label, byteLimit }) {
  const budget = { bytes: 0, nodes: 0 };
  const ancestors = new WeakSet();
  visit(value, rootLocation, 0);

  function visit(item, location, depth) {
    if (depth > ARCHITECTURE_PROFILE_LIMITS.depth) {
      throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.depth, depth);
    }
    budget.nodes += 1;
    if (budget.nodes > ARCHITECTURE_PROFILE_LIMITS.relations) {
      throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.relations, budget.nodes);
    }
    if (typeof item === "string") {
      consume((Buffer.byteLength(item, "utf8") * 6) + 2, location);
      return;
    }
    if (
      item === undefined
        || ["bigint", "function", "symbol"].includes(typeof item)
        || (typeof item === "number" && !Number.isFinite(item))
    ) {
      throw profileError(
        "ARCHITECTURE_PROFILE_INPUT_INVALID",
        `Architecture Profile ${label} must contain only finite JSON values.`,
        { location }
      );
    }
    if (!item || typeof item !== "object") {
      consume(16, location);
      return;
    }
    if (ancestors.has(item)) {
      throw profileError(
        "ARCHITECTURE_PROFILE_INPUT_INVALID",
        `Architecture Profile ${label} must be acyclic JSON.`,
        { location }
      );
    }
    assertPlainJsonContainer(item, location, label);
    ancestors.add(item);
    if (Array.isArray(item)) {
      if (item.length > ARCHITECTURE_PROFILE_LIMITS.relations) {
        throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.relations, item.length);
      }
      consume(item.length + 2, location);
      for (let index = 0; index < item.length; index += 1) {
        const nestedLocation = `${location}.${index}`;
        visit(readJsonDataProperty(item, String(index), nestedLocation), nestedLocation, depth + 1);
      }
    } else {
      consume(2, location);
      let fieldCount = 0;
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        fieldCount += 1;
        if (fieldCount > ARCHITECTURE_PROFILE_LIMITS.refsPerFact) {
          throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.refsPerFact, fieldCount);
        }
        consume((Buffer.byteLength(key, "utf8") * 6) + 3, location);
        const nestedLocation = `${location}.${key}`;
        visit(readJsonDataProperty(item, key, nestedLocation), nestedLocation, depth + 1);
      }
    }
    ancestors.delete(item);
  }

  function consume(bytes, location) {
    budget.bytes += bytes;
    if (budget.bytes > byteLimit) {
      throw boundsError(location, byteLimit, budget.bytes);
    }
  }
}

function preflightArchitectureProfileModel(model) {
  const modules = preflightArray(model.modules, "modules", "model.modules");
  for (const module of modules) {
    preflightRefs(module?.dependencies, `module.${readReference(module) ?? "unknown"}.dependencies`);
    preflightRefs(module?.publicContracts, `module.${readReference(module) ?? "unknown"}.publicContracts`);
    preflightRefs(module?.paths?.include, `module.${readReference(module) ?? "unknown"}.paths.include`);
  }

  const contracts = preflightArray(model.contracts, "contracts", "model.contracts");
  let claimCount = 0;
  for (const contract of contracts) {
    const claims = asArray(contract?.claims);
    claimCount += claims.length;
    assertLimit("claims", claimCount);
    preflightRefs(contract?.consumers, `contract.${readReference(contract) ?? "unknown"}.consumers`);
    preflightRefs(
      contract?.normativeSources,
      `contract.${readReference(contract) ?? "unknown"}.normativeSources`
    );
  }

  const gates = preflightArray(model.gates, "gates", "model.gates");
  let commandCount = 0;
  for (const gate of gates) {
    const gateRef = readReference(gate) ?? "unknown";
    preflightRefs(gate?.appliesTo, `gate.${gateRef}.appliesTo`);
    const commands = Array.isArray(gate?.commands) ? gate.commands : gate?.command ? [gate] : [];
    commandCount += commands.length;
    assertLimit("routes", commandCount);
    for (const command of commands) {
      const commandRef = readReference(command) ?? "unknown";
      preflightRefs(command?.appliesTo, `gate.${gateRef}.command.${commandRef}.appliesTo`);
      preflightRefs(command?.claimRefs, `gate.${gateRef}.command.${commandRef}.claimRefs`);
      preflightCommandSpecification(
        command?.command,
        `gate.${gateRef}.command.${commandRef}.argv`
      );
      for (const field of [
        "oracle",
        "applicability",
        "discriminatoryPower",
        "residualUncertainty"
      ]) {
        preflightMetadata(
          command?.[field],
          `gate.${gateRef}.command.${commandRef}.${field}`
        );
      }
    }
  }

  const stages = preflightArray(model.plan?.stages, "stages", "model.plan.stages");
  for (const stage of stages) {
    preflightRefs(stage?.outcomeRefs, `stage.${readReference(stage) ?? "unknown"}.outcomeRefs`);
  }
  const outcomes = preflightArray(model.plan?.outcomes, "outcomes", "model.plan.outcomes");
  let criterionCount = 0;
  for (const outcome of outcomes) {
    const outcomeRef = readReference(outcome) ?? "unknown";
    preflightRefs(outcome?.dependsOn, `outcome.${outcomeRef}.dependsOn`);
    preflightRefs(outcome?.allowedChangeKinds, `outcome.${outcomeRef}.allowedChangeKinds`);
    preflightRefs(outcome?.acceptance?.exitCriteria, `outcome.${outcomeRef}.acceptance.exitCriteria`);
    preflightRefs(outcome?.acceptance?.claimRefs, `outcome.${outcomeRef}.acceptance.claimRefs`);
    preflightRefs(outcome?.acceptance?.gapRefs, `outcome.${outcomeRef}.acceptance.gapRefs`);
    const criteria = asArray(outcome?.acceptance?.criteria);
    criterionCount += criteria.length;
    assertLimit("criteria", criterionCount);
    for (const criterion of criteria) {
      const criterionRef = readReference(criterion) ?? "unknown";
      preflightRefs(criterion?.claimRefs, `criterion.${criterionRef}.claimRefs`);
      preflightRefs(criterion?.gapRefs, `criterion.${criterionRef}.gapRefs`);
    }
  }
  const transitions = asArray(model.plan?.outcomeTransitions);
  preflightRefs(transitions, "model.plan.outcomeTransitions");
  for (const transition of transitions) {
    const transitionRef = readReference(transition) ?? "unknown";
    preflightRefs(transition?.packageRefs, `transition.${transitionRef}.packageRefs`);
    preflightRefs(
      transition?.criterionAssessments,
      `transition.${transitionRef}.criterionAssessments`
    );
    preflightRefs(transition?.gapDispositions, `transition.${transitionRef}.gapDispositions`);
  }
  preflightRefs(model.plan?.principles, "model.plan.principles");
  preflightRefs(
    model.plan?.referenceAcceptanceScenario?.faults,
    "model.plan.referenceAcceptanceScenario.faults"
  );
  preflightRefs(
    model.plan?.referenceAcceptanceScenario?.mustDemonstrate,
    "model.plan.referenceAcceptanceScenario.mustDemonstrate"
  );
  preflightRefs(model.plan?.bootstrapBaseline?.outcomeRefs, "model.plan.bootstrapBaseline.outcomeRefs");

  const gaps = preflightArray(model.knowledgeGaps, "gaps", "model.knowledgeGaps");
  for (const gap of gaps) {
    const gapRef = readReference(gap) ?? "unknown";
    preflightRefs(gap?.proofClaimRefs, `gap.${gapRef}.proofClaimRefs`);
    preflightRefs(gap?.affects, `gap.${gapRef}.affects`);
    preflightRefs(gap?.closedBy, `gap.${gapRef}.closedBy`);
  }

  preflightRefs(model.projectDocument?.normativeSources, "model.projectDocument.normativeSources");
  preflightRefs(model.projectDocument?.authorities?.fact, "model.projectDocument.authorities.fact");
  const decisionAuthorities = asArray(model.projectDocument?.authorities?.decision);
  preflightRefs(decisionAuthorities, "model.projectDocument.authorities.decision");
  for (const authority of decisionAuthorities) {
    preflightRefs(authority?.may, `model.projectDocument.authority.${readReference(authority) ?? "unknown"}.may`);
  }
  for (const state of ["governed", "provisional", "opaque"]) {
    preflightRefs(
      model.projectDocument?.assuranceBoundary?.[state],
      `model.projectDocument.assuranceBoundary.${state}`
    );
  }
  preflightRefs(
    model.projectDocument?.changePolicy?.fullGateBefore,
    "model.projectDocument.changePolicy.fullGateBefore"
  );
}

function preflightArray(value, dimension, location) {
  const values = asArray(value);
  const limit = ARCHITECTURE_PROFILE_LIMITS[dimension];
  if (Number.isFinite(limit) && values.length > limit) {
    throw boundsError(location, limit, values.length);
  }
  return values;
}

function preflightRefs(value, location) {
  if (Array.isArray(value)) assertRefsPerFact(value.length, location);
}

function preflightCommandSpecification(value, location) {
  const budget = { bytes: 0 };
  if (typeof value === "string") {
    preflightCommandText(value, location, budget);
    return;
  }
  if (Array.isArray(value)) {
    assertRefsPerFact(value.length, location);
    for (const [index, part] of value.entries()) {
      preflightCommandText(part, `${location}.${index}`, budget);
    }
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const field of ["command", "program", "display"]) {
    preflightCommandText(value[field], `${location}.${field}`, budget);
  }
  if (Array.isArray(value.args)) {
    assertRefsPerFact(value.args.length, `${location}.args`);
    for (const [index, part] of value.args.entries()) {
      preflightCommandText(part, `${location}.args.${index}`, budget);
    }
  }
}

function preflightCommandText(value, location, budget) {
  if (typeof value !== "string") return;
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > ARCHITECTURE_PROFILE_LIMITS.textBytes) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.textBytes, bytes);
  }
  budget.bytes += bytes;
  if (budget.bytes > ARCHITECTURE_PROFILE_LIMITS.metadataBytes) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.metadataBytes, budget.bytes);
  }
}

function preflightMetadata(value, location) {
  if (value === undefined || value === null) return;
  const budget = { bytes: 0, nodes: 0 };
  const ancestors = new WeakSet();
  visit(value, location, 0);

  function visit(item, itemLocation, depth) {
    if (depth > ARCHITECTURE_PROFILE_LIMITS.depth) {
      throw boundsError(itemLocation, ARCHITECTURE_PROFILE_LIMITS.depth, depth);
    }
    budget.nodes += 1;
    if (budget.nodes > ARCHITECTURE_PROFILE_LIMITS.metadataBytes) {
      throw boundsError(itemLocation, ARCHITECTURE_PROFILE_LIMITS.metadataBytes, budget.nodes);
    }
    if (typeof item === "string") {
      const bytes = Buffer.byteLength(item, "utf8");
      if (bytes > ARCHITECTURE_PROFILE_LIMITS.textBytes) {
        throw boundsError(itemLocation, ARCHITECTURE_PROFILE_LIMITS.textBytes, bytes);
      }
      consume(bytes + 2, itemLocation);
      return;
    }
    if (
      item === undefined
        || ["bigint", "function", "symbol"].includes(typeof item)
        || (typeof item === "number" && !Number.isFinite(item))
    ) {
      throw profileError(
        "ARCHITECTURE_PROFILE_INPUT_INVALID",
        "Architecture Profile metadata must contain only finite JSON values.",
        { location: itemLocation }
      );
    }
    if (!item || typeof item !== "object") {
      consume(16, itemLocation);
      return;
    }
    if (ancestors.has(item)) {
      throw profileError(
        "ARCHITECTURE_PROFILE_INPUT_INVALID",
        "Architecture Profile metadata must be an acyclic JSON value.",
        { location: itemLocation }
      );
    }
    assertPlainJsonContainer(item, itemLocation, "metadata");
    ancestors.add(item);
    if (Array.isArray(item)) {
      assertRefsPerFact(item.length, itemLocation);
      consume(item.length + 2, itemLocation);
      for (let index = 0; index < item.length; index += 1) {
        const nestedLocation = `${itemLocation}.${index}`;
        visit(
          readJsonDataProperty(item, String(index), nestedLocation),
          nestedLocation,
          depth + 1
        );
      }
    } else {
      let fieldCount = 0;
      consume(2, itemLocation);
      for (const key in item) {
        if (!Object.hasOwn(item, key)) continue;
        fieldCount += 1;
        assertRefsPerFact(fieldCount, itemLocation);
        assertProfileKeyAllowed(key, itemLocation);
        const keyBytes = Buffer.byteLength(key, "utf8");
        if (keyBytes > ARCHITECTURE_PROFILE_LIMITS.textBytes) {
          throw boundsError(`${itemLocation}.${key}`, ARCHITECTURE_PROFILE_LIMITS.textBytes, keyBytes);
        }
        consume(keyBytes + 3, itemLocation);
        const nestedLocation = `${itemLocation}.${key}`;
        visit(readJsonDataProperty(item, key, nestedLocation), nestedLocation, depth + 1);
      }
    }
    ancestors.delete(item);
  }

  function consume(bytes, itemLocation) {
    budget.bytes += bytes;
    if (budget.bytes > ARCHITECTURE_PROFILE_LIMITS.metadataBytes) {
      throw boundsError(itemLocation, ARCHITECTURE_PROFILE_LIMITS.metadataBytes, budget.bytes);
    }
  }
}

function assertPlainJsonContainer(value, location, label) {
  const array = Array.isArray(value);
  const prototype = Object.getPrototypeOf(value);
  const expectedPrototype = array ? Array.prototype : Object.prototype;
  if ((prototype !== expectedPrototype && !(prototype === null && !array)) || Object.hasOwn(value, "toJSON")) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `Architecture Profile ${label} containers must use plain JSON identity without toJSON hooks.`,
      { location }
    );
  }
}

function readJsonDataProperty(value, key, location) {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      "Architecture Profile JSON input cannot contain holes or accessor properties.",
      { location }
    );
  }
  return descriptor.value;
}

function compileSource(value, model) {
  assertPlainObject(value, "source");
  assertAllowedKeys(
    value,
    ["snapshotDigest", "projectModelDigest", "gitContentDigest", "changeStoreDigest"],
    "source"
  );
  const source = {};
  for (const field of ["snapshotDigest", "projectModelDigest", "gitContentDigest", "changeStoreDigest"]) {
    const digest = readString(value[field]);
    if (!DIGEST_PATTERN.test(digest ?? "")) {
      throw profileError(
        "ARCHITECTURE_PROFILE_SOURCE_INVALID",
        `source.${field} must be a canonical sha256 digest.`,
        { field }
      );
    }
    source[field] = digest;
  }
  const observedProjectModelDigest = projectModelContentDigest(model);
  const declaredProjectModelDigest = readString(model.digest) ?? null;
  if (
    declaredProjectModelDigest !== observedProjectModelDigest
      || source.projectModelDigest !== observedProjectModelDigest
  ) {
    throw profileError(
      "ARCHITECTURE_PROFILE_SOURCE_MISMATCH",
      "The supplied source snapshot does not bind the supplied Project Model.",
      {
        suppliedProjectModelDigest: source.projectModelDigest,
        declaredProjectModelDigest,
        observedProjectModelDigest
      }
    );
  }
  return source;
}

function compileModelGraph(model, claimGateRouteIndex) {
  const entities = {
    stages: [],
    outcomes: [],
    criteria: [],
    modules: [],
    areas: [],
    contracts: [],
    changes: [],
    claims: [],
    gates: [],
    routes: [],
    evidence: [],
    residuals: [],
    gaps: []
  };
  const relations = {
    outcomeCriteria: [],
    outcomeClaims: [],
    outcomeGaps: [],
    criterionClaims: [],
    criterionGaps: [],
    gapProofClaims: [],
    gapAffects: [],
    contributions: [],
    contributionClaims: [],
    claimGateRoutes: [],
    routeModules: [],
    routeResiduals: [],
    currentEvidenceClaimAssociations: [],
    historicalEvidenceClaimAssociations: [],
    evidenceResiduals: []
  };

  const indices = {
    stages: new Map(),
    outcomes: new Map(),
    criteria: new Map(),
    modules: new Map(),
    areas: new Map(),
    contracts: new Map(),
    claims: new Map(),
    gates: new Map(),
    routes: new Map(),
    changes: new Set(),
    contributionOccurrences: new Set(),
    evidenceOccurrences: new Set(),
    evidenceObligationBindings: new Map(),
    evidenceClaimAssociationOccurrences: new Set()
  };
  const graph = {
    entities,
    relations,
    indices,
    budget: { relations: 0, bytes: 0 }
  };

  const stages = asArray(model.plan?.stages);
  assertLimit("stages", stages.length);
  assertLimit("outcomes", asArray(model.plan?.outcomes).length);
  for (const stage of stages) {
    const id = requiredId(stage, "stage");
    addUnique(indices.stages, id, "stage");
    pushEntity(graph, "stages", compactObject({
      id,
      name: boundedText(stage?.name, `stage.${id}.name`),
      status: boundedText(stage?.status, `stage.${id}.status`)
    }));
  }

  for (const module of asArray(model.modules)) {
    const id = requiredId(module, "module");
    addUnique(indices.modules, id, "module");
    pushEntity(graph, "modules", compactObject({
      id,
      name: boundedText(module?.name, `module.${id}.name`),
      status: boundedText(module?.status, `module.${id}.status`)
    }));
  }
  assertLimit("modules", entities.modules.length);

  for (const contract of asArray(model.contracts)) {
    const id = requiredId(contract, "contract");
    addUnique(indices.contracts, id, "contract");
    const ownerModuleRef = requiredReference(contract?.owner, `contract.${id}.owner`);
    assertReference(indices.modules, ownerModuleRef, "module", `contract.${id}.owner`);
    pushEntity(graph, "contracts", compactObject({
      id,
      name: boundedText(contract?.name, `contract.${id}.name`),
      ownerModuleRef,
      maturity: boundedText(contract?.maturity, `contract.${id}.maturity`)
    }));
    for (const claim of asArray(contract?.claims)) {
      const claimId = requiredId(claim, `contract.${id}.claim`);
      addUnique(indices.claims, claimId, "claim");
      indices.claims.set(claimId, { contractRef: id, ownerModuleRef });
      pushEntity(graph, "claims", {
        id: claimId,
        contractRef: id,
        ownerModuleRef,
        statement: requiredText(claim?.statement, `claim.${claimId}.statement`)
      });
    }
  }
  assertLimit("contracts", entities.contracts.length);
  assertLimit("claims", entities.claims.length);

  let gateCommandCount = 0;
  for (const gate of asArray(model.gates)) {
    const id = requiredId(gate, "gate");
    addUnique(indices.gates, id, "gate");
    indices.gates.set(id, gate);
    pushEntity(graph, "gates", compactObject({
      id,
      name: boundedText(gate?.name, `gate.${id}.name`)
    }));
    const commands = Array.isArray(gate?.commands) ? gate.commands : gate?.command ? [gate] : [];
    gateCommandCount += commands.length;
    assertLimit("routes", gateCommandCount);
    for (const command of commands) {
      assertRefsPerFact(asArray(command?.claimRefs).length, `gate.${id}.command.claimRefs`);
    }
  }
  assertLimit("gates", entities.gates.length);

  const criterionCount = asArray(model.plan?.outcomes)
    .reduce((total, outcome) => total + asArray(outcome?.acceptance?.criteria).length, 0);
  assertLimit("criteria", criterionCount);
  for (const outcome of asArray(model.plan?.outcomes)) {
    const id = requiredId(outcome, "outcome");
    addUnique(indices.outcomes, id, "outcome");
    const stageRef = requiredReference(outcome?.stage, `outcome.${id}.stage`);
    assertReference(indices.stages, stageRef, "stage", `outcome.${id}.stage`);
    indices.outcomes.set(id, outcome);
    pushEntity(graph, "outcomes", {
      id,
      stageRef,
      status: requiredText(outcome?.status, `outcome.${id}.status`),
      statement: requiredText(outcome?.outcome, `outcome.${id}.statement`)
    });
    for (const claimRef of referenceList(outcome?.acceptance?.claimRefs, `outcome.${id}.claimRefs`)) {
      assertReference(indices.claims, claimRef, "claim", `outcome.${id}.claimRefs`);
      pushRelation(graph, "outcomeClaims", { outcomeRef: id, claimRef });
    }
    for (const gapRef of referenceList(outcome?.acceptance?.gapRefs, `outcome.${id}.gapRefs`)) {
      pushRelation(graph, "outcomeGaps", { outcomeRef: id, gapRef });
    }
    for (const criterion of asArray(outcome?.acceptance?.criteria)) {
      const criterionId = requiredId(criterion, `outcome.${id}.criterion`);
      addUnique(indices.criteria, criterionId, "criterion");
      const criterionClaimRefs = referenceList(
        criterion?.claimRefs,
        `criterion.${criterionId}.claimRefs`
      );
      indices.criteria.set(criterionId, { outcomeRef: id, claimRefs: new Set(criterionClaimRefs) });
      pushEntity(graph, "criteria", {
        id: criterionId,
        outcomeRef: id,
        statement: requiredText(criterion?.statement, `criterion.${criterionId}.statement`)
      });
      pushRelation(graph, "outcomeCriteria", { outcomeRef: id, criterionRef: criterionId });
      for (const claimRef of criterionClaimRefs) {
        assertReference(indices.claims, claimRef, "claim", `criterion.${criterionId}.claimRefs`);
        pushRelation(graph, "criterionClaims", { criterionRef: criterionId, claimRef });
      }
      for (const gapRef of referenceList(criterion?.gapRefs, `criterion.${criterionId}.gapRefs`)) {
        pushRelation(graph, "criterionGaps", { criterionRef: criterionId, gapRef });
      }
    }
  }

  for (const gap of asArray(model.knowledgeGaps)) {
    const id = requiredId(gap, "knowledge-gap");
    const gapIndex = indices.gaps ??= new Map();
    addUnique(gapIndex, id, "knowledge-gap");
    pushEntity(graph, "gaps", compactObject({
      id,
      status: requiredText(gap?.status, `gap.${id}.status`),
      ownerRef: boundedText(readReference(gap?.owner), `gap.${id}.owner`),
      statement: requiredText(gap?.statement, `gap.${id}.statement`),
      expansionTrigger: boundedText(gap?.expansionTrigger, `gap.${id}.expansionTrigger`),
      resolution: boundedText(gap?.resolution, `gap.${id}.resolution`),
      reopenTrigger: boundedText(gap?.reopenTrigger, `gap.${id}.reopenTrigger`)
    }));
    for (const claimRef of referenceList(gap?.proofClaimRefs, `gap.${id}.proofClaimRefs`)) {
      assertReference(indices.claims, claimRef, "claim", `gap.${id}.proofClaimRefs`);
      pushRelation(graph, "gapProofClaims", { gapRef: id, claimRef });
    }
    for (const moduleRef of referenceList(gap?.affects, `gap.${id}.affects`)) {
      if (indices.modules.has(moduleRef)) {
        pushRelation(graph, "gapAffects", { gapRef: id, targetKind: "module", targetRef: moduleRef });
      } else {
        if (!indices.areas.has(moduleRef)) {
          indices.areas.set(moduleRef, true);
          pushEntity(graph, "areas", { id: moduleRef, kind: "declared-gap-affect" });
        }
        pushRelation(graph, "gapAffects", { gapRef: id, targetKind: "declared-area", targetRef: moduleRef });
      }
    }
  }
  assertLimit("gaps", entities.gaps.length);
  assertLimit("areas", entities.areas.length);
  for (const collection of [relations.outcomeGaps, relations.criterionGaps]) {
    for (const relation of collection) {
      assertReference(indices.gaps ?? new Map(), relation.gapRef, "knowledge-gap", "plan.gapRefs");
    }
  }

  compileRoutes(graph, claimGateRouteIndex);
  return graph;
}

function validateArchitectureProfileModel(model) {
  const claimRefs = asArray(model.contracts)
    .flatMap((contract) => asArray(contract?.claims))
    .map((claim) => readString(claim?.id))
    .filter(Boolean);
  try {
    return validateProjectModel(model, {
      claimGateRouteIndexRequest: {
        claimRefs,
        limits: {
          claimRefs: ARCHITECTURE_PROFILE_LIMITS.claims,
          modules: ARCHITECTURE_PROFILE_LIMITS.modules,
          gates: ARCHITECTURE_PROFILE_LIMITS.gates,
          commands: ARCHITECTURE_PROFILE_LIMITS.routes,
          refsPerCommand: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
          routes: ARCHITECTURE_PROFILE_LIMITS.routes,
          totalRouteBytes: ARCHITECTURE_PROFILE_LIMITS.profileBytes,
          depth: ARCHITECTURE_PROFILE_LIMITS.depth,
          textBytes: ARCHITECTURE_PROFILE_LIMITS.textBytes
        }
      }
    });
  } catch (error) {
    if (error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED") {
      const dimension = readString(error?.details?.dimension) ?? "routes";
      const limit = Number.isFinite(error?.details?.limit)
        ? error.details.limit
        : ARCHITECTURE_PROFILE_LIMITS.routes;
      const observed = Number.isFinite(error?.details?.observed)
        ? error.details.observed
        : limit + 1;
      throw boundsError(`claimGateRouteIndex.${dimension}`, limit, observed);
    }
    throw error;
  }
}

function compileRoutes(graph, routesByClaim) {
  const { entities, relations, indices } = graph;
  for (const claim of entities.claims) {
    for (const route of routesByClaim.get(claim.id) ?? []) {
      const gateRef = requiredReference(route?.gateId, `route.${claim.id}.gateId`);
      const commandRef = requiredReference(route?.commandId, `route.${claim.id}.commandId`);
      assertReference(indices.gates, gateRef, "gate", `route.${claim.id}.gateId`);
      const effectiveModuleRefs = asArray(route?.effectiveModuleRefs);
      assertRefsPerFact(effectiveModuleRefs.length, `route.${claim.id}.effectiveModuleRefs`);
      for (const moduleRef of effectiveModuleRefs) {
        assertReference(indices.modules, moduleRef, "module", `route.${claim.id}.effectiveModuleRefs`);
      }
      assertMetadata(route?.oracle, `route.${claim.id}.oracle`);
      assertMetadata(route?.applicability, `route.${claim.id}.applicability`);
      assertMetadata(route?.discriminatoryPower, `route.${claim.id}.discriminatoryPower`);
      const routeRef = `route-${canonicalDigest({ claimRef: claim.id, gateRef, commandRef }).slice(7)}`;
      if (indices.routes.has(routeRef)) {
        throw duplicateError("route", routeRef);
      }
      const compiledRoute = compactObject({
        id: routeRef,
        claimRef: claim.id,
        gateRef,
        commandRef,
        commandDigest: canonicalDigest(route?.command),
        routeDigest: canonicalDigest(route),
        timeoutMs: Number.isFinite(route?.timeoutMs) ? route.timeoutMs : null,
        oracle: cloneJson(route?.oracle),
        applicability: cloneJson(route?.applicability),
        discriminatoryPower: cloneJson(route?.discriminatoryPower)
      });
      indices.routes.set(routeKey(claim.id, gateRef, commandRef), compiledRoute);
      pushEntity(graph, "routes", compiledRoute);
      pushRelation(graph, "claimGateRoutes", { claimRef: claim.id, routeRef });
      for (const moduleRef of effectiveModuleRefs.map(readString).filter(Boolean).sort()) {
        pushRelation(graph, "routeModules", { routeRef, moduleRef });
      }
      addResiduals({
        ownerKind: "route",
        ownerRef: routeRef,
        value: route?.residualUncertainty,
        graph,
        relationCollection: "routeResiduals",
        relationKey: "routeRef"
      });
    }
  }
  assertLimit("routes", entities.routes.length);
}

function compileChangeFacts(changeFacts, graph, source) {
  let contributionCount = 0;
  let evidenceCount = 0;
  for (const fact of changeFacts) {
    assertPlainObject(fact, "changeFact");
    assertAllowedKeys(fact, [
      "schemaVersion",
      "sourceSnapshotDigest",
      "id",
      "state",
      "primaryModuleRef",
      "contributions",
      "evidence"
    ], "changeFact");
    if (fact.schemaVersion !== 1) {
      throw profileError(
        "ARCHITECTURE_PROFILE_INPUT_INVALID",
        "A normalized Change fact requires schemaVersion 1.",
        { schemaVersion: fact.schemaVersion ?? null }
      );
    }
    const factSnapshotDigest = requiredDigest(
      fact.sourceSnapshotDigest,
      "changeFact.sourceSnapshotDigest"
    );
    if (factSnapshotDigest !== source.snapshotDigest) {
      throw profileError(
        "ARCHITECTURE_PROFILE_SOURCE_MISMATCH",
        "A normalized Change fact does not bind the Profile source snapshot.",
        { changeRef: readReference(fact.id) ?? null }
      );
    }
    const changeRef = requiredReference(fact.id, "changeFact.id");
    if (graph.indices.changes.has(changeRef)) throw duplicateError("change", changeRef);
    graph.indices.changes.add(changeRef);
    const primaryModuleRef = requiredReference(fact.primaryModuleRef, `change.${changeRef}.primaryModuleRef`);
    assertReference(graph.indices.modules, primaryModuleRef, "module", `change.${changeRef}.primaryModuleRef`);
    pushEntity(graph, "changes", {
      id: changeRef,
      state: requiredText(fact.state, `change.${changeRef}.state`),
      primaryModuleRef
    });

    const contributions = fact.contributions ?? [];
    assertArray(contributions, `change.${changeRef}.contributions`);
    assertRefsPerFact(contributions.length, `change.${changeRef}.contributions`);
    contributionCount += contributions.length;
    assertLimit("contributions", contributionCount);
    for (const contribution of contributions) {
      compileContribution(contribution, changeRef, graph);
    }

    const evidence = fact.evidence ?? [];
    assertArray(evidence, `change.${changeRef}.evidence`);
    assertRefsPerFact(evidence.length, `change.${changeRef}.evidence`);
    evidenceCount += evidence.length;
    assertLimit("evidence", evidenceCount);
    for (const item of evidence) compileEvidenceFact(item, changeRef, graph, source);
  }
}

function compileContribution(value, changeRef, graph) {
  assertPlainObject(value, `change.${changeRef}.contribution`);
  assertAllowedKeys(value, [
    "contributionRef",
    "origin",
    "acceptanceDigest",
    "outcomeRef",
    "criterionRef",
    "moduleRef",
    "claimRefs",
    "bindingDigest"
  ], `change.${changeRef}.contribution`);
  const origin = requiredEnum(value.origin, CONTRIBUTION_ORIGINS, "contribution.origin");
  const acceptanceDigest = readOptionalDigest(value.acceptanceDigest, "contribution.acceptanceDigest");
  assertSealedOrigin(origin, acceptanceDigest, "contribution");
  const contributionRef = requiredReference(value.contributionRef, "contribution.contributionRef");
  const outcomeRef = requiredReference(value.outcomeRef, `contribution.${contributionRef}.outcomeRef`);
  const criterionRef = requiredReference(value.criterionRef, `contribution.${contributionRef}.criterionRef`);
  const moduleRef = requiredReference(value.moduleRef, `contribution.${contributionRef}.moduleRef`);
  const bindingDigest = requiredDigest(value.bindingDigest, `contribution.${contributionRef}.bindingDigest`);
  assertReference(graph.indices.outcomes, outcomeRef, "outcome", `contribution.${contributionRef}.outcomeRef`);
  assertReference(graph.indices.criteria, criterionRef, "criterion", `contribution.${contributionRef}.criterionRef`);
  if (graph.indices.criteria.get(criterionRef)?.outcomeRef !== outcomeRef) {
    throw danglingError("criterion-for-outcome", criterionRef, `contribution.${contributionRef}`);
  }
  assertReference(graph.indices.modules, moduleRef, "module", `contribution.${contributionRef}.moduleRef`);
  const claimRefs = referenceList(value.claimRefs, `contribution.${contributionRef}.claimRefs`);
  for (const claimRef of claimRefs) {
    assertReference(graph.indices.claims, claimRef, "claim", `contribution.${contributionRef}.claimRefs`);
    if (!graph.indices.criteria.get(criterionRef)?.claimRefs.has(claimRef)) {
      throw profileError(
        "ARCHITECTURE_PROFILE_DANGLING_REFERENCE",
        "An Outcome Contribution Claim must be declared by its exact Criterion.",
        { contributionRef, criterionRef, claimRef }
      );
    }
  }
  const occurrenceRef = `contribution-${canonicalDigest({
    changeRef,
    origin,
    acceptanceDigest,
    contributionRef,
    bindingDigest
  }).slice(7)}`;
  if (graph.indices.contributionOccurrences.has(occurrenceRef)) throw duplicateError("contribution", occurrenceRef);
  graph.indices.contributionOccurrences.add(occurrenceRef);
  pushRelation(graph, "contributions", compactObject({
    contributionRef: occurrenceRef,
    declaredContributionRef: contributionRef,
    changeRef,
    origin,
    acceptanceDigest,
    outcomeRef,
    criterionRef,
    moduleRef,
    bindingDigest,
    semantics: "relevance-only"
  }));
  for (const claimRef of claimRefs) {
    pushRelation(graph, "contributionClaims", { contributionRef: occurrenceRef, claimRef });
  }
}

function compileEvidenceFact(value, changeRef, graph, source) {
  assertPlainObject(value, `change.${changeRef}.evidence`);
  assertAllowedKeys(value, [
    "evidenceRef",
    "evidenceDigest",
    "origin",
    "acceptanceDigest",
    "currency",
    "observationStatus",
    "provenance",
    "claimEnvelopeRefs",
    "claimAssociations",
    "residualUncertainty"
  ], `change.${changeRef}.evidence`);
  const origin = requiredEnum(value.origin, EVIDENCE_ORIGINS, "evidence.origin");
  const currency = requiredEnum(value.currency, EVIDENCE_CURRENCIES, "evidence.currency");
  const acceptanceDigest = readOptionalDigest(value.acceptanceDigest, "evidence.acceptanceDigest");
  assertEvidenceOrigin(origin, currency, acceptanceDigest);
  const evidenceRef = requiredReference(value.evidenceRef, "evidence.evidenceRef");
  const evidenceDigest = requiredDigest(value.evidenceDigest, `evidence.${evidenceRef}.evidenceDigest`);
  const provenance = compileEvidenceProvenance(value.provenance, evidenceRef);
  if (currency === "current" && (
    provenance.projectModelDigest !== source.projectModelDigest
      || provenance.gitContentDigest !== source.gitContentDigest
  )) {
    throw profileError(
      "ARCHITECTURE_PROFILE_SOURCE_MISMATCH",
      "Current Evidence must bind the Profile Project Model and Git source digests.",
      { evidenceRef }
    );
  }
  const claimEnvelopeRefs = referenceList(
    value.claimEnvelopeRefs,
    `evidence.${evidenceRef}.claimEnvelopeRefs`
  );
  for (const claimRef of claimEnvelopeRefs) {
    assertReference(graph.indices.claims, claimRef, "claim", `evidence.${evidenceRef}.claimEnvelopeRefs`);
  }
  const occurrenceRef = `evidence-${canonicalDigest({
    changeRef,
    origin,
    acceptanceDigest,
    evidenceRef,
    evidenceDigest
  }).slice(7)}`;
  if (graph.indices.evidenceOccurrences.has(occurrenceRef)) throw duplicateError("evidence", occurrenceRef);
  graph.indices.evidenceOccurrences.add(occurrenceRef);
  pushEntity(graph, "evidence", compactObject({
    id: occurrenceRef,
    evidenceRef,
    evidenceDigest,
    changeRef,
    origin,
    acceptanceDigest,
    currency,
    observationStatus: boundedText(value.observationStatus, `evidence.${evidenceRef}.observationStatus`),
    provenance,
    claimEnvelopeRefs
  }));

  const claimAssociations = value.claimAssociations ?? [];
  assertArray(claimAssociations, `evidence.${evidenceRef}.claimAssociations`);
  assertRefsPerFact(claimAssociations.length, `evidence.${evidenceRef}.claimAssociations`);
  if (["stale", "invalid"].includes(currency) && claimAssociations.length > 0) {
    throw profileError(
      "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      "Stale or invalid Evidence cannot produce a current Claim association.",
      { evidenceRef, currency }
    );
  }
  for (const association of claimAssociations) {
    compileEvidenceClaimAssociation({
      association,
      evidenceRef,
      occurrenceRef,
      currency,
      provenance,
      claimEnvelopeRefs,
      graph
    });
  }
  addResiduals({
    ownerKind: "evidence",
    ownerRef: occurrenceRef,
    value: value.residualUncertainty,
    graph,
    relationCollection: "evidenceResiduals",
    relationKey: "evidenceRef"
  });
}

function compileEvidenceProvenance(value, evidenceRef) {
  assertPlainObject(value, `evidence.${evidenceRef}.provenance`);
  assertAllowedKeys(value, [
    "kind",
    "sourceId",
    "gateId",
    "commandId",
    "projectModelDigest",
    "gitContentDigest",
    "verificationSubjectDigest"
  ], `evidence.${evidenceRef}.provenance`);
  return compactObject({
    kind: requiredText(value.kind, `evidence.${evidenceRef}.provenance.kind`),
    sourceId: boundedText(value.sourceId, `evidence.${evidenceRef}.provenance.sourceId`),
    gateId: boundedText(value.gateId, `evidence.${evidenceRef}.provenance.gateId`),
    commandId: boundedText(value.commandId, `evidence.${evidenceRef}.provenance.commandId`),
    projectModelDigest: readOptionalDigest(
      value.projectModelDigest,
      `evidence.${evidenceRef}.provenance.projectModelDigest`
    ),
    gitContentDigest: readOptionalDigest(
      value.gitContentDigest,
      `evidence.${evidenceRef}.provenance.gitContentDigest`
    ),
    verificationSubjectDigest: readOptionalDigest(
      value.verificationSubjectDigest,
      `evidence.${evidenceRef}.provenance.verificationSubjectDigest`
    )
  });
}

function compileEvidenceClaimAssociation({
  association,
  evidenceRef,
  occurrenceRef,
  currency,
  provenance,
  claimEnvelopeRefs,
  graph
}) {
  const location = `evidence.${evidenceRef}.claimAssociation`;
  assertPlainObject(association, location);
  const kind = requiredEnum(association.kind, CLAIM_ASSOCIATION_KINDS, `${location}.kind`);
  const commonFields = [
    "kind",
    "targetClaimRef",
    "sourceClaimRef",
    "obligationRef",
    "obligationDigest"
  ];
  const kindFields = kind === "builtin"
    ? ["sourceId"]
    : kind === "cross-claim"
      ? ["gateId", "commandId", "authorityDecisionDigest"]
      : ["gateId", "commandId"];
  assertAllowedKeys(association, [...commonFields, ...kindFields], location);
  const targetClaimRef = requiredReference(association.targetClaimRef, `${location}.targetClaimRef`);
  const sourceClaimRef = requiredReference(association.sourceClaimRef, `${location}.sourceClaimRef`);
  const obligationRef = requiredReference(association.obligationRef, `${location}.obligationRef`);
  const obligationDigest = requiredDigest(association.obligationDigest, `${location}.obligationDigest`);
  for (const claimRef of [targetClaimRef, sourceClaimRef]) {
    assertReference(graph.indices.claims, claimRef, "claim", location);
  }
  if (!claimEnvelopeRefs.includes(sourceClaimRef)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      "An Evidence Claim association source must be present in its exact Claim envelope.",
      { evidenceRef, sourceClaimRef }
    );
  }

  let routeRef = null;
  let sourceId = null;
  let authorityDecisionDigest = null;
  if (kind === "builtin") {
    if (provenance.kind !== "builtin-oracle") {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "builtin-provenance-required");
    }
    sourceId = requiredReference(association.sourceId, `${location}.sourceId`);
    if (sourceId !== provenance.sourceId) {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "builtin-source-mismatch");
    }
    if (sourceClaimRef !== targetClaimRef) {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "builtin-cross-claim-forbidden");
    }
  } else {
    if (provenance.kind !== "gate-command") {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "gate-provenance-required");
    }
    const gateRef = requiredReference(association.gateId, `${location}.gateId`);
    const commandRef = requiredReference(association.commandId, `${location}.commandId`);
    if (gateRef !== provenance.gateId || commandRef !== provenance.commandId) {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "provenance-route-mismatch");
    }
    const route = graph.indices.routes.get(routeKey(sourceClaimRef, gateRef, commandRef));
    if (!route) throw routeMismatchError(evidenceRef, sourceClaimRef, "route-not-declared");
    routeRef = route.id;
    if (kind === "direct" && sourceClaimRef !== targetClaimRef) {
      throw routeMismatchError(evidenceRef, sourceClaimRef, "direct-target-mismatch");
    }
    if (kind === "cross-claim") {
      if (sourceClaimRef === targetClaimRef) {
        throw routeMismatchError(evidenceRef, sourceClaimRef, "cross-claim-source-equals-target");
      }
      authorityDecisionDigest = requiredDigest(
        association.authorityDecisionDigest,
        `${location}.authorityDecisionDigest`
      );
    }
  }
  const relation = compactObject({
    evidenceRef: occurrenceRef,
    targetClaimRef,
    sourceClaimRef,
    routeRef,
    sourceId,
    associationKind: kind,
    obligationRef,
    obligationDigest,
    authorityDecisionDigest
  });
  const obligationOccurrence = `${occurrenceRef}\u0000${obligationRef}`;
  const obligationBindingDigest = canonicalDigest({
    associationKind: kind,
    targetClaimRef,
    obligationDigest,
    authorityDecisionDigest
  });
  const priorObligationBinding = graph.indices.evidenceObligationBindings.get(obligationOccurrence);
  if (priorObligationBinding && priorObligationBinding !== obligationBindingDigest) {
    throw profileError(
      "ARCHITECTURE_PROFILE_OBLIGATION_CONFLICT",
      "One Evidence occurrence cannot assign conflicting semantics to the same Verification Obligation.",
      { evidenceRef, obligationRef }
    );
  }
  graph.indices.evidenceObligationBindings.set(obligationOccurrence, obligationBindingDigest);
  const associationOccurrence = canonicalDigest({
    occurrenceRef,
    obligationRef,
    targetClaimRef,
    sourceClaimRef,
    routeRef,
    sourceId
  });
  if (graph.indices.evidenceClaimAssociationOccurrences.has(associationOccurrence)) {
    throw duplicateError("Evidence Claim association", associationOccurrence);
  }
  graph.indices.evidenceClaimAssociationOccurrences.add(associationOccurrence);
  if (currency === "current") {
    pushRelation(graph, "currentEvidenceClaimAssociations", relation);
  } else if (currency === "sealed-historical") {
    pushRelation(graph, "historicalEvidenceClaimAssociations", relation);
  }
}

function addResiduals({ ownerKind, ownerRef, value, graph, relationCollection, relationKey }) {
  const values = value === undefined || value === null ? [] : Array.isArray(value) ? value : [value];
  assertRefsPerFact(values.length, `${ownerKind}.${ownerRef}.residualUncertainty`);
  for (const [ordinal, residualValue] of values.entries()) {
    assertMetadata(residualValue, `${ownerKind}.${ownerRef}.residualUncertainty.${ordinal}`);
    const residualRef = `residual-${canonicalDigest({
      ownerKind,
      ownerRef,
      ordinal,
      valueDigest: canonicalDigest(residualValue)
    }).slice(7)}`;
    pushEntity(graph, "residuals", {
      id: residualRef,
      ownerKind,
      ownerRef,
      ordinal,
      value: cloneJson(residualValue)
    });
    pushRelation(graph, relationCollection, { [relationKey]: ownerRef, residualRef });
  }
}

function assertEvidenceOrigin(origin, currency, acceptanceDigest) {
  if (origin === "current-record" && acceptanceDigest) {
    throw profileError(
      "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      "Current-record Evidence cannot carry a sealed-package acceptanceDigest.",
      { origin, currency }
    );
  }
  if (currency === "sealed-historical") {
    if (origin !== "sealed-package" || !acceptanceDigest) {
      throw profileError(
        "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
        "sealed-historical Evidence requires sealed-package origin and acceptanceDigest.",
        { origin, currency }
      );
    }
    return;
  }
  if (currency === "current" && origin !== "current-record") {
    throw profileError(
      "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      "Current Evidence must originate from the current record.",
      { origin, currency }
    );
  }
  if (origin === "sealed-package" && !acceptanceDigest) {
    throw profileError(
      "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      "A sealed-package Evidence occurrence requires acceptanceDigest.",
      { origin, currency }
    );
  }
}

function assertSealedOrigin(origin, acceptanceDigest, label) {
  if (origin === "sealed-package" && !acceptanceDigest) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${label} sealed-package origin requires acceptanceDigest.`,
      { origin }
    );
  }
  if (origin === "current-record" && acceptanceDigest) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${label} current-record origin cannot carry acceptanceDigest.`,
      { origin }
    );
  }
}

function routeKey(claimRef, gateRef, commandRef) {
  return `${claimRef}\u0000${gateRef}\u0000${commandRef}`;
}

function referenceList(value, location) {
  const rawValues = asArray(value);
  assertRefsPerFact(rawValues.length, location);
  const values = [];
  const seen = new Set();
  for (const rawValue of rawValues) {
    const reference = readReference(rawValue);
    if (!reference) continue;
    if (seen.has(reference)) throw duplicateError("reference", location);
    seen.add(reference);
    values.push(reference);
  }
  return values.sort();
}

function requiredId(value, label) {
  return requiredReference(value?.id, `${label}.id`);
}

function requiredReference(value, location) {
  const reference = readReference(value);
  if (!reference) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} requires a non-empty reference.`,
      { location }
    );
  }
  return requiredText(reference, location);
}

function requiredText(value, location) {
  const text = boundedText(value, location);
  if (!text) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} requires a non-empty string.`,
      { location }
    );
  }
  return text;
}

function boundedText(value, location) {
  const text = readString(value);
  if (!text) return undefined;
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > ARCHITECTURE_PROFILE_LIMITS.textBytes) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.textBytes, bytes);
  }
  return text;
}

function requiredDigest(value, location) {
  const digest = readString(value);
  if (!DIGEST_PATTERN.test(digest ?? "")) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} requires a canonical sha256 digest.`,
      { location }
    );
  }
  return digest;
}

function readOptionalDigest(value, location) {
  if (value === undefined || value === null) return null;
  return requiredDigest(value, location);
}

function requiredEnum(value, allowed, location) {
  const exact = requiredText(value, location);
  if (!allowed.has(exact)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} has an unsupported value.`,
      { location, allowed: [...allowed].sort() }
    );
  }
  return exact;
}

function assertMetadata(value, location) {
  if (value === undefined || value === null) return;
  preflightMetadata(value, location);
  assertProfileKeys(value, location);
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > ARCHITECTURE_PROFILE_LIMITS.metadataBytes) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.metadataBytes, bytes);
  }
}

function assertProfileKeys(value, location = "profile") {
  if (Array.isArray(value)) {
    for (const item of value) assertProfileKeys(item, location);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    assertProfileKeyAllowed(key, location);
    assertProfileKeys(item, `${location}.${key}`);
  }
}

function assertProfileKeyAllowed(key, location) {
  const normalized = key.toLowerCase().replace(/[^a-z]/gu, "");
  if (FORBIDDEN_PROFILE_KEYS.has(normalized)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_AGGREGATE_FORBIDDEN",
      "Architecture Profiles cannot collapse assurance dimensions into aggregate conclusions or output bodies.",
      { location, key }
    );
  }
}

function assertAllowedKeys(value, allowed, location) {
  const accepted = new Set(allowed);
  const unknown = Object.keys(value).filter((key) => !accepted.has(key)).sort();
  if (unknown.length > 0) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} contains unsupported fields.`,
      { location, fields: unknown.slice(0, 32), fieldCount: unknown.length }
    );
  }
}

function assertPlainObject(value, location) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} must be an object.`,
      { location }
    );
  }
}

function assertArray(value, location) {
  if (!Array.isArray(value)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INPUT_INVALID",
      `${location} must be an array.`,
      { location }
    );
  }
}

function assertReference(index, reference, kind, location) {
  if (!index.has(reference)) throw danglingError(kind, reference, location);
}

function addUnique(index, id, kind) {
  if (index.has(id)) throw duplicateError(kind, id);
  index.set(id, true);
}

function pushEntity(graph, collection, value) {
  const target = graph.entities[collection];
  if (!Array.isArray(target)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INTERNAL_INVALID",
      "Architecture Profile compiler selected an unknown entity collection.",
      { collection },
      500
    );
  }
  assertLimit(collection, target.length + 1);
  consumeGraphBytes(graph, value, `entities.${collection}`);
  target.push(value);
}

function pushRelation(graph, collection, value) {
  const target = graph.relations[collection];
  if (!Array.isArray(target)) {
    throw profileError(
      "ARCHITECTURE_PROFILE_INTERNAL_INVALID",
      "Architecture Profile compiler selected an unknown relation collection.",
      { collection },
      500
    );
  }
  const observed = graph.budget.relations + 1;
  assertLimit("relations", observed);
  assertLimit(collection, target.length + 1);
  consumeGraphBytes(graph, value, `relations.${collection}`);
  target.push(value);
  graph.budget.relations = observed;
}

function consumeGraphBytes(graph, value, location) {
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8") + 1;
  const observed = graph.budget.bytes + bytes;
  if (observed > ARCHITECTURE_PROFILE_LIMITS.profileBytes) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.profileBytes, observed);
  }
  graph.budget.bytes = observed;
}

function assertLimit(dimension, observed) {
  const limit = ARCHITECTURE_PROFILE_LIMITS[dimension];
  if (Number.isFinite(limit) && observed > limit) throw boundsError(dimension, limit, observed);
}

function assertRefsPerFact(observed, location) {
  if (observed > ARCHITECTURE_PROFILE_LIMITS.refsPerFact) {
    throw boundsError(location, ARCHITECTURE_PROFILE_LIMITS.refsPerFact, observed);
  }
}

function boundsError(dimension, limit, observed) {
  return profileError(
    "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
    "Architecture Profile compilation exceeded a declared hard bound.",
    { dimension, limit, observed },
    413
  );
}

function danglingError(kind, reference, location) {
  return profileError(
    "ARCHITECTURE_PROFILE_DANGLING_REFERENCE",
    `Architecture Profile input references an unknown ${kind}.`,
    { kind, reference, location }
  );
}

function duplicateError(kind, reference) {
  return profileError(
    "ARCHITECTURE_PROFILE_DUPLICATE_IDENTITY",
    `Architecture Profile input contains a duplicate ${kind} identity.`,
    { kind, reference }
  );
}

function routeMismatchError(evidenceRef, sourceClaimRef, reason) {
  return profileError(
    "ARCHITECTURE_PROFILE_ROUTE_MISMATCH",
    "Normalized Evidence support does not match an exact compiler-owned route.",
    { evidenceRef, sourceClaimRef, reason }
  );
}

function sortFacts(values) {
  values.sort((left, right) => canonicalDigest(left).localeCompare(canonicalDigest(right)));
}

function compactObject(value) {
  return Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined && item !== null));
}

function readReference(value) {
  if (typeof value === "string") return readString(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  for (const key of ["id", "ref", "module", "moduleId", "contract", "contractId", "target"]) {
    const exact = readString(value[key]);
    if (exact) return exact;
  }
  return undefined;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function profileError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  error.details = details;
  return error;
}
