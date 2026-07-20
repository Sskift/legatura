import { Buffer } from "node:buffer";
import { types as utilTypes } from "node:util";

import { canonicalDigest } from "./canonical.mjs";
import {
  projectCompiledContextCapsuleModelBinding,
  projectCompiledContextCapsulePlanBinding
} from "./change-compiler.mjs";
import {
  pathSelectorWithin,
  projectCompiledModulePathOwnershipIndex
} from "./path-ownership.mjs";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const SOURCE_BINDING_KEYS = Object.freeze([
  "gitContentDigest",
  "manifestDigest",
  "pathSetDigest",
  "productDigest",
  "repositoryIdentityDigest",
  "trackedPathFactsDigest"
]);
const HARD_LIMITS = Object.freeze({
  contracts: 2_048,
  dataBytes: 64 * 1024 * 1024,
  dataDepth: 64,
  fileBytes: 4 * 1024 * 1024,
  modules: 2_048,
  pathBytes: 4_096,
  pathRefs: 1_024,
  relations: 65_536,
  totalPathBytes: 16 * 1024 * 1024,
  totalBytes: 16 * 1024 * 1024,
  trackedPaths: 65_536,
  workUnits: 4_194_304
});

export const CONTEXT_COMPILER_LIMITS = deepFreeze({ schemaVersion: 1, ...HARD_LIMITS });

export function compileContextMaterializationPlan(input, options = {}) {
  const normalizedOptions = normalizeOptions(options, "materialization");
  const budget = createBudget(normalizedOptions.limits, "materialization");
  assertFinitePlainData(input, "materializationInput", budget);
  assertExactKeys(
    input,
    ["contextCapsule", "model", "trackedPathFacts"],
    "materializationInput"
  );

  const model = input.model;
  assertFrozenGovernanceBaseline(model);
  const capsule = input.contextCapsule;
  const trackedPathFacts = normalizeTrackedPathFacts(input.trackedPathFacts, budget);
  const primaryModuleRef = requireIdentifier(capsule?.primaryModule, "contextCapsule.primaryModule");
  const modelIndex = indexModel(model, budget);
  const primaryModule = modelIndex.modules.get(primaryModuleRef);
  if (!primaryModule || !["governed", "provisional"].includes(primaryModule.status)) {
    throw inputError("Context Capsule primaryModule must name a governed or provisional Module.");
  }
  const capsuleBinding = assertCompiledContextCapsule({
    capsule,
    model,
    modelIndex,
    primaryModule,
    budget
  });

  const readScope = normalizeScope(capsule.scope?.read, "contextCapsule.scope.read", budget);
  const writeScope = normalizeScope(capsule.scope?.write, "contextCapsule.scope.write", budget);
  assertExactDerivedValue(
    { read: readScope, write: writeScope },
    { read: capsule.scope.read, write: capsule.scope.write },
    "Context Capsule scopes are not exact normalized compiler outputs."
  );
  assertReadScopeAuthorized({
    modelBinding: capsuleBinding.modelBinding,
    readScope,
    budget
  });

  const pathRefs = trackedPathFacts.paths.filter((pathRef) => (
    readScope.include.some((selector) => selectorMatchesPath(selector, pathRef))
      && !readScope.exclude.some((selector) => selectorMatchesPath(selector, pathRef))
  ));
  assertLimit("pathRefs", pathRefs.length, budget.limits.pathRefs, budget.kind);
  const readScopeDigest = canonicalDigest(readScope);
  const writeScopeDigest = canonicalDigest(writeScope);

  const capsuleOwnership = normalizeCapsuleOwnershipBinding(capsule, budget);
  const projection = projectCompiledModulePathOwnershipIndex(
    normalizedOptions.modulePathOwnershipProduct,
    {
      model,
      moduleRefs: [primaryModuleRef],
      pathRefs,
      scopeSelections: [{
        id: "context-materialization-write",
        moduleRef: primaryModuleRef,
        scope: writeScope,
        expectedScopeDigest: capsuleOwnership.effectiveScopeDigest
      }],
      limits: ownershipProjectionLimits(budget.limits)
    }
  );
  assertOwnershipBinding({
    capsuleOwnership,
    projection,
    trackedPathFacts,
    primaryModuleRef,
    writeScopeDigest
  });

  const decisions = projection.pathDecisionsByModule.get(primaryModuleRef);
  if (!(decisions instanceof Map) || decisions.size !== pathRefs.length) {
    throw inputError("Ownership projection omitted materialized path decisions.");
  }
  const pathFacts = pathRefs.map((pathRef) => materializationPathFact(
    pathRef,
    decisions.get(pathRef)
  ));
  const contractSurfaceFacts = compileContractSurfaceFacts({
    modelBinding: capsuleBinding.modelBinding,
    modelIndex,
    pathRefs,
    primaryModuleRef,
    budget
  });
  const pathSetDigest = canonicalDigest({ schemaVersion: 1, paths: pathRefs });
  const content = {
    schemaVersion: 1,
    kind: "context-materialization-plan",
    primaryModuleRef,
    modelDigest: projection.sourceBinding.modelDigest,
    contextCapsuleDigest: canonicalDigest(capsule),
    trackedPathFactsDigest: trackedPathFacts.digest,
    ownershipProductDigest: projection.sourceBinding.productDigest,
    readScopeDigest,
    writeScopeDigest,
    pathSetDigest,
    pathRefs,
    pathFacts,
    contractSurfaceFacts
  };
  return deepFreeze({
    ...content,
    materializationPlanDigest: canonicalDigest(content)
  });
}

export function compileContextExpansionImpact(input, options = {}) {
  const normalizedOptions = normalizeOptions(options, "impact");
  const budget = createBudget(normalizedOptions.limits, "impact");
  assertFinitePlainData(input, "impactInput", budget);
  assertExactKeys(input, [
    "model",
    "primaryModuleRef",
    "priorDisclosedPaths",
    "priorDisclosedPathsDigest",
    "repositorySourceProjection",
    "requestedPathRefs"
  ], "impactInput");

  const model = input.model;
  assertFrozenGovernanceBaseline(model);
  const modelIndex = indexModel(model, budget);
  const primaryModuleRef = requireIdentifier(input.primaryModuleRef, "primaryModuleRef");
  const primaryModule = modelIndex.modules.get(primaryModuleRef);
  if (!primaryModule || !["governed", "provisional"].includes(primaryModule.status)) {
    throw inputError("primaryModuleRef must name a governed or provisional Module.");
  }
  const priorDisclosedPaths = normalizePathRefs(
    input.priorDisclosedPaths,
    "priorDisclosedPaths",
    budget.limits.pathRefs,
    budget
  );
  const requestedPathRefs = normalizePathRefs(
    input.requestedPathRefs,
    "requestedPathRefs",
    budget.limits.pathRefs,
    budget
  );
  const priorDisclosedPathsDigest = requireDigest(
    input.priorDisclosedPathsDigest,
    "priorDisclosedPathsDigest"
  );
  if (priorDisclosedPathsDigest !== canonicalDigest({
    schemaVersion: 1,
    paths: priorDisclosedPaths
  })) {
    throw inputError("priorDisclosedPathsDigest does not match priorDisclosedPaths.");
  }
  const priorSet = new Set(priorDisclosedPaths);
  const overlap = requestedPathRefs.filter((pathRef) => priorSet.has(pathRef));
  if (overlap.length > 0) {
    throw inputError("requestedPathRefs must be a normalized disclosure delta with no prior path.", {
      overlap: overlap.slice(0, 32)
    });
  }
  const proposalPathRefs = [...priorDisclosedPaths, ...requestedPathRefs].sort(compareUtf8);
  assertLimit("pathRefs", proposalPathRefs.length, budget.limits.pathRefs, budget.kind);

  const source = normalizeRepositorySourceProjection(
    input.repositorySourceProjection,
    proposalPathRefs,
    budget
  );
  const projection = projectCompiledModulePathOwnershipIndex(
    normalizedOptions.modulePathOwnershipProduct,
    {
      model,
      moduleRefs: [primaryModuleRef],
      pathRefs: proposalPathRefs,
      limits: ownershipProjectionLimits(budget.limits)
    }
  );
  if (source.trackedPathFactsDigest !== projection.sourceBinding.trackedPathFactsDigest) {
    throw inputError("Repository Source tracked-path facts do not match the ownership product.");
  }

  const decisions = projection.pathDecisionsByModule.get(primaryModuleRef);
  if (!(decisions instanceof Map) || decisions.size !== proposalPathRefs.length) {
    throw inputError("Ownership projection omitted proposal path decisions.");
  }
  const pathFacts = requestedPathRefs.map((pathRef) => impactPathFact(pathRef, decisions.get(pathRef)));
  const contractRelations = [];
  const assuranceCrossings = [];
  for (const pathFact of pathFacts) {
    const ownerModule = modelIndex.modules.get(pathFact.ownerModuleRef);
    if (!ownerModule) throw inputError("Impact path owner is absent from the frozen Model.");
    contractRelations.push(...compileContractRelations({
      pathRef: pathFact.pathRef,
      primaryModule,
      ownerModule,
      modelIndex,
      budget
    }));
    if (ownerModule.id !== primaryModule.id) {
      assuranceCrossings.push({
        pathRef: pathFact.pathRef,
        fromModuleRef: primaryModule.id,
        toModuleRef: ownerModule.id,
        fromStatus: requireModuleStatus(primaryModule.status),
        toStatus: requireModuleStatus(ownerModule.status),
        fromFactAuthorityRef: readReference(primaryModule.factAuthority) ?? null,
        toFactAuthorityRef: readReference(ownerModule.factAuthority) ?? null
      });
    }
  }
  assertLimit("relations", contractRelations.length, budget.limits.relations, budget.kind);
  assertLimit("relations", assuranceCrossings.length, budget.limits.relations, budget.kind);
  contractRelations.sort(compareRelationFacts);
  assuranceCrossings.sort(compareRelationFacts);

  const repositorySourceBinding = Object.fromEntries(
    SOURCE_BINDING_KEYS.map((key) => [key, source[key]])
  );
  const requestedPathsDigest = canonicalDigest({ schemaVersion: 1, paths: requestedPathRefs });
  const content = {
    schemaVersion: 1,
    kind: "context-expansion-impact",
    modelDigest: projection.sourceBinding.modelDigest,
    ownershipProductDigest: projection.sourceBinding.productDigest,
    primaryModuleRef,
    repositorySourceBinding,
    priorDisclosedPathsDigest,
    requestedPathsDigest,
    requestedPathRefs,
    newlyDisclosedPathRefs: [...requestedPathRefs],
    pathFacts,
    contractRelations,
    assuranceCrossings,
    dispositionRefs: []
  };
  return deepFreeze({ ...content, impactDigest: canonicalDigest(content) });
}

function normalizeOptions(options, kind) {
  assertPlainRecord(options, `${kind}Options`);
  assertExactKeys(options, ["limits", "modulePathOwnershipProduct"], `${kind}Options`, {
    optionalKeys: ["limits"]
  });
  const product = options.modulePathOwnershipProduct;
  if ((typeof product !== "object" && typeof product !== "function")
    || product === null
    || utilTypes.isProxy(product)) {
    throw inputError("A live, non-proxied modulePathOwnershipProduct is required.");
  }
  return { modulePathOwnershipProduct: product, limits: resolveLimits(options.limits) };
}

function resolveLimits(value) {
  if (value === undefined) return { ...HARD_LIMITS };
  assertPlainRecord(value, "limits");
  assertExactKeys(value, Object.keys(HARD_LIMITS), "limits", {
    optionalKeys: Object.keys(HARD_LIMITS)
  });
  return Object.fromEntries(Object.entries(HARD_LIMITS).map(([key, hardLimit]) => {
    const configured = value[key] ?? hardLimit;
    if (!Number.isSafeInteger(configured) || configured < 1 || configured > hardLimit) {
      throw inputError(`limits.${key} must be a positive integer no greater than ${hardLimit}.`);
    }
    return [key, configured];
  }));
}

function createBudget(limits, kind) {
  return { kind, limits, workUnits: 0, dataBytes: 0, totalPathBytes: 0 };
}

function indexModel(model, budget) {
  assertPlainRecord(model, "model");
  const modules = requireDenseArray(model.modules, "model.modules", budget.limits.modules);
  const contracts = requireDenseArray(model.contracts, "model.contracts", budget.limits.contracts);
  const moduleMap = new Map();
  for (const module of modules) {
    consumeWork(budget);
    assertPlainRecord(module, "model.modules[]");
    const id = requireIdentifier(module.id, "model.modules[].id");
    if (moduleMap.has(id)) throw inputError(`Duplicate Module id: ${id}.`);
    moduleMap.set(id, module);
  }
  const contractMap = new Map();
  for (const contract of contracts) {
    consumeWork(budget);
    assertPlainRecord(contract, "model.contracts[]");
    const id = requireIdentifier(contract.id, "model.contracts[].id");
    if (contractMap.has(id)) throw inputError(`Duplicate Contract id: ${id}.`);
    contractMap.set(id, contract);
  }
  return { modules: moduleMap, contracts: contractMap };
}

function normalizeTrackedPathFacts(value, budget) {
  assertExactKeys(value, ["digest", "paths", "schemaVersion"], "trackedPathFacts");
  if (value.schemaVersion !== 1) throw inputError("trackedPathFacts.schemaVersion must be 1.");
  const paths = normalizePathRefs(
    value.paths,
    "trackedPathFacts.paths",
    budget.limits.trackedPaths,
    budget
  );
  const digest = requireDigest(value.digest, "trackedPathFacts.digest");
  if (digest !== canonicalDigest({ schemaVersion: 1, paths })) {
    throw inputError("trackedPathFacts.digest does not match its exact paths.");
  }
  return { schemaVersion: 1, paths, digest };
}

function assertCompiledContextCapsule({ capsule, model, modelIndex, primaryModule, budget }) {
  assertExactKeys(capsule, [
    "annotations",
    "assurance",
    "compiledFrom",
    "contextExpansionPolicy",
    "dependencies",
    "dependencyContracts",
    "knowledgeGaps",
    "module",
    "normativeSources",
    "notes",
    "outcomeAlignment",
    "planOutcomes",
    "primaryModule",
    "publicContracts",
    "schemaVersion",
    "scope",
    "workerInstructions"
  ], "contextCapsule", {
    optionalKeys: ["annotations", "notes", "workerInstructions"]
  });
  if (capsule.schemaVersion !== 1) throw inputError("contextCapsule.schemaVersion must be 1.");
  assertExactKeys(capsule.compiledFrom, [
    "governanceBaselineDigest",
    "pathOwnership",
    "projectModelFiles"
  ], "contextCapsule.compiledFrom");
  assertExactKeys(capsule.scope, [
    "otherModuleImplementation",
    "read",
    "write"
  ], "contextCapsule.scope");
  if (capsule.scope.otherModuleImplementation
    !== "contract-only; expansion must be recorded before reading implementation") {
    throw inputError("Context Capsule implementation boundary is not compiler-derived.");
  }
  const publicContractRefs = normalizeContextContractRefs(
    capsule.publicContracts,
    "contextCapsule.publicContracts",
    budget
  );
  const dependencyContractRefs = normalizeContextContractRefs(
    capsule.dependencyContracts,
    "contextCapsule.dependencyContracts",
    budget
  );
  const expectedPublic = uniqueSorted(
    asArray(primaryModule.publicContracts).map(readReference).filter(Boolean)
  );
  for (const contractRef of expectedPublic) {
    const contract = modelIndex.contracts.get(contractRef);
    if (!contract
      || readReference(contract.owner, ["module", "moduleId", "id"]) !== primaryModule.id) {
      throw inputError("Primary Module public Contract ownership is invalid.", { contractRef });
    }
  }
  const dependencyRefs = [];
  for (const dependency of asArray(primaryModule.dependencies)) {
    const providerRef = readReference(dependency, ["module", "moduleId", "target", "id"]);
    const contractRef = readReference(dependency, ["via", "contract", "contractId"]);
    const contract = contractRef ? modelIndex.contracts.get(contractRef) : null;
    if (!providerRef
      || !modelIndex.modules.has(providerRef)
      || !contract
      || readReference(contract.owner, ["module", "moduleId", "id"]) !== providerRef) {
      throw inputError("Primary Module dependency Contract binding is invalid.");
    }
    dependencyRefs.push(contractRef);
  }
  const expectedDependencies = uniqueSorted(dependencyRefs);
  if (!sameStrings(publicContractRefs, expectedPublic)
    || !sameStrings(dependencyContractRefs, expectedDependencies)) {
    throw inputError("Context Capsule Contract surfaces do not match the frozen primary Module.");
  }

  let modelBinding;
  try {
    modelBinding = projectCompiledContextCapsuleModelBinding(model, primaryModule.id);
  } catch (error) {
    throw inputError("Context Capsule model binding cannot be reproduced.", {
      cause: error?.code ?? "unknown"
    });
  }
  const expectedModelFields = {
    governanceBaselineDigest: modelBinding.governanceBaselineDigest,
    projectModelFiles: modelBinding.projectModelFiles,
    primaryModule: modelBinding.primaryModuleRef,
    module: modelBinding.module,
    publicContracts: modelBinding.publicContracts,
    dependencyContracts: modelBinding.dependencyContracts,
    dependencies: modelBinding.dependencies,
    normativeSources: modelBinding.normativeSources,
    contextExpansionPolicy: modelBinding.contextExpansionPolicy
  };
  const observedModelFields = {
    governanceBaselineDigest: capsule.compiledFrom.governanceBaselineDigest,
    projectModelFiles: capsule.compiledFrom.projectModelFiles,
    primaryModule: capsule.primaryModule,
    module: capsule.module,
    publicContracts: capsule.publicContracts,
    dependencyContracts: capsule.dependencyContracts,
    dependencies: capsule.dependencies,
    normativeSources: capsule.normativeSources,
    contextExpansionPolicy: capsule.contextExpansionPolicy
  };
  assertExactDerivedValue(
    observedModelFields,
    expectedModelFields,
    "Context Capsule Model projection is incomplete, forged, or stale."
  );

  const planOutcomes = requireDenseArray(
    capsule.planOutcomes,
    "contextCapsule.planOutcomes",
    budget.limits.pathRefs
  );
  const selectedOutcomeRefs = planOutcomes.map((outcome, index) => {
    assertPlainRecord(outcome, `contextCapsule.planOutcomes[${index}]`);
    return requireIdentifier(outcome.id, `contextCapsule.planOutcomes[${index}].id`);
  });
  if (new Set(selectedOutcomeRefs).size !== selectedOutcomeRefs.length) {
    throw inputError("Context Capsule selected Outcomes must be duplicate-free.");
  }
  if (capsule.outcomeAlignment !== null) {
    assertExactKeys(capsule.outcomeAlignment, [
      "contributions",
      "exceptions",
      "mode",
      "schemaVersion",
      "selectedOutcomeRefs",
      "status",
      "unresolved"
    ], "contextCapsule.outcomeAlignment");
  }
  let planBinding;
  try {
    planBinding = projectCompiledContextCapsulePlanBinding(
      model,
      primaryModule.id,
      selectedOutcomeRefs,
      capsule.outcomeAlignment
    );
  } catch (error) {
    throw inputError("Context Capsule Plan projection cannot be reproduced.", {
      cause: error?.code ?? "unknown"
    });
  }
  assertExactDerivedValue(
    { planOutcomes: capsule.planOutcomes, knowledgeGaps: capsule.knowledgeGaps },
    { planOutcomes: planBinding.planOutcomes, knowledgeGaps: planBinding.knowledgeGaps },
    "Context Capsule Plan projection is incomplete, forged, or stale."
  );
  assertCompiledAssurance(capsule.assurance, primaryModule);
  return { modelBinding };
}

function assertFrozenGovernanceBaseline(model) {
  assertExactKeys(model, [
    "contracts",
    "digest",
    "files",
    "gates",
    "knowledgeGaps",
    "modelDigest",
    "modules",
    "plan",
    "project",
    "projectDocument",
    "schemaVersion"
  ], "model");
  if (model.schemaVersion !== 1) throw inputError("model.schemaVersion must be 1.");
  const digest = requireDigest(model.digest, "model.digest");
  requireDigest(model.modelDigest, "model.modelDigest");
  const snapshot = Object.fromEntries(
    Object.entries(model).filter(([key]) => key !== "digest")
  );
  if (digest !== canonicalDigest(snapshot)) {
    throw inputError("Frozen Governance Baseline digest does not match its exact content.");
  }
}

function assertExactDerivedValue(observed, expected, message) {
  if (canonicalDigest(observed) !== canonicalDigest(expected)) throw inputError(message);
}

function assertCompiledAssurance(value, primaryModule) {
  assertPlainRecord(value, "contextCapsule.assurance");
  if (primaryModule.status === "governed") {
    assertExactDerivedValue(
      value,
      { status: "governed", writeScopeMode: "module-paths" },
      "Context Capsule assurance does not match the governed primary Module."
    );
    return;
  }
  assertExactKeys(value, ["modelExpansion", "status", "writeScopeMode"], "contextCapsule.assurance");
  if (value.status !== "provisional"
    || value.writeScopeMode !== "module-paths-with-model-expansion") {
    throw inputError("Context Capsule assurance does not match the provisional primary Module.");
  }
  assertPlainRecord(value.modelExpansion, "contextCapsule.assurance.modelExpansion");
}

function assertReadScopeAuthorized({ modelBinding, readScope, budget }) {
  const generatedInclude = normalizeSelectorList(
    modelBinding.generatedReadScope.include,
    "modelBinding.generatedReadScope.include",
    budget
  );
  const generatedExclude = normalizeSelectorList(
    modelBinding.generatedReadScope.exclude,
    "modelBinding.generatedReadScope.exclude",
    budget
  );
  for (const selector of readScope.include) {
    if (!generatedInclude.some((parent) => pathSelectorWithin(selector, parent))) {
      throw inputError("Context Capsule read scope broadens the frozen generated scope.", { selector });
    }
  }
  for (const selector of readScope.exclude) {
    if (!generatedInclude.some((parent) => pathSelectorWithin(selector, parent))) {
      throw inputError("Context Capsule read exclusions fall outside the generated scope.", { selector });
    }
  }
  if (generatedExclude.some((selector) => !readScope.exclude.includes(selector))) {
    throw inputError("Context Capsule read scope removed a frozen Module exclusion.");
  }
}

function normalizeCapsuleOwnershipBinding(capsule, budget) {
  const value = capsule.compiledFrom?.pathOwnership;
  assertExactKeys(value, [
    "assignmentDigest",
    "effectiveScopeDigest",
    "modelDigest",
    "ownershipPolicyDigest",
    "productDigest",
    "schemaVersion",
    "scopeDigest",
    "trackedPathFactsDigest"
  ], "contextCapsule.compiledFrom.pathOwnership");
  if (value.schemaVersion !== 1) throw inputError("Capsule ownership schemaVersion must be 1.");
  for (const key of [
    "assignmentDigest",
    "effectiveScopeDigest",
    "modelDigest",
    "ownershipPolicyDigest",
    "productDigest",
    "scopeDigest",
    "trackedPathFactsDigest"
  ]) requireDigest(value[key], `contextCapsule.compiledFrom.pathOwnership.${key}`);
  consumeWork(budget);
  return value;
}

function assertOwnershipBinding({
  capsuleOwnership,
  projection,
  trackedPathFacts,
  primaryModuleRef,
  writeScopeDigest
}) {
  const expectedSource = projection.sourceBinding;
  const observedSource = {
    schemaVersion: capsuleOwnership.schemaVersion,
    modelDigest: capsuleOwnership.modelDigest,
    trackedPathFactsDigest: capsuleOwnership.trackedPathFactsDigest,
    ownershipPolicyDigest: capsuleOwnership.ownershipPolicyDigest,
    assignmentDigest: capsuleOwnership.assignmentDigest,
    productDigest: capsuleOwnership.productDigest
  };
  if (canonicalDigest(observedSource) !== canonicalDigest(expectedSource)
    || trackedPathFacts.digest !== expectedSource.trackedPathFactsDigest) {
    throw inputError("Context Capsule, tracked facts, and ownership product bindings differ.");
  }
  const authoritative = projection.writeScopesByModule.get(primaryModuleRef);
  const effective = projection.scopeBindingsBySelection.get("context-materialization-write");
  if (!authoritative
    || !effective
    || capsuleOwnership.scopeDigest !== authoritative.digest
    || capsuleOwnership.effectiveScopeDigest !== writeScopeDigest
    || effective.effectiveScopeDigest !== writeScopeDigest) {
    throw inputError("Context Capsule write-scope binding is stale or broadened.");
  }
}

function compileContractSurfaceFacts({
  modelBinding,
  modelIndex,
  pathRefs,
  primaryModuleRef,
  budget
}) {
  const selected = new Set(pathRefs);
  const publicRefs = new Set(modelBinding.publicContracts.map((contract) => contract.id));
  const dependencyRefs = new Set(
    modelBinding.dependencyContracts.map((contract) => contract.id)
  );
  const facts = [];
  for (const contractRef of [...publicRefs, ...dependencyRefs]) {
    consumeWork(budget);
    const contract = modelIndex.contracts.get(contractRef);
    const sourceFile = contract?.sourceFile;
    if (typeof sourceFile !== "string" || !selected.has(sourceFile)) continue;
    const ownerModuleRef = readReference(contract.owner, ["module", "moduleId", "id"]);
    facts.push({
      pathRef: sourceFile,
      contractRef,
      relation: publicRefs.has(contractRef)
        ? "primary-public-contract" : "dependency-interface-contract",
      ownerModuleRef: ownerModuleRef ?? null,
      dependencyModuleRef: publicRefs.has(contractRef) ? null : ownerModuleRef ?? null
    });
  }
  assertLimit("relations", facts.length, budget.limits.relations, budget.kind);
  facts.sort(compareRelationFacts);
  return dedupeFacts(facts);
}

function materializationPathFact(pathRef, decision) {
  if (!decision || decision.classification === "unassigned") {
    throw inputError("Materialized path is unowned.", { pathRef });
  }
  if (decision.classification === "ungoverned-disposition") {
    const dispositionRef = requireIdentifier(decision.dispositionRef, "path decision dispositionRef");
    return { pathRef, kind: "ungoverned-disposition", dispositionRef };
  }
  const ownerModuleRef = requireIdentifier(decision.ownerModuleRef, "path decision ownerModuleRef");
  return { pathRef, kind: "module-owner", ownerModuleRef };
}

function impactPathFact(pathRef, decision) {
  if (!decision
    || decision.classification === "unassigned"
    || decision.classification === "ungoverned-disposition") {
    throw inputError("Impact disclosure delta requires a Module-owned path.", { pathRef });
  }
  return {
    pathRef,
    ownerModuleRef: requireIdentifier(decision.ownerModuleRef, "path decision ownerModuleRef")
  };
}

function compileContractRelations({ pathRef, primaryModule, ownerModule, modelIndex, budget }) {
  if (primaryModule.id === ownerModule.id) {
    return [{
      pathRef,
      ownerModuleRef: ownerModule.id,
      relation: "same-module",
      fromModuleRef: primaryModule.id,
      toModuleRef: ownerModule.id,
      contractRef: null,
      access: null
    }];
  }
  const relations = [];
  for (const [consumer, provider] of [
    [primaryModule, ownerModule],
    [ownerModule, primaryModule]
  ]) {
    for (const dependency of asArray(consumer.dependencies)) {
      consumeWork(budget);
      const providerRef = readReference(dependency, ["module", "moduleId", "target", "id"]);
      if (providerRef !== provider.id) continue;
      const contractRef = readReference(dependency, ["via", "contract", "contractId"]);
      const contract = contractRef ? modelIndex.contracts.get(contractRef) : null;
      const contractOwner = readReference(contract?.owner, ["module", "moduleId", "id"]);
      if (!contract || contractOwner !== provider.id) {
        throw inputError("A declared dependency Contract is absent or owned by another Module.");
      }
      relations.push({
        pathRef,
        ownerModuleRef: ownerModule.id,
        relation: "declared-dependency",
        fromModuleRef: consumer.id,
        toModuleRef: provider.id,
        contractRef,
        access: typeof dependency.access === "string" ? dependency.access : null
      });
    }
  }
  if (relations.length === 0) {
    relations.push({
      pathRef,
      ownerModuleRef: ownerModule.id,
      relation: "undeclared-cross-module",
      fromModuleRef: primaryModule.id,
      toModuleRef: ownerModule.id,
      contractRef: null,
      access: null
    });
  }
  relations.sort(compareRelationFacts);
  return dedupeFacts(relations);
}

function normalizeRepositorySourceProjection(value, expectedPaths, budget) {
  assertExactKeys(value, [
    ...SOURCE_BINDING_KEYS,
    "manifest",
    "schemaVersion"
  ], "repositorySourceProjection");
  if (value.schemaVersion !== 1) {
    throw inputError("repositorySourceProjection.schemaVersion must be 1.");
  }
  for (const key of SOURCE_BINDING_KEYS) requireDigest(value[key], `repositorySourceProjection.${key}`);
  let totalBytes = 0;
  const manifest = requireDenseArray(
    value.manifest,
    "repositorySourceProjection.manifest",
    budget.limits.pathRefs
  ).map((entry, index) => {
    consumeWork(budget);
    assertExactKeys(entry, ["byteLength", "contentDigest", "pathRef"], `manifest[${index}]`);
    const pathRef = normalizePathRef(entry.pathRef, `manifest[${index}].pathRef`, budget);
    if (!Number.isSafeInteger(entry.byteLength) || entry.byteLength < 0) {
      throw inputError(`manifest[${index}].byteLength must be a non-negative safe integer.`);
    }
    if (entry.byteLength > budget.limits.fileBytes) {
      throw limitError(
        "fileBytes",
        budget.limits.fileBytes,
        entry.byteLength,
        budget.kind,
        `manifest[${index}].byteLength`
      );
    }
    totalBytes += entry.byteLength;
    if (totalBytes > budget.limits.totalBytes) {
      throw limitError("totalBytes", budget.limits.totalBytes, totalBytes, budget.kind);
    }
    return {
      pathRef,
      byteLength: entry.byteLength,
      contentDigest: requireDigest(entry.contentDigest, `manifest[${index}].contentDigest`)
    };
  });
  const manifestPaths = manifest.map((entry) => entry.pathRef);
  if (!isCanonicalUniqueOrder(manifestPaths) || !sameStrings(manifestPaths, expectedPaths)) {
    throw inputError("Repository Source manifest paths must equal the canonical proposal path union.");
  }
  const pathSetDigest = canonicalDigest({ schemaVersion: 1, paths: manifestPaths });
  const manifestDigest = canonicalDigest({ schemaVersion: 1, entries: manifest });
  const productDigest = canonicalDigest({
    schemaVersion: 1,
    repositoryIdentityDigest: value.repositoryIdentityDigest,
    gitContentDigest: value.gitContentDigest,
    trackedPathFactsDigest: value.trackedPathFactsDigest,
    pathSetDigest,
    manifestDigest
  });
  if (value.pathSetDigest !== pathSetDigest
    || value.manifestDigest !== manifestDigest
    || value.productDigest !== productDigest) {
    throw inputError("Repository Source projection digest formulas are inconsistent.");
  }
  return { ...value, manifest };
}

function normalizeContextContractRefs(value, location, budget) {
  const refs = requireDenseArray(value, location, budget.limits.contracts).map((item, index) => {
    consumeWork(budget);
    return requireIdentifier(readReference(item), `${location}[${index}].id`);
  });
  if (new Set(refs).size !== refs.length) {
    throw inputError(`${location} contains a duplicate Contract reference.`);
  }
  return [...refs].sort(compareUtf8);
}

function normalizeScope(value, location, budget) {
  assertExactKeys(value, ["exclude", "include"], location);
  return {
    include: normalizeSelectorList(value.include, `${location}.include`, budget),
    exclude: normalizeSelectorList(value.exclude, `${location}.exclude`, budget)
  };
}

function normalizeSelectorList(value, location, budget) {
  const values = requireDenseArray(value, location, budget.limits.pathRefs);
  const normalized = values.map((selector, index) => (
    normalizeSelector(selector, `${location}[${index}]`, budget)
  ));
  if (new Set(normalized).size !== normalized.length) {
    throw inputError(`${location} contains a duplicate selector.`);
  }
  return normalized;
}

function normalizeSelector(value, location, budget) {
  if (value === "**") {
    observePathBytes(value, location, budget);
    return value;
  }
  if (typeof value !== "string" || value.length === 0 || /[?*[\]]/u.test(
    value.endsWith("/**") ? value.slice(0, -3) : value
  )) {
    throw inputError(`${location} is not an exact-or-recursive-prefix selector.`);
  }
  const base = value.endsWith("/**") ? value.slice(0, -3) : value;
  normalizePathRef(base, location, budget);
  const fullBytes = Buffer.byteLength(value, "utf8");
  const baseBytes = Buffer.byteLength(base, "utf8");
  if (fullBytes > budget.limits.pathBytes) {
    throw limitError("pathBytes", budget.limits.pathBytes, fullBytes, budget.kind, location);
  }
  budget.totalPathBytes += fullBytes - baseBytes;
  if (budget.totalPathBytes > budget.limits.totalPathBytes) {
    throw limitError(
      "totalPathBytes",
      budget.limits.totalPathBytes,
      budget.totalPathBytes,
      budget.kind,
      location
    );
  }
  return value;
}

function selectorMatchesPath(selector, pathRef) {
  return pathSelectorWithin(pathRef, selector);
}

function normalizePathRefs(value, location, limit, budget) {
  const paths = requireDenseArray(value, location, limit).map((pathRef, index) => (
    normalizePathRef(pathRef, `${location}[${index}]`, budget)
  ));
  if (!isCanonicalUniqueOrder(paths)) {
    throw inputError(`${location} must be duplicate-free and use canonical UTF-8 byte ordering.`);
  }
  return paths;
}

function normalizePathRef(value, location, budget) {
  if (typeof value !== "string"
    || value.length === 0
    || !value.isWellFormed()
    || value.includes("\uFFFD")
    || value.includes("\0")
    || value.startsWith("/")
    || value.startsWith("./")
    || /^[A-Za-z]:\//u.test(value)
    || value.startsWith("\\\\")
    || value.endsWith("/")
    || value.includes("//")
    || value.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw inputError(`${location} is not a canonical repository-relative path.`);
  }
  observePathBytes(value, location, budget);
  return value;
}

function observePathBytes(value, location, budget) {
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes > budget.limits.pathBytes) {
    throw limitError("pathBytes", budget.limits.pathBytes, bytes, budget.kind, location);
  }
  budget.totalPathBytes += bytes;
  if (budget.totalPathBytes > budget.limits.totalPathBytes) {
    throw limitError(
      "totalPathBytes",
      budget.limits.totalPathBytes,
      budget.totalPathBytes,
      budget.kind
    );
  }
}

function ownershipProjectionLimits(limits) {
  return {
    trackedPaths: limits.trackedPaths,
    pathRefs: limits.pathRefs,
    moduleRefs: limits.modules,
    totalPathBytes: limits.totalPathBytes,
    workUnits: limits.workUnits
  };
}

function assertFinitePlainData(value, location, budget, depth = 0, ancestors = new WeakSet()) {
  consumeWork(budget);
  if (depth > budget.limits.dataDepth) {
    throw limitError("dataDepth", budget.limits.dataDepth, depth, budget.kind, location);
  }
  if (typeof value === "string") {
    budget.dataBytes += Buffer.byteLength(value, "utf8");
  } else if (value === null || typeof value === "boolean") {
    budget.dataBytes += 8;
  } else if (typeof value === "number") {
    if (!Number.isFinite(value)) throw inputError(`${location} contains a non-finite number.`);
    budget.dataBytes += 16;
  } else if (typeof value === "object") {
    if (utilTypes.isProxy(value) || ancestors.has(value)) {
      throw inputError(`${location} contains a proxy or cycle.`);
    }
    ancestors.add(value);
    if (Array.isArray(value)) {
      requireDenseArray(value, location, budget.limits.workUnits);
      for (let index = 0; index < value.length; index += 1) {
        assertFinitePlainData(value[index], `${location}[${index}]`, budget, depth + 1, ancestors);
      }
    } else {
      assertPlainRecord(value, location);
      for (const key of Object.keys(value)) {
        budget.dataBytes += Buffer.byteLength(key, "utf8");
        assertFinitePlainData(value[key], `${location}.${key}`, budget, depth + 1, ancestors);
      }
    }
    ancestors.delete(value);
  } else {
    throw inputError(`${location} contains unsupported data.`);
  }
  if (budget.dataBytes > budget.limits.dataBytes) {
    throw limitError("dataBytes", budget.limits.dataBytes, budget.dataBytes, budget.kind, location);
  }
}

function assertPlainRecord(value, location) {
  if (!value
    || typeof value !== "object"
    || Array.isArray(value)
    || utilTypes.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw inputError(`${location} must be a plain non-proxied record.`);
  }
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if (!Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw inputError(`${location} cannot contain accessors or hidden properties.`);
    }
  }
  if (Object.getOwnPropertySymbols(value).length > 0) {
    throw inputError(`${location} cannot contain symbol keys.`);
  }
}

function assertExactKeys(value, keys, location, { optionalKeys = [] } = {}) {
  assertPlainRecord(value, location);
  const allowed = new Set(keys);
  const optional = new Set(optionalKeys);
  const observed = Object.keys(value).sort();
  const unknown = observed.filter((key) => !allowed.has(key));
  const missing = keys.filter((key) => !optional.has(key) && !Object.hasOwn(value, key));
  if (unknown.length > 0 || missing.length > 0) {
    throw inputError(`${location} has an invalid closed shape.`, { unknown, missing });
  }
}

function requireDenseArray(value, location, limit) {
  if (!Array.isArray(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype
    || value.length > limit) {
    if (Array.isArray(value) && value.length > limit) {
      throw limitError(location, limit, value.length, "context");
    }
    throw inputError(`${location} must be a bounded dense array.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = descriptors[index];
    if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw inputError(
        `${location} must be dense and cannot contain accessors or hidden elements.`
      );
    }
  }
  const extraKeys = Reflect.ownKeys(value).filter((key) => {
    if (key === "length") return false;
    return typeof key !== "string" || !/^(0|[1-9][0-9]*)$/u.test(key)
      || Number(key) >= value.length;
  });
  if (extraKeys.length > 0) throw inputError(`${location} contains extra array properties.`);
  return value;
}

function requireIdentifier(value, location) {
  if (typeof value !== "string"
    || value.trim() !== value
    || value.length === 0
    || Buffer.byteLength(value, "utf8") > HARD_LIMITS.pathBytes) {
    throw inputError(`${location} must be a bounded non-empty identifier.`);
  }
  return value;
}

function requireDigest(value, location) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw inputError(`${location} must be a canonical sha256 digest.`);
  }
  return value;
}

function requireModuleStatus(value) {
  if (!["governed", "provisional", "opaque"].includes(value)) {
    throw inputError("Impact owner Module has an invalid status.");
  }
  return value;
}

function readReference(value, keys = ["id", "ref", "module", "contract"]) {
  if (typeof value === "string" && value.trim()) return value.trim();
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  for (const key of keys) {
    if (typeof value[key] === "string" && value[key].trim()) return value[key].trim();
  }
  return null;
}

function consumeWork(budget, amount = 1) {
  budget.workUnits += amount;
  if (budget.workUnits > budget.limits.workUnits) {
    throw limitError("workUnits", budget.limits.workUnits, budget.workUnits, budget.kind);
  }
}

function assertLimit(dimension, observed, limit, kind) {
  if (observed > limit) throw limitError(dimension, limit, observed, kind);
}

function isCanonicalUniqueOrder(values) {
  return new Set(values).size === values.length
    && sameStrings(values, [...values].sort(compareUtf8));
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function compareRelationFacts(left, right) {
  const pathOrder = compareUtf8(left.pathRef ?? "", right.pathRef ?? "");
  if (pathOrder !== 0) return pathOrder;
  return compareUtf8(canonicalSortKey(left), canonicalSortKey(right));
}

function canonicalSortKey(value) {
  return Object.keys(value).sort().map((key) => `${key}\u0000${String(value[key])}`).join("\u0001");
}

function dedupeFacts(values) {
  const seen = new Set();
  return values.filter((value) => {
    const digest = canonicalDigest(value);
    if (seen.has(digest)) return false;
    seen.add(digest);
    return true;
  });
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function uniqueSorted(values) {
  return [...new Set(values)].sort(compareUtf8);
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

function inputError(message, details) {
  const error = new Error(message);
  error.code = "CONTEXT_COMPILATION_INPUT_INVALID";
  error.statusCode = 422;
  if (details !== undefined) error.details = details;
  return error;
}

function limitError(dimension, limit, observed, kind, location) {
  const error = new Error(`Context ${kind} compilation exceeded the ${dimension} limit.`);
  error.code = "CONTEXT_COMPILATION_LIMIT_EXCEEDED";
  error.statusCode = 413;
  error.details = { dimension, limit, observed, ...(location ? { location } : {}) };
  return error;
}
