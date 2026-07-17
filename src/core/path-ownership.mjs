import { types as utilTypes } from "node:util";

import { canonicalDigest, cloneJson } from "./canonical.mjs";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const COMPILED_PRODUCTS = new WeakMap();

const HARD_LIMITS = Object.freeze({
  modules: 2048,
  dispositions: 2048,
  selectorsPerSubject: 1024,
  selectors: 65_536,
  trackedPaths: 65_536,
  moduleRefs: 2048,
  pathRefs: 65_536,
  scopeSelections: 2048,
  scopeSelectors: 65_536,
  projectionBindings: 262_144,
  segmentsPerPath: 256,
  selectorBytes: 4096,
  rationaleBytes: 4096,
  totalPathBytes: 64 * 1024 * 1024,
  dataDepth: 64,
  workUnits: 4_194_304
});

const PATH_GOVERNANCE_KEYS = [
  "conflictResolution",
  "dispositionPolicy",
  "dispositions",
  "effectiveMatch",
  "overlapPolicy",
  "schemaVersion",
  "selectorGrammar"
];
const DISPOSITION_POLICY_KEYS = [
  "allowedKinds",
  "grantsWriteAuthority",
  "minimumRationaleCharacters",
  "requiredFields"
];
const DISPOSITION_KEYS = ["id", "kind", "paths", "rationale"];
const REQUIRED_DISPOSITION_FIELDS = ["id", "kind", "paths.include", "paths.exclude", "rationale"];

export function compileModulePathOwnershipIndex(model, repositoryPathFacts, options = {}) {
  assertPlainRecord(options, "compile options");
  assertAllowedKeys(options, ["limits"], "compile options");
  const limits = resolveLimits(readOwn(options, "limits"), HARD_LIMITS, "compile");
  const budget = createBudget(limits);
  assertFinitePlainData(model, "model", budget);
  assertFinitePlainData(repositoryPathFacts, "repositoryPathFacts", budget);

  const modelGuardDigest = canonicalDigest(model);
  const modelDigest = readModelDigest(model);
  const facts = normalizeTrackedPathFacts(repositoryPathFacts, budget);
  const projectDocument = readOwn(model, "projectDocument");
  const policy = normalizePathGovernance(readOwn(projectDocument, "pathGovernance"), budget);
  const subjects = [
    ...normalizeModuleSubjects(readOwn(model, "modules"), budget),
    ...normalizeDispositionSubjects(policy.dispositions, budget)
  ];
  sortWithBudget(subjects, compareSubjects, budget);
  assertUniqueSubjectRefs(subjects);
  const moduleSubjects = new Map(subjects
    .filter((subject) => subject.kind === "module")
    .map((subject) => [subject.ref, subject]));
  let selectorCount = 0;
  for (const subject of subjects) {
    consumeWork(budget);
    selectorCount += subject.includes.length + subject.excludes.length;
  }
  assertLimit("selectors", selectorCount, limits.selectors);

  assertNoSubjectConflicts(subjects, budget);
  const assignments = new Map();
  const unassigned = [];
  for (const trackedPath of facts.paths) {
    consumeWork(budget);
    const decision = classifyPath(subjects, trackedPath, budget);
    if (!decision) {
      if (unassigned.length < 32) unassigned.push(trackedPath);
      continue;
    }
    assignments.set(trackedPath, decision);
  }
  if (assignments.size !== facts.paths.length) {
    throw ownershipError(
      "MODULE_PATH_OWNERSHIP_INCOMPLETE",
      "Every tracked path requires exactly one Module owner or explicit ungoverned disposition.",
      { unassignedCount: facts.paths.length - assignments.size, unassigned }
    );
  }

  const ownershipPolicyDigest = canonicalDigest({
    schemaVersion: policy.schemaVersion,
    selectorGrammar: policy.selectorGrammar,
    effectiveMatch: policy.effectiveMatch,
    overlapPolicy: policy.overlapPolicy,
    conflictResolution: policy.conflictResolution,
    dispositionPolicy: policy.dispositionPolicy,
    subjects: subjects.map(publicSubject)
  });
  const assignmentDigest = canonicalDigest([...assignments.entries()]);
  const observation = Object.freeze({
    schemaVersion: 1,
    modules: moduleSubjects.size,
    dispositions: subjects.length - moduleSubjects.size,
    selectors: selectorCount,
    selectorsPerSubject: budget.selectorsPerSubject,
    trackedPaths: facts.paths.length,
    segmentsPerPath: budget.segmentsPerPath,
    selectorBytes: budget.selectorBytes,
    rationaleBytes: budget.rationaleBytes,
    totalPathBytes: budget.totalPathBytes,
    dataDepth: budget.dataDepth,
    workUnits: budget.workUnits
  });
  const sourceBinding = {
    schemaVersion: 1,
    modelDigest,
    trackedPathFactsDigest: facts.digest,
    ownershipPolicyDigest,
    assignmentDigest
  };
  const productDigest = canonicalDigest(sourceBinding);
  sourceBinding.productDigest = productDigest;

  const token = Object.freeze(Object.create(null));
  COMPILED_PRODUCTS.set(token, {
    token,
    model,
    repositoryPathFacts,
    modelGuardDigest,
    factsGuardDigest: canonicalDigest(repositoryPathFacts),
    facts,
    subjects,
    moduleSubjects,
    assignments,
    limits,
    sourceBinding: Object.freeze(cloneJson(sourceBinding)),
    observation,
    productDigest
  });
  return token;
}

export function projectCompiledModulePathOwnershipIndex(product, options = {}) {
  if (!product || typeof product !== "object" || utilTypes.isProxy(product)) {
    throw productError("Module path ownership product is absent, malformed, or proxied.");
  }
  const state = COMPILED_PRODUCTS.get(product);
  if (!state || state.token !== product) {
    throw productError("Module path ownership product is forged or serialized.");
  }
  assertPlainRecord(options, "projection options");
  assertAllowedKeys(
    options,
    ["limits", "model", "moduleRefs", "pathRefs", "scopeSelections"],
    "projection options"
  );
  const model = readOwn(options, "model");
  const limits = resolveLimits(readOwn(options, "limits"), state.limits, "projection");
  assertCompiledUsageWithinLimits(state.observation, limits);
  const budget = createBudget(limits);
  assertFinitePlainData(model, "projection.model", budget);
  assertFinitePlainData(state.repositoryPathFacts, "compiled.repositoryPathFacts", budget);
  if (model !== state.model || canonicalDigest(model) !== state.modelGuardDigest) {
    throw productError("Module path ownership product does not match the exact unchanged Model.");
  }
  if (canonicalDigest(state.repositoryPathFacts) !== state.factsGuardDigest
    || canonicalDigest({
      schemaVersion: state.repositoryPathFacts.schemaVersion,
      paths: state.repositoryPathFacts.paths
    }) !== state.repositoryPathFacts.digest) {
    throw productError("Module path ownership product tracked-path facts have drifted.");
  }
  if (canonicalDigest(omitProductDigest(state.sourceBinding)) !== state.productDigest) {
    throw productError("Module path ownership product state is inconsistent.");
  }

  const moduleRefs = normalizeRequestedRefs(
    readOwn(options, "moduleRefs"),
    "moduleRefs",
    limits.moduleRefs,
    budget
  );
  const pathRefs = normalizeRequestedPaths(readOwn(options, "pathRefs"), limits.pathRefs, budget);
  const scopeSelections = normalizeScopeSelections(
    readOwn(options, "scopeSelections"),
    limits,
    budget
  );
  const unknownModuleRefs = moduleRefs.filter((moduleRef) => !state.moduleSubjects.has(moduleRef));
  const unknownSelectionModuleRefs = scopeSelections
    .map((selection) => selection.moduleRef)
    .filter((moduleRef) => !state.moduleSubjects.has(moduleRef));
  if (unknownModuleRefs.length > 0 || unknownSelectionModuleRefs.length > 0) {
    const unknownRefs = [...new Set([...unknownModuleRefs, ...unknownSelectionModuleRefs])]
      .sort(compareUtf8);
    throw projectionError("Projection references unknown Modules.", {
      unknownModuleRefCount: unknownRefs.length,
      unknownModuleRefs: unknownRefs.slice(0, 32)
    });
  }
  const projectionBindings = (moduleRefs.length + scopeSelections.length) * pathRefs.length;
  assertLimit(
    "projectionBindings",
    projectionBindings,
    limits.projectionBindings
  );

  const writeScopesByModule = new Map();
  const pathDecisionsByModule = new Map();
  const scopeBindingsBySelection = new Map();
  const writeDecisionsBySelection = new Map();
  const authoritativeDecisions = new Map();
  for (const pathRef of pathRefs) {
    consumeWork(budget);
    authoritativeDecisions.set(
      pathRef,
      state.assignments.has(pathRef)
        ? state.assignments.get(pathRef)
        : classifyPath(state.subjects, pathRef, budget)
    );
  }
  for (const moduleRef of moduleRefs) {
    consumeWork(budget);
    const subject = state.moduleSubjects.get(moduleRef);
    const scope = {
      include: projectSelectorDisplays(subject.includes, budget),
      exclude: projectSelectorDisplays(subject.excludes, budget)
    };
    writeScopesByModule.set(moduleRef, {
      ...scope,
      digest: canonicalDigest(scope)
    });
    const decisions = new Map();
    for (const pathRef of pathRefs) {
      consumeWork(budget);
      const decision = authoritativeDecisions.get(pathRef);
      decisions.set(pathRef, projectPathDecision(decision, moduleRef));
    }
    pathDecisionsByModule.set(moduleRef, decisions);
  }
  for (const selection of scopeSelections) {
    consumeWork(budget);
    const authoritativeSubject = state.moduleSubjects.get(selection.moduleRef);
    const effectiveSelection = compileEffectiveScopeSelection(
      selection,
      authoritativeSubject,
      budget
    );
    const authoritativeScope = {
      include: projectSelectorDisplays(authoritativeSubject.includes, budget),
      exclude: projectSelectorDisplays(authoritativeSubject.excludes, budget)
    };
    scopeBindingsBySelection.set(selection.id, {
      schemaVersion: 1,
      selectionId: selection.id,
      moduleRef: selection.moduleRef,
      authoritativeScopeDigest: canonicalDigest(authoritativeScope),
      requestScopeDigest: selection.requestScopeDigest,
      effectiveScope: cloneJson(effectiveSelection.scope),
      effectiveScopeDigest: effectiveSelection.digest
    });
    const decisions = new Map();
    for (const pathRef of pathRefs) {
      consumeWork(budget);
      const ownershipDecision = projectPathDecision(
        authoritativeDecisions.get(pathRef),
        selection.moduleRef
      );
      const scopeAllowsWrite = someSelectorMatches(effectiveSelection.includes, pathRef, budget)
        && !someSelectorMatches(effectiveSelection.excludes, pathRef, budget);
      decisions.set(pathRef, {
        ...ownershipDecision,
        scopeAllowsWrite,
        writeAllowed: ownershipDecision.ownershipAllowsWrite && scopeAllowsWrite
      });
    }
    writeDecisionsBySelection.set(selection.id, decisions);
  }

  return {
    sourceBinding: cloneJson(state.sourceBinding),
    writeScopesByModule,
    pathDecisionsByModule,
    scopeBindingsBySelection,
    writeDecisionsBySelection,
    observation: {
      schemaVersion: 1,
      moduleRefs: moduleRefs.length,
      pathRefs: pathRefs.length,
      scopeSelections: scopeSelections.length,
      bindings: projectionBindings,
      workUnits: budget.workUnits
    }
  };
}

export function pathSelectorWithin(candidateValue, parentValue) {
  try {
    const candidate = normalizeSelector(candidateValue, "candidate", null);
    const parent = normalizeSelector(parentValue, "parent", null);
    return selectorCovers(parent, candidate);
  } catch {
    return false;
  }
}

function normalizeTrackedPathFacts(value, budget) {
  assertExactKeys(value, ["digest", "paths", "schemaVersion"], "repositoryPathFacts");
  if (value.schemaVersion !== 1 || !DIGEST_PATTERN.test(value.digest ?? "")) {
    throw inputError("Tracked path facts require schemaVersion 1 and a canonical digest.");
  }
  const paths = normalizeDenseStringList(
    value.paths,
    "repositoryPathFacts.paths",
    budget.limits.trackedPaths,
    budget,
    normalizeConcretePath
  );
  const sorted = [...paths];
  sortWithBudget(sorted, compareUtf8, budget);
  if (paths.some((pathRef, index) => pathRef !== sorted[index])) {
    throw inputError("Tracked path facts must use canonical UTF-8 byte ordering.");
  }
  const digest = canonicalDigest({ schemaVersion: 1, paths });
  if (digest !== value.digest) {
    throw inputError("Tracked path facts digest does not match their exact content.");
  }
  return { schemaVersion: 1, paths, digest };
}

function normalizePathGovernance(value, budget) {
  assertPlainRecord(value, "projectDocument.pathGovernance");
  assertExactKeys(value, PATH_GOVERNANCE_KEYS, "projectDocument.pathGovernance");
  if (value.schemaVersion !== 1
    || value.selectorGrammar !== "exact-or-recursive-prefix"
    || value.effectiveMatch !== "include-minus-exclude"
    || value.overlapPolicy !== "reject-latent-and-concrete"
    || value.conflictResolution !== "none") {
    throw inputError("Path governance policy does not match the frozen LGT-011 grammar.");
  }
  assertPlainRecord(value.dispositionPolicy, "pathGovernance.dispositionPolicy");
  assertExactKeys(value.dispositionPolicy, DISPOSITION_POLICY_KEYS, "pathGovernance.dispositionPolicy");
  if (canonicalDigest(value.dispositionPolicy.allowedKinds) !== canonicalDigest(["ungoverned"])
    || canonicalDigest(value.dispositionPolicy.requiredFields) !== canonicalDigest(REQUIRED_DISPOSITION_FIELDS)
    || value.dispositionPolicy.minimumRationaleCharacters !== 12
    || value.dispositionPolicy.grantsWriteAuthority !== false) {
    throw inputError("Path disposition policy does not match the frozen LGT-011 schema.");
  }
  assertDenseArray(value.dispositions, "pathGovernance.dispositions", budget.limits.dispositions);
  return value;
}

function normalizeModuleSubjects(modules, budget) {
  assertDenseArray(modules, "model.modules", budget.limits.modules);
  return modules.map((module, index) => {
    consumeWork(budget);
    assertPlainRecord(module, `model.modules[${index}]`);
    const ref = requireBoundedString(
      readOwn(module, "id"),
      `model.modules[${index}].id`,
      budget.limits.selectorBytes
    );
    observeTextUsage(budget, "selectorBytes", ref);
    return normalizeSubject({
      kind: "module",
      ref,
      paths: readOwn(module, "paths"),
      location: `model.modules[${index}].paths`
    }, budget);
  });
}

function normalizeDispositionSubjects(dispositions, budget) {
  return dispositions.map((disposition, index) => {
    consumeWork(budget);
    const location = `pathGovernance.dispositions[${index}]`;
    assertPlainRecord(disposition, location);
    assertExactKeys(disposition, DISPOSITION_KEYS, location);
    const ref = requireBoundedString(disposition.id, `${location}.id`, budget.limits.selectorBytes);
    observeTextUsage(budget, "selectorBytes", ref);
    if (disposition.kind !== "ungoverned") {
      throw inputError(`${location}.kind must be ungoverned.`);
    }
    const rationale = requireBoundedString(
      disposition.rationale,
      `${location}.rationale`,
      budget.limits.rationaleBytes
    );
    observeTextUsage(budget, "rationaleBytes", rationale);
    if ([...rationale.trim()].length < 12) {
      throw inputError(`${location}.rationale must be substantive.`);
    }
    return normalizeSubject({
      kind: "disposition",
      ref,
      paths: disposition.paths,
      location: `${location}.paths`
    }, budget);
  });
}

function normalizeSubject({ kind, ref, paths, location }, budget) {
  assertPlainRecord(paths, location);
  assertExactKeys(paths, ["exclude", "include"], location);
  const includes = normalizeSelectorList(paths.include, `${location}.include`, budget);
  const excludes = normalizeSelectorList(paths.exclude, `${location}.exclude`, budget);
  budget.selectorsPerSubject = Math.max(
    budget.selectorsPerSubject,
    includes.length,
    excludes.length
  );
  return {
    kind,
    ref,
    includes: minimizeSelectors(includes, budget),
    excludes: minimizeSelectors(excludes, budget)
  };
}

function normalizeSelectorList(value, location, budget) {
  return normalizeDenseStringList(
    value,
    location,
    budget.limits.selectorsPerSubject,
    budget,
    (selector, itemLocation) => normalizeSelector(selector, itemLocation, budget)
  );
}

function normalizeSelector(value, location, budget) {
  const display = requireBoundedString(value, location, budget?.limits.selectorBytes ?? 4096);
  if (budget) {
    consumePathBytes(budget, display);
    observeTextUsage(budget, "selectorBytes", display);
  }
  if (display === "**") return { kind: "prefix", base: "", display };
  if (display.endsWith("/**")) {
    const base = display.slice(0, -3);
    if (/[*?[\]]/u.test(base)) {
      throw inputError(`${location} uses unsupported wildcard syntax.`);
    }
    assertCanonicalSelectorPath(base, location, budget);
    return { kind: "prefix", base, display };
  }
  if (/[*?[\]]/u.test(display)) {
    throw inputError(`${location} uses unsupported wildcard syntax.`);
  }
  assertCanonicalSelectorPath(display, location, budget);
  return { kind: "exact", base: display, display };
}

function assertCanonicalSelectorPath(value, location, budget) {
  const normalized = normalizeConcretePath(value, location, budget);
  if (normalized.includes("\\") || /[\u0000-\u001f\u007f]/u.test(normalized)) {
    throw inputError(`${location} is not a portable canonical selector.`);
  }
}

function normalizeConcretePath(value, location, budget) {
  const pathRef = requireBoundedString(value, location, budget?.limits.selectorBytes ?? 4096);
  if (budget) {
    consumePathBytes(budget, pathRef);
    observeTextUsage(budget, "selectorBytes", pathRef);
  }
  const segments = pathRef.split("/");
  if (budget) budget.segmentsPerPath = Math.max(budget.segmentsPerPath, segments.length);
  if (!pathRef.isWellFormed()
    || pathRef.includes("\uFFFD")
    || pathRef.startsWith("/")
    || pathRef.startsWith("./")
    || /^[A-Za-z]:\//u.test(pathRef)
    || pathRef.startsWith("\\\\")
    || pathRef.endsWith("/")
    || segments.length > (budget?.limits.segmentsPerPath ?? 256)
    || segments.some((segment) => !segment || segment === "." || segment === "..")) {
    throw inputError(`${location} is not a canonical repository-relative path.`);
  }
  return pathRef;
}

function assertNoSubjectConflicts(subjects, budget) {
  for (let leftIndex = 0; leftIndex < subjects.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < subjects.length; rightIndex += 1) {
      consumeWork(budget);
      const left = subjects[leftIndex];
      const right = subjects[rightIndex];
      for (const leftInclude of left.includes) {
        for (const rightInclude of right.includes) {
          consumeWork(budget);
          const domain = selectorIntersection(leftInclude, rightInclude);
          if (!domain) continue;
          if (someSelectorCovers(left.excludes, domain, budget)
            || someSelectorCovers(right.excludes, domain, budget)) {
            continue;
          }
          throw ownershipError(
            "MODULE_PATH_OWNERSHIP_CONFLICT",
            "Module path ownership subjects have an overlapping effective domain.",
            {
              conflict: domain.kind === "exact" ? "concrete" : "latent",
              relation: conflictRelation(left, right),
              left: publicSubjectIdentity(left),
              right: publicSubjectIdentity(right),
              domain: { kind: domain.kind, selector: domain.display }
            }
          );
        }
      }
    }
  }
}

function classifyPath(subjects, pathRef, budget) {
  const matches = [];
  for (const subject of subjects) {
    consumeWork(budget);
    if (someSelectorMatches(subject.includes, pathRef, budget)
      && !someSelectorMatches(subject.excludes, pathRef, budget)) {
      matches.push(subject);
      if (matches.length > 1) {
        throw ownershipError(
          "MODULE_PATH_OWNERSHIP_CONFLICT",
          "A concrete path resolves to more than one ownership subject.",
          {
            conflict: "concrete",
            relation: conflictRelation(matches[0], matches[1]),
            left: publicSubjectIdentity(matches[0]),
            right: publicSubjectIdentity(matches[1]),
            domain: { kind: "exact", selector: pathRef }
          }
        );
      }
    }
  }
  if (matches.length === 0) return null;
  const subject = matches[0];
  return Object.freeze({
    kind: subject.kind === "module" ? "module-owner" : "ungoverned-disposition",
    ownerModuleRef: subject.kind === "module" ? subject.ref : null,
    dispositionRef: subject.kind === "disposition" ? subject.ref : null
  });
}

function projectPathDecision(decision, requestedModuleRef) {
  if (!decision) {
    return {
      classification: "unassigned",
      ownershipAllowsWrite: false,
      ownerModuleRef: null,
      dispositionRef: null
    };
  }
  if (decision.kind === "ungoverned-disposition") {
    return {
      classification: "ungoverned-disposition",
      ownershipAllowsWrite: false,
      ownerModuleRef: null,
      dispositionRef: decision.dispositionRef
    };
  }
  return {
    classification: decision.ownerModuleRef === requestedModuleRef
      ? "owned-by-requested-module"
      : "owned-by-other-module",
    ownershipAllowsWrite: decision.ownerModuleRef === requestedModuleRef,
    ownerModuleRef: decision.ownerModuleRef,
    dispositionRef: null
  };
}

function normalizeScopeSelections(value, limits, budget) {
  assertDenseArray(value ?? [], "scopeSelections", limits.scopeSelections);
  const seen = new Set();
  let selectorCount = 0;
  const selections = (value ?? []).map((selection, index) => {
    consumeWork(budget);
    const location = `scopeSelections[${index}]`;
    assertExactKeys(
      selection,
      ["expectedScopeDigest", "id", "moduleRef", "scope"],
      location
    );
    const id = requireBoundedString(selection.id, `${location}.id`, limits.selectorBytes);
    const moduleRef = requireBoundedString(
      selection.moduleRef,
      `${location}.moduleRef`,
      limits.selectorBytes
    );
    if (seen.has(id)) throw projectionError("Scope selection ids must be unique.", { id });
    seen.add(id);
    if (!DIGEST_PATTERN.test(selection.expectedScopeDigest ?? "")) {
      throw projectionError("Scope selection requires a canonical request scope digest.", {
        selectionId: id
      });
    }
    assertFinitePlainData(selection.scope, `${location}.scope`, budget);
    const requestScopeDigest = canonicalDigest(selection.scope);
    if (requestScopeDigest !== selection.expectedScopeDigest) {
      throw projectionError("Scope selection digest does not match its exact request scope.", {
        selectionId: id,
        expectedScopeDigest: selection.expectedScopeDigest,
        observedScopeDigest: requestScopeDigest
      });
    }
    const request = normalizeScopeRequest(selection.scope, `${location}.scope`, budget);
    selectorCount += (request.includes?.length ?? 0) + request.excludes.length;
    assertLimit("scopeSelectors", selectorCount, limits.scopeSelectors);
    return {
      id,
      moduleRef,
      request,
      requestScopeDigest
    };
  });
  return sortWithBudget(selections, (left, right) => compareUtf8(left.id, right.id), budget);
}

function normalizeScopeRequest(value, location, budget) {
  if (value === null) return { includes: null, excludes: [] };
  if (typeof value === "string" || Array.isArray(value)) {
    return {
      includes: normalizeSelectorInput(value, `${location}.include`, budget),
      excludes: []
    };
  }
  assertPlainRecord(value, location);
  assertAllowedKeys(value, ["exclude", "include"], location);
  return {
    includes: readOwn(value, "include") === undefined
      ? null
      : normalizeSelectorInput(readOwn(value, "include"), `${location}.include`, budget),
    excludes: readOwn(value, "exclude") === undefined
      ? []
      : normalizeSelectorInput(readOwn(value, "exclude"), `${location}.exclude`, budget)
  };
}

function normalizeSelectorInput(value, location, budget) {
  const values = typeof value === "string" ? [value] : value;
  return minimizeSelectors(normalizeSelectorList(values, location, budget), budget);
}

function compileEffectiveScopeSelection(selection, authoritativeSubject, budget) {
  const includes = selection.request.includes ?? authoritativeSubject.includes;
  const outsideIncludes = includes.filter((candidate) => (
    !someSelectorCovers(authoritativeSubject.includes, candidate, budget)
  ));
  if (outsideIncludes.length > 0) {
    throw projectionError("Scope selection may only narrow the authoritative Module scope.", {
      selectionId: selection.id,
      moduleRef: selection.moduleRef,
      outsideIncludes: outsideIncludes.map((selector) => selector.display).slice(0, 32)
    });
  }
  const excludes = minimizeSelectors(uniqueSelectors([
    ...authoritativeSubject.excludes,
    ...selection.request.excludes
  ]), budget);
  const scope = {
    include: projectSelectorDisplays(includes, budget),
    exclude: projectSelectorDisplays(excludes, budget)
  };
  return {
    includes,
    excludes,
    scope,
    digest: canonicalDigest(scope)
  };
}

function uniqueSelectors(selectors) {
  return [...new Map(selectors.map((selector) => [selector.display, selector])).values()];
}

function selectorIntersection(left, right) {
  if (left.kind === "exact" && right.kind === "exact") {
    return left.base === right.base ? left : null;
  }
  if (left.kind === "exact") return selectorMatches(right, left.base) ? left : null;
  if (right.kind === "exact") return selectorMatches(left, right.base) ? right : null;
  if (left.base === "") return right;
  if (right.base === "") return left;
  if (left.base === right.base) return left;
  if (left.base.startsWith(`${right.base}/`)) return left;
  if (right.base.startsWith(`${left.base}/`)) return right;
  return null;
}

function selectorCovers(cover, domain) {
  if (domain.kind === "exact") return selectorMatches(cover, domain.base);
  if (cover.kind === "exact") return false;
  return cover.base === ""
    || cover.base === domain.base
    || domain.base.startsWith(`${cover.base}/`);
}

function selectorMatches(selector, pathRef) {
  if (selector.kind === "exact") return selector.base === pathRef;
  return selector.base === "" || pathRef.startsWith(`${selector.base}/`);
}

function someSelectorCovers(selectors, domain, budget) {
  for (const selector of selectors) {
    consumeWork(budget);
    if (selectorCovers(selector, domain)) return true;
  }
  return false;
}

function someSelectorMatches(selectors, pathRef, budget) {
  for (const selector of selectors) {
    consumeWork(budget);
    if (selectorMatches(selector, pathRef)) return true;
  }
  return false;
}

function projectSelectorDisplays(selectors, budget) {
  const displays = [];
  for (const selector of selectors) {
    consumeWork(budget);
    displays.push(selector.display);
  }
  return displays;
}

function minimizeSelectors(selectors, budget) {
  const minimal = [];
  for (let index = 0; index < selectors.length; index += 1) {
    let covered = false;
    for (let otherIndex = 0; otherIndex < selectors.length; otherIndex += 1) {
      consumeWork(budget);
      if (index !== otherIndex && selectorCovers(selectors[otherIndex], selectors[index])) {
        covered = true;
        break;
      }
    }
    if (!covered) minimal.push(selectors[index]);
  }
  return sortWithBudget(minimal, compareSelectors, budget);
}

function normalizeRequestedRefs(value, location, limit, budget) {
  const refs = normalizeDenseStringList(value ?? [], location, limit, budget, (item, itemLocation) => (
    requireBoundedString(item, itemLocation, budget.limits.selectorBytes)
  ));
  return sortWithBudget(refs, compareUtf8, budget);
}

function normalizeRequestedPaths(value, limit, budget) {
  const paths = normalizeDenseStringList(
    value ?? [],
    "pathRefs",
    limit,
    budget,
    normalizeConcretePath
  );
  return sortWithBudget(paths, compareUtf8, budget);
}

function normalizeDenseStringList(value, location, limit, budget, normalizeItem) {
  assertDenseArray(value, location, limit);
  const seen = new Set();
  return value.map((item, index) => {
    consumeWork(budget);
    const normalized = normalizeItem(item, `${location}[${index}]`, budget);
    const identity = typeof normalized === "string" ? normalized : normalized.display;
    if (seen.has(identity)) throw inputError(`${location} contains a duplicate value: ${identity}.`);
    seen.add(identity);
    return normalized;
  });
}

function assertDenseArray(value, location, limit) {
  if (!Array.isArray(value) || utilTypes.isProxy(value) || value.length > limit) {
    if (Array.isArray(value) && value.length > limit) {
      throw limitError(location, limit, value.length);
    }
    throw inputError(`${location} must be a dense bounded array.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) throw inputError(`${location} must not contain sparse entries.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0
    || Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)
    || Object.entries(descriptors).some(([key, descriptor]) => key !== "length" && !descriptor.enumerable)
    || Object.getOwnPropertyNames(value).some((key) => key !== "length"
      && (!/^(0|[1-9][0-9]*)$/u.test(key)
      || Number(key) >= value.length))) {
    throw inputError(`${location} must not contain accessors, symbols, or extra properties.`);
  }
}

function assertFinitePlainData(value, location, budget, depth = 0) {
  consumeWork(budget);
  if (depth > budget.limits.dataDepth) throw limitError("dataDepth", budget.limits.dataDepth, depth);
  budget.dataDepth = Math.max(budget.dataDepth, depth);
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw inputError(`${location} contains a non-finite number.`);
    return;
  }
  if (typeof value === "string") {
    consumePathBytes(budget, value);
    return;
  }
  if (!value || typeof value !== "object" || utilTypes.isProxy(value)) {
    throw inputError(`${location} must contain only finite plain data.`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== Array.prototype && prototype !== null) {
    throw inputError(`${location} must contain only plain objects and arrays.`);
  }
  const ownNames = Object.getOwnPropertyNames(value);
  consumeWork(budget, ownNames.length);
  for (const key of ownNames) consumePathBytes(budget, key);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0
    || Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)
    || Object.entries(descriptors).some(([key, descriptor]) => (
      key !== "length" && !descriptor.enumerable
    ))) {
    throw inputError(`${location} must not contain accessors, symbol keys, or non-enumerable data.`);
  }
  if (Array.isArray(value)) assertDenseArray(value, location, Number.MAX_SAFE_INTEGER);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key === "length") continue;
    assertFinitePlainData(descriptor.value, `${location}.${key}`, budget, depth + 1);
  }
}

function assertPlainRecord(value, location) {
  if (!value || typeof value !== "object" || Array.isArray(value) || utilTypes.isProxy(value)
    || (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
    throw inputError(`${location} must be a plain object.`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Object.getOwnPropertySymbols(value).length > 0
    || Object.values(descriptors).some((descriptor) => descriptor.get || descriptor.set)
    || Object.values(descriptors).some((descriptor) => !descriptor.enumerable)) {
    throw inputError(`${location} must not contain accessors, symbol keys, or non-enumerable data.`);
  }
}

function assertExactKeys(value, expected, location) {
  assertPlainRecord(value, location);
  const observed = Object.getOwnPropertyNames(value).sort();
  const exact = [...expected].sort();
  if (canonicalDigest(observed) !== canonicalDigest(exact)) {
    throw inputError(`${location} must contain exactly: ${exact.join(", ")}.`);
  }
}

function assertAllowedKeys(value, allowed, location) {
  assertPlainRecord(value, location);
  const unknown = Object.getOwnPropertyNames(value).filter((key) => !allowed.includes(key));
  if (unknown.length > 0) throw inputError(`${location} contains unsupported fields: ${unknown.sort().join(", ")}.`);
}

function resolveLimits(value, ceilings, label) {
  if (value === undefined || value === null) return { ...ceilings };
  assertPlainRecord(value, `${label}.limits`);
  const limits = { ...ceilings };
  for (const [dimension, requested] of Object.entries(value)) {
    if (!Object.hasOwn(ceilings, dimension)
      || !Number.isSafeInteger(requested)
      || requested <= 0
      || requested > ceilings[dimension]) {
      throw ownershipError(
        "MODULE_PATH_OWNERSHIP_LIMIT_INVALID",
        `${label} ownership limits may only tighten known positive hard ceilings.`,
        { dimension, requested, ceiling: ceilings[dimension] ?? null }
      );
    }
    limits[dimension] = requested;
  }
  return limits;
}

function createBudget(limits) {
  return {
    limits,
    workUnits: 0,
    totalPathBytes: 0,
    selectorsPerSubject: 0,
    segmentsPerPath: 0,
    selectorBytes: 0,
    rationaleBytes: 0,
    dataDepth: 0
  };
}

function consumeWork(budget, units = 1) {
  budget.workUnits += units;
  assertLimit("workUnits", budget.workUnits, budget.limits.workUnits);
}

function consumePathBytes(budget, value) {
  budget.totalPathBytes += Buffer.byteLength(value, "utf8");
  assertLimit("totalPathBytes", budget.totalPathBytes, budget.limits.totalPathBytes);
}

function observeTextUsage(budget, dimension, value) {
  budget[dimension] = Math.max(budget[dimension], Buffer.byteLength(value, "utf8"));
}

function assertLimit(dimension, observed, limit) {
  if (observed > limit) throw limitError(dimension, limit, observed);
}

function assertCompiledUsageWithinLimits(observation, limits) {
  for (const dimension of [
    "modules",
    "dispositions",
    "selectors",
    "selectorsPerSubject",
    "trackedPaths",
    "segmentsPerPath",
    "selectorBytes",
    "rationaleBytes",
    "totalPathBytes",
    "dataDepth",
    "workUnits"
  ]) {
    assertLimit(dimension, observation[dimension], limits[dimension]);
  }
}

function requireBoundedString(value, location, limit) {
  if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > limit) {
    if (typeof value === "string" && Buffer.byteLength(value, "utf8") > limit) {
      throw limitError(location, limit, Buffer.byteLength(value, "utf8"));
    }
    throw inputError(`${location} must be a non-empty bounded string.`);
  }
  return value;
}

function assertUniqueSubjectRefs(subjects) {
  const seen = new Set();
  for (const subject of subjects) {
    if (seen.has(subject.ref)) throw inputError(`Ownership subject id is duplicated: ${subject.ref}.`);
    seen.add(subject.ref);
  }
}

function readModelDigest(model) {
  const digest = readOwn(model, "modelDigest") ?? readOwn(model, "digest");
  return DIGEST_PATTERN.test(digest ?? "") ? digest : canonicalDigest(model);
}

function readOwn(value, key) {
  return value && typeof value === "object" && Object.hasOwn(value, key)
    ? value[key]
    : undefined;
}

function publicSubject(subject) {
  return {
    ...publicSubjectIdentity(subject),
    include: subject.includes.map((selector) => selector.display),
    exclude: subject.excludes.map((selector) => selector.display)
  };
}

function publicSubjectIdentity(subject) {
  return { kind: subject.kind, ref: subject.ref };
}

function conflictRelation(left, right) {
  if (left.kind === "module" && right.kind === "module") return "owner-owner";
  if (left.kind === "disposition" && right.kind === "disposition") return "disposition-disposition";
  return "owner-disposition";
}

function compareSubjects(left, right) {
  return compareUtf8(left.kind, right.kind) || compareUtf8(left.ref, right.ref);
}

function compareSelectors(left, right) {
  return compareUtf8(left.display, right.display) || compareUtf8(left.kind, right.kind);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function sortWithBudget(values, compare, budget) {
  values.sort((left, right) => {
    consumeWork(budget);
    return compare(left, right);
  });
  return values;
}

function omitProductDigest(binding) {
  const { productDigest: _productDigest, ...sourceBinding } = binding;
  return sourceBinding;
}

function inputError(message, details) {
  return ownershipError("MODULE_PATH_OWNERSHIP_INPUT_INVALID", message, details);
}

function productError(message, details) {
  return ownershipError("MODULE_PATH_OWNERSHIP_PRODUCT_INVALID", message, details);
}

function projectionError(message, details) {
  return ownershipError("MODULE_PATH_OWNERSHIP_PROJECTION_INVALID", message, details);
}

function limitError(dimension, limit, observed) {
  return ownershipError(
    "MODULE_PATH_OWNERSHIP_LIMIT_EXCEEDED",
    `Module path ownership exceeded the ${dimension} limit.`,
    { dimension, limit, observed },
    413
  );
}

function ownershipError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details !== undefined) error.details = details;
  return error;
}
