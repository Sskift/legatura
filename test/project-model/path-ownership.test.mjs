import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileChangeAgainstGovernance } from "../../src/core/change-compiler.mjs";
import {
  compileModulePathOwnershipIndex,
  loadProjectModel,
  validateProjectModel,
  projectCompiledModulePathOwnershipIndex
} from "../../src/core/project-model.mjs";

const execFileAsync = promisify(execFile);
const BROWNFIELD_REFERENCE_ROOT = path.resolve(
  import.meta.dirname,
  "../../examples/brownfield-app-apk-relay"
);

test("the ownership product binds exact sources and projects total, narrowed write decisions", () => {
  const { model, facts } = ownershipFixture();
  const product = compileModulePathOwnershipIndex(model, facts);
  const projection = projectCompiledModulePathOwnershipIndex(product, {
    model,
    moduleRefs: ["core"],
    pathRefs: facts.paths
  });

  const { productDigest, ...sourceWithoutProductDigest } = projection.sourceBinding;
  assert.deepEqual(
    {
      modelDigest: projection.sourceBinding.modelDigest,
      trackedPathFactsDigest: projection.sourceBinding.trackedPathFactsDigest,
      productDigest
    },
    {
      modelDigest: model.modelDigest,
      trackedPathFactsDigest: facts.digest,
      productDigest: canonicalDigest(sourceWithoutProductDigest)
    }
  );
  assert.deepEqual(
    facts.paths.map((pathRef) => [
      pathRef,
      projection.pathDecisionsByModule.get("core").get(pathRef).classification
    ]),
    [
      ["docs/legacy/readme.md", "ungoverned-disposition"],
      ["src/core/feature/inside.mjs", "owned-by-requested-module"],
      ["src/core/index.mjs", "owned-by-requested-module"],
      ["src/other/index.mjs", "owned-by-other-module"]
    ]
  );
  assert.equal(JSON.stringify(product), "{}");
  assert.deepEqual(JSON.parse(JSON.stringify(product)), {});

  const compiled = compileChangeAgainstGovernance(
    syntheticChange({ include: ["src/core/feature/**"] }),
    model,
    { modulePathOwnershipProduct: product }
  );
  const compiledBinding = compiled.contextCapsule.compiledFrom.pathOwnership;
  const authoritativeScope = projection.writeScopesByModule.get("core");
  assert.deepEqual(compiled.contextCapsule.scope.write, {
    include: ["src/core/feature/**"],
    exclude: ["src/core/generated/**"]
  });
  assert.deepEqual(compiledBinding, {
    ...projection.sourceBinding,
    scopeDigest: authoritativeScope.digest,
    effectiveScopeDigest: canonicalDigest(compiled.contextCapsule.scope.write)
  });
  assert.equal(JSON.stringify(compiledBinding).includes("src/core/index.mjs"), false);

  const effectiveProjection = projectCompiledModulePathOwnershipIndex(product, {
    model,
    moduleRefs: ["core"],
    pathRefs: [
      "docs/legacy/readme.md",
      "src/core/feature/prospective.mjs",
      "src/core/outside.mjs",
      "src/other/index.mjs",
      "unassigned/prospective.mjs"
    ],
    scopeSelections: [{
      id: "compiled-context-write",
      moduleRef: "core",
      scope: compiled.contextCapsule.scope.write,
      expectedScopeDigest: compiledBinding.effectiveScopeDigest
    }]
  });
  const decisions = effectiveProjection.writeDecisionsBySelection.get("compiled-context-write");
  assert.deepEqual(
    [...decisions.entries()].map(([pathRef, decision]) => [
      pathRef,
      decision.classification,
      decision.ownershipAllowsWrite,
      decision.scopeAllowsWrite,
      decision.writeAllowed
    ]),
    [
      ["docs/legacy/readme.md", "ungoverned-disposition", false, false, false],
      ["src/core/feature/prospective.mjs", "owned-by-requested-module", true, true, true],
      ["src/core/outside.mjs", "owned-by-requested-module", true, false, false],
      ["src/other/index.mjs", "owned-by-other-module", false, false, false],
      ["unassigned/prospective.mjs", "unassigned", false, false, false]
    ]
  );
  assert.deepEqual(
    effectiveProjection.scopeBindingsBySelection.get("compiled-context-write"),
    {
      schemaVersion: 1,
      selectionId: "compiled-context-write",
      moduleRef: "core",
      authoritativeScopeDigest: authoritativeScope.digest,
      requestScopeDigest: compiledBinding.effectiveScopeDigest,
      effectiveScope: compiled.contextCapsule.scope.write,
      effectiveScopeDigest: compiledBinding.effectiveScopeDigest
    }
  );

  const brownfield = rebindModelDigests(model, (draft) => {
    delete draft.projectDocument.pathGovernance;
  });
  const legacyCompiled = compileChangeAgainstGovernance(syntheticChange(), brownfield);
  assert.equal(
    Object.hasOwn(legacyCompiled.contextCapsule.compiledFrom, "pathOwnership"),
    false
  );
});

test("ownership and governed Context attacks fail closed at the product seam", () => {
  const attacks = [
    {
      name: "unassigned tracked path",
      code: "MODULE_PATH_OWNERSHIP_INCOMPLETE",
      run() {
        const { model, facts } = ownershipFixture();
        facts.paths.push("unassigned/file.mjs");
        facts.digest = factsDigest(facts.paths);
        return compileModulePathOwnershipIndex(model, facts);
      }
    },
    ...[
      {
        name: "latent owner-owner overlap",
        relation: "owner-owner",
        mutate(model) {
          model.modules[1].paths.include = ["src/core/feature/**"];
        }
      },
      {
        name: "owner-disposition overlap",
        relation: "owner-disposition",
        mutate(model) {
          model.projectDocument.pathGovernance.dispositions[0].paths.include =
            ["src/core/feature/**"];
        }
      },
      {
        name: "disposition-disposition overlap",
        relation: "disposition-disposition",
        mutate(model) {
          model.projectDocument.pathGovernance.dispositions.push({
            id: "nested-legacy",
            kind: "ungoverned",
            paths: { include: ["docs/legacy/nested/**"], exclude: [] },
            rationale: "Nested legacy files remain explicitly outside write authority."
          });
        }
      }
    ].map(({ name, relation, mutate }) => ({
      name,
      code: "MODULE_PATH_OWNERSHIP_CONFLICT",
      relation,
      run() {
        const { model, facts } = ownershipFixture();
        mutate(model);
        return compileModulePathOwnershipIndex(model, facts);
      }
    })),
    ...[
      ["absolute selector", "/absolute/**"],
      ["parent selector", "../escape/**"],
      ["NUL selector", "src/\u0000bad/**"],
      ["unsupported wildcard selector", "src/core/*"]
    ].map(([name, selector]) => ({
      name,
      mutate(model) {
        model.modules[0].paths.include = [selector];
      }
    })).concat([
      {
        name: "malformed disposition",
        mutate(model) {
          model.projectDocument.pathGovernance.dispositions[0].rationale = "too short";
        }
      }
    ]).map(({ name, mutate }) => ({
      name,
      code: "MODULE_PATH_OWNERSHIP_INPUT_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        mutate(model);
        return compileModulePathOwnershipIndex(model, facts);
      }
    })),
    {
      name: "forged product",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID",
      run() {
        const { model } = ownershipFixture();
        return projectCompiledModulePathOwnershipIndex({}, { model });
      }
    },
    {
      name: "serialized product",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        return projectCompiledModulePathOwnershipIndex(
          JSON.parse(JSON.stringify(product)),
          { model }
        );
      }
    },
    {
      name: "product used with a different Model object",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        return projectCompiledModulePathOwnershipIndex(product, {
          model: structuredClone(model)
        });
      }
    },
    {
      name: "product used after tracked facts drift",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        facts.paths.push("src/core/drift.mjs");
        return projectCompiledModulePathOwnershipIndex(product, { model });
      }
    },
    {
      name: "product reused under a tighter limit than its observation",
      code: "MODULE_PATH_OWNERSHIP_LIMIT_EXCEEDED",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        return projectCompiledModulePathOwnershipIndex(product, {
          model,
          limits: { trackedPaths: 1 }
        });
      }
    },
    {
      name: "governed Context without a product",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_REQUIRED",
      run() {
        const { model } = ownershipFixture();
        return compileChangeAgainstGovernance(syntheticChange(), model);
      }
    },
    {
      name: "present but null governance cannot become brownfield",
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_REQUIRED",
      run() {
        const { model } = ownershipFixture();
        model.projectDocument.pathGovernance = null;
        return compileChangeAgainstGovernance(syntheticChange(), model);
      }
    },
    {
      name: "forged effective scope digest",
      code: "MODULE_PATH_OWNERSHIP_PROJECTION_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        return projectCompiledModulePathOwnershipIndex(product, {
          model,
          scopeSelections: [{
            id: "forged-digest",
            moduleRef: "core",
            scope: { include: ["src/core/feature/**"] },
            expectedScopeDigest: canonicalDigest({ include: ["src/core/**"] })
          }]
        });
      }
    },
    {
      name: "duplicate effective scope selection",
      code: "MODULE_PATH_OWNERSHIP_PROJECTION_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        const scope = { include: ["src/core/feature/**"] };
        const selection = {
          id: "duplicate",
          moduleRef: "core",
          scope,
          expectedScopeDigest: canonicalDigest(scope)
        };
        return projectCompiledModulePathOwnershipIndex(product, {
          model,
          scopeSelections: [selection, structuredClone(selection)]
        });
      }
    },
    ...[
      ["broadened governed Context", { include: ["src/**"] }],
      ["disposition-only governed Context", { include: ["docs/legacy/**"] }]
    ].map(([name, writeScope]) => ({
      name,
      code: "MODULE_PATH_OWNERSHIP_PROJECTION_INVALID",
      run() {
        const { model, facts } = ownershipFixture();
        const product = compileModulePathOwnershipIndex(model, facts);
        return compileChangeAgainstGovernance(
          syntheticChange(writeScope),
          model,
          { modulePathOwnershipProduct: product }
        );
      }
    }))
  ];

  for (const attack of attacks) {
    assert.throws(
      attack.run,
      (error) => error?.code === attack.code
        && (attack.relation === undefined || error.details?.relation === attack.relation),
      attack.name
    );
  }
});

test("the brownfield reference closes path ownership while relay sees dependency Contracts only", async (t) => {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "legatura-brownfield-model-"));
  const repoPath = path.join(fixtureRoot, "repo");
  t.after(() => rm(fixtureRoot, { recursive: true, force: true }));
  await cp(BROWNFIELD_REFERENCE_ROOT, repoPath, { recursive: true });
  await initializeGitRepository(repoPath);

  const model = await loadProjectModel(repoPath);
  const validation = validateProjectModel(model);
  assert.equal(validation.valid, true, JSON.stringify(validation.errors, null, 2));
  assert.deepEqual(validation.errors, []);
  assert.ok(validation.warnings.some((warning) => (
    warning.code === "assurance.opaque.unmodeled"
      && warning.message.includes("legacy-device-bridge")
  )));

  const modules = new Map(model.modules.map((module) => [module.id, module]));
  assert.deepEqual([...modules.keys()].sort(), ["apk", "app", "relay", "repository-governance"]);
  assert.deepEqual(
    Object.fromEntries([...modules].map(([id, module]) => [id, module.status])),
    {
      apk: "provisional",
      app: "provisional",
      relay: "governed",
      "repository-governance": "governed"
    }
  );
  assert.deepEqual(modules.get("app").dependencies, []);
  assert.deepEqual(modules.get("apk").dependencies, []);
  assert.deepEqual(modules.get("app").publicContracts, ["app-relay-request"]);
  assert.deepEqual(modules.get("apk").publicContracts, ["apk-delivery-port"]);
  assert.deepEqual(
    modules.get("relay").dependencies.map(({ module, via, access }) => ({ module, via, access })),
    [
      { module: "app", via: "app-relay-request", access: "interface-only" },
      { module: "apk", via: "apk-delivery-port", access: "interface-only" }
    ]
  );

  const contracts = new Map(model.contracts.map((contract) => [contract.id, contract]));
  assert.deepEqual(
    ["app-relay-request", "apk-delivery-port"].map((contractRef) => ({
      contractRef,
      owner: contracts.get(contractRef)?.owner,
      consumers: contracts.get(contractRef)?.consumers
    })),
    [
      { contractRef: "app-relay-request", owner: "app", consumers: ["relay"] },
      { contractRef: "apk-delivery-port", owner: "apk", consumers: ["relay"] }
    ]
  );
  assert.ok(model.projectDocument.assuranceBoundary.opaque.some((entry) => (
    entry.module === "legacy-device-bridge"
  )));
  const legacyDisposition = model.projectDocument.pathGovernance.dispositions.find(
    (disposition) => disposition.id === "legacy-ungoverned"
  );
  assert.deepEqual(legacyDisposition.paths, { include: ["legacy/**"], exclude: [] });
  assert.equal(model.projectDocument.pathGovernance.dispositionPolicy.grantsWriteAuthority, false);

  const trackedPathFacts = await observeTrackedPathFacts(repoPath);
  assert.deepEqual(trackedPathFacts.paths, [
    ".legatura/.gitignore",
    ".legatura/contracts/apk-delivery-port.json",
    ".legatura/contracts/app-relay-request.json",
    ".legatura/contracts/relay-routing.json",
    ".legatura/gates/minimum.json",
    ".legatura/knowledge-gaps.json",
    ".legatura/modules/apk.json",
    ".legatura/modules/app.json",
    ".legatura/modules/relay.json",
    ".legatura/modules/repository-governance.json",
    ".legatura/plan.json",
    ".legatura/project.json",
    "README.md",
    "apk/public.mjs",
    "app/public.mjs",
    "legacy/device-bridge.mjs",
    "relay/index.mjs",
    "relay/relay.proof.mjs"
  ]);
  const product = compileModulePathOwnershipIndex(model, trackedPathFacts);
  const projection = projectCompiledModulePathOwnershipIndex(product, {
    model,
    moduleRefs: [...modules.keys()],
    pathRefs: trackedPathFacts.paths
  });
  for (const trackedPath of trackedPathFacts.paths) {
    const expectedOwner = expectedBrownfieldOwner(trackedPath);
    const decisions = [...projection.pathDecisionsByModule.values()].map(
      (byPath) => byPath.get(trackedPath)
    );
    assert.ok(decisions.every((decision) => decision.classification !== "unassigned"), trackedPath);
    assert.deepEqual(
      [...new Set(decisions.map((decision) => decision.ownerModuleRef))],
      [expectedOwner],
      trackedPath
    );
    assert.equal(
      decisions.filter((decision) => decision.ownershipAllowsWrite).length,
      expectedOwner === null ? 0 : 1,
      `${trackedPath} has exactly one authorizing owner or one non-authorizing disposition`
    );
    if (expectedOwner === null) {
      assert.ok(decisions.every((decision) => (
        decision.classification === "ungoverned-disposition"
          && decision.dispositionRef === "legacy-ungoverned"
          && decision.ownershipAllowsWrite === false
      )), trackedPath);
    }
  }

  const relayClaim = contracts.get("relay-routing").claims.find(
    (claim) => claim.id === "relay-preserves-correlation-id"
  );
  const compiled = compileChangeAgainstGovernance({
    id: "brownfield-relay-context",
    primaryModule: "relay",
    changeKind: "implementation",
    planRefs: ["LGT-001"],
    claims: [relayClaim],
    compilerInput: {
      verificationObligations: [],
      impact: null,
      contextCapsule: null,
      outcomeContributionHints: [],
      outcomeExceptions: []
    }
  }, model, { modulePathOwnershipProduct: product });
  assert.deepEqual(
    compiled.contextCapsule.dependencyContracts.map((contract) => contract.id).sort(),
    ["apk-delivery-port", "app-relay-request"]
  );
  assert.deepEqual(
    compiled.contextCapsule.dependencies
      .map(({ module, interfaceRef, access }) => ({ module, interfaceRef, access })),
    [
      { module: "app", interfaceRef: "app-relay-request", access: "interface-only" },
      { module: "apk", interfaceRef: "apk-delivery-port", access: "interface-only" }
    ]
  );
  assert.deepEqual(
    compiled.contextCapsule.publicContracts.map((contract) => contract.id),
    ["relay-routing"]
  );
  assert.ok(compiled.contextCapsule.scope.read.include.includes("relay/**"));
  assert.ok(compiled.contextCapsule.scope.read.include.every((pathRef) => (
    !pathRef.startsWith("app/")
      && !pathRef.startsWith("apk/")
      && !pathRef.startsWith("legacy/")
  )));
  assert.equal(
    compiled.contextCapsule.scope.otherModuleImplementation,
    "contract-only; expansion must be recorded before reading implementation"
  );

  await writeFile(path.join(repoPath, "unmodeled.mjs"), "export const unmodeled = true;\n");
  await runGit(repoPath, "add", "unmodeled.mjs");
  const attackedFacts = await observeTrackedPathFacts(repoPath);
  assert.throws(
    () => compileModulePathOwnershipIndex(model, attackedFacts),
    (error) => error?.code === "MODULE_PATH_OWNERSHIP_INCOMPLETE"
      && error.details?.unassigned?.includes("unmodeled.mjs")
  );
});

function ownershipFixture() {
  const model = syntheticModel();
  const paths = [
    "docs/legacy/readme.md",
    "src/core/feature/inside.mjs",
    "src/core/index.mjs",
    "src/other/index.mjs"
  ];
  return {
    model,
    facts: { schemaVersion: 1, paths, digest: factsDigest(paths) }
  };
}

function factsDigest(paths) {
  return canonicalDigest({ schemaVersion: 1, paths });
}

function rebindModelDigests(model, mutate) {
  const content = structuredClone(model);
  delete content.digest;
  delete content.modelDigest;
  mutate(content);
  const modelDigest = canonicalDigest(content);
  const snapshot = { ...content, modelDigest };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function syntheticChange(writeScope = null) {
  return {
    id: "synthetic-core-change",
    primaryModule: "core",
    changeKind: "implementation",
    planRefs: [],
    claims: [],
    compilerInput: {
      verificationObligations: [],
      impact: null,
      contextCapsule: writeScope === null ? null : { scope: { write: writeScope } },
      outcomeContributionHints: [],
      outcomeExceptions: []
    }
  };
}

function syntheticModel() {
  const content = {
    schemaVersion: 1,
    project: { id: "path-ownership-fixture" },
    projectDocument: {
      project: { id: "path-ownership-fixture" },
      normativeSources: [],
      authorities: {
        fact: [{ id: "fixture-facts" }],
        decision: [{ id: "fixture-maintainer", may: ["case-decision"] }]
      },
      assuranceBoundary: {
        governed: ["core", "other"],
        provisional: [],
        opaque: []
      },
      changePolicy: { defaultGate: "minimum", requirePlanRefs: false },
      pathGovernance: {
        schemaVersion: 1,
        selectorGrammar: "exact-or-recursive-prefix",
        effectiveMatch: "include-minus-exclude",
        overlapPolicy: "reject-latent-and-concrete",
        conflictResolution: "none",
        dispositionPolicy: {
          allowedKinds: ["ungoverned"],
          requiredFields: ["id", "kind", "paths.include", "paths.exclude", "rationale"],
          minimumRationaleCharacters: 12,
          grantsWriteAuthority: false
        },
        dispositions: [{
          id: "legacy-docs",
          kind: "ungoverned",
          paths: { include: ["docs/legacy/**"], exclude: [] },
          rationale: "Legacy documents are classified but grant no automatic write authority."
        }]
      }
    },
    modules: [
      {
        id: "core",
        status: "governed",
        paths: { include: ["src/core/**"], exclude: ["src/core/generated/**"] },
        interface: { description: "Synthetic core behavior." },
        factAuthority: "fixture-facts",
        decisionAuthority: "fixture-maintainer",
        publicContracts: [],
        dependencies: []
      },
      {
        id: "other",
        status: "governed",
        paths: { include: ["src/other/**"], exclude: [] },
        interface: { description: "Synthetic peer behavior." },
        factAuthority: "fixture-facts",
        decisionAuthority: "fixture-maintainer",
        publicContracts: [],
        dependencies: []
      }
    ],
    contracts: [],
    gates: [{ id: "minimum", appliesTo: ["core", "other"], commands: [] }],
    plan: {
      id: "synthetic-plan",
      authority: "fixture-maintainer",
      northStar: "Keep the ownership fixture exact and bounded.",
      stages: [],
      outcomes: []
    },
    knowledgeGaps: [],
    files: []
  };
  const modelDigest = canonicalDigest(content);
  const snapshot = { ...content, modelDigest };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

async function initializeGitRepository(repoPath) {
  await runGit(repoPath, "init", "--quiet");
  await runGit(repoPath, "config", "user.name", "Legatura Brownfield Proof");
  await runGit(repoPath, "config", "user.email", "brownfield-proof@legatura.test");
  await runGit(repoPath, "add", ".");
  await runGit(repoPath, "commit", "--quiet", "-m", "fixture: brownfield reference");
}

async function observeTrackedPathFacts(repoPath) {
  const { stdout } = await runGit(repoPath, "ls-files", "-z");
  const paths = stdout.split("\0").filter(Boolean).sort(compareUtf8);
  return { schemaVersion: 1, paths, digest: factsDigest(paths) };
}

function expectedBrownfieldOwner(pathRef) {
  if (pathRef === "README.md" || pathRef.startsWith(".legatura/")) {
    return "repository-governance";
  }
  for (const moduleRef of ["app", "apk", "relay"]) {
    if (pathRef.startsWith(`${moduleRef}/`)) return moduleRef;
  }
  if (pathRef.startsWith("legacy/")) return null;
  assert.fail(`Unexpected tracked brownfield path: ${pathRef}`);
}

function compareUtf8(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}

function runGit(repoPath, ...args) {
  return execFileAsync("git", args, { cwd: repoPath });
}

export const BROWNFIELD_ADOPTION_PROJECT_MODEL_PROOF_VERSION = 1;
