import assert from "node:assert/strict";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileChangeAgainstGovernance } from "../../src/core/change-compiler.mjs";
import {
  compileContextExpansionImpact,
  compileContextMaterializationPlan,
  compileModulePathOwnershipIndex
} from "../../src/core/project-model.mjs";

test("Context materialization derives one exact ordered plan including explicit read dispositions", () => {
  const fixture = contextFixture();
  const plan = compileContextMaterializationPlan({
    model: fixture.model,
    contextCapsule: fixture.capsule,
    trackedPathFacts: fixture.facts
  }, { modulePathOwnershipProduct: fixture.product });

  assert.deepEqual(Object.keys(plan), [
    "schemaVersion",
    "kind",
    "primaryModuleRef",
    "modelDigest",
    "contextCapsuleDigest",
    "trackedPathFactsDigest",
    "ownershipProductDigest",
    "readScopeDigest",
    "writeScopeDigest",
    "pathSetDigest",
    "pathRefs",
    "pathFacts",
    "contractSurfaceFacts",
    "materializationPlanDigest"
  ]);
  assert.deepEqual(plan.pathRefs, [
    ".legatura/contracts/core-api.json",
    ".legatura/contracts/peer-api.json",
    ".legatura/project.json",
    "docs/policy.md",
    "src/core/index.mjs",
    "test/core.test.mjs"
  ]);
  assert.deepEqual(plan.pathFacts, [
    {
      pathRef: ".legatura/contracts/core-api.json",
      kind: "module-owner",
      ownerModuleRef: "governance"
    },
    {
      pathRef: ".legatura/contracts/peer-api.json",
      kind: "module-owner",
      ownerModuleRef: "governance"
    },
    {
      pathRef: ".legatura/project.json",
      kind: "module-owner",
      ownerModuleRef: "governance"
    },
    {
      pathRef: "docs/policy.md",
      kind: "ungoverned-disposition",
      dispositionRef: "external-docs"
    },
    { pathRef: "src/core/index.mjs", kind: "module-owner", ownerModuleRef: "core" },
    { pathRef: "test/core.test.mjs", kind: "module-owner", ownerModuleRef: "core" }
  ]);
  assert.deepEqual(plan.contractSurfaceFacts, [
    {
      pathRef: ".legatura/contracts/core-api.json",
      contractRef: "core-api",
      relation: "primary-public-contract",
      ownerModuleRef: "core",
      dependencyModuleRef: null
    },
    {
      pathRef: ".legatura/contracts/peer-api.json",
      contractRef: "peer-api",
      relation: "dependency-interface-contract",
      ownerModuleRef: "peer",
      dependencyModuleRef: "peer"
    }
  ]);
  assert.equal(plan.contextCapsuleDigest, canonicalDigest(fixture.capsule));
  assert.equal(plan.readScopeDigest, canonicalDigest(fixture.capsule.scope.read));
  assert.equal(plan.writeScopeDigest, canonicalDigest(fixture.capsule.scope.write));
  assert.equal(plan.pathSetDigest, canonicalDigest({ schemaVersion: 1, paths: plan.pathRefs }));
  const { materializationPlanDigest, ...content } = plan;
  assert.equal(materializationPlanDigest, canonicalDigest(content));
  assert.equal(JSON.stringify(plan).includes("semantic"), false);
  assert.equal(JSON.stringify(plan).includes("acceptance"), false);
});

test("Context materialization fails closed on scope, source, product, shape, and limit attacks", () => {
  const cases = [
    {
      name: "serialized ownership product",
      mutate: ({ options }) => { options.modulePathOwnershipProduct = {}; },
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID"
    },
    {
      name: "wrong tracked facts",
      mutate: ({ input }) => {
        input.trackedPathFacts = trackedFacts([...input.trackedPathFacts.paths].reverse().sort());
        input.trackedPathFacts = trackedFacts([
          ...input.trackedPathFacts.paths,
          "src/core/new.mjs"
        ].sort(compareUtf8));
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "broadened read selector",
      mutate: ({ input }) => { input.contextCapsule.scope.read.include = ["src/peer/**"]; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "incomplete compiled Capsule",
      mutate: ({ input }) => { delete input.contextCapsule.dependencies; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "extra aggregate Capsule field",
      mutate: ({ input }) => { input.contextCapsule.score = 100; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "stale Capsule Baseline binding",
      mutate: ({ input }) => {
        input.contextCapsule.compiledFrom.governanceBaselineDigest = canonicalDigest("stale");
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "forged Capsule Module projection",
      mutate: ({ input }) => { input.contextCapsule.module.status = "opaque"; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "forged Capsule Plan projection",
      mutate: ({ input }) => {
        input.contextCapsule.planOutcomes = [{ id: "invented", status: "active" }];
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "stale frozen Model",
      mutate: ({ input }) => { input.model.project.id = "stale-context-fixture"; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "stale write binding",
      mutate: ({ input }) => {
        input.contextCapsule.compiledFrom.pathOwnership.effectiveScopeDigest = canonicalDigest("stale");
      },
      code: "MODULE_PATH_OWNERSHIP_PROJECTION_INVALID"
    },
    {
      name: "caller classification",
      mutate: ({ input }) => { input.pathFacts = []; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "bounded selected paths",
      mutate: ({ options }) => { options.limits = { pathRefs: 1 }; },
      code: "CONTEXT_COMPILATION_LIMIT_EXCEEDED"
    }
  ];
  for (const attack of cases) {
    const fixture = contextFixture();
    const state = {
      input: {
        model: fixture.model,
        contextCapsule: structuredClone(fixture.capsule),
        trackedPathFacts: structuredClone(fixture.facts)
      },
      options: { modulePathOwnershipProduct: fixture.product }
    };
    attack.mutate(state);
    assert.throws(
      () => compileContextMaterializationPlan(state.input, state.options),
      (error) => error?.code === attack.code,
      attack.name
    );
  }

  const fixture = contextFixture();
  let getterCalls = 0;
  const accessorInput = {
    model: fixture.model,
    contextCapsule: fixture.capsule
  };
  Object.defineProperty(accessorInput, "trackedPathFacts", {
    enumerable: true,
    get() { getterCalls += 1; return fixture.facts; }
  });
  assert.throws(
    () => compileContextMaterializationPlan(accessorInput, {
      modulePathOwnershipProduct: fixture.product
    }),
    (error) => error?.code === "CONTEXT_COMPILATION_INPUT_INVALID"
  );
  assert.equal(getterCalls, 0, "closed input validation must not invoke getters");

  const inheritedGetterFixture = contextFixture();
  let inheritedGetterCalls = 0;
  const hostileArrayPrototype = Object.create(Array.prototype);
  Object.defineProperty(hostileArrayPrototype, Symbol.iterator, {
    get() {
      inheritedGetterCalls += 1;
      return Array.prototype[Symbol.iterator];
    }
  });
  Object.setPrototypeOf(
    inheritedGetterFixture.facts.paths,
    hostileArrayPrototype
  );
  assert.throws(
    () => compileContextMaterializationPlan({
      model: inheritedGetterFixture.model,
      contextCapsule: inheritedGetterFixture.capsule,
      trackedPathFacts: inheritedGetterFixture.facts
    }, { modulePathOwnershipProduct: inheritedGetterFixture.product }),
    (error) => error?.code === "CONTEXT_COMPILATION_INPUT_INVALID"
  );
  assert.equal(
    inheritedGetterCalls,
    0,
    "array validation must reject inherited iteration hooks without invoking them"
  );

  const grammarFixture = contextFixture();
  assert.throws(
    () => compileChangeAgainstGovernance({
      id: "unsupported-context-selector",
      changeKind: "implementation",
      primaryModule: "core",
      planRefs: [],
      claims: [],
      compilerInput: {
        contextCapsule: {
          scope: { read: { include: ["src/core/*.mjs"] } }
        }
      }
    }, grammarFixture.model, {
      modulePathOwnershipProduct: grammarFixture.product
    }),
    (error) => error?.code === "CONTEXT_SCOPE_EXPANSION_FORBIDDEN",
    "Change compilation and materialization must share exact-or-recursive-prefix grammar"
  );

  assert.throws(
    () => contextFixture({ focusedTestPath: "test/*.mjs" }),
    (error) => error?.code === "CONTEXT_CAPSULE_MODEL_BINDING_INVALID",
    "Model-generated Context scope must pass the same selector grammar"
  );
});

test("Context Impact derives directional structural facts and a canonical empty delta", () => {
  const fixture = contextFixture();
  const priorDisclosedPaths = ["src/core/index.mjs"];
  const requestedPathRefs = ["src/isolated/secret.mjs", "src/peer/index.mjs"];
  const projection = sourceProjection(fixture.facts.digest, [
    ...priorDisclosedPaths,
    ...requestedPathRefs
  ].sort(compareUtf8));
  const impact = compileContextExpansionImpact({
    model: fixture.model,
    primaryModuleRef: "core",
    priorDisclosedPaths,
    priorDisclosedPathsDigest: pathSetDigest(priorDisclosedPaths),
    requestedPathRefs,
    repositorySourceProjection: projection
  }, { modulePathOwnershipProduct: fixture.product });

  assert.deepEqual(Object.keys(impact), [
    "schemaVersion",
    "kind",
    "modelDigest",
    "ownershipProductDigest",
    "primaryModuleRef",
    "repositorySourceBinding",
    "priorDisclosedPathsDigest",
    "requestedPathsDigest",
    "requestedPathRefs",
    "newlyDisclosedPathRefs",
    "pathFacts",
    "contractRelations",
    "assuranceCrossings",
    "dispositionRefs",
    "impactDigest"
  ]);
  assert.deepEqual(impact.pathFacts, [
    { pathRef: "src/isolated/secret.mjs", ownerModuleRef: "isolated" },
    { pathRef: "src/peer/index.mjs", ownerModuleRef: "peer" }
  ]);
  assert.deepEqual(impact.contractRelations, [
    {
      pathRef: "src/isolated/secret.mjs",
      ownerModuleRef: "isolated",
      relation: "undeclared-cross-module",
      fromModuleRef: "core",
      toModuleRef: "isolated",
      contractRef: null,
      access: null
    },
    {
      pathRef: "src/peer/index.mjs",
      ownerModuleRef: "peer",
      relation: "declared-dependency",
      fromModuleRef: "core",
      toModuleRef: "peer",
      contractRef: "peer-api",
      access: "interface-only"
    }
  ]);
  assert.deepEqual(impact.assuranceCrossings, [
    {
      pathRef: "src/isolated/secret.mjs",
      fromModuleRef: "core",
      toModuleRef: "isolated",
      fromStatus: "governed",
      toStatus: "opaque",
      fromFactAuthorityRef: "core-facts",
      toFactAuthorityRef: null
    },
    {
      pathRef: "src/peer/index.mjs",
      fromModuleRef: "core",
      toModuleRef: "peer",
      fromStatus: "governed",
      toStatus: "provisional",
      fromFactAuthorityRef: "core-facts",
      toFactAuthorityRef: "peer-facts"
    }
  ]);
  assert.deepEqual(impact.dispositionRefs, []);
  assert.deepEqual(impact.repositorySourceBinding, withoutManifest(projection));
  const { impactDigest, ...impactContent } = impact;
  assert.equal(impactDigest, canonicalDigest(impactContent));
  assert.equal(JSON.stringify(impact).includes("score"), false);
  assert.equal(JSON.stringify(impact).includes("confidence"), false);

  const emptyProjection = sourceProjection(fixture.facts.digest, priorDisclosedPaths);
  const empty = compileContextExpansionImpact({
    model: fixture.model,
    primaryModuleRef: "core",
    priorDisclosedPaths,
    priorDisclosedPathsDigest: pathSetDigest(priorDisclosedPaths),
    requestedPathRefs: [],
    repositorySourceProjection: emptyProjection
  }, { modulePathOwnershipProduct: fixture.product });
  assert.deepEqual({
    requestedPathRefs: empty.requestedPathRefs,
    newlyDisclosedPathRefs: empty.newlyDisclosedPathRefs,
    pathFacts: empty.pathFacts,
    contractRelations: empty.contractRelations,
    assuranceCrossings: empty.assuranceCrossings,
    dispositionRefs: empty.dispositionRefs
  }, {
    requestedPathRefs: [],
    newlyDisclosedPathRefs: [],
    pathFacts: [],
    contractRelations: [],
    assuranceCrossings: [],
    dispositionRefs: []
  });
});

test("Context Impact rejects binding, overlap, classification, disposition, and resource attacks", () => {
  const cases = [
    {
      name: "already disclosed request",
      mutate: ({ input }) => { input.requestedPathRefs = ["src/core/index.mjs"]; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "disposition-only request",
      mutate: ({ input, fixture }) => {
        input.requestedPathRefs = ["docs/policy.md"];
        input.repositorySourceProjection = sourceProjection(
          fixture.facts.digest,
          ["docs/policy.md", ...input.priorDisclosedPaths].sort(compareUtf8)
        );
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "forged source product digest",
      mutate: ({ input }) => {
        input.repositorySourceProjection.productDigest = canonicalDigest("forged");
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "source manifest broader than union",
      mutate: ({ input, fixture }) => {
        input.repositorySourceProjection = sourceProjection(fixture.facts.digest, [
          ...input.repositorySourceProjection.manifest.map((entry) => entry.pathRef),
          "test/core.test.mjs"
        ].sort(compareUtf8));
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "source facts differ from ownership",
      mutate: ({ input }) => {
        input.repositorySourceProjection = rebindSourceProjection(
          input.repositorySourceProjection,
          { trackedPathFactsDigest: canonicalDigest("stale-facts") }
        );
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "unknown primary Module",
      mutate: ({ input }) => { input.primaryModuleRef = "unknown"; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "caller-supplied classifications",
      mutate: ({ input }) => { input.contractRelations = []; },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "hidden caller-supplied classifications",
      mutate: ({ input }) => {
        Object.defineProperty(input, "contractRelations", {
          value: [{ forged: true }],
          enumerable: false
        });
      },
      code: "CONTEXT_COMPILATION_INPUT_INVALID"
    },
    {
      name: "forged ownership product",
      mutate: ({ options }) => { options.modulePathOwnershipProduct = {}; },
      code: "MODULE_PATH_OWNERSHIP_PRODUCT_INVALID"
    },
    {
      name: "bounded proposal",
      mutate: ({ options }) => { options.limits = { pathRefs: 1 }; },
      code: "CONTEXT_COMPILATION_LIMIT_EXCEEDED"
    },
    {
      name: "bounded source byte facts",
      mutate: ({ input }) => {
        input.repositorySourceProjection = rebindSourceManifest(
          input.repositorySourceProjection,
          input.repositorySourceProjection.manifest.map((entry, index) => ({
            ...entry,
            byteLength: index === 0 ? 4 * 1024 * 1024 + 1 : entry.byteLength
          }))
        );
      },
      code: "CONTEXT_COMPILATION_LIMIT_EXCEEDED"
    }
  ];
  for (const attack of cases) {
    const fixture = contextFixture();
    const priorDisclosedPaths = ["src/core/index.mjs"];
    const requestedPathRefs = ["src/peer/index.mjs"];
    const state = {
      fixture,
      input: {
        model: fixture.model,
        primaryModuleRef: "core",
        priorDisclosedPaths,
        priorDisclosedPathsDigest: pathSetDigest(priorDisclosedPaths),
        requestedPathRefs,
        repositorySourceProjection: sourceProjection(fixture.facts.digest, [
          ...priorDisclosedPaths,
          ...requestedPathRefs
        ].sort(compareUtf8))
      },
      options: { modulePathOwnershipProduct: fixture.product }
    };
    attack.mutate(state);
    assert.throws(
      () => compileContextExpansionImpact(state.input, state.options),
      (error) => error?.code === attack.code,
      attack.name
    );
  }
});

function contextFixture({ focusedTestPath = " ./test/core.test.mjs " } = {}) {
  const content = {
    schemaVersion: 1,
    project: { id: "context-fixture" },
    projectDocument: {
      project: { id: "context-fixture" },
      normativeSources: [{ id: "policy", path: " ./docs/policy.md ", kind: "policy" }],
      authorities: {
        fact: [
          { id: "core-facts" },
          { id: "peer-facts" },
          { id: "governance-facts" }
        ],
        decision: [{ id: "maintainer", may: ["case-decision"] }]
      },
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
          id: "external-docs",
          kind: "ungoverned",
          paths: { include: ["docs/**"], exclude: [] },
          rationale: "External policy documents are readable but grant no write authority."
        }]
      }
    },
    modules: [
      {
        id: "core",
        status: "governed",
        factAuthority: "core-facts",
        paths: {
          include: ["src/core/**", "test/core.test.mjs"],
          exclude: ["src/core/generated/**"]
        },
        focusedTests: [{ path: focusedTestPath }],
        publicContracts: ["core-api"],
        dependencies: [{ module: "peer", via: "peer-api", access: "interface-only" }]
      },
      {
        id: "peer",
        status: "provisional",
        factAuthority: "peer-facts",
        paths: { include: ["src/peer/**"], exclude: [] },
        publicContracts: ["peer-api"],
        dependencies: []
      },
      {
        id: "isolated",
        status: "opaque",
        paths: { include: ["src/isolated/**"], exclude: [] },
        publicContracts: [],
        dependencies: []
      },
      {
        id: "governance",
        status: "governed",
        factAuthority: "governance-facts",
        paths: { include: [".legatura/**"], exclude: [] },
        publicContracts: [],
        dependencies: []
      }
    ],
    contracts: [
      {
        id: "core-api",
        owner: "core",
        sourceFile: ".legatura/contracts/core-api.json",
        consumers: [],
        normativeSources: ["policy"]
      },
      {
        id: "peer-api",
        owner: "peer",
        sourceFile: ".legatura/contracts/peer-api.json",
        consumers: ["core"],
        normativeSources: []
      }
    ],
    gates: [],
    plan: null,
    knowledgeGaps: [],
    files: [
      ".legatura/contracts/core-api.json",
      ".legatura/contracts/peer-api.json",
      ".legatura/project.json"
    ]
  };
  const snapshot = { ...content, modelDigest: canonicalDigest(content) };
  const model = { ...snapshot, digest: canonicalDigest(snapshot) };
  const facts = trackedFacts([
    ".legatura/contracts/core-api.json",
    ".legatura/contracts/peer-api.json",
    ".legatura/project.json",
    "docs/policy.md",
    "src/core/index.mjs",
    "src/isolated/secret.mjs",
    "src/peer/index.mjs",
    "test/core.test.mjs"
  ]);
  const product = compileModulePathOwnershipIndex(model, facts);
  const capsule = compileChangeAgainstGovernance({
    id: "context-fixture-change",
    changeKind: "implementation",
    primaryModule: "core",
    planRefs: [],
    claims: [],
    compilerInput: {}
  }, model, { modulePathOwnershipProduct: product }).contextCapsule;
  return { model, facts, product, capsule };
}

function trackedFacts(paths) {
  const canonicalPaths = [...paths].sort(compareUtf8);
  return {
    schemaVersion: 1,
    paths: canonicalPaths,
    digest: canonicalDigest({ schemaVersion: 1, paths: canonicalPaths })
  };
}

function sourceProjection(trackedPathFactsDigest, pathRefs) {
  const manifest = pathRefs.map((pathRef) => ({
    pathRef,
    byteLength: Buffer.byteLength(pathRef, "utf8"),
    contentDigest: canonicalDigest(`bytes:${pathRef}`)
  }));
  const source = {
    schemaVersion: 1,
    repositoryIdentityDigest: canonicalDigest("fixture-repository"),
    gitContentDigest: canonicalDigest("fixture-git"),
    trackedPathFactsDigest,
    pathSetDigest: pathSetDigest(pathRefs),
    manifestDigest: canonicalDigest({ schemaVersion: 1, entries: manifest })
  };
  return {
    ...source,
    productDigest: canonicalDigest(source),
    manifest
  };
}

function rebindSourceProjection(source, replacements) {
  return sourceProjection(
    replacements.trackedPathFactsDigest ?? source.trackedPathFactsDigest,
    source.manifest.map((entry) => entry.pathRef)
  );
}

function rebindSourceManifest(source, manifest) {
  const content = {
    schemaVersion: 1,
    repositoryIdentityDigest: source.repositoryIdentityDigest,
    gitContentDigest: source.gitContentDigest,
    trackedPathFactsDigest: source.trackedPathFactsDigest,
    pathSetDigest: pathSetDigest(manifest.map((entry) => entry.pathRef)),
    manifestDigest: canonicalDigest({ schemaVersion: 1, entries: manifest })
  };
  return { ...content, productDigest: canonicalDigest(content), manifest };
}

function withoutManifest(source) {
  const { manifest: _manifest, schemaVersion: _schemaVersion, ...binding } = source;
  return binding;
}

function pathSetDigest(paths) {
  return canonicalDigest({ schemaVersion: 1, paths });
}

function compareUtf8(left, right) {
  return Buffer.from(left).compare(Buffer.from(right));
}
