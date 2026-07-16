import assert from "node:assert/strict";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileClaimGateRouteIndex } from "../../src/core/change-compiler.mjs";
import {
  projectCompiledClaimGateRouteIndex,
  projectCompiledModuleClaimGateIndex,
  projectModelContentDigest
} from "../../src/core/project-model.mjs";

test("Project Model projects exact module Claim/Gate semantics from one bounded route product", () => {
  const model = projectionFixture();
  const allClaimRefs = model.contracts
    .flatMap((contract) => contract.claims)
    .map((claim) => claim.id);
  const product = compileClaimGateRouteIndex(model, { claimRefs: allClaimRefs });
  const sourceRoutes = projectCompiledClaimGateRouteIndex(product, {
    model,
    claimRefs: allClaimRefs
  }).routesByClaim;
  assert.doesNotThrow(
    () => compileClaimGateRouteIndex(model, {
      claimRefs: ["core-public"],
      limits: { claimRefs: 1 }
    }),
    "the scalar requested-Claim limit is not reused for all Model Claims"
  );
  assert.throws(
    () => compileClaimGateRouteIndex(model, {
      claimRefs: [],
      limits: { totalRouteBytes: 0 }
    }),
    (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED"
      && error?.statusCode === 413
      && error?.details?.dimension === "totalRouteBytes",
    "private Module, Contract, and Claim metadata is charged before a route is emitted"
  );
  assert.throws(
    () => compileClaimGateRouteIndex(
      { modules: [], contracts: [], gates: [] },
      {
        claimRefs: ["x".repeat(4096)],
        limits: { totalRouteBytes: 0 }
      }
    ),
    (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED"
      && error?.details?.dimension === "totalRouteBytes",
    "opaque Claim coverage and empty private entries cannot bypass the byte budget"
  );
  const projection = projectCompiledModuleClaimGateIndex(product, {
    model,
    moduleRefs: ["consumer", "core"],
    routeSelections: [{ moduleRef: "core", claimRefs: ["foreign-frozen"] }]
  });

  assert.deepEqual([...projection.claimsByModule.keys()], ["consumer", "core"]);
  assert.equal(projection.claimsByModule.has("foreign"), false);
  assert.equal(projection.routesByModule.has("foreign"), false, "unrequested Modules remain unrelated");
  assert.deepEqual(claimRefs(projection, "core"), ["core-empty", "core-public"]);
  assert.deepEqual(
    projection.claimsByModule.get("core").find((claim) => claim.claimRef === "core-public")
      .visibilityKinds,
    ["owned"],
    "publicContracts alone define the Module's owned authoring visibility"
  );
  assert.deepEqual(
    claimRefs(projection, "consumer"),
    ["consumer-public", "core-empty", "core-public"],
    "dependencies[*].via adds exactly that Contract's Claims"
  );
  assert.deepEqual(
    projection.claimsByModule.get("consumer").find((claim) => claim.claimRef === "core-public"),
    {
      claimRef: "core-public",
      statement: "Core public behavior is stable.",
      contractRef: "core-api",
      visibilityKinds: ["dependency"]
    }
  );
  for (const hiddenClaimRef of ["owner-only-hidden", "foreign-frozen"]) {
    assert.equal(
      projection.claimsByModule.get("core").some((claim) => claim.claimRef === hiddenClaimRef),
      false,
      `${hiddenClaimRef} is not made author-visible by ownership or an explicit frozen-Plan route selection`
    );
  }

  const coreRoutes = projection.routesByModule.get("core");
  const consumerRoutes = projection.routesByModule.get("consumer");
  assert.equal(consumerRoutes.has("foreign-frozen"), false, "explicit pairs never fan out to peers");
  assert.deepEqual(coreRoutes.get("core-empty"), [], "an exact visible pair with no route is retained");
  assert.deepEqual(
    coreRoutes.get("core-public").map(routeIdentity),
    ["acceptance/alpha-core", "acceptance/core-only"],
    "parent and command Module scopes intersect and preserve canonical route order"
  );
  assert.deepEqual(
    consumerRoutes.get("core-public").map(routeIdentity),
    ["acceptance/consumer-only"],
    "a dependency Claim receives only routes effective for the consuming Module"
  );
  assert.deepEqual(
    coreRoutes.get("foreign-frozen").map(routeIdentity),
    ["acceptance/foreign-frozen-proof"],
    "an explicit foreign frozen-Plan pair is projected without widening authoring visibility"
  );
  assert.equal(
    [...coreRoutes.values()].flat().some((route) => route.gateId === "full"),
    false,
    "integration/release-only full-Gate expansion is never an acceptance route"
  );

  for (const [moduleRef, claimRef] of [
    ["core", "core-public"],
    ["consumer", "core-public"],
    ["core", "foreign-frozen"]
  ]) {
    const projected = projection.routesByModule.get(moduleRef).get(claimRef);
    const expected = sourceRoutes.get(claimRef).filter((route) => (
      route.gateId !== "full" && route.effectiveModuleRefs.includes(moduleRef)
    ));
    assert.deepEqual(projected, expected, `${moduleRef}/${claimRef} preserves original route shape and order`);
    assert.deepEqual(
      projected.map(canonicalDigest),
      expected.map(canonicalDigest),
      `${moduleRef}/${claimRef} preserves every canonical route digest`
    );
  }
  assert.equal(Object.isFrozen(projection.observation), true);
  assert.equal(projection.observation.schemaVersion, 1);
  for (const dimension of ["routes", "totalRouteBytes", "workUnits"]) {
    assert.equal(Number.isSafeInteger(projection.observation[dimension]), true);
  }

  const wrongModel = structuredClone(model);
  wrongModel.digest = projectModelContentDigest(wrongModel);
  const incompleteProduct = compileClaimGateRouteIndex(model, {
    claimRefs: allClaimRefs.filter((claimRef) => claimRef !== "foreign-frozen")
  });
  for (const [label, invoke] of [
    ["forged product", () => projectCompiledModuleClaimGateIndex(Object.freeze({}), {
      model,
      moduleRefs: ["core"],
      routeSelections: []
    })],
    ["wrong Model identity", () => projectCompiledModuleClaimGateIndex(product, {
      model: wrongModel,
      moduleRefs: ["core"],
      routeSelections: []
    })],
    ["incomplete Claim coverage", () => projectCompiledModuleClaimGateIndex(incompleteProduct, {
      model,
      moduleRefs: ["core"],
      routeSelections: [{ moduleRef: "core", claimRefs: ["foreign-frozen"] }]
    })]
  ]) {
    assert.throws(
      invoke,
      (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID" && error?.statusCode === 422,
      label
    );
  }

  for (const [label, invoke] of [
    ["unknown Module", () => projectCompiledModuleClaimGateIndex(product, {
      model,
      moduleRefs: ["unknown-module"],
      routeSelections: []
    })],
    ["unknown explicit Claim", () => projectCompiledModuleClaimGateIndex(product, {
      model,
      moduleRefs: [],
      routeSelections: [{ moduleRef: "core", claimRefs: ["unknown-claim"] }]
    })]
  ]) {
    assert.throws(
      invoke,
      (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID"
        && error?.statusCode === 422,
      label
    );
  }

  for (const dimension of ["routes", "totalRouteBytes", "workUnits"]) {
    const observed = projection.observation[dimension];
    assert.ok(observed > 0);
    assert.throws(
      () => projectCompiledModuleClaimGateIndex(product, {
        model,
        moduleRefs: ["consumer", "core"],
        routeSelections: [{ moduleRef: "core", claimRefs: ["foreign-frozen"] }],
        limits: { [dimension]: observed - 1 }
      }),
      (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED"
        && error?.statusCode === 413
        && error?.details?.dimension === dimension,
      `one aggregate ${dimension} bound covers both visibility and explicit selections`
    );
  }

  const driftedModel = projectionFixture();
  const driftedProduct = compileClaimGateRouteIndex(driftedModel, { claimRefs: allClaimRefs });
  driftedModel.contracts.find((contract) => contract.id === "core-api")
    .claims[0].statement = "Drifted after route-product compilation.";
  assert.throws(
    () => projectCompiledModuleClaimGateIndex(driftedProduct, {
      model: driftedModel,
      moduleRefs: ["core"],
      routeSelections: []
    }),
    (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID" && error?.statusCode === 422,
    "content drift after compilation fails closed"
  );
});

function projectionFixture() {
  const model = {
    projectDocument: {
      schemaVersion: 1,
      project: { id: "module-claim-gate-fixture" },
      changePolicy: { defaultGate: "acceptance", fullGate: "full", fullGateBefore: ["integrated"] }
    },
    modules: [
      moduleDocument("core", ["core-api"]),
      moduleDocument("consumer", ["consumer-api"], [
        { module: "core", via: "core-api", access: "interface-only" }
      ]),
      moduleDocument("foreign", ["foreign-api"])
    ],
    contracts: [
      contractDocument("core-api", "core", [
        ["core-public", "Core public behavior is stable."],
        ["core-empty", "An unrouted public Claim remains explicit."]
      ]),
      contractDocument("consumer-api", "consumer", [
        ["consumer-public", "Consumer public behavior is stable."]
      ]),
      contractDocument("foreign-api", "foreign", [
        ["foreign-frozen", "A frozen Plan may reference this foreign Claim."]
      ]),
      contractDocument("owner-only", "core", [
        ["owner-only-hidden", "Ownership alone does not expose a Contract Claim."]
      ])
    ],
    gates: [
      gateDocument("acceptance", ["core", "consumer"], [
        commandDocument("core-only", ["core"], ["core-public"]),
        commandDocument("consumer-only", ["consumer"], ["core-public", "consumer-public"]),
        commandDocument("foreign-frozen-proof", ["core"], ["foreign-frozen"]),
        commandDocument("alpha-core", ["core"], ["core-public"])
      ]),
      gateDocument("parent-command-conflict", ["consumer"], [
        commandDocument("parent-excludes-core", ["core"], ["core-public"])
      ]),
      gateDocument("full", ["integration", "release"], [
        commandDocument("full-core", ["core"], ["core-public"]),
        commandDocument("full-consumer", ["consumer"], ["core-public"])
      ])
    ],
    plan: null,
    knowledgeGaps: []
  };
  model.digest = projectModelContentDigest(model);
  return model;
}

function moduleDocument(id, publicContracts, dependencies = []) {
  return { id, status: "governed", publicContracts, dependencies };
}

function contractDocument(id, owner, claims) {
  return {
    id,
    owner,
    claims: claims.map(([claimId, statement]) => ({ id: claimId, statement }))
  };
}

function gateDocument(id, appliesTo, commands) {
  return { id, appliesTo, commands };
}

function commandDocument(id, appliesTo, claimRefs) {
  return {
    id,
    appliesTo,
    command: [process.execPath, "--test", `test/${id}.test.mjs`],
    timeoutMs: 30_000,
    claimRefs,
    oracle: { kind: "fixture", description: `${id} exits zero.` },
    applicability: { phase: "acceptance" },
    discriminatoryPower: { rejects: [`A failing ${id} rejects its exact Claim.`] },
    residualUncertainty: [`${id} observes only this deterministic fixture.`]
  };
}

function claimRefs(projection, moduleRef) {
  return projection.claimsByModule.get(moduleRef).map((claim) => claim.claimRef);
}

function routeIdentity(route) {
  return `${route.gateId}/${route.commandId}`;
}
