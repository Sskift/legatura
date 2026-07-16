import assert from "node:assert/strict";
import test from "node:test";

import { validateProjectModel } from "../../src/core/project-model.mjs";

test("Project Model rejects unknown decision authorities, dependency Contracts, and policy Gates", () => {
  const model = baseModel();
  model.modules[0].decisionAuthority = "invented-authority";
  model.modules[0].dependencies = [{ module: "dependency", via: "missing-contract" }];
  model.projectDocument.changePolicy.defaultGate = "missing-gate";

  const validation = validateProjectModel(model);
  const codes = validation.errors.map((error) => error.code);
  assert.equal(validation.valid, false);
  assert.ok(codes.includes("module.decision-authority.unknown"));
  assert.ok(codes.includes("module.dependency.contract.unknown"));
  assert.ok(codes.includes("change-policy.defaultGate.unknown"));
});

test("Project Model accepts a dependency only through its owner's Contract", () => {
  const model = baseModel();
  const validation = validateProjectModel(model);
  assert.equal(validation.valid, true, JSON.stringify(validation.errors));
});

function baseModel() {
  return {
    project: { id: "model-fixture" },
    projectDocument: {
      project: { id: "model-fixture" },
      normativeSources: [{ id: "requirements" }],
      authorities: {
        fact: [{ id: "facts" }],
        decision: [{ id: "maintainer", may: ["case-decision"] }]
      },
      assuranceBoundary: { governed: ["core", "dependency"], provisional: [], opaque: [] },
      changePolicy: { defaultGate: "minimum" }
    },
    modules: [
      {
        id: "core",
        status: "governed",
        paths: { include: ["src/core/**"] },
        interface: { description: "Core behavior." },
        factAuthority: "facts",
        decisionAuthority: "maintainer",
        publicContracts: ["core-api"],
        dependencies: [{ module: "dependency", via: "dependency-api" }]
      },
      {
        id: "dependency",
        status: "governed",
        paths: { include: ["src/dependency/**"] },
        interface: { description: "Dependency behavior." },
        factAuthority: "facts",
        decisionAuthority: "maintainer",
        publicContracts: ["dependency-api"],
        dependencies: []
      }
    ],
    contracts: [
      {
        id: "core-api",
        owner: "core",
        consumers: [],
        normativeSources: ["requirements"],
        claims: [{ id: "core-works", statement: "Core remains correct." }]
      },
      {
        id: "dependency-api",
        owner: "dependency",
        consumers: ["core"],
        normativeSources: ["requirements"],
        claims: [{ id: "dependency-works", statement: "Dependency remains correct." }]
      }
    ],
    gates: [{
      id: "minimum",
      appliesTo: ["core", "dependency"],
      commands: [{
        id: "minimum-command",
        command: [process.execPath, "-e", "process.exit(0)"],
        claimRefs: ["core-works"],
        oracle: { kind: "process-exit", description: "The command exits zero." },
        applicability: { modules: ["core"] },
        discriminatoryPower: { rejects: ["a failing command"] },
        residualUncertainty: ["The fixture is bounded."]
      }]
    }],
    knowledgeGaps: [],
    files: []
  };
}
