import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
  loadProjectModel,
  publicProjectModel,
  validateProjectModel
} from "../../src/core/project-model.mjs";

test("Project Model accepts owned dependencies and rejects dangling governance references", async () => {
  const model = baseModel();
  const valid = validateProjectModel(model);
  assert.equal(valid.valid, true, JSON.stringify(valid.errors));

  const optionalPlan = baseModel();
  optionalPlan.projectDocument.changePolicy.requirePlanRefs = false;
  delete optionalPlan.plan;
  assert.equal(validateProjectModel(optionalPlan).valid, true);

  const requiredPlan = baseModel();
  delete requiredPlan.plan;
  assert.ok(validateProjectModel(requiredPlan).errors.some((error) => error.code === "plan.missing"));

  const incapableAuthority = baseModel();
  incapableAuthority.projectDocument.authorities.decision[0].may = ["case-decision"];
  assert.ok(validateProjectModel(incapableAuthority).errors.some(
    (error) => error.code === "plan.authority.amendment-forbidden"
  ));

  const unsatisfiedPlan = baseModel();
  unsatisfiedPlan.plan.outcomes.push({
    id: "LGT-002",
    stage: "S1",
    status: "planned",
    outcome: "A later fixture capability remains planned.",
    dependsOn: ["LGT-001"],
    acceptance: { exitCriteria: ["The prerequisite is explicitly achieved before activation."] }
  });
  unsatisfiedPlan.plan.stages[0].outcomeRefs.push("LGT-002");
  unsatisfiedPlan.plan.outcomes[0].dependsOn = ["LGT-002"];
  const unsatisfiedErrors = validateProjectModel(unsatisfiedPlan).errors;
  assert.ok(unsatisfiedErrors.some(
    (error) => error.code === "plan.outcome.dependency.unsatisfied"
  ));
  assert.ok(unsatisfiedErrors.some((error) => error.code === "plan.outcome.dependency.cycle"));

  const directory = await mkdtemp(path.join(tmpdir(), "legatura-project-model-"));
  try {
    await mkdir(path.join(directory, ".legatura"));
    await writeFile(path.join(directory, ".legatura", "plan.json"), JSON.stringify(model.plan));
    const loaded = await loadProjectModel(directory);
    assert.deepEqual(loaded.plan, model.plan);
    assert.ok(loaded.files.includes(".legatura/plan.json"));
    assert.deepEqual(publicProjectModel(loaded).plan, model.plan);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }

  model.modules[0].decisionAuthority = "invented-authority";
  model.modules[0].dependencies = [{ module: "dependency", via: "missing-contract" }];
  model.projectDocument.changePolicy.defaultGate = "missing-gate";
  model.gates[0].commands[0].appliesTo = ["missing-module"];
  model.gates[0].commands[0].applicability.modules = ["dependency"];
  model.plan.northStar = "";
  model.plan.authority = "invented-authority";
  model.plan.outcomes[0].outcome = "";
  model.plan.outcomes[0].status = "queued";
  model.plan.outcomes[0].dependsOn = ["LGT-001", "LGT-404"];
  model.plan.outcomes[0].acceptance.exitCriteria = [];
  model.plan.outcomes[0].acceptance.claimRefs = ["missing-claim"];
  model.plan.outcomes[0].acceptance.gapRefs = ["missing-gap"];
  model.plan.outcomes.push({
    id: "LGT-001",
    stage: "S1",
    status: "planned",
    outcome: "A duplicate Outcome exists only to exercise validation.",
    dependsOn: [],
    acceptance: { exitCriteria: ["A duplicate Outcome exists only to exercise validation."] }
  });
  model.plan.outcomes.push({
    id: "unstable-id",
    stage: "S1",
    status: "planned",
    outcome: "An unstable identifier is rejected.",
    dependsOn: [],
    acceptance: { exitCriteria: ["Only permanent LGT numeric identifiers remain."] }
  });
  model.plan.stages[0].outcomeRefs = ["LGT-404"];
  model.plan.coreCompletion = { stage: "S404", definition: "" };
  model.plan.referenceAcceptanceScenario = { id: "", topology: "", mustDemonstrate: [] };
  model.plan.bootstrapBaseline = {
    head: "not-a-commit",
    outcomeRefs: ["LGT-404"],
    rationale: "",
    residualUncertainty: ""
  };

  const validation = validateProjectModel(model);
  const codes = validation.errors.map((error) => error.code);
  assert.equal(validation.valid, false);
  assert.ok(codes.includes("module.decision-authority.unknown"));
  assert.ok(codes.includes("module.dependency.contract.unknown"));
  assert.ok(codes.includes("change-policy.defaultGate.unknown"));
  assert.ok(codes.includes("gate.command.applies-to.unknown"));
  assert.ok(codes.includes("gate.command.applicability.module-scope"));
  assert.ok(codes.includes("plan.north-star.missing"));
  assert.ok(codes.includes("plan.authority.unknown"));
  assert.ok(codes.includes("plan.outcome.id.duplicate"));
  assert.ok(codes.includes("plan.outcome.id.unstable"));
  assert.ok(codes.includes("plan.outcome.statement.missing"));
  assert.ok(codes.includes("plan.outcome.status.invalid"));
  assert.ok(codes.includes("plan.outcome.dependency.self"));
  assert.ok(codes.includes("plan.outcome.dependency.unknown"));
  assert.ok(codes.includes("plan.outcome.acceptance.exit-criteria.missing"));
  assert.ok(codes.includes("plan.outcome.claim.unknown"));
  assert.ok(codes.includes("plan.outcome.gap.unknown"));
  assert.ok(codes.includes("plan.stage.outcome.unknown"));
  assert.ok(codes.includes("plan.outcome.stage.unlisted"));
  assert.ok(codes.includes("plan.active.missing"));
  assert.ok(codes.includes("plan.core-completion.stage.unknown"));
  assert.ok(codes.includes("plan.core-completion.definition.missing"));
  assert.ok(codes.includes("plan.reference-scenario.identity.invalid"));
  assert.ok(codes.includes("plan.reference-scenario.acceptance.missing"));
  assert.ok(codes.includes("plan.bootstrap.invalid"));
});

function baseModel() {
  return {
    project: { id: "model-fixture" },
    projectDocument: {
      project: { id: "model-fixture" },
      normativeSources: [{ id: "requirements" }],
      authorities: {
        fact: [{ id: "facts" }],
        decision: [{ id: "maintainer", may: ["case-decision", "normative-amendment"] }]
      },
      assuranceBoundary: { governed: ["core", "dependency"], provisional: [], opaque: [] },
      changePolicy: { defaultGate: "minimum", requirePlanRefs: true }
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
        applicability: { phase: "acceptance" },
        discriminatoryPower: { rejects: ["a failing command"] },
        residualUncertainty: ["The fixture is bounded."]
      }]
    }],
    plan: {
      id: "fixture-plan",
      authority: "maintainer",
      northStar: "Every accepted change is aligned with an explicit trusted outcome.",
      stages: [{
        id: "S1",
        name: "Fixture Stage",
        status: "active",
        outcomeRefs: ["LGT-001"]
      }],
      outcomes: [{
        id: "LGT-001",
        stage: "S1",
        status: "active",
        outcome: "The fixture Project Model enforces explicit trusted Outcome alignment.",
        dependsOn: [],
        acceptance: {
          exitCriteria: ["The Project Model validates plan alignment inputs."],
          claimRefs: ["core-works"],
          gapRefs: ["fixture-gap"]
        }
      }]
    },
    knowledgeGaps: [{ id: "fixture-gap", statement: "The fixture leaves one bounded uncertainty." }],
    files: []
  };
}
