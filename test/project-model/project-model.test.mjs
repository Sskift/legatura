import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileChangeAgainstGovernance } from "../../src/core/change-compiler.mjs";
import {
  loadProjectModel,
  publicProjectModel,
  validateProjectModel
} from "../../src/core/project-model.mjs";

test("Project Model accepts owned dependencies and rejects dangling governance references", async () => {
  const model = baseModel();
  const valid = validateProjectModel(model);
  assert.equal(valid.valid, true, JSON.stringify(valid.errors));

  const criteriaModel = baseModel();
  enableOutcomeCriteria(criteriaModel);
  assert.equal(validateProjectModel(criteriaModel).valid, true);

  const invalidCriteria = structuredClone(criteriaModel);
  invalidCriteria.plan.outcomes[0].acceptance.criteria[0] = {
    id: "LGT-404-C1",
    statement: "This no longer mirrors the declared exit Criterion.",
    claimRefs: ["missing-claim"],
    gapRefs: ["missing-gap"]
  };
  const invalidCriteriaCodes = validateProjectModel(invalidCriteria).errors.map((error) => error.code);
  assert.ok(invalidCriteriaCodes.includes("plan.outcome.criterion.id.invalid"));
  assert.ok(invalidCriteriaCodes.includes("plan.outcome.criterion.claim.unknown"));
  assert.ok(invalidCriteriaCodes.includes("plan.outcome.criterion.gap.unknown"));
  assert.ok(invalidCriteriaCodes.includes("plan.outcome.criteria.statement-mirror"));

  const missingCriterionOutcomeId = structuredClone(criteriaModel);
  delete missingCriterionOutcomeId.plan.outcomes[0].id;
  assert.doesNotThrow(() => validateProjectModel(missingCriterionOutcomeId));
  assert.ok(validateProjectModel(missingCriterionOutcomeId).errors.some(
    (error) => error.code === "plan.outcome.id.missing"
  ));

  const missingEnforcedCriteria = baseModel();
  missingEnforcedCriteria.projectDocument.changePolicy.outcomeAlignmentMode = "enforced";
  missingEnforcedCriteria.projectDocument.changePolicy.outcomeCriterionSelection =
    "unique-claim-match-or-explicit-hint";
  assert.ok(validateProjectModel(missingEnforcedCriteria).errors.some(
    (error) => error.code === "plan.outcome.criteria.required"
  ));

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
  model.modules[0].publicContracts = ["dependency-api"];
  model.projectDocument.changePolicy.defaultGate = "missing-gate";
  model.projectDocument.changePolicy.outcomeAlignmentMode = true;
  model.projectDocument.changePolicy.outcomeTransitionMode = "enforced";
  model.projectDocument.changePolicy.outcomeCriterionSelection = "semantic-similarity";
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
  assert.ok(codes.includes("module.contract.owner-mismatch"));
  assert.ok(codes.includes("change-policy.defaultGate.unknown"));
  assert.ok(codes.includes("change-policy.outcomeAlignmentMode.invalid"));
  assert.ok(codes.includes("change-policy.outcomeTransitionMode.invalid"));
  assert.ok(codes.includes("change-policy.outcome-criterion-selection.invalid"));
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

test("Outcome Contributions use exact accessible Claims, stable Criteria, and explicit ambiguity", () => {
  const uniqueModel = baseModel();
  enableOutcomeCriteria(uniqueModel);
  const uniqueBaseline = governanceBaseline(uniqueModel);
  const change = outcomeChange();

  const compiled = compileChangeAgainstGovernance(change, uniqueBaseline);
  const repeated = compileChangeAgainstGovernance(change, uniqueBaseline);
  assert.equal(compiled.outcomeAlignment.status, "complete");
  assert.deepEqual(compiled.outcomeAlignment.contributions.map((entry) => entry.criterionRef), ["LGT-001-C1"]);
  assert.equal(
    compiled.outcomeAlignment.contributions[0].bindingDigest,
    repeated.outcomeAlignment.contributions[0].bindingDigest
  );
  assert.deepEqual(
    compiled.contextCapsule.planOutcomes[0].acceptance.criteria.map((criterion) => criterion.id),
    ["LGT-001-C1"]
  );
  assert.ok(compiled.contextCapsule.knowledgeGaps.some((gap) => gap.id === "fixture-gap"));

  const dependencyModel = baseModel();
  enableOutcomeCriteria(dependencyModel, [], "dependency-works");
  const dependencyCompiled = compileChangeAgainstGovernance(outcomeChange({
    claims: [{ id: "dependency-works", statement: "Dependency remains correct." }]
  }), governanceBaseline(dependencyModel));
  assert.deepEqual(dependencyCompiled.outcomeAlignment.contributions.map((entry) => entry.claimRefs), [
    ["dependency-works"]
  ]);

  const mixedAmbiguityModel = baseModel();
  enableOutcomeCriteria(mixedAmbiguityModel, [{
    id: "LGT-001-C2",
    statement: "A caller assigns an ambiguous Claim to exactly one Criterion.",
    claimRefs: ["core-works"],
    gapRefs: []
  }]);
  mixedAmbiguityModel.plan.outcomes[0].acceptance.criteria[0].claimRefs.push("dependency-works");
  mixedAmbiguityModel.plan.outcomes[0].acceptance.claimRefs.push("dependency-works");
  const mixedChange = outcomeChange({
    claims: [
      { id: "core-works", statement: "Core remains correct." },
      { id: "dependency-works", statement: "Dependency remains correct." }
    ]
  });
  const partiallyResolved = compileChangeAgainstGovernance(mixedChange, governanceBaseline(mixedAmbiguityModel));
  assert.deepEqual(partiallyResolved.outcomeAlignment.contributions.map((entry) => entry.claimRefs), [
    ["dependency-works"]
  ]);
  const fullyResolved = compileChangeAgainstGovernance({
    ...mixedChange,
    compilerInput: {
      ...mixedChange.compilerInput,
      outcomeContributionHints: [{ outcomeRef: "LGT-001", criterionRefs: ["LGT-001-C2"] }]
    }
  }, governanceBaseline(mixedAmbiguityModel));
  assert.deepEqual(fullyResolved.outcomeAlignment.contributions.map((entry) => ({
    criterionRef: entry.criterionRef,
    claimRefs: entry.claimRefs
  })), [
    { criterionRef: "LGT-001-C1", claimRefs: ["dependency-works"] },
    { criterionRef: "LGT-001-C2", claimRefs: ["core-works"] }
  ]);

  const ambiguousModel = baseModel();
  enableOutcomeCriteria(ambiguousModel, [{
    id: "LGT-001-C2",
    statement: "A caller resolves a genuinely ambiguous Criterion explicitly.",
    claimRefs: ["core-works"],
    gapRefs: []
  }]);
  const ambiguousBaseline = governanceBaseline(ambiguousModel);
  const unresolved = compileChangeAgainstGovernance(change, ambiguousBaseline);
  assert.equal(unresolved.outcomeAlignment.status, "unresolved");
  assert.deepEqual(unresolved.outcomeAlignment.unresolved[0].candidateCriterionRefs, [
    "LGT-001-C1",
    "LGT-001-C2"
  ]);

  const hinted = compileChangeAgainstGovernance({
    ...change,
    compilerInput: {
      ...change.compilerInput,
      outcomeContributionHints: [{ outcomeRef: "LGT-001", criterionRefs: ["LGT-001-C2"] }]
    }
  }, ambiguousBaseline);
  assert.equal(hinted.outcomeAlignment.status, "complete");
  assert.deepEqual(hinted.outcomeAlignment.contributions.map((entry) => entry.criterionRef), ["LGT-001-C2"]);
  assert.throws(
    () => compileChangeAgainstGovernance({
      ...change,
      compilerInput: {
        ...change.compilerInput,
        outcomeContributionHints: [{ outcomeRef: "LGT-001", criterionRefs: ["LGT-001-C404"] }]
      }
    }, ambiguousBaseline),
    (error) => error.code === "OUTCOME_CRITERION_UNKNOWN"
  );
  assert.throws(
    () => compileChangeAgainstGovernance({
      ...change,
      compilerInput: {
        ...change.compilerInput,
        outcomeContributionHints: [{
          outcomeRef: "LGT-001",
          criterionRefs: ["LGT-001-C1", "LGT-001-C2"]
        }]
      }
    }, ambiguousBaseline),
    (error) => error.code === "OUTCOME_HINT_AMBIGUOUS"
  );

  ambiguousModel.projectDocument.changePolicy.outcomeAlignmentMode = "enforced";
  const enforcedAmbiguousBaseline = governanceBaseline(ambiguousModel);
  assert.throws(
    () => compileChangeAgainstGovernance(change, enforcedAmbiguousBaseline),
    (error) => error.code === "OUTCOME_CRITERION_AMBIGUOUS"
  );

  const inaccessibleModel = baseModel();
  addForeignContract(inaccessibleModel);
  enableOutcomeCriteria(inaccessibleModel, [], "foreign-works");
  assert.equal(validateProjectModel(inaccessibleModel).valid, true);
  const inaccessibleBaseline = governanceBaseline(inaccessibleModel);
  const foreignChange = outcomeChange({
    claims: [{ id: "foreign-works", statement: "The foreign Module remains correct." }]
  });
  const inaccessible = compileChangeAgainstGovernance(foreignChange, inaccessibleBaseline);
  assert.equal(inaccessible.outcomeAlignment.status, "unresolved");
  assert.ok(inaccessible.outcomeAlignment.unresolved[0].inaccessibleClaimRefs.includes("foreign-works"));

  const excepted = compileChangeAgainstGovernance({
    ...foreignChange,
    compilerInput: {
      ...foreignChange.compilerInput,
      outcomeExceptions: [{
        outcomeRef: "LGT-001",
        reason: "Required work has no honest accessible Criterion mapping.",
        residualUncertainty: "The exception records no Outcome progress."
      }]
    }
  }, inaccessibleBaseline);
  assert.equal(excepted.outcomeAlignment.status, "pending-authority");
  assert.deepEqual(excepted.outcomeAlignment.exceptions.map((entry) => ({
    requiredAuthorityRef: entry.requiredAuthorityRef,
    progress: entry.progress,
    transitionUse: entry.transitionUse
  })), [{ requiredAuthorityRef: "maintainer", progress: "none", transitionUse: "forbidden" }]);

  inaccessibleModel.projectDocument.changePolicy.outcomeAlignmentMode = "enforced";
  const enforcedInaccessibleBaseline = governanceBaseline(inaccessibleModel);
  assert.throws(
    () => compileChangeAgainstGovernance(foreignChange, enforcedInaccessibleBaseline),
    (error) => error.code === "OUTCOME_CONTRIBUTION_REQUIRED"
  );
  assert.throws(
    () => compileChangeAgainstGovernance({
      ...foreignChange,
      compilerInput: {
        ...foreignChange.compilerInput,
        outcomeExceptions: [{
          outcomeRef: "LGT-001",
          reason: "Required work has no honest accessible Criterion mapping.",
          residualUncertainty: "The exception records no Outcome progress."
        }]
      }
    }, enforcedInaccessibleBaseline),
    (error) => error.code === "OUTCOME_EXCEPTION_AUTHORITY_UNENFORCED"
  );
});

function enableOutcomeCriteria(model, additionalCriteria = [], claimRef = "core-works") {
  model.projectDocument.changePolicy.outcomeAlignmentMode = "declared";
  model.projectDocument.changePolicy.outcomeCriterionSelection = "unique-claim-match-or-explicit-hint";
  const outcome = model.plan.outcomes[0];
  const primaryCriterion = {
    id: "LGT-001-C1",
    statement: outcome.acceptance.exitCriteria[0],
    claimRefs: [claimRef],
    gapRefs: ["fixture-gap"]
  };
  outcome.acceptance.criteria = [primaryCriterion, ...structuredClone(additionalCriteria)];
  outcome.acceptance.exitCriteria = outcome.acceptance.criteria.map((criterion) => criterion.statement);
  outcome.acceptance.claimRefs = [...new Set(outcome.acceptance.criteria.flatMap((criterion) => criterion.claimRefs))];
  outcome.acceptance.gapRefs = [...new Set(outcome.acceptance.criteria.flatMap((criterion) => criterion.gapRefs))];
}

function governanceBaseline(model) {
  const snapshot = {
    schemaVersion: 1,
    modelDigest: "fixture-model",
    project: structuredClone(model.project),
    projectDocument: structuredClone(model.projectDocument),
    modules: structuredClone(model.modules),
    contracts: structuredClone(model.contracts),
    gates: structuredClone(model.gates),
    plan: structuredClone(model.plan),
    knowledgeGaps: structuredClone(model.knowledgeGaps),
    files: structuredClone(model.files)
  };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function outcomeChange(overrides = {}) {
  return {
    id: "compile-outcome-contribution",
    primaryModule: "core",
    changeKind: "implementation",
    planRefs: ["LGT-001"],
    claims: [{ id: "core-works", statement: "Core remains correct." }],
    compilerInput: {
      verificationObligations: [],
      impact: null,
      contextCapsule: null,
      outcomeContributionHints: [],
      outcomeExceptions: []
    },
    ...overrides
  };
}

function addForeignContract(model) {
  model.modules.push({
    id: "foreign",
    status: "governed",
    paths: { include: ["src/foreign/**"] },
    interface: { description: "Foreign behavior." },
    factAuthority: "facts",
    decisionAuthority: "maintainer",
    publicContracts: ["foreign-api"],
    dependencies: []
  });
  model.contracts.push({
    id: "foreign-api",
    owner: "foreign",
    consumers: [],
    normativeSources: ["requirements"],
    claims: [{ id: "foreign-works", statement: "The foreign Module remains correct." }]
  });
  model.projectDocument.assuranceBoundary.governed.push("foreign");
}

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
