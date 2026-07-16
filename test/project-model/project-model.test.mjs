import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileChangeAgainstGovernance } from "../../src/core/change-compiler.mjs";
import { compileOutcomeTransitions } from "../../src/core/outcome-transitions.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  compileClaimGateRoutes,
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

  const proofContractModel = structuredClone(criteriaModel);
  proofContractModel.knowledgeGaps[0].proofClaimRefs = ["dependency-works"];
  assert.equal(validateProjectModel(proofContractModel).valid, true);
  assert.deepEqual(compileClaimGateRoutes(proofContractModel, "dependency-works"), [{
    claimRef: "dependency-works",
    gateId: "minimum",
    commandId: "dependency-proof-command",
    command: [process.execPath, "-e", "process.exit(0)"],
    timeoutMs: null,
    effectiveModuleRefs: ["core"],
    oracle: {
      kind: "process-exit",
      description: "The dependency proof command exits zero only for the bounded fixture behavior."
    },
    applicability: { phase: "acceptance", dependency: "dependency" },
    discriminatoryPower: { rejects: ["an incorrect dependency behavior"] },
    residualUncertainty: ["The dependency proof remains bounded to the synthetic fixture."]
  }]);
  const unroutableProofContract = structuredClone(proofContractModel);
  unroutableProofContract.gates[0].commands = [unroutableProofContract.gates[0].commands[0]];
  assert.ok(validateProjectModel(unroutableProofContract).errors.some(
    (error) => error.code === "knowledge-gap.proof-claim.gate-route-missing"
  ));
  const disjointProofRoute = structuredClone(proofContractModel);
  disjointProofRoute.gates[0].appliesTo = ["dependency"];
  disjointProofRoute.gates[0].commands[1].appliesTo = ["core"];
  assert.ok(validateProjectModel(disjointProofRoute).errors.some(
    (error) => error.code === "knowledge-gap.proof-claim.gate-route-missing"
  ));
  const invalidGateTimeout = structuredClone(proofContractModel);
  invalidGateTimeout.gates[0].commands[1].timeoutMs = 0;
  assert.ok(validateProjectModel(invalidGateTimeout).errors.some(
    (error) => error.code === "gate.command.timeout.invalid"
  ));
  const duplicateGateClaim = structuredClone(proofContractModel);
  duplicateGateClaim.gates[0].commands[1].claimRefs.push("dependency-works");
  assert.ok(validateProjectModel(duplicateGateClaim).errors.some(
    (error) => error.code === "gate.claim.duplicate"
  ));
  const proofContractBaseline = governanceBaseline(proofContractModel);
  const closedProofContract = structuredClone(proofContractModel);
  closedProofContract.knowledgeGaps[0].status = "closed";
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: proofContractBaseline,
      currentModel: closedProofContract
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("gap-closure-transition-uncompiled")
  );
  const closedProofContractBaseline = governanceBaseline(closedProofContract);
  const rewrittenClosureHistory = structuredClone(closedProofContract);
  rewrittenClosureHistory.knowledgeGaps[0].resolution = "A replacement closure narrative.";
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: closedProofContractBaseline,
      currentModel: rewrittenClosureHistory
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("gap-closure-history-mismatch")
  );

  const rewrittenProofClaim = structuredClone(closedProofContract);
  rewrittenProofClaim.contracts[1].claims[0].statement = "A weaker dependency statement is substituted.";
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: proofContractBaseline,
      currentModel: rewrittenProofClaim
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("proof-claim-semantic-mismatch")
  );

  const movedProofClaim = structuredClone(closedProofContract);
  movedProofClaim.contracts[0].claims.push(movedProofClaim.contracts[1].claims.pop());
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: proofContractBaseline,
      currentModel: movedProofClaim
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("proof-claim-semantic-mismatch")
  );

  const unrelatedRouteExpansion = structuredClone(proofContractModel);
  unrelatedRouteExpansion.gates[0].commands[1].claimRefs.push("core-works");
  addForeignContract(unrelatedRouteExpansion);
  unrelatedRouteExpansion.gates[0].appliesTo.push("foreign");
  assert.deepEqual(
    compileClaimGateRoutes(unrelatedRouteExpansion, "dependency-works"),
    compileClaimGateRoutes(proofContractModel, "dependency-works")
  );
  assert.doesNotThrow(() => assertKnowledgeGapProofContractsPreserved({
    governanceBaseline: proofContractBaseline,
    currentModel: unrelatedRouteExpansion
  }));
  const scalarGateScope = structuredClone(proofContractModel);
  scalarGateScope.gates[0].appliesTo = "core";
  assert.deepEqual(
    compileClaimGateRoutes(scalarGateScope, "dependency-works"),
    compileClaimGateRoutes(proofContractModel, "dependency-works")
  );
  assert.doesNotThrow(() => assertKnowledgeGapProofContractsPreserved({
    governanceBaseline: proofContractBaseline,
    currentModel: scalarGateScope
  }));

  const proofRouteAttacks = [
    ["effective Module set", (model) => { delete model.gates[0].commands[1].appliesTo; }],
    ["scalar parent Gate effective scope", (model) => { model.gates[0].appliesTo = "dependency"; }],
    ["command", (model) => { model.gates[0].commands[1].command[2] = "process.exit(1)"; }],
    ["command id", (model) => { model.gates[0].commands[1].id = "substituted-proof-command"; }],
    ["timeout", (model) => { model.gates[0].commands[1].timeoutMs = 1; }],
    ["oracle", (model) => {
      model.gates[0].commands[1].oracle.description = "A weaker process-only oracle.";
    }],
    ["applicability", (model) => {
      model.gates[0].commands[1].applicability.phase = "release";
    }],
    ["discriminatory power", (model) => {
      model.gates[0].commands[1].discriminatoryPower = {
        rejects: ["only a weaker dependency failure"]
      };
    }],
    ["residual uncertainty", (model) => {
      model.gates[0].commands[1].residualUncertainty = ["The proof no longer has the declared bound."];
    }],
    ["second route for the same Claim", (model) => {
      model.gates[0].commands.push({
        ...structuredClone(model.gates[0].commands[1]),
        id: "second-dependency-proof-command"
      });
    }]
  ];
  for (const [name, mutate] of proofRouteAttacks) {
    const rewrittenProofRoute = structuredClone(proofContractModel);
    mutate(rewrittenProofRoute);
    assert.throws(
      () => assertKnowledgeGapProofContractsPreserved({
        governanceBaseline: proofContractBaseline,
        currentModel: rewrittenProofRoute
      }),
      (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
        && error.details.problems.includes("gate-route-semantic-mismatch"),
      name
    );
  }

  const fullGateProofContract = structuredClone(proofContractModel);
  fullGateProofContract.projectDocument.changePolicy.fullGate = "minimum";
  fullGateProofContract.gates[0].appliesTo = ["integration"];
  assert.equal(validateProjectModel(fullGateProofContract).valid, true);
  const rewrittenFullGatePolicy = structuredClone(fullGateProofContract);
  delete rewrittenFullGatePolicy.projectDocument.changePolicy.fullGate;
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: governanceBaseline(fullGateProofContract),
      currentModel: rewrittenFullGatePolicy
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("gate-route-semantic-mismatch")
  );

  const declarationBaselineModel = criteriaModel;
  const declaredOpenContract = structuredClone(declarationBaselineModel);
  declaredOpenContract.knowledgeGaps[0].proofClaimRefs = ["dependency-works"];
  assert.doesNotThrow(() => assertKnowledgeGapProofContractsPreserved({
    governanceBaseline: governanceBaseline(declarationBaselineModel),
    currentModel: declaredOpenContract
  }));
  declaredOpenContract.knowledgeGaps[0].status = "closed";
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: governanceBaseline(declarationBaselineModel),
      currentModel: declaredOpenContract
    }),
    (error) => error.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error.details.problems.includes("proof-contract-and-closure-mixed")
  );

  const invalidProofContracts = structuredClone(criteriaModel);
  invalidProofContracts.knowledgeGaps[0].proofClaimRefs = [
    "core-works",
    "missing-proof-claim",
    "missing-proof-claim"
  ];
  invalidProofContracts.knowledgeGaps.push({
    id: "second-fixture-gap",
    status: "open",
    statement: "A second Gap cannot own the first Gap's proof Claim.",
    proofClaimRefs: ["core-works"]
  });
  const invalidProofCodes = validateProjectModel(invalidProofContracts).errors
    .map((error) => error.code);
  assert.ok(invalidProofCodes.includes("knowledge-gap.proof-claim.unknown"));
  assert.ok(invalidProofCodes.includes("knowledge-gap.proof-claim.duplicate"));
  assert.ok(invalidProofCodes.includes("knowledge-gap.proof-claim.criterion-overlap"));
  assert.ok(invalidProofCodes.includes("knowledge-gap.proof-claim.shared"));
  const emptyProofContract = structuredClone(criteriaModel);
  emptyProofContract.knowledgeGaps[0].proofClaimRefs = [];
  assert.ok(validateProjectModel(emptyProofContract).errors.some(
    (error) => error.code === "knowledge-gap.proof-claim.invalid"
  ));

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
  model.projectDocument.changePolicy.outcomeTransitionMode = "automatic";
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

  const duplicateGapModel = baseModel();
  duplicateGapModel.knowledgeGaps.push(structuredClone(duplicateGapModel.knowledgeGaps[0]));
  assert.ok(validateProjectModel(duplicateGapModel).errors
    .some((error) => error.code === "knowledge-gap.id.duplicate"));
});

test("Outcome Contributions and Transitions bind exact Claims, Criteria, Evidence, and history", () => {
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
  const enforcedException = compileChangeAgainstGovernance({
    ...foreignChange,
    compilerInput: {
      ...foreignChange.compilerInput,
      outcomeExceptions: [{
        outcomeRef: "LGT-001",
        reason: "Required work has no honest accessible Criterion mapping.",
        residualUncertainty: "The exception records no Outcome progress."
      }]
    }
  }, enforcedInaccessibleBaseline);
  assert.equal(enforcedException.outcomeAlignment.status, "pending-authority");
  assert.deepEqual(enforcedException.outcomeAlignment.exceptions.map((entry) => entry.requiredAuthorityRef), [
    "maintainer"
  ]);

  const transitionCase = transitionFixture();
  const transitionCompiled = compileOutcomeTransitions(transitionCase);
  const transitionRepeated = compileOutcomeTransitions(transitionCase);
  assert.deepEqual(transitionCompiled, transitionRepeated);
  const routeExpansionTransition = transitionFixture();
  routeExpansionTransition.currentModel.gates[0].commands[1].claimRefs.push("core-works");
  addForeignContract(routeExpansionTransition.currentModel);
  routeExpansionTransition.currentModel.gates[0].appliesTo.push("foreign");
  assert.equal(compileOutcomeTransitions(routeExpansionTransition).status, "complete");
  assert.equal(transitionCompiled.schemaVersion, 1);
  assert.equal(transitionCompiled.mode, "enforced");
  assert.equal(transitionCompiled.status, "complete");
  assert.equal(transitionCompiled.requiredAuthorityRef, "maintainer");
  assert.equal(transitionCompiled.priorAcceptedPackagesDigest, transitionCase.priorAcceptedPackages.digest);
  assert.match(transitionCompiled.digest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(transitionCompiled.appendedTransitions.map((entry) => ({
    id: entry.id,
    outcomeRef: entry.outcomeRef,
    route: `${entry.from}->${entry.to}`,
    criterionRefs: entry.criterionProofs.map((proof) => proof.criterionRef),
    gapRefs: entry.gapDispositions.map((gap) => gap.gapRef)
  })), [{
    id: "LGT-001-T1",
    outcomeRef: "LGT-001",
    route: "active->achieved",
    criterionRefs: ["LGT-001-C1", "LGT-001-C2"],
    gapRefs: ["fixture-gap"]
  }]);
  const projectedProofs = transitionCompiled.appendedTransitions[0].criterionProofs;
  assert.deepEqual(projectedProofs.map((proof) => proof.claimRefs), [
    ["core-works"],
    ["dependency-works"]
  ]);
  assert.ok(projectedProofs.every((proof) => (
    proof.packages.length === 1
      && proof.authorityAssessment.conclusion === "satisfied"
      && proof.authorityAssessment.rationale.length > 20
      && proof.authorityAssessment.residualUncertainty.length > 20
      && proof.packages[0].evidenceBindings.length === 1
      && proof.packages[0].evidenceBindings[0].observationStatus === "passed"
      && /^sha256:[a-f0-9]{64}$/u.test(proof.packages[0].evidenceBindings[0].evidenceDigest)
  )));
  assert.equal(
    Object.hasOwn(projectedProofs[0].packages[0].evidenceBindings[0], "provenanceKind"),
    false
  );
  const gapProof = transitionCompiled.appendedTransitions[0].gapDispositions[0];
  assert.deepEqual(gapProof.proofClaimRefs, ["dependency-works"]);
  assert.deepEqual(
    gapProof.packages.map((entry) => ({
      changeId: entry.changeId,
      acceptanceDigest: entry.acceptanceDigest,
      claimRefs: entry.claimRefs,
      evidenceRoutes: entry.evidenceBindings.map((binding) => ({
        provenanceKind: binding.provenanceKind,
        gateId: binding.gateId,
        commandId: binding.commandId,
        claimRefs: binding.claimRefs
      }))
    })),
    [{
      ...transitionCase.packageRef,
      claimRefs: ["dependency-works"],
      evidenceRoutes: [{
        provenanceKind: "gate-command",
        gateId: "minimum",
        commandId: "dependency-proof-command",
        claimRefs: ["dependency-works"]
      }]
    }]
  );
  const legacyTransitionCompiled = compileOutcomeTransitions(transitionFixture({ proofContract: false }));
  const legacyGap = legacyTransitionCompiled.appendedTransitions[0].gapDispositions[0];
  assert.equal(Object.hasOwn(legacyGap, "proofClaimRefs"), false);
  assert.deepEqual(Object.keys(legacyGap.packages[0]).sort(), [
    "acceptanceDigest",
    "acceptedAt",
    "changeId"
  ]);

  const transitionFailures = [
    {
      name: "Gap closed without an Outcome Transition consuming the closure",
      code: "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      mutate(fixture) {
        fixture.currentModel.plan.outcomes[0].status = "active";
        fixture.currentModel.plan.outcomeTransitions = [];
      }
    },
    {
      name: "missing stable Criterion proof",
      code: "OUTCOME_TRANSITION_CRITERIA_INCOMPLETE",
      mutate(fixture) {
        fixture.currentModel.plan.outcomeTransitions[0].criterionAssessments.pop();
      }
    },
    {
      name: "wrong Claim coverage",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        const contribution = fixture.acceptedRecord.acceptance.package.outcomeAlignment.contributions
          .find((entry) => entry.criterionRef === "LGT-001-C2");
        contribution.claimRefs = ["core-works"];
        const criterion = fixture.governanceBaseline.plan.outcomes[0].acceptance.criteria
          .find((entry) => entry.id === "LGT-001-C2");
        const claim = fixture.acceptedRecord.acceptance.package.claims
          .find((entry) => entry.id === "core-works");
        contribution.bindingDigest = canonicalDigest({
          schemaVersion: 1,
          changeId: fixture.acceptedRecord.id,
          governanceBaselineDigest: fixture.governanceBaseline.digest,
          outcome: { id: "LGT-001", statement: fixture.governanceBaseline.plan.outcomes[0].outcome },
          criterion,
          moduleRef: "core",
          claims: [claim]
        });
        contribution.contributionId = `oc-${contribution.bindingDigest.slice("sha256:".length)}`;
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "non-progress exception used as proof",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        const alignment = fixture.acceptedRecord.acceptance.package.outcomeAlignment;
        alignment.contributions = [];
        alignment.exceptions = [{
          outcomeRef: "LGT-001",
          progress: "none",
          transitionUse: "forbidden"
        }];
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "indirect-only Evidence used as Gap closure proof",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        const evidence = fixture.acceptedRecord.acceptance.package.evidence
          .find((item) => item.id === "evidence-dependency-works");
        evidence.directSupportBindings = [];
        evidence.supportBindings = [{
          obligationId: "indirect-fixture-obligation",
          claimId: "dependency-works"
        }];
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "Evidence self-identifies as Gate output but its bound run is not configured",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        fixture.acceptedRecord.acceptance.package.gateRuns[0].kind = "builtin-oracle";
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "configured Gate selection does not contain the proof command",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        fixture.acceptedRecord.acceptance.package.gateRuns[0].selection.selectedCommandIds = [
          "minimum-command"
        ];
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "Package accepted before the Gap proof Contract declaration",
      code: "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      mutate(fixture) {
        const packageBaseline = fixture.acceptedRecord.acceptance.package.governanceBaseline;
        delete packageBaseline.knowledgeGaps[0].proofClaimRefs;
        refreshGovernanceDigest(packageBaseline);
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "Package froze a proof Claim under the wrong Contract owner",
      code: "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      mutate(fixture) {
        const packageBaseline = fixture.acceptedRecord.acceptance.package.governanceBaseline;
        packageBaseline.contracts[0].claims.push(packageBaseline.contracts[1].claims.pop());
        refreshGovernanceDigest(packageBaseline);
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "unrelated accepted implementation used as closedBy proof",
      code: "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      mutate(fixture) {
        replaceTransitionProofPackage(fixture, outcomeChange({
          id: "accepted-unrelated-implementation",
          claims: [{ id: "core-works", statement: "Core remains correct." }]
        }));
      }
    },
    {
      name: "current Gate proof route drift",
      code: "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN",
      mutate(fixture) {
        fixture.currentModel.gates[0].commands[1].command = [
          process.execPath,
          "-e",
          "process.exit(1)"
        ];
      }
    },
    {
      name: "Package Gate proof route drift",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        const packageBaseline = fixture.acceptedRecord.acceptance.package.governanceBaseline;
        packageBaseline.gates[0].commands[1].oracle.description =
          "A historically weaker oracle no longer matches the Closure Contract route.";
        refreshGovernanceDigest(packageBaseline);
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "inexact closed Gap disposition",
      code: "OUTCOME_TRANSITION_GAP_UNRESOLVED",
      mutate(fixture) {
        fixture.currentModel.plan.outcomeTransitions[0].gapDispositions = [];
      }
    },
    {
      name: "Knowledge Gap meaning rewritten during closure",
      code: "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN",
      mutate(fixture) {
        fixture.currentModel.knowledgeGaps[0].statement = "A weaker uncertainty replaces the frozen Gap.";
      }
    },
    {
      name: "status change without a ledger entry",
      code: "OUTCOME_TRANSITION_STATUS_UNBOUND",
      mutate(fixture) {
        fixture.currentModel.plan.outcomeTransitions = [];
      }
    },
    {
      name: "ledger entry without a status change",
      code: "OUTCOME_TRANSITION_STATUS_UNBOUND",
      mutate(fixture) {
        fixture.currentModel.plan.outcomes[0].status = "active";
      }
    },
    {
      name: "unsupported lifecycle edge",
      code: "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
      mutate(fixture) {
        fixture.currentModel.plan.outcomes[0].status = "planned";
        fixture.currentModel.plan.outcomeTransitions[0].to = "planned";
      }
    },
    {
      name: "unfrozen plain Package catalog",
      code: "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      mutate(fixture) {
        fixture.priorAcceptedPackages = fixture.priorAcceptedPackages.entries;
      }
    },
    {
      name: "Evidence bound to another Change",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        fixture.acceptedRecord.acceptance.package.evidence[0].provenance.changeId = "another-change";
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "Evidence carried by a failed Gate run",
      code: "OUTCOME_TRANSITION_PROOF_INELIGIBLE",
      mutate(fixture) {
        fixture.acceptedRecord.acceptance.package.gateRuns[0].status = "failed";
        resealFixtureRecord(fixture);
      }
    },
    {
      name: "Accepted timestamp disagrees with history",
      code: "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      mutate(fixture) {
        fixture.acceptedRecord.acceptance.acceptedAt = "2026-07-16T10:30:00.000Z";
      }
    },
    {
      name: "Package accepted after Candidate creation",
      code: "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      mutate(fixture) {
        const acceptedAt = "2030-01-01T00:00:00.000Z";
        fixture.acceptedRecord.acceptance.acceptedAt = acceptedAt;
        fixture.acceptedRecord.history[0].at = acceptedAt;
      }
    },
    {
      name: "Outcome semantics rewritten without a status delta",
      code: "OUTCOME_TRANSITION_ROUTE_FORBIDDEN",
      mutate(fixture) {
        fixture.currentModel.plan.outcomes[0].status = "active";
        fixture.currentModel.plan.outcomes[0].outcome = "A rewritten Outcome is not lifecycle evidence.";
        fixture.currentModel.plan.outcomeTransitions = [];
      }
    },
    {
      name: "invalid frozen Governance Baseline seal",
      code: "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID",
      mutate(fixture) {
        fixture.governanceBaseline.digest = `sha256:${"0".repeat(64)}`;
      }
    }
  ];
  for (const scenario of transitionFailures) {
    const fixture = transitionFixture();
    scenario.mutate(fixture);
    assert.throws(
      () => compileOutcomeTransitions(fixture),
      (error) => error.code === scenario.code,
      scenario.name
    );
  }

  const satisfiedEvidence = transitionFixture();
  satisfiedEvidence.acceptedRecord.acceptance.package.evidence[0].observation.status = "satisfied";
  resealFixtureRecord(satisfiedEvidence);
  assert.equal(compileOutcomeTransitions(satisfiedEvidence).status, "complete");

  const historicallyAccepted = transitionFixture();
  historicallyAccepted.acceptedRecord.state = "Submitted";
  historicallyAccepted.acceptedRecord.history.push({
    from: "Accepted",
    to: "Submitted",
    at: "2026-07-16T11:00:00.000Z",
    reason: "Current repository drift invalidated applicability, not the historical Package seal."
  });
  assert.equal(compileOutcomeTransitions(historicallyAccepted).status, "complete");

  const rewrittenPrefix = transitionFixture();
  const sealedPrefix = {
    id: "LGT-000-T1",
    outcomeRef: "LGT-000",
    from: "active",
    to: "retired",
    rationale: "A prior sealed transition is immutable.",
    packageRefs: [],
    criterionAssessments: [],
    gapDispositions: []
  };
  rewrittenPrefix.governanceBaseline.plan.outcomeTransitions = [sealedPrefix];
  refreshGovernanceDigest(rewrittenPrefix.governanceBaseline);
  rewrittenPrefix.currentModel.plan.outcomeTransitions = [
    { ...structuredClone(sealedPrefix), rationale: "A rewritten historical rationale is forbidden." },
    rewrittenPrefix.transition
  ];
  assert.throws(
    () => compileOutcomeTransitions(rewrittenPrefix),
    (error) => error.code === "OUTCOME_TRANSITION_LEDGER_REWRITE_FORBIDDEN"
  );

  const declaredMissingLedger = transitionFixture({ mode: "declared" });
  declaredMissingLedger.currentModel.plan.outcomeTransitions = [];
  declaredMissingLedger.currentModel.knowledgeGaps[0] = structuredClone(
    declaredMissingLedger.governanceBaseline.knowledgeGaps[0]
  );
  const declaredCompilation = compileOutcomeTransitions(declaredMissingLedger);
  assert.equal(declaredCompilation.status, "unresolved");
  assert.deepEqual(declaredCompilation.unresolved, [{
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved",
    reason: "status-delta-has-no-appended-transition"
  }]);

  const conditionalActivation = transitionFixture();
  const frozenTarget = conditionalActivation.governanceBaseline.plan.outcomes[0];
  const currentTarget = conditionalActivation.currentModel.plan.outcomes[0];
  frozenTarget.status = "conditional";
  currentTarget.status = "active";
  frozenTarget.acceptance.activationCriterionRefs = ["LGT-001-C1"];
  currentTarget.acceptance.activationCriterionRefs = ["LGT-001-C1"];
  frozenTarget.dependsOn = ["LGT-000"];
  currentTarget.dependsOn = ["LGT-000"];
  const achievedDependency = {
    id: "LGT-000",
    stage: "S1",
    status: "achieved",
    outcome: "A frozen bootstrap dependency is already achieved.",
    dependsOn: [],
    acceptance: { exitCriteria: ["Bootstrap records this prior Outcome."] }
  };
  conditionalActivation.governanceBaseline.plan.outcomes.push(achievedDependency);
  conditionalActivation.currentModel.plan.outcomes.push(structuredClone(achievedDependency));
  conditionalActivation.governanceBaseline.plan.bootstrapBaseline = {
    head: "0000000000000000000000000000000000000000",
    outcomeRefs: ["LGT-000"],
    rationale: "The fixture dependency predates governed Transition history.",
    residualUncertainty: "Only the fixture dependency is bootstrapped."
  };
  conditionalActivation.currentModel.plan.bootstrapBaseline = structuredClone(
    conditionalActivation.governanceBaseline.plan.bootstrapBaseline
  );
  conditionalActivation.transition.from = "conditional";
  conditionalActivation.transition.to = "active";
  conditionalActivation.transition.criterionAssessments = conditionalActivation.transition.criterionAssessments
    .filter((assessment) => assessment.criterionRef === "LGT-001-C1");
  refreshGovernanceDigest(conditionalActivation.governanceBaseline);
  const activationCompilation = compileOutcomeTransitions(conditionalActivation);
  assert.deepEqual(activationCompilation.appendedTransitions[0].dependencyProofs, [{
    outcomeRef: "LGT-000",
    source: "bootstrap-baseline",
    head: "0000000000000000000000000000000000000000"
  }]);
  assert.deepEqual(
    activationCompilation.appendedTransitions[0].criterionProofs.map((proof) => proof.criterionRef),
    ["LGT-001-C1"]
  );

  const unsatisfiedFrozenDependency = structuredClone(conditionalActivation);
  unsatisfiedFrozenDependency.governanceBaseline.plan.outcomes
    .find((outcome) => outcome.id === "LGT-000").status = "planned";
  unsatisfiedFrozenDependency.currentModel.plan.outcomes
    .find((outcome) => outcome.id === "LGT-000").status = "planned";
  refreshGovernanceDigest(unsatisfiedFrozenDependency.governanceBaseline);
  assert.throws(
    () => compileOutcomeTransitions(unsatisfiedFrozenDependency),
    (error) => error.code === "OUTCOME_TRANSITION_ROUTE_FORBIDDEN"
      && error.details.dependencyRef === "LGT-000"
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

function transitionFixture({ mode = "enforced", proofContract = true } = {}) {
  const baselineModel = baseModel();
  enableOutcomeCriteria(baselineModel, [{
    id: "LGT-001-C2",
    statement: "The dependency behavior remains covered by discriminating Evidence.",
    claimRefs: ["dependency-works"],
    gapRefs: []
  }]);
  if (proofContract) baselineModel.knowledgeGaps[0].proofClaimRefs = ["dependency-works"];
  baselineModel.projectDocument.changePolicy.outcomeTransitionMode = mode;
  baselineModel.plan.outcomeTransitions = [];
  const governance = governanceBaseline(baselineModel);
  const implementationChange = outcomeChange({
    id: "accepted-transition-evidence",
    claims: [
      { id: "dependency-works", statement: "Dependency remains correct." },
      { id: "core-works", statement: "Core remains correct." }
    ]
  });
  const compiledImplementation = compileChangeAgainstGovernance(implementationChange, governance);
  const acceptedRecord = sealedAcceptedRecord({
    change: implementationChange,
    governanceBaseline: governance,
    outcomeAlignment: compiledImplementation.outcomeAlignment
  });
  const packageRef = {
    changeId: acceptedRecord.id,
    acceptanceDigest: acceptedRecord.acceptance.digest
  };
  const transition = {
    id: "LGT-001-T1",
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved",
    rationale: "Both stable Criteria have exact prior Accepted Package Evidence.",
    packageRefs: [structuredClone(packageRef), structuredClone(packageRef)],
    criterionAssessments: ["LGT-001-C2", "LGT-001-C1"].map((criterionRef) => ({
      criterionRef,
      authorityAssessment: {
        conclusion: "satisfied",
        rationale: `The sealed implementation Package directly covers ${criterionRef}.`,
        residualUncertainty: "The fixture authority identity is locally asserted."
      }
    })),
    gapDispositions: [{
      gapRef: "fixture-gap",
      rationale: "The same sealed Package closes the exact bounded fixture Gap."
    }]
  };
  const currentModel = structuredClone(baselineModel);
  currentModel.plan.outcomes[0].status = "achieved";
  currentModel.plan.outcomeTransitions = [transition];
  currentModel.knowledgeGaps[0] = {
    ...currentModel.knowledgeGaps[0],
    status: "closed",
    resolution: "The exact accepted transition fixture supplies discriminating Evidence.",
    reopenTrigger: "Reopen if the sealed Package or exact Criterion Evidence binding is weakened.",
    closedBy: [structuredClone(packageRef)]
  };
  return {
    change: {
      id: "achieve-fixture-outcome",
      changeKind: "plan-amendment",
      createdAt: "2026-07-16T12:00:00.000Z",
      authorityDecision: {
        status: "approved",
        authority: "maintainer",
        decidedBy: "fixture-maintainer",
        decisionType: "normative-amendment",
        rationale: "The exact prior Evidence satisfies every stable Criterion."
      }
    },
    governanceBaseline: governance,
    currentModel,
    resolvedPackages: [acceptedRecord],
    priorAcceptedPackages: acceptedPackageCatalog([packageRef]),
    acceptedRecord,
    packageRef,
    transition
  };
}

function sealedAcceptedRecord({ change, governanceBaseline, outcomeAlignment }) {
  const acceptedAt = "2026-07-16T10:00:00.000Z";
  const gate = governanceBaseline.gates.find((candidate) => candidate.id === "minimum");
  const evidence = change.claims.map((claim) => {
    const command = gate.commands.find((candidate) => candidate.claimRefs.includes(claim.id));
    return {
      id: `evidence-${claim.id}`,
      claim: structuredClone(claim),
      oracle: structuredClone(command.oracle),
      observation: { status: "passed", exitCode: 0 },
      provenance: {
        kind: "gate-command",
        changeId: change.id,
        gateId: gate.id,
        commandId: command.id,
        command: structuredClone(command.command),
        verificationSubjectDigest: "sha256:fixture-subject",
        projectModelDigest: "sha256:fixture-model",
        git: { contentDigest: "sha256:fixture-git" }
      },
      applicability: { ...structuredClone(command.applicability), module: change.primaryModule },
      discriminatoryPower: structuredClone(command.discriminatoryPower),
      residualUncertainty: structuredClone(command.residualUncertainty),
      directSupportBindings: [{ claimId: claim.id, claimStatement: claim.statement }]
    };
  });
  const acceptedPackage = {
    schemaVersion: 1,
    changeId: change.id,
    primaryModule: change.primaryModule,
    changeKind: "implementation",
    planRefs: structuredClone(change.planRefs),
    claims: structuredClone(change.claims),
    outcomeContributionHints: structuredClone(change.compilerInput?.outcomeContributionHints ?? []),
    outcomeExceptions: structuredClone(change.compilerInput?.outcomeExceptions ?? []),
    evidence,
    gateRuns: [{
      gateId: "minimum",
      kind: "configured-gate",
      status: "passed",
      projectModelDigest: "sha256:fixture-model",
      gitContentDigest: "sha256:fixture-git",
      verificationSubjectDigest: "sha256:fixture-subject",
      selection: {
        primaryModule: change.primaryModule,
        selectedCommandIds: evidence.map((item) => item.provenance.commandId),
        skippedCommandIds: []
      },
      commandResults: evidence.map((item) => ({
        id: item.provenance.commandId,
        status: "passed",
        exitCode: 0,
        evidenceId: item.id
      })),
      evidenceIds: evidence.map((item) => item.id),
      evidenceBindings: evidence.map((item) => ({ id: item.id, digest: canonicalDigest(item) }))
    }],
    outcomeAlignment: structuredClone(outcomeAlignment),
    governanceBaseline: structuredClone(governanceBaseline)
  };
  const digest = canonicalDigest(acceptedPackage);
  return {
    id: change.id,
    state: "Accepted",
    history: [{ from: "EvidenceReady", to: "Accepted", at: acceptedAt, digest }],
    acceptance: {
      valid: false,
      acceptedAt,
      digest,
      package: acceptedPackage
    }
  };
}

function replaceTransitionProofPackage(fixture, implementationChange) {
  const compiled = compileChangeAgainstGovernance(implementationChange, fixture.governanceBaseline);
  const acceptedRecord = sealedAcceptedRecord({
    change: implementationChange,
    governanceBaseline: fixture.governanceBaseline,
    outcomeAlignment: compiled.outcomeAlignment
  });
  const packageRef = {
    changeId: acceptedRecord.id,
    acceptanceDigest: acceptedRecord.acceptance.digest
  };
  fixture.acceptedRecord = acceptedRecord;
  fixture.packageRef = packageRef;
  fixture.resolvedPackages = [acceptedRecord];
  fixture.transition.packageRefs = [structuredClone(packageRef)];
  fixture.currentModel.plan.outcomeTransitions[0].packageRefs = [structuredClone(packageRef)];
  fixture.currentModel.knowledgeGaps[0].closedBy = [structuredClone(packageRef)];
  fixture.priorAcceptedPackages = acceptedPackageCatalog([packageRef]);
}

function resealFixtureRecord(fixture) {
  const packageContent = fixture.acceptedRecord.acceptance.package;
  for (const run of packageContent.gateRuns) {
    for (const binding of run.evidenceBindings ?? []) {
      const evidence = packageContent.evidence.find((item) => item.id === binding.id);
      if (evidence) binding.digest = canonicalDigest(evidence);
    }
  }
  const digest = canonicalDigest(packageContent);
  fixture.acceptedRecord.acceptance.digest = digest;
  fixture.acceptedRecord.history[0].digest = digest;
  fixture.packageRef.acceptanceDigest = digest;
  const retarget = (refs) => {
    for (const ref of refs ?? []) {
      if (ref.changeId === fixture.acceptedRecord.id) ref.acceptanceDigest = digest;
    }
  };
  retarget(fixture.currentModel.plan.outcomeTransitions[0].packageRefs);
  retarget(fixture.currentModel.knowledgeGaps[0].closedBy);
  retarget(fixture.priorAcceptedPackages.entries);
  fixture.priorAcceptedPackages = acceptedPackageCatalog(fixture.priorAcceptedPackages.entries);
}

function acceptedPackageCatalog(entries) {
  const snapshot = {
    schemaVersion: 1,
    entries: structuredClone(entries).sort((left, right) => (
      left.changeId.localeCompare(right.changeId)
        || left.acceptanceDigest.localeCompare(right.acceptanceDigest)
    ))
  };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function refreshGovernanceDigest(governanceBaseline) {
  const { digest: ignored, ...snapshot } = governanceBaseline;
  governanceBaseline.digest = canonicalDigest(snapshot);
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
      }, {
        id: "dependency-proof-command",
        command: [process.execPath, "-e", "process.exit(0)"],
        appliesTo: ["core"],
        claimRefs: ["dependency-works"],
        oracle: {
          kind: "process-exit",
          description: "The dependency proof command exits zero only for the bounded fixture behavior."
        },
        applicability: { phase: "acceptance", dependency: "dependency" },
        discriminatoryPower: { rejects: ["an incorrect dependency behavior"] },
        residualUncertainty: ["The dependency proof remains bounded to the synthetic fixture."]
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
    knowledgeGaps: [{
      id: "fixture-gap",
      status: "open",
      statement: "The fixture leaves one bounded uncertainty."
    }],
    files: []
  };
}
