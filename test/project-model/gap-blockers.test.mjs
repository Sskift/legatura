import assert from "node:assert/strict";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { compileChangeAgainstGovernance } from "../../src/core/change-compiler.mjs";
import {
  compileOutcomeTransitions,
  validateOutcomeTransitionLedger
} from "../../src/core/outcome-transitions.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  validateProjectModel
} from "../../src/core/project-model.mjs";

test("Knowledge Gap blockers are exact, append-only, transitive Transition prerequisites", () => {
  const model = blockerModel();
  assert.equal(validateProjectModel(model).valid, true);

  const invalidCases = [{
    code: "knowledge-gap.blocker-source.proof-contract-missing",
    mutate(candidate) {
      delete gap(candidate, "blocker-a").proofClaimRefs;
    }
  }, {
    code: "knowledge-gap.blocked-gap.duplicate",
    mutate(candidate) {
      gap(candidate, "blocker-a").blocksGapClosureRefs.push("target-gap");
    }
  }, {
    code: "knowledge-gap.blocked-gap.unknown",
    mutate(candidate) {
      gap(candidate, "blocker-a").blocksGapClosureRefs = ["unknown-gap"];
    }
  }, {
    code: "knowledge-gap.blocked-gap.self",
    mutate(candidate) {
      gap(candidate, "blocker-a").blocksGapClosureRefs = ["blocker-a"];
    }
  }, {
    code: "knowledge-gap.blocked-route.invalid",
    mutate(candidate) {
      gap(candidate, "route-blocker").blocksOutcomeTransitionRoutes[0].reason = "caller prose";
    }
  }, {
    code: "knowledge-gap.blocker-cycle",
    mutate(candidate) {
      const target = gap(candidate, "target-gap");
      target.proofClaimRefs = ["target-works"];
      target.blocksGapClosureRefs = ["blocker-b"];
    }
  }, {
    code: "knowledge-gap.blocked-gap.already-closed",
    mutate(candidate) {
      closeGap(candidate, "target-gap", fixturePackageRef());
    }
  }, {
    code: "knowledge-gap.blocked-route.state-bypassed",
    mutate(candidate) {
      candidate.plan.outcomes[0].status = "achieved";
    }
  }];
  for (const { code, mutate } of invalidCases) {
    const candidate = structuredClone(model);
    mutate(candidate);
    assert.ok(
      validateProjectModel(candidate).errors.some((error) => error.code === code),
      `expected static blocker rejection ${code}`
    );
  }

  const retiredRouteEscape = structuredClone(model);
  retiredRouteEscape.plan.outcomes[0].status = "retired";
  assert.equal(
    validateProjectModel(retiredRouteEscape).errors.some((error) => (
      error.code === "knowledge-gap.blocked-route.state-bypassed"
        || error.code === "knowledge-gap.blocked-route.already-transitioned"
    )),
    false,
    "active->retired remains reachable when only active->achieved is blocked"
  );

  const closedHistory = structuredClone(model);
  for (const historicalGap of closedHistory.knowledgeGaps) {
    closeGap(closedHistory, historicalGap.id, fixturePackageRef());
  }
  assert.equal(
    validateProjectModel(closedHistory).valid,
    true,
    "retained historical relations remain valid after their source and target close"
  );

  const removed = transitionFixture();
  delete gap(removed.currentModel, "blocker-a").blocksGapClosureRefs;
  assert.throws(
    () => assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: removed.governanceBaseline,
      currentModel: removed.currentModel
    }),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_REWRITE_FORBIDDEN"
      && error.details.problems.includes("blocker-relation-removed-or-mutated")
  );

  const postClosureExtension = noTransitionFixture((baselineModel) => {
    baselineModel.knowledgeGaps.push({
      id: "closed-source",
      status: "closed",
      statement: "This source was closed before any blocker relation was declared.",
      proofClaimRefs: ["target-works"],
      resolution: "The isolated source was resolved earlier.",
      reopenTrigger: "Reopen if its exact historical proof changes.",
      closedBy: [fixturePackageRef()]
    });
  });
  gap(postClosureExtension.currentModel, "closed-source").blocksOutcomeTransitionRoutes = [{
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved"
  }];
  assert.throws(
    () => compileOutcomeTransitions(postClosureExtension),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_REWRITE_FORBIDDEN"
      && error.details.problems.includes("blocker-source-not-open-across-amendment")
  );

  const bootstrapDeclaration = noTransitionFixture();
  bootstrapDeclaration.currentModel.knowledgeGaps.push({
    id: "new-open-source",
    status: "open",
    statement: "A later-discovered prerequisite is declared before either side closes.",
    proofClaimRefs: ["target-works"],
    blocksGapClosureRefs: ["target-gap"]
  });
  assert.equal(
    compileOutcomeTransitions(bootstrapDeclaration).status,
    "not-applicable",
    "a new open source may declare its proof contract and blocker relation together"
  );

  const existingRetirementEscape = noTransitionFixture();
  existingRetirementEscape.currentModel.plan.outcomes[0].status = "retired";
  assert.equal(assertKnowledgeGapProofContractsPreserved({
    governanceBaseline: existingRetirementEscape.governanceBaseline,
    currentModel: existingRetirementEscape.currentModel
  }).valid, true);

  const newRetirementEscape = noTransitionFixture((baselineModel) => {
    delete gap(baselineModel, "route-blocker").blocksOutcomeTransitionRoutes;
  });
  newRetirementEscape.currentModel.plan.outcomes[0].status = "retired";
  gap(newRetirementEscape.currentModel, "route-blocker").blocksOutcomeTransitionRoutes = [{
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved"
  }];
  assert.equal(assertKnowledgeGapProofContractsPreserved({
    governanceBaseline: newRetirementEscape.governanceBaseline,
    currentModel: newRetirementEscape.currentModel
  }).valid, true);

  const newOutcomeRoute = noTransitionFixture();
  newOutcomeRoute.currentModel.plan.stages[0].outcomeRefs.push("LGT-002");
  newOutcomeRoute.currentModel.plan.outcomes.push({
    id: "LGT-002",
    stage: "S1",
    status: "planned",
    outcome: "A newly declared Outcome remains blocked before activation.",
    dependsOn: [],
    acceptance: {
      exitCriteria: ["The new Outcome has an exact future proof."],
      claimRefs: ["target-works"],
      gapRefs: []
    }
  });
  gap(newOutcomeRoute.currentModel, "route-blocker").blocksOutcomeTransitionRoutes.push({
    outcomeRef: "LGT-002",
    from: "active",
    to: "achieved"
  });
  assert.equal(validateProjectModel(newOutcomeRoute.currentModel).valid, true);
  assert.equal(
    compileOutcomeTransitions(newOutcomeRoute).status,
    "not-applicable",
    "an open source may predeclare a future route blocker before a planned Outcome reaches from"
  );

  const successfulFixture = transitionFixture();
  const compilation = compileOutcomeTransitions(successfulFixture);
  assert.equal(compilation.status, "complete");
  assert.deepEqual(
    compileOutcomeTransitions(successfulFixture),
    compilation,
    "repeated compilation is deterministic"
  );
  assert.deepEqual(
    compilation.appendedTransitions[0].gapDispositions.map((entry) => entry.gapRef),
    ["blocker-a", "blocker-b", "route-blocker", "target-gap"],
    "the compiler derives route blockers and transitive incoming Gap blockers from the frozen baseline"
  );

  const missingTransitive = transitionFixture();
  missingTransitive.currentModel.plan.outcomeTransitions[0].gapDispositions =
    missingTransitive.currentModel.plan.outcomeTransitions[0].gapDispositions
      .filter((entry) => entry.gapRef !== "blocker-b");
  assert.throws(
    () => compileOutcomeTransitions(missingTransitive),
    (error) => error.code === "OUTCOME_TRANSITION_GAP_UNRESOLVED"
      && error.details.missingGapRefs.includes("blocker-b")
  );

  const forgedClearance = transitionFixture();
  gap(forgedClearance.currentModel, "blocker-b").status = "open";
  delete gap(forgedClearance.currentModel, "blocker-b").resolution;
  delete gap(forgedClearance.currentModel, "blocker-b").reopenTrigger;
  delete gap(forgedClearance.currentModel, "blocker-b").closedBy;
  assert.throws(
    () => compileOutcomeTransitions(forgedClearance),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_RELATION_INVALID"
      && error.details.problems.includes("open-blocker-target-gap-already-closed")
  );

  const wrongTargetContribution = transitionFixture();
  wrongTargetContribution.resolvedPackages[0].acceptance.package
    .outcomeAlignment.contributions[0].outcomeRef = "LGT-999";
  resealAcceptedFixture(wrongTargetContribution);
  assert.throws(
    () => compileOutcomeTransitions(wrongTargetContribution),
    (error) => error.code === "OUTCOME_TRANSITION_PROOF_INELIGIBLE"
      && error.details.problems.includes("target-outcome-contribution-missing")
  );

  const closureBypass = noTransitionFixture();
  closeGap(closureBypass.currentModel, "target-gap", fixturePackageRef());
  assert.throws(
    () => compileOutcomeTransitions(closureBypass),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_RELATION_INVALID"
      && error.details.problems.includes("open-blocker-target-gap-already-closed")
  );

  const declaredRouteBypass = noTransitionFixture((baselineModel) => {
    baselineModel.projectDocument.changePolicy.outcomeTransitionMode = "declared";
  });
  declaredRouteBypass.currentModel.plan.outcomes[0].status = "achieved";
  closeGap(declaredRouteBypass.currentModel, "route-blocker", fixturePackageRef());
  assert.throws(
    () => compileOutcomeTransitions(declaredRouteBypass),
    (error) => error.code === "OUTCOME_TRANSITION_GAP_UNRESOLVED"
      && error.details.problems.includes("blocked-outcome-transition-unbound")
  );

  const newlyDeclaredGapBypass = noTransitionFixture((baselineModel) => {
    delete gap(baselineModel, "blocker-a").blocksGapClosureRefs;
  });
  gap(newlyDeclaredGapBypass.currentModel, "blocker-a").blocksGapClosureRefs = ["target-gap"];
  closeGap(newlyDeclaredGapBypass.currentModel, "target-gap", fixturePackageRef());
  assert.throws(
    () => compileOutcomeTransitions(newlyDeclaredGapBypass),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_RELATION_INVALID"
      && error.details.problems.includes("open-blocker-target-gap-already-closed")
  );

  const newlyDeclaredRouteBypass = transitionFixture((baselineModel) => {
    delete gap(baselineModel, "route-blocker").blocksOutcomeTransitionRoutes;
  });
  gap(newlyDeclaredRouteBypass.currentModel, "route-blocker").blocksOutcomeTransitionRoutes = [{
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved"
  }];
  for (const gapRef of ["route-blocker", "blocker-a", "target-gap"]) {
    reopenGap(newlyDeclaredRouteBypass.currentModel, gapRef);
  }
  assert.throws(
    () => compileOutcomeTransitions(newlyDeclaredRouteBypass),
    (error) => error.code === "KNOWLEDGE_GAP_BLOCKER_RELATION_INVALID"
      && error.details.problems.includes("blocked-route-transition-already-recorded")
  );

  const duplicateLedger = structuredClone(transitionFixture().currentModel.plan);
  duplicateLedger.outcomeTransitions[0].gapDispositions.push(
    structuredClone(duplicateLedger.outcomeTransitions[0].gapDispositions[0])
  );
  assert.ok(validateOutcomeTransitionLedger(
    duplicateLedger,
    model.knowledgeGaps
  ).errors.some((error) => error.code === "plan.outcome-transition.gap.duplicate"));
});

function transitionFixture(mutateBaseline = () => {}) {
  const baselineModel = blockerModel();
  mutateBaseline(baselineModel);
  const governanceBaseline = sealGovernance(baselineModel);
  const implementationChange = {
    id: "accepted-blocker-proof",
    primaryModule: "core",
    changeKind: "implementation",
    planRefs: ["LGT-001"],
    claims: baselineModel.contracts[0].claims.map((claim) => structuredClone(claim)),
    compilerInput: {
      verificationObligations: [],
      impact: null,
      contextCapsule: null,
      outcomeContributionHints: [],
      outcomeExceptions: []
    }
  };
  const aligned = compileChangeAgainstGovernance(implementationChange, governanceBaseline);
  const acceptedRecord = acceptedRecordFor({
    change: implementationChange,
    governanceBaseline,
    outcomeAlignment: aligned.outcomeAlignment
  });
  const packageRef = {
    changeId: acceptedRecord.id,
    acceptanceDigest: acceptedRecord.acceptance.digest
  };
  const currentModel = structuredClone(baselineModel);
  currentModel.plan.outcomes[0].status = "achieved";
  currentModel.plan.outcomeTransitions = [{
    id: "LGT-001-T1",
    outcomeRef: "LGT-001",
    from: "active",
    to: "achieved",
    rationale: "The exact prior implementation closes every prerequisite.",
    packageRefs: [structuredClone(packageRef)],
    criterionAssessments: [{
      criterionRef: "LGT-001-C1",
      authorityAssessment: {
        conclusion: "satisfied",
        rationale: "The sealed implementation directly covers the stable Criterion.",
        residualUncertainty: "This fixture retains only its bounded synthetic uncertainty."
      }
    }],
    gapDispositions: ["blocker-a", "blocker-b", "route-blocker", "target-gap"]
      .map((gapRef) => ({ gapRef, rationale: `The exact proof closes ${gapRef}.` }))
  }];
  for (const currentGap of currentModel.knowledgeGaps) {
    closeGap(currentModel, currentGap.id, packageRef);
  }
  return {
    change: {
      id: "achieve-blocker-fixture",
      changeKind: "plan-amendment",
      createdAt: "2026-07-17T12:00:00.000Z",
      authorityDecision: {
        status: "approved",
        authority: "maintainer",
        decidedBy: "fixture-maintainer",
        decisionType: "normative-amendment",
        rationale: "Every exact frozen prerequisite has prior proof."
      }
    },
    governanceBaseline,
    currentModel,
    resolvedPackages: [acceptedRecord],
    priorAcceptedPackages: acceptedCatalog([packageRef])
  };
}

function noTransitionFixture(mutateBaseline = () => {}) {
  const baselineModel = blockerModel();
  mutateBaseline(baselineModel);
  return {
    change: {
      id: "blocker-plan-amendment",
      changeKind: "plan-amendment",
      createdAt: "2026-07-17T12:00:00.000Z"
    },
    governanceBaseline: sealGovernance(baselineModel),
    currentModel: structuredClone(baselineModel),
    resolvedPackages: [],
    priorAcceptedPackages: acceptedCatalog([])
  };
}

function blockerModel() {
  const claims = ["core", "blocker-a", "blocker-b", "route-blocker", "target"]
    .map((name) => ({ id: `${name}-works`, statement: `${name} works exactly.` }));
  const commands = claims.map((claim) => ({
    id: `${claim.id}-command`,
    command: [process.execPath, "-e", "process.exit(0)"],
    claimRefs: [claim.id],
    oracle: { kind: "process-exit", description: `Proves ${claim.id}.` },
    applicability: { phase: "acceptance" },
    discriminatoryPower: { rejects: [`a broken ${claim.id}`] },
    residualUncertainty: ["The proof is bounded to the fixture."]
  }));
  return {
    project: { id: "gap-blocker-fixture" },
    projectDocument: {
      project: { id: "gap-blocker-fixture" },
      normativeSources: [{ id: "requirements" }],
      authorities: {
        fact: [{ id: "facts" }],
        decision: [{ id: "maintainer", may: ["case-decision", "normative-amendment"] }]
      },
      assuranceBoundary: { governed: ["core"], provisional: [], opaque: [] },
      changePolicy: {
        defaultGate: "minimum",
        requirePlanRefs: true,
        outcomeAlignmentMode: "enforced",
        outcomeCriterionSelection: "unique-claim-match-or-explicit-hint",
        outcomeTransitionMode: "enforced"
      }
    },
    modules: [{
      id: "core",
      status: "governed",
      paths: { include: ["src/core/**"] },
      interface: { description: "Core behavior." },
      factAuthority: "facts",
      decisionAuthority: "maintainer",
      publicContracts: ["core-api"],
      dependencies: []
    }],
    contracts: [{
      id: "core-api",
      owner: "core",
      consumers: [],
      normativeSources: ["requirements"],
      claims
    }],
    gates: [{ id: "minimum", appliesTo: ["core"], commands }],
    plan: {
      id: "blocker-plan",
      authority: "maintainer",
      northStar: "Exact prerequisites cannot be bypassed.",
      stages: [{ id: "S1", name: "Fixture", status: "active", outcomeRefs: ["LGT-001"] }],
      outcomes: [{
        id: "LGT-001",
        stage: "S1",
        status: "active",
        outcome: "The blocker fixture becomes complete.",
        dependsOn: [],
        acceptance: {
          exitCriteria: ["All direct behavior and blockers are proven."],
          claimRefs: ["blocker-a-works", "blocker-b-works", "core-works", "route-blocker-works"],
          gapRefs: ["target-gap"],
          criteria: [{
            id: "LGT-001-C1",
            statement: "All direct behavior and blockers are proven.",
            claimRefs: ["blocker-a-works", "blocker-b-works", "core-works", "route-blocker-works"],
            gapRefs: ["target-gap"]
          }]
        }
      }],
      outcomeTransitions: []
    },
    knowledgeGaps: [{
      id: "target-gap",
      status: "open",
      statement: "The target uncertainty remains open."
    }, {
      id: "blocker-a",
      status: "open",
      statement: "The first prerequisite remains open.",
      proofClaimRefs: ["blocker-a-works"],
      blocksGapClosureRefs: ["target-gap"]
    }, {
      id: "blocker-b",
      status: "open",
      statement: "A transitive prerequisite remains open.",
      proofClaimRefs: ["blocker-b-works"],
      blocksGapClosureRefs: ["blocker-a"]
    }, {
      id: "route-blocker",
      status: "open",
      statement: "The exact Outcome route remains blocked.",
      proofClaimRefs: ["route-blocker-works"],
      blocksGapClosureRefs: ["blocker-a"],
      blocksOutcomeTransitionRoutes: [{ outcomeRef: "LGT-001", from: "active", to: "achieved" }]
    }],
    files: []
  };
}

function acceptedRecordFor({ change, governanceBaseline, outcomeAlignment }) {
  const acceptedAt = "2026-07-17T10:00:00.000Z";
  const gate = governanceBaseline.gates[0];
  const evidence = change.claims.map((claim) => {
    const command = gate.commands.find((entry) => entry.claimRefs.includes(claim.id));
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
    outcomeContributionHints: [],
    outcomeExceptions: [],
    evidence,
    gateRuns: [{
      gateId: gate.id,
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
    acceptance: { acceptedAt, digest, package: acceptedPackage }
  };
}

function sealGovernance(model) {
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

function acceptedCatalog(entries) {
  const snapshot = { schemaVersion: 1, entries: structuredClone(entries) };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function resealAcceptedFixture(fixture) {
  const record = fixture.resolvedPackages[0];
  const digest = canonicalDigest(record.acceptance.package);
  const changeId = record.id;
  record.acceptance.digest = digest;
  record.history[0].digest = digest;
  for (const reference of fixture.currentModel.plan.outcomeTransitions[0].packageRefs) {
    if (reference.changeId === changeId) reference.acceptanceDigest = digest;
  }
  for (const currentGap of fixture.currentModel.knowledgeGaps) {
    for (const reference of currentGap.closedBy ?? []) {
      if (reference.changeId === changeId) reference.acceptanceDigest = digest;
    }
  }
  fixture.priorAcceptedPackages = acceptedCatalog([{ changeId, acceptanceDigest: digest }]);
}

function closeGap(model, gapRef, packageRef) {
  Object.assign(gap(model, gapRef), {
    status: "closed",
    resolution: `${gapRef} is closed by exact accepted proof.`,
    reopenTrigger: `Reopen ${gapRef} if its exact proof binding changes.`,
    closedBy: [structuredClone(packageRef)]
  });
}

function reopenGap(model, gapRef) {
  const currentGap = gap(model, gapRef);
  currentGap.status = "open";
  delete currentGap.resolution;
  delete currentGap.reopenTrigger;
  delete currentGap.closedBy;
}

function gap(model, gapRef) {
  return model.knowledgeGaps.find((entry) => entry.id === gapRef);
}

function fixturePackageRef() {
  return { changeId: "fixture-proof", acceptanceDigest: `sha256:${"a".repeat(64)}` };
}
