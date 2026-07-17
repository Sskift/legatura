import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createKernel, EVIDENCE_FIELDS } from "../../src/core/index.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import { readExpectedAuthorities } from "../../src/core/evidence.mjs";

const execFileAsync = promisify(execFile);
const TRANSITION_GAP_ID = "transition-evidence-gap";
const TRANSITION_GAP_PROOF_CLAIM_ID = "transition-gap-proof-exact";
const TRANSITION_GAP_PROOF_STATEMENT =
  "The fixture Outcome Gap closes only through its exact configured proof route.";

test("inspectProject exposes validated Project Model and repository state", async () => {
  const fixture = await createFixture();
  await writeFile(path.join(fixture.repoPath, "untracked.txt"), "untracked content\n");
  const kernel = createKernel({ repoPath: fixture.repoPath });

  const inspection = await kernel.inspectProject();

  assert.equal(inspection.valid, true);
  assert.equal(inspection.validation.valid, true);
  assert.equal(inspection.git.available, true);
  assert.equal(inspection.git.dirty, true);
  assert.equal(inspection.modules[0].status, "governed");
});

test("plan alignment injects only an active Outcome into bounded Context", async () => {
  const fixture = await createFixture();
  await enablePlanPolicy(fixture.repoPath);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Expose verification context without broadening capability",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });

  await assert.rejects(
    kernel.compileChange(change.id),
    (error) => error.code === "CHANGE_PLAN_REF_REQUIRED"
      && error.details.activeOutcomeIds.includes("LGT-900")
  );
  await assert.rejects(
    kernel.compileChange(change.id, { planRefs: ["LGT-missing"] }),
    (error) => error.code === "CHANGE_PLAN_REF_UNKNOWN"
  );
  await assert.rejects(
    kernel.compileChange(change.id, { planRefs: ["LGT-901"] }),
    (error) => error.code === "CHANGE_PLAN_REF_NOT_ACTIVE"
      && error.details.inactive[0].status === "planned"
  );

  const compiled = await kernel.compileChange(change.id, {
    planRefs: ["LGT-900"],
    outcomeContributionHints: [{ outcomeRef: "LGT-900", criterionRefs: ["LGT-900-C1"] }]
  });

  assert.deepEqual(compiled.planRefs, ["LGT-900"]);
  assert.deepEqual(compiled.contextCapsule.planOutcomes.map((outcome) => outcome.id), ["LGT-900"]);
  assert.deepEqual(compiled.contextCapsule.planOutcomes[0].acceptance.criteria.map((criterion) => criterion.id), [
    "LGT-900-C1"
  ]);
  assert.deepEqual(compiled.outcomeAlignment.contributions.map((entry) => entry.criterionRef), ["LGT-900-C1"]);
  assert.deepEqual(readExpectedAuthorities(compiled.governanceBaseline, compiled), ["module-maintainer"]);
  assert.ok(compiled.contextCapsule.scope.read.include.includes("test/core/**"));
  assert.ok(!compiled.contextCapsule.scope.write.include.includes("test/core/**"));
  assert.deepEqual(compiled.contextCapsule.module.focusedTests, [{
    path: "test/core/**",
    command: "node --test test/core"
  }]);
});

test("Outcome alignment inputs are subject-bound and preserved in the Accepted Package", async () => {
  const fixture = await createFixture();
  await enablePlanPolicy(fixture.repoPath);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const firstHints = [{ outcomeRef: "LGT-900", criterionRefs: ["LGT-900-C1"] }];
  const secondHints = [{ outcomeRef: "LGT-900", criterionRefs: ["LGT-900-C2"] }];
  const change = await kernel.createChange({
    title: "Bind Outcome alignment input",
    primaryModule: "core",
    planRefs: ["LGT-900"],
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }],
    outcomeContributionHints: firstHints,
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture Change introduces no future-relevant project knowledge."
    }
  });
  assert.deepEqual(change.compilerInput.outcomeContributionHints, firstHints);

  const compiled = await kernel.compileChange(change.id);
  assert.equal(compiled.outcomeAlignment.status, "complete");
  assert.deepEqual(compiled.outcomeAlignment.contributions.map((entry) => entry.criterionRef), ["LGT-900-C1"]);
  const firstGate = await kernel.runGate(change.id);
  const firstSubjectDigest = firstGate.gateRuns
    .find((entry) => entry.gateId === "minimum")
    .verificationSubjectDigest;

  const recompiled = await kernel.compileChange(change.id, {
    outcomeContributionHints: secondHints
  });
  assert.equal(recompiled.state, "Submitted");
  assert.deepEqual(recompiled.compilerInput.outcomeContributionHints, secondHints);
  assert.deepEqual(recompiled.outcomeAlignment.contributions.map((entry) => entry.criterionRef), ["LGT-900-C2"]);
  const stale = await kernel.getChange(change.id);
  assert.deepEqual(stale.readiness.missingOrStaleGateIds, ["project-model", "minimum"]);
  assert.equal(stale.readiness.coverage.satisfied, false);
  assert.ok(stale.readiness.coverage.uncoveredClaimIds.includes("behavior-correct"));

  const secondGate = await kernel.runGate(change.id);
  const secondSubjectDigest = secondGate.gateRuns
    .find((entry) => entry.gateId === "minimum")
    .verificationSubjectDigest;
  assert.notEqual(secondSubjectDigest, firstSubjectDigest);

  const accepted = await kernel.acceptChange(change.id, {
    authority: "module-maintainer",
    decidedBy: "maintainer@example.test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "The exact Outcome alignment input and governed behavior are acceptance-bound."
  });
  assert.equal(accepted.acceptance.package.outcomeAlignmentSchemaVersion, 1);
  assert.deepEqual(accepted.acceptance.package.outcomeContributionHints, secondHints);
  assert.deepEqual(accepted.acceptance.package.outcomeAlignment, recompiled.outcomeAlignment);
  assert.equal(
    accepted.acceptance.package.compilation.outcomeAlignmentDigest,
    canonicalDigest(recompiled.outcomeAlignment)
  );
  assert.equal(
    accepted.acceptance.package.gateRuns.find((entry) => entry.gateId === "minimum").verificationSubjectDigest,
    secondSubjectDigest
  );

  const exceptionRequests = [{
    outcomeRef: "LGT-900",
    reason: "The built-in model Claim has no honest Contract Criterion mapping.",
    residualUncertainty: "This exception grants no Outcome progress."
  }];
  const exceptionChange = await kernel.createChange({
    title: "Request a non-progress Outcome exception",
    primaryModule: "core",
    planRefs: ["LGT-900"],
    claims: [{
      id: "project-model-self-consistent",
      statement: "The versioned Project Model is internally self-consistent for this Change."
    }],
    outcomeExceptions: exceptionRequests,
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture exception introduces no future-relevant project knowledge."
    }
  });
  const exceptionCompiled = await kernel.compileChange(exceptionChange.id);
  assert.equal(exceptionCompiled.outcomeAlignment.status, "pending-authority");
  assert.deepEqual(readExpectedAuthorities(exceptionCompiled.governanceBaseline, exceptionCompiled), [
    "project-maintainer"
  ]);
  const exceptionRecordPath = path.join(
    fixture.repoPath,
    ".legatura/runtime/changes",
    `${exceptionChange.id}.json`
  );
  const tamperedException = JSON.parse(await readFile(exceptionRecordPath, "utf8"));
  tamperedException.outcomeAlignment.exceptions = [];
  await writeJson(exceptionRecordPath, tamperedException);
  const tamperedGate = await kernel.runGate(exceptionChange.id);
  assert.equal(tamperedGate.change.state, "EvidenceReady");
  await assert.rejects(
    kernel.acceptChange(exceptionChange.id, {
      authority: "module-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "case-decision",
      status: "approved",
      rationale: "Deleting compiled exceptions must not restore Module authority."
    }),
    (error) => error.code === "OUTCOME_EXCEPTION_BINDING_INVALID"
      && error.details.problems.includes("request-output-mismatch")
  );
  const restoredException = await kernel.compileChange(exceptionChange.id);
  assert.equal(restoredException.outcomeAlignment.status, "pending-authority");
  const coordinatedTamper = JSON.parse(await readFile(exceptionRecordPath, "utf8"));
  coordinatedTamper.compilerInput.outcomeExceptions = [];
  coordinatedTamper.outcomeAlignment = {
    schemaVersion: 1,
    mode: "declared",
    status: "complete",
    selectedOutcomeRefs: ["LGT-900"],
    contributions: [],
    exceptions: [],
    unresolved: []
  };
  coordinatedTamper.contextCapsule.outcomeAlignment = coordinatedTamper.outcomeAlignment;
  coordinatedTamper.compilation.outcomeAlignmentDigest = canonicalDigest(coordinatedTamper.outcomeAlignment);
  await writeJson(exceptionRecordPath, coordinatedTamper);
  const coordinatedTamperGate = await kernel.runGate(exceptionChange.id);
  assert.equal(coordinatedTamperGate.change.state, "EvidenceReady");
  await assert.rejects(
    kernel.acceptChange(exceptionChange.id, {
      authority: "module-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "case-decision",
      status: "approved",
      rationale: "Coordinated input and output tampering must not fabricate complete alignment."
    }),
    (error) => error.code === "CHANGE_COMPILATION_STALE"
      && error.details.changedFields.includes("outcomeAlignment")
  );
  await kernel.compileChange(exceptionChange.id, { outcomeExceptions: exceptionRequests });
  const exceptionGate = await kernel.runGate(exceptionChange.id);
  assert.equal(exceptionGate.change.state, "EvidenceReady");
  await assert.rejects(
    kernel.acceptChange(exceptionChange.id, {
      authority: "module-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "case-decision",
      status: "approved",
      rationale: "A Module authority must not authorize an Outcome exception."
    }),
    (error) => error.code === "AUTHORITY_DECISION_REQUIRED"
      && error.details.expectedAuthorities.includes("project-maintainer")
  );
  const acceptedException = await kernel.acceptChange(exceptionChange.id, {
    authority: "project-maintainer",
    decidedBy: "plan-maintainer@example.test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "Plan authority records the non-progress exception without granting Outcome completion."
  });
  assert.deepEqual(acceptedException.acceptance.package.outcomeAlignment.exceptions.map((entry) => ({
    requiredAuthorityRef: entry.requiredAuthorityRef,
    progress: entry.progress,
    transitionUse: entry.transitionUse
  })), [{
    requiredAuthorityRef: "project-maintainer",
    progress: "none",
    transitionUse: "forbidden"
  }]);
});

test("integrity maintenance requires content-exact failed Evidence and Plan authority", async () => {
  const fixture = await createFixture();
  await enablePlanPolicy(fixture.repoPath);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Repair an observed governed regression",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  await assert.rejects(
    kernel.compileChange(change.id, { planRefs: ["LGT-999"] }),
    (error) => error.code === "CHANGE_INTEGRITY_CHANNEL_MISUSED"
  );
  await assert.rejects(
    kernel.compileChange(change.id, { changeKind: "regression-repair", planRefs: ["LGT-999"] }),
    (error) => error.code === "CHANGE_INTEGRITY_TARGET_REQUIRED"
  );

  const integrityTarget = {
    claimRef: "behavior-correct",
    failureEvidenceRef: "integrity-failure-observation"
  };
  await assert.rejects(
    kernel.compileChange(change.id, {
      changeKind: "regression-repair",
      planRefs: ["LGT-999"],
      integrityTarget,
      evidence: [createIntegrityFailureEvidence({ status: "passed" })]
    }),
    (error) => error.code === "CHANGE_INTEGRITY_FAILURE_EVIDENCE_INVALID"
      && error.details.problems.includes("observation-not-failed")
  );
  const repair = await kernel.compileChange(change.id, {
    changeKind: "regression-repair",
    planRefs: ["LGT-999"],
    integrityTarget,
    evidence: [createIntegrityFailureEvidence()]
  });
  assert.match(repair.integrityTarget.failureEvidenceDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(readExpectedAuthorities(repair.governanceBaseline, repair), ["project-maintainer"]);

  const inspection = await kernel.inspectProject();
  const builtinEvidenceId = `evidence-project-model-${canonicalDigest({
    model: inspection.digest,
    git: inspection.git.contentDigest
  }).slice("sha256:".length, "sha256:".length + 16)}`;
  await kernel.compileChange(change.id, {
    changeKind: "regression-repair",
    planRefs: ["LGT-999"],
    integrityTarget: { claimRef: "behavior-correct", failureEvidenceRef: builtinEvidenceId },
    evidence: [createIntegrityFailureEvidence({ id: builtinEvidenceId })]
  });
  await assert.rejects(
    kernel.runGate(change.id, "minimum"),
    (error) => error.code === "CHANGE_INTEGRITY_FAILURE_EVIDENCE_INVALID"
      && error.details.problems.includes("failure-evidence-digest-mismatch")
  );
});

test("plan amendments preserve history, isolate implementation, and use Plan authority", async () => {
  const fixture = await createFixture();
  await enablePlanPolicy(fixture.repoPath);
  await enableTransitionGapProofContract(fixture.repoPath);
  const kernel = createKernel({ repoPath: fixture.repoPath, clock: monotonicClock() });
  const declaredModel = await kernel.inspectProject();
  assert.equal(declaredModel.valid, true, JSON.stringify(declaredModel.validation.errors));

  const planPath = path.join(fixture.repoPath, ".legatura/plan.json");
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const proofA = await acceptTransitionProof(kernel, "transition-proof-a");
  const proofPackage = proofA.change.acceptance.package;
  assert.deepEqual(
    proofPackage.governanceBaseline.knowledgeGaps.find((gap) => gap.id === TRANSITION_GAP_ID)
      .proofClaimRefs,
    [TRANSITION_GAP_PROOF_CLAIM_ID]
  );
  assert.ok(proofPackage.claims.some((claim) => (
    claim.id === TRANSITION_GAP_PROOF_CLAIM_ID
      && claim.statement === TRANSITION_GAP_PROOF_STATEMENT
  )));
  const proofEvidence = proofPackage.evidence.find((evidence) => (
    evidence.provenance?.kind === "gate-command"
      && evidence.directSupportBindings?.some((binding) => (
        binding.claimId === TRANSITION_GAP_PROOF_CLAIM_ID
          && binding.claimStatement === TRANSITION_GAP_PROOF_STATEMENT
      ))
  ));
  assert.equal(proofEvidence?.provenance?.gateId, "minimum");
  assert.equal(proofEvidence?.provenance?.commandId, "transition-gap-proof");
  const historyChange = await kernel.createChange({
    title: "Preserve permanent Outcome identity across amendments",
    changeKind: "plan-amendment",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  const frozenCatalog = structuredClone(historyChange.priorAcceptedPackages);
  assert.deepEqual(frozenCatalog.entries, [proofA.reference]);
  assert.equal(
    frozenCatalog.digest,
    canonicalDigest({ schemaVersion: 1, entries: [proofA.reference] })
  );
  const proofB = await acceptTransitionProof(kernel, "transition-proof-b");
  assert.deepEqual((await kernel.getChange(historyChange.id)).priorAcceptedPackages, frozenCatalog);
  assert.deepEqual(readExpectedAuthorities(historyChange.governanceBaseline, historyChange), ["project-maintainer"]);
  const renamedPlan = JSON.parse(JSON.stringify(plan));
  renamedPlan.outcomes.find((outcome) => outcome.id === "LGT-901").id = "LGT-902";
  renamedPlan.stages[0].outcomeRefs = renamedPlan.stages[0].outcomeRefs
    .map((outcomeId) => outcomeId === "LGT-901" ? "LGT-902" : outcomeId);
  await writeJson(planPath, renamedPlan);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN"
      && error.details.removedOutcomeRefs.includes("LGT-901")
  );
  await writeJson(planPath, plan);

  const rewrittenCriterionPlan = JSON.parse(JSON.stringify(plan));
  const rewrittenOutcome = rewrittenCriterionPlan.outcomes.find((outcome) => outcome.id === "LGT-900");
  rewrittenOutcome.acceptance.criteria[0].statement = "The active fixture Criterion was silently reinterpreted.";
  rewrittenOutcome.acceptance.exitCriteria[0] = rewrittenOutcome.acceptance.criteria[0].statement;
  await writeJson(planPath, rewrittenCriterionPlan);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "OUTCOME_REVISION_STATUS_FORBIDDEN"
      && error.details.outcomeRef === "LGT-900"
  );
  await writeJson(planPath, plan);

  const reorderedAchievedPlan = JSON.parse(JSON.stringify(plan));
  const achievedOutcome = reorderedAchievedPlan.outcomes.find((outcome) => outcome.id === "LGT-898");
  achievedOutcome.acceptance.criteria.reverse();
  achievedOutcome.acceptance.exitCriteria.reverse();
  await writeJson(planPath, reorderedAchievedPlan);
  await assert.doesNotReject(kernel.compileChange(historyChange.id));
  await writeJson(planPath, plan);

  const deletedLegacyReferencePlan = JSON.parse(JSON.stringify(plan));
  deletedLegacyReferencePlan.outcomes.find((outcome) => outcome.id === "LGT-897").acceptance.claimRefs = [];
  await writeJson(planPath, deletedLegacyReferencePlan);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "OUTCOME_REVISION_STATUS_FORBIDDEN"
      && error.details.outcomeRef === "LGT-897"
  );
  await writeJson(planPath, plan);

  const statusChangeCriteriaPlan = JSON.parse(JSON.stringify(plan));
  const activatingOutcome = statusChangeCriteriaPlan.outcomes.find((outcome) => outcome.id === "LGT-901");
  activatingOutcome.status = "active";
  activatingOutcome.dependsOn = [];
  activatingOutcome.acceptance.criteria = [{
    id: "LGT-901-C1",
    statement: activatingOutcome.acceptance.exitCriteria[0],
    claimRefs: ["behavior-correct"],
    gapRefs: []
  }];
  await writeJson(planPath, statusChangeCriteriaPlan);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "OUTCOME_REVISION_TRANSITION_MIXED"
      && error.details.revisedOutcomeRefs.includes("LGT-901")
      && error.details.statusOutcomeRefs.includes("LGT-901")
  );
  await writeJson(planPath, plan);

  const transitionPlan = (packageRef) => {
    const next = structuredClone(plan);
    next.outcomes.find((outcome) => outcome.id === "LGT-903").status = "achieved";
    next.outcomeTransitions = [{
      id: "LGT-903-T1",
      outcomeRef: "LGT-903",
      from: "active",
      to: "achieved",
      rationale: "The stable fixture Criterion has exact prior Accepted Package Evidence.",
      packageRefs: [structuredClone(packageRef)],
      criterionAssessments: [{
        criterionRef: "LGT-903-C1",
        authorityAssessment: {
          conclusion: "satisfied",
          rationale: "The prior Minimum Gate directly rejects incorrect governed fixture behavior.",
          residualUncertainty: "The synthetic fixture covers only its declared behavior boundary."
        }
      }],
      gapDispositions: [{
        gapRef: TRANSITION_GAP_ID,
        rationale: "The same prior Package directly proves the separately governed Gap Closure Contract."
      }]
    }];
    return next;
  };

  const unresolvedPlan = structuredClone(plan);
  unresolvedPlan.outcomes.find((outcome) => outcome.id === "LGT-903").status = "achieved";
  await writeJson(planPath, unresolvedPlan);
  const unresolved = await kernel.compileChange(historyChange.id);
  assert.equal(unresolved.outcomePlanAmendmentCompilation.mode, "declared");
  assert.equal(unresolved.outcomePlanAmendmentCompilation.status, "unresolved");
  assert.deepEqual(unresolved.outcomePlanAmendmentCompilation.unresolved, [{
    outcomeRef: "LGT-903",
    from: "active",
    to: "achieved",
    reason: "status-delta-has-no-appended-transition"
  }]);

  await writeJson(planPath, transitionPlan(proofB.reference));
  await closeTransitionGap(fixture.repoPath, proofB.reference);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR"
  );

  const amendedPlan = transitionPlan(proofA.reference);
  await writeJson(planPath, amendedPlan);
  await closeTransitionGap(fixture.repoPath, proofA.reference);
  const compilePatch = {
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-amendment",
        refs: [".legatura/knowledge-gaps.json", ".legatura/plan.json"],
        statement: "The fixture Plan records an Evidence-bound Transition and closes its exact governed Gap.",
        rationale: "Future Changes inherit the terminal status, Gap disposition, and append-only proof history."
      }]
    },
    authorityDecision: {
      status: "approved",
      authority: "project-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "normative-amendment",
      rationale: "Approve the isolated Plan Transition and exact Gap closure from prior Evidence.",
      amendmentRefs: [".legatura/knowledge-gaps.json", ".legatura/plan.json"]
    }
  };
  let planCompiled = await kernel.compileChange(historyChange.id, compilePatch);
  assert.equal(planCompiled.state, "Submitted");
  assert.equal(planCompiled.outcomePlanAmendmentCompilation.status, "complete");
  assert.equal(planCompiled.outcomePlanAmendmentCompilation.priorAcceptedPackagesDigest, frozenCatalog.digest);
  const compiledProof = planCompiled.outcomePlanAmendmentCompilation.appendedTransitions[0]
    .criterionProofs[0].packages[0];
  assert.deepEqual(
    { changeId: compiledProof.changeId, acceptanceDigest: compiledProof.acceptanceDigest },
    proofA.reference
  );
  assert.ok(compiledProof.evidenceBindings.length > 0);
  const compiledGapProof = planCompiled.outcomePlanAmendmentCompilation.appendedTransitions[0]
    .gapDispositions[0];
  assert.deepEqual(compiledGapProof.proofClaimRefs, [TRANSITION_GAP_PROOF_CLAIM_ID]);
  assert.deepEqual(
    compiledGapProof.packages.map((entry) => ({
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
      ...proofA.reference,
      claimRefs: [TRANSITION_GAP_PROOF_CLAIM_ID],
      evidenceRoutes: [{
        provenanceKind: "gate-command",
        gateId: "minimum",
        commandId: "transition-gap-proof",
        claimRefs: [TRANSITION_GAP_PROOF_CLAIM_ID]
      }]
    }]
  );

  const candidateRecordPath = path.join(
    fixture.repoPath,
    ".legatura/runtime/changes",
    `${historyChange.id}.json`
  );
  const forgedProjection = JSON.parse(await readFile(candidateRecordPath, "utf8"));
  forgedProjection.outcomePlanAmendmentCompilation.status = "forged";
  await writeJson(candidateRecordPath, forgedProjection);
  await assert.rejects(
    kernel.runGate(historyChange.id, "minimum"),
    (error) => error.code === "OUTCOME_PLAN_AMENDMENT_COMPILATION_STALE"
  );
  planCompiled = await kernel.compileChange(historyChange.id, compilePatch);
  const planGate = await kernel.runGate(historyChange.id, "minimum");
  assert.equal(planGate.change.state, "EvidenceReady");

  await writeFile(path.join(fixture.repoPath, "src/index.mjs"), "export const value = false;\n");
  await assert.rejects(
    kernel.acceptChange(historyChange.id),
    (error) => error.code === "PLAN_AMENDMENT_IMPLEMENTATION_MIXED"
      && error.details.implementationPaths.includes("src/index.mjs")
  );
  await writeFile(path.join(fixture.repoPath, "src/index.mjs"), "export const value = true;\n");

  const proofRecordPath = path.join(
    fixture.repoPath,
    ".legatura/runtime/changes",
    `${proofA.change.id}.json`
  );
  const sealedProofText = await readFile(proofRecordPath, "utf8");
  const tamperedProof = JSON.parse(sealedProofText);
  tamperedProof.acceptance.package.evidence
    .find((item) => item.directSupportBindings?.some((binding) => binding.claimId === "behavior-correct"))
    .observation.status = "failed";
  await writeJson(proofRecordPath, tamperedProof);
  await assert.rejects(
    kernel.acceptChange(historyChange.id),
    (error) => error.code === "OUTCOME_TRANSITION_PACKAGE_SEAL_INVALID"
  );
  await writeFile(proofRecordPath, sealedProofText);

  const acceptedPlan = await kernel.acceptChange(historyChange.id);
  assert.equal(acceptedPlan.state, "Accepted");
  assert.deepEqual(acceptedPlan.acceptance.package.priorAcceptedPackages, frozenCatalog);
  assert.deepEqual(
    acceptedPlan.acceptance.package.outcomePlanAmendmentCompilation,
    planCompiled.outcomePlanAmendmentCompilation
  );
  assert.equal(acceptedPlan.acceptance.acceptedAt, acceptedPlan.history.find((entry) => (
    entry.to === "Accepted" && entry.digest === acceptedPlan.acceptance.digest
  )).at);
});

test("minimum Gate execution selects only commands for the primary Module", async () => {
  const fixture = await createFixture();
  await addAuxiliaryGateCommand(fixture.repoPath);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Select focused verification",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  await kernel.compileChange(change.id);

  const result = await kernel.runGate(change.id, "minimum");
  const run = result.gateRuns.find((entry) => entry.gateId === "minimum");

  assert.equal(result.status, "passed");
  assert.deepEqual(run.selection, {
    primaryModule: "core",
    selectedCommandIds: ["behavior"],
    skippedCommandIds: ["auxiliary-failure"]
  });
  assert.deepEqual(run.commandResults.map((entry) => entry.id), ["behavior"]);
  const commandEvidence = result.change.evidence.find((item) => item.provenance?.commandId === "behavior");
  assert.equal(commandEvidence.applicability.module, "core");
  assert.equal(Object.hasOwn(commandEvidence.applicability, "modules"), false);

  const auxiliaryClaim = await kernel.createChange({
    title: "Do not map a skipped command",
    primaryModule: "core",
    claims: [{
      id: "auxiliary-correct",
      statement: "The auxiliary behavior remains correct."
    }]
  });
  const compiled = await kernel.compileChange(auxiliaryClaim.id);
  assert.deepEqual(compiled.verificationObligations[0].exactGateIds, []);
  assert.equal(compiled.verificationObligations[0].mapping.status, "unmapped");
});

test("Change follows Candidate to Integrated with Evidence, Knowledge Closure, Authority, and digest", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath, clock: monotonicClock() });
  const candidate = await kernel.createChange({
    title: "Preserve the governed behavior",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }],
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture Change introduces no future-relevant project knowledge."
    }
  });
  assert.equal(candidate.state, "Candidate");

  const submitted = await kernel.compileChange(candidate.id);
  assert.equal(submitted.state, "Submitted");

  const candidateRecordPath = path.join(
    fixture.repoPath,
    ".legatura/runtime/changes",
    `${candidate.id}.json`
  );
  const tamperedCompilation = JSON.parse(await readFile(candidateRecordPath, "utf8"));
  delete tamperedCompilation.outcomeAlignmentSchemaVersion;
  tamperedCompilation.impact = { schemaVersion: 1, directModule: "forged-module" };
  await writeJson(candidateRecordPath, tamperedCompilation);

  const gate = await kernel.runGate(candidate.id);
  assert.equal(gate.status, "passed");
  assert.equal(gate.change.state, "EvidenceReady");
  assert.ok(gate.change.evidence.every((item) => EVIDENCE_FIELDS.every((field) => field in item)));
  const gateReadiness = await kernel.getChange(candidate.id);
  assert.deepEqual(gateReadiness.readiness.coverage.mismatchedClaimEvidenceIds, []);
  await assert.rejects(
    kernel.acceptChange(candidate.id, {
      authority: "project-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "case-decision",
      status: "approved",
      rationale: "A fresh Gate cannot legitimize forged compiler-owned projections."
    }),
    (error) => error.code === "CHANGE_COMPILATION_STALE"
      && error.details.changedFields.includes("impact")
  );
  await kernel.compileChange(candidate.id);
  await kernel.runGate(candidate.id);

  const accepted = await kernel.acceptChange(candidate.id, {
    authority: "project-maintainer",
    decidedBy: "maintainer@example.test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "Existing governed behavior is preserved by the bound Gate evidence."
  });
  assert.equal(accepted.state, "Accepted");
  assert.equal(accepted.acceptance.valid, true);
  assert.match(accepted.acceptance.digest, /^sha256:[a-f0-9]{64}$/u);
  assert.equal(accepted.acceptance.digest, accepted.history.at(-1).digest);

  const integrated = await kernel.acceptChange(candidate.id, { integrate: true });
  assert.equal(integrated.state, "Integrated");
  assert.equal(integrated.integration.acceptanceDigest, accepted.acceptance.digest);
});

test("a passing Gate cannot support an unrelated Change Claim without an explicit Verification Obligation mapping", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Introduce new semantics",
    primaryModule: "core",
    claims: [{ id: "new-feature", statement: "The new feature behaves as requested." }]
  });
  await kernel.compileChange(change.id);

  const unmapped = await kernel.runGate(change.id);
  assert.equal(unmapped.status, "passed");
  assert.equal(unmapped.change.state, "Submitted");

  const crossClaimCompiled = await kernel.compileChange(change.id, {
    verificationObligations: [{
      id: "verify-new-feature",
      claimId: "new-feature",
      gateClaimRefs: ["behavior-correct"],
      mappingRationale: "The fixture intentionally treats the existing deterministic behavior Oracle as the new feature Oracle.",
      applicability: "Only the fixture Core Module.",
      discriminatoryPower: "A non-zero deterministic process exit rejects the new feature Claim."
    }],
    authorityDecision: {
      status: "approved",
      authority: "project-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "case-decision",
      rationale: "Approve this explicit fixture-only cross-Claim Oracle mapping.",
      approvedObligationIds: ["verify-new-feature"]
    }
  });
  assert.deepEqual(crossClaimCompiled.verificationObligations[0].mapping.sourceRoutes, [{
    sourceClaimId: "behavior-correct",
    gateId: "minimum",
    commandId: "behavior"
  }]);
  const mapped = await kernel.runGate(change.id);
  assert.equal(mapped.change.state, "EvidenceReady");

  const routeFixture = await createFixture();
  await configureCommandExactCoverageFixture(routeFixture.repoPath);
  const routeKernel = createKernel({ repoPath: routeFixture.repoPath });
  const routeChange = await routeKernel.createChange({
    title: "Reject trusted Evidence from the wrong Gate command route",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  const routeCompiled = await routeKernel.compileChange(routeChange.id);
  assert.deepEqual(routeCompiled.verificationObligations[0].mapping.routes, [{
    gateId: "target-acceptance",
    commandId: "target-acceptance-command"
  }]);

  const unrelatedMinimum = await routeKernel.runGate(routeChange.id, "minimum");
  assert.equal(unrelatedMinimum.status, "passed");
  assert.equal(unrelatedMinimum.change.state, "Submitted");
  const integrationFull = await routeKernel.runGate(routeChange.id, "full");
  const fullEvidence = integrationFull.change.evidence.find((item) => (
    item.provenance?.gateId === "full" && item.provenance?.commandId === "full-target-command"
  ));
  assert.ok(fullEvidence);
  assert.equal(integrationFull.status, "passed");
  assert.equal(integrationFull.change.state, "Submitted");
  const fullReadiness = await routeKernel.getChange(routeChange.id);
  assert.ok(fullReadiness.readiness.coverage.uncoveredClaimIds.includes("behavior-correct"));
  assert.ok(fullReadiness.readiness.coverage.ineligibleRouteEvidenceIds.includes(fullEvidence.id));

  const targetAcceptance = await routeKernel.runGate(routeChange.id, "target-acceptance");
  assert.equal(targetAcceptance.status, "passed");
  assert.equal(targetAcceptance.change.state, "EvidenceReady");
  const targetEvidence = targetAcceptance.change.evidence.find((item) => (
    item.provenance?.gateId === "target-acceptance"
      && item.provenance?.commandId === "target-acceptance-command"
  ));
  assert.ok(targetEvidence?.directSupportBindings?.some((binding) => (
    binding.claimId === "behavior-correct"
      && binding.claimStatement === "The governed behavior remains correct."
  )));
});

test("failed Evidence never satisfies a Verification Obligation", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Evidence must discriminate",
    primaryModule: "core",
    claims: [{ id: "new-feature", statement: "The new feature behaves as requested." }]
  });
  await kernel.compileChange(change.id, {
    evidence: [{
      claim: { id: "new-feature", statement: "The new feature behaves as requested." },
      oracle: { kind: "behavior", description: "Reject the wrong result." },
      observation: { status: "failed", detail: "Wrong result observed." },
      provenance: { source: "manual", gitHead: "fixture" },
      applicability: "Fixture scenario.",
      discriminatoryPower: "Rejects the observed wrong result.",
      residualUncertainty: "Other scenarios remain unobserved."
    }]
  });

  const result = await kernel.runGate(change.id);
  assert.equal(result.change.state, "Submitted");
  await assert.rejects(
    kernel.acceptChange(change.id, "project-maintainer"),
    (error) => error.code === "CHANGE_NOT_EVIDENCE_READY"
  );
});

test("the built-in Project Model Oracle blocks shell Gates when governed knowledge becomes invalid", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Detect model drift",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  await kernel.compileChange(change.id);
  const modulePath = path.join(fixture.repoPath, ".legatura/modules/core.json");
  const module = JSON.parse(await readFile(modulePath, "utf8"));
  delete module.interface;
  await writeJson(modulePath, module);

  const result = await kernel.runGate(change.id);

  assert.equal(result.status, "failed");
  assert.equal(result.blocked, true);
  assert.ok(result.modelValidation.errors.some((error) => error.code === "module.interface.missing"));
  await assert.rejects(readFile(path.join(fixture.repoPath, "gate-ran.txt"), "utf8"), { code: "ENOENT" });
});

test("repository content changes invalidate the exact Accepted Change Package", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Bind acceptance to exact content",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }],
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture Change introduces no future-relevant project knowledge."
    }
  });
  await kernel.compileChange(change.id);
  await kernel.runGate(change.id);
  const accepted = await kernel.acceptChange(change.id, {
    authority: "project-maintainer",
    decidedBy: "maintainer@example.test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "The current exact Change content is accepted."
  });
  assert.equal(accepted.acceptance.valid, true);

  await writeFile(path.join(fixture.repoPath, "README.md"), "changed after acceptance\n");
  const observed = await kernel.getChange(change.id);

  assert.equal(observed.acceptance.valid, true, "a read preserves historical acceptance");
  assert.equal(observed.state, "Accepted");
  assert.equal(observed.observation.seal.intact, true);
  assert.equal(observed.observation.currentApplicability.status, "stale");
  assert.equal(observed.readiness.evidenceReady, false);
  await assert.rejects(
    kernel.compileChange(change.id),
    (error) => error.code === "CHANGE_SEALED"
  );
});

test("incomplete Evidence is rejected instead of becoming assurance material", async () => {
  const fixture = await createFixture();
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const change = await kernel.createChange({
    title: "Reject weak evidence",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });

  await assert.rejects(
    kernel.compileChange(change.id, {
      evidence: [{
        claim: { id: "behavior-correct", statement: "The governed behavior remains correct." },
        oracle: "tests pass",
        observation: { status: "passed" }
      }]
    }),
    (error) => error.code === "EVIDENCE_INCOMPLETE"
      && error.details.missingFields.includes("residualUncertainty")
  );
});

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-core-"));
  await mkdir(path.join(repoPath, ".legatura/modules"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/contracts"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/gates"), { recursive: true });
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "fixture", name: "Fixture" },
    authorities: {
      decision: [{ id: "project-maintainer", may: ["case-decision"] }],
      fact: [{ id: "core-facts", module: "core", owns: "Fixture behavior" }]
    },
    assuranceBoundary: {
      governed: [{ module: "core", reason: "Fixture" }],
      provisional: [],
      opaque: []
    },
    changePolicy: { defaultGate: "minimum" }
  });
  await writeJson(path.join(repoPath, ".legatura/modules/core.json"), {
    schemaVersion: 1,
    id: "core",
    name: "Core",
    status: "governed",
    summary: "Fixture Module.",
    factAuthority: "core-facts",
    interface: { accepts: ["request"], returns: ["result"] },
    paths: { include: ["src/**"], exclude: [] },
    focusedTests: [{ path: "test/core/**", command: "node --test test/core" }],
    publicContracts: ["core-behavior"],
    dependencies: []
  });
  await writeJson(path.join(repoPath, ".legatura/contracts/core-behavior.json"), {
    schemaVersion: 1,
    id: "core-behavior",
    name: "Core Behavior",
    owner: "core",
    maturity: "governed",
    normativeSources: [],
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }],
    consumers: []
  });
  await writeJson(path.join(repoPath, ".legatura/gates/minimum.json"), {
    schemaVersion: 1,
    id: "minimum",
    name: "Minimum Gate",
    purpose: "Fixture verification.",
    appliesTo: ["core"],
    commands: [{
      id: "behavior",
      command: "node -e \"require('node:fs').writeFileSync('gate-ran.txt','yes'); require('node:fs').unlinkSync('gate-ran.txt')\"",
      timeoutMs: 30_000,
      claimRefs: ["behavior-correct"],
      oracle: { kind: "fixture", description: "The fixture command exits zero." },
      applicability: "Fixture repository.",
      discriminatoryPower: "A non-zero exit rejects the fixture.",
      residualUncertainty: "Only fixture behavior is covered."
    }]
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), { schemaVersion: 1, gaps: [] });
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const value = true;\n");
  await writeFile(path.join(repoPath, "README.md"), "fixture\n");

  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return { repoPath };
}

async function enablePlanPolicy(repoPath) {
  const projectPath = path.join(repoPath, ".legatura/project.json");
  const project = JSON.parse(await readFile(projectPath, "utf8"));
  const planAuthority = project.authorities.decision.find((authority) => authority.id === "project-maintainer");
  planAuthority.may = [...new Set([...(planAuthority.may ?? []), "normative-amendment"])];
  project.authorities.decision.push({ id: "module-maintainer", may: ["case-decision", "normative-amendment"] });
  project.changePolicy.requirePlanRefs = true;
  project.changePolicy.outcomeAlignmentMode = "declared";
  project.changePolicy.outcomeTransitionMode = "declared";
  project.changePolicy.outcomeCriterionSelection = "unique-claim-match-or-explicit-hint";
  await writeJson(projectPath, project);
  const modulePath = path.join(repoPath, ".legatura/modules/core.json");
  const module = JSON.parse(await readFile(modulePath, "utf8"));
  module.decisionAuthority = "module-maintainer";
  await writeJson(modulePath, module);
  await writeJson(path.join(repoPath, ".legatura/plan.json"), {
    schemaVersion: 1,
    id: "fixture-plan",
    authority: "project-maintainer",
    northStar: "Every Change advances an explicit trusted Outcome.",
    stages: [{
      id: "S1",
      name: "Fixture Stage",
      status: "active",
      outcomeRefs: ["LGT-897", "LGT-898", "LGT-900", "LGT-901", "LGT-903", "LGT-999"]
    }],
    outcomes: [
      {
        id: "LGT-897",
        stage: "S1",
        status: "achieved",
        outcome: "The legacy achieved fixture Outcome preserves object-form acceptance references.",
        dependsOn: [],
        acceptance: {
          claimRefs: [{ id: "behavior-correct" }],
          gapRefs: [],
          exitCriteria: ["Legacy achieved acceptance references remain durable."]
        }
      },
      {
        id: "LGT-898",
        stage: "S1",
        status: "achieved",
        outcome: "The achieved fixture Outcome preserves semantically stable acceptance history.",
        dependsOn: [],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: [
            "The achieved fixture acceptance remains durable.",
            "Equivalent Criterion ordering does not rewrite history."
          ],
          criteria: [
            {
              id: "LGT-898-C1",
              statement: "The achieved fixture acceptance remains durable.",
              claimRefs: ["behavior-correct"],
              gapRefs: []
            },
            {
              id: "LGT-898-C2",
              statement: "Equivalent Criterion ordering does not rewrite history.",
              claimRefs: ["behavior-correct"],
              gapRefs: []
            }
          ]
        }
      },
      {
        id: "LGT-900",
        stage: "S1",
        status: "active",
        outcome: "The fixture Change receives only its active capability Outcome.",
        dependsOn: [],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: [
            "The active fixture Outcome is injected into the Context Capsule.",
            "The selected fixture Criterion is sealed into the Accepted Change Package."
          ],
          criteria: [
            {
              id: "LGT-900-C1",
              statement: "The active fixture Outcome is injected into the Context Capsule.",
              claimRefs: ["behavior-correct"],
              gapRefs: []
            },
            {
              id: "LGT-900-C2",
              statement: "The selected fixture Criterion is sealed into the Accepted Change Package.",
              claimRefs: ["behavior-correct"],
              gapRefs: []
            }
          ]
        }
      },
      {
        id: "LGT-901",
        stage: "S1",
        status: "planned",
        outcome: "A planned fixture capability cannot authorize implementation.",
        dependsOn: ["LGT-900"],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: ["The planned fixture Outcome must be activated before use."]
        }
      },
      {
        id: "LGT-903",
        stage: "S1",
        status: "active",
        outcome: "A single stable fixture Criterion can be achieved only from prior exact Evidence.",
        dependsOn: [],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: ["The exact governed fixture behavior is proven by a prior Accepted Package."],
          criteria: [{
            id: "LGT-903-C1",
            statement: "The exact governed fixture behavior is proven by a prior Accepted Package.",
            claimRefs: ["behavior-correct"],
            gapRefs: []
          }]
        }
      },
      {
        id: "LGT-999",
        stage: "S1",
        status: "active",
        kind: "integrity-maintenance",
        outcome: "Existing fixture trust Claims remain intact.",
        dependsOn: [],
        allowedChangeKinds: ["regression-repair"],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: ["A repair names the protected Claim and its concrete observed failure."]
        }
      }
    ]
  });
  await git(repoPath, "add", ".legatura/project.json", ".legatura/plan.json", ".legatura/modules/core.json");
  await git(repoPath, "commit", "-qm", "enable plan policy");
}

async function enableTransitionGapProofContract(repoPath) {
  const contractPath = path.join(repoPath, ".legatura/contracts/core-behavior.json");
  const contract = JSON.parse(await readFile(contractPath, "utf8"));
  contract.claims.push({
    id: TRANSITION_GAP_PROOF_CLAIM_ID,
    statement: TRANSITION_GAP_PROOF_STATEMENT
  });
  await writeJson(contractPath, contract);

  const gatePath = path.join(repoPath, ".legatura/gates/minimum.json");
  const gate = JSON.parse(await readFile(gatePath, "utf8"));
  gate.commands.push({
    id: "transition-gap-proof",
    command: [process.execPath, "-e", "process.exit(0)"],
    timeoutMs: 30_000,
    appliesTo: ["core"],
    claimRefs: [TRANSITION_GAP_PROOF_CLAIM_ID],
    oracle: {
      kind: "fixture-gap-proof",
      description: "The exact fixture Gap proof command exits zero."
    },
    applicability: { phase: "acceptance" },
    discriminatoryPower: {
      rejects: ["A non-zero proof process exit rejects the governed Gap Closure Claim."]
    },
    residualUncertainty: ["Only the synthetic fixture Gap proof boundary is covered."]
  });
  await writeJson(gatePath, gate);

  const gapPath = path.join(repoPath, ".legatura/knowledge-gaps.json");
  await writeJson(gapPath, {
    schemaVersion: 1,
    gaps: [{
      id: TRANSITION_GAP_ID,
      status: "open",
      statement: "Exact Evidence has not yet closed the fixture Outcome Gap.",
      affects: ["core"],
      owner: "project-maintainer",
      expansionTrigger: "The proof route or bounded fixture behavior changes.",
      proofClaimRefs: [TRANSITION_GAP_PROOF_CLAIM_ID]
    }]
  });

  const planPath = path.join(repoPath, ".legatura/plan.json");
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const outcome = plan.outcomes.find((entry) => entry.id === "LGT-903");
  outcome.acceptance.gapRefs = [TRANSITION_GAP_ID];
  outcome.acceptance.criteria[0].gapRefs = [TRANSITION_GAP_ID];
  await writeJson(planPath, plan);

  await git(
    repoPath,
    "add",
    ".legatura/contracts/core-behavior.json",
    ".legatura/gates/minimum.json",
    ".legatura/knowledge-gaps.json",
    ".legatura/plan.json"
  );
  await git(repoPath, "commit", "-qm", "declare transition Gap proof contract");
}

async function closeTransitionGap(repoPath, packageRef) {
  const gapPath = path.join(repoPath, ".legatura/knowledge-gaps.json");
  const document = JSON.parse(await readFile(gapPath, "utf8"));
  const gap = document.gaps.find((entry) => entry.id === TRANSITION_GAP_ID);
  gap.status = "closed";
  gap.resolution = "The exact prior Package directly proves the governed fixture Gap Claim.";
  gap.reopenTrigger = "Reopen if the Package seal, proof Claim, or configured Gate route changes.";
  gap.closedBy = [structuredClone(packageRef)];
  await writeJson(gapPath, document);
}

async function acceptTransitionProof(kernel, id) {
  const change = await kernel.createChange({
    id,
    title: `Prove the stable Transition fixture with ${id}`,
    primaryModule: "core",
    planRefs: ["LGT-903"],
    claims: [
      { id: "behavior-correct", statement: "The governed behavior remains correct." },
      { id: TRANSITION_GAP_PROOF_CLAIM_ID, statement: TRANSITION_GAP_PROOF_STATEMENT }
    ],
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture Package adds bounded behavioral Evidence without changing durable project knowledge."
    }
  });
  await kernel.compileChange(change.id);
  await kernel.runGate(change.id, "minimum");
  const accepted = await kernel.acceptChange(change.id, {
    authority: "module-maintainer",
    decidedBy: "maintainer@example.test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "The exact fixture behavior is supported by the bound Minimum Gate Evidence."
  });
  return {
    change: accepted,
    reference: { changeId: accepted.id, acceptanceDigest: accepted.acceptance.digest }
  };
}

function createIntegrityFailureEvidence({ id = "integrity-failure-observation", status = "failed" } = {}) {
  return {
    id,
    claim: { id: "behavior-correct", statement: "The governed behavior remains correct." },
    oracle: {
      kind: "reported-fixture-regression",
      description: "A concrete pre-repair fixture observation distinguishes the regression from expected behavior."
    },
    observation: {
      status,
      detail: "The governed fixture behavior returned an incorrect result."
    },
    provenance: {
      kind: "reported-incident",
      source: "fixture-incident",
      observedAt: "2026-07-16T00:00:00.000Z"
    },
    applicability: { module: "core", phase: "pre-repair" },
    discriminatoryPower: {
      rejects: ["Classifying an unobserved feature request as a regression repair."]
    },
    residualUncertainty: ["The fixture incident report is not itself proof that the repair succeeds."]
  };
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function addAuxiliaryGateCommand(repoPath) {
  const projectPath = path.join(repoPath, ".legatura/project.json");
  const project = JSON.parse(await readFile(projectPath, "utf8"));
  project.authorities.fact.push({ id: "aux-facts", module: "aux", owns: "Auxiliary fixture behavior" });
  project.assuranceBoundary.governed.push({ module: "aux", reason: "Selector fixture" });
  await writeJson(projectPath, project);

  await mkdir(path.join(repoPath, "aux"));
  await writeFile(path.join(repoPath, "aux/index.mjs"), "export const auxiliary = true;\n");
  await writeJson(path.join(repoPath, ".legatura/modules/aux.json"), {
    schemaVersion: 1,
    id: "aux",
    name: "Auxiliary",
    status: "governed",
    summary: "Selector fixture Module.",
    factAuthority: "aux-facts",
    interface: { returns: ["auxiliary result"] },
    paths: { include: ["aux/**"], exclude: [] },
    publicContracts: ["aux-behavior"],
    dependencies: []
  });
  await writeJson(path.join(repoPath, ".legatura/contracts/aux-behavior.json"), {
    schemaVersion: 1,
    id: "aux-behavior",
    name: "Auxiliary Behavior",
    owner: "aux",
    maturity: "governed",
    normativeSources: [],
    claims: [{
      id: "auxiliary-correct",
      statement: "The auxiliary behavior remains correct."
    }],
    consumers: []
  });

  const gatePath = path.join(repoPath, ".legatura/gates/minimum.json");
  const gate = JSON.parse(await readFile(gatePath, "utf8"));
  gate.appliesTo.push("aux");
  gate.commands[0].appliesTo = ["core"];
  gate.commands.push({
    ...gate.commands[0],
    id: "auxiliary-failure",
    appliesTo: ["aux"],
    command: [process.execPath, "-e", "process.exit(17)"],
    claimRefs: ["auxiliary-correct"]
  });
  await writeJson(gatePath, gate);

  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "add selector fixture");
}

async function configureCommandExactCoverageFixture(repoPath) {
  const projectPath = path.join(repoPath, ".legatura/project.json");
  const project = JSON.parse(await readFile(projectPath, "utf8"));
  project.changePolicy.fullGate = "full";
  project.changePolicy.fullGateBefore = ["integrated"];
  await writeJson(projectPath, project);

  const contractPath = path.join(repoPath, ".legatura/contracts/core-behavior.json");
  const contract = JSON.parse(await readFile(contractPath, "utf8"));
  contract.claims.push({
    id: "minimum-observation",
    statement: "The unrelated minimum observation remains correct."
  });
  await writeJson(contractPath, contract);

  const minimumPath = path.join(repoPath, ".legatura/gates/minimum.json");
  const minimum = JSON.parse(await readFile(minimumPath, "utf8"));
  minimum.commands[0].claimRefs = ["minimum-observation"];
  await writeJson(minimumPath, minimum);

  const targetCommand = {
    id: "target-acceptance-command",
    command: [process.execPath, "-e", "process.exit(0)"],
    timeoutMs: 30_000,
    claimRefs: ["behavior-correct"],
    oracle: {
      kind: "target-acceptance-exit",
      description: "The exact target acceptance command exits zero."
    },
    applicability: { phase: "acceptance" },
    discriminatoryPower: {
      rejects: ["a non-zero target acceptance exit"]
    },
    residualUncertainty: ["The target proof remains bounded to the fixture."]
  };
  await writeJson(path.join(repoPath, ".legatura/gates/target-acceptance.json"), {
    schemaVersion: 1,
    id: "target-acceptance",
    name: "Target Acceptance Gate",
    appliesTo: ["core"],
    commands: [targetCommand]
  });
  await writeJson(path.join(repoPath, ".legatura/gates/full.json"), {
    schemaVersion: 1,
    id: "full",
    name: "Full Integration Gate",
    appliesTo: ["integration"],
    commands: [{
      ...targetCommand,
      id: "full-target-command",
      applicability: { phase: "integration" }
    }]
  });

  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "add command-exact coverage fixture");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}

function monotonicClock() {
  let current = Date.parse("2026-07-15T00:00:00.000Z");
  return () => new Date(current++);
}
