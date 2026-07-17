import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);
const OUTCOME_REF = "LGT-900";

test("Outcome Plan Amendment compilation is rederived across Kernel lifecycle boundaries", async (t) => {
  const repoPath = await copyFixtureRepository(t);
  const planPath = path.join(repoPath, ".legatura/plan.json");
  const baselinePlan = JSON.parse(await readFile(planPath, "utf8"));
  baselinePlan.stages.find((stage) => stage.id === "S1").outcomeRefs.push(OUTCOME_REF);
  baselinePlan.outcomes.push({
    id: OUTCOME_REF,
    stage: "S1",
    status: "planned",
    outcome: "A speculative fixture Outcome can be refined before activation.",
    dependsOn: [],
    acceptance: {
      claimRefs: [],
      gapRefs: [],
      exitCriteria: ["The refined fixture meaning remains exact and recoverable."]
    },
    nonGoals: ["Task tracking"]
  });
  await writeJson(planPath, baselinePlan);
  await runGit(repoPath, "add", ".legatura/plan.json");
  await runGit(repoPath, "commit", "-m", "test: declare planned revision fixture");

  const kernel = createKernel({ repoPath });
  const inspection = await kernel.inspectProject();
  assert.equal(inspection.valid, true, JSON.stringify(inspection.validation.errors));
  const claim = inspection.contracts.flatMap((contract) => contract.claims ?? [])
    .find((candidate) => candidate.id === "planned-outcome-revisions-are-append-only");
  assert.ok(claim);

  const oldCandidate = await kernel.createChange({
    id: "candidate-before-revision",
    title: "Remain bound to the pre-Revision Governance Baseline",
    primaryModule: "change-kernel",
    planRefs: ["LGT-018"],
    claims: [{
      id: "change-lifecycle-requires-preconditions",
      statement: "A Change reaches Accepted only after explicit Claims, compiled verification obligations, current direct Evidence, Knowledge Closure, scope compliance, and the required Authority Decision are all present."
    }]
  });
  const revisionChange = await kernel.createChange({
    id: "accept-planned-outcome-revision",
    title: "Revise one planned Outcome through append-only history",
    changeKind: "plan-amendment",
    primaryModule: "project-model",
    claims: [claim],
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-amendment",
        refs: [".legatura/plan.json"],
        statement: "The fixture Plan appends one complete, authority-bound pre-activation Revision.",
        rationale: "Later Candidates must inherit the refined definition only from an Accepted Governance Baseline."
      }]
    }
  });

  const currentPlan = JSON.parse(await readFile(planPath, "utf8"));
  const target = currentPlan.outcomes.find((outcome) => outcome.id === OUTCOME_REF);
  const previousDefinition = normalizedDefinition(target);
  target.outcome = "A bounded fixture Outcome is refined before activation with its earlier meaning preserved.";
  const currentDefinition = normalizedDefinition(target);
  currentPlan.outcomeRevisions.push({
    id: `${OUTCOME_REF}-R1`,
    outcomeRef: OUTCOME_REF,
    amendmentChangeId: revisionChange.id,
    governanceBaselineDigest: revisionChange.governanceBaseline.digest,
    previousDefinition,
    previousDefinitionDigest: canonicalDigest(previousDefinition),
    currentDefinitionDigest: canonicalDigest(currentDefinition),
    changedFields: ["outcome"],
    rationale: "Refine the speculative fixture meaning while preserving its exact earlier definition.",
    requiredAuthorityRef: currentPlan.authority
  });
  await writeJson(planPath, currentPlan);

  const authorityDecision = {
    status: "approved",
    authority: "governance-maintainer",
    decidedBy: "kernel-proof-governance-maintainer",
    decisionType: "normative-amendment",
    rationale: "Approve only this exact planned Outcome Revision and its append-only frozen-baseline binding.",
    amendmentRefs: [".legatura/plan.json"]
  };
  const compiled = await kernel.compileChange(revisionChange.id, { authorityDecision });
  assert.equal(compiled.outcomePlanAmendmentSchemaVersion, 1);
  assert.equal(compiled.outcomePlanAmendmentCompilation.amendmentKind, "revision");
  assert.equal(compiled.outcomePlanAmendmentCompilation.appendedRevisions[0].id, `${OUTCOME_REF}-R1`);
  assert.equal(Object.hasOwn(compiled, "outcomeTransitionCompilation"), false);

  await mutateRevisionRationale(planPath, " Gate-time tamper.");
  await assert.rejects(
    kernel.runGate(revisionChange.id, "outcome-revisions"),
    (error) => error.code === "OUTCOME_PLAN_AMENDMENT_COMPILATION_STALE"
  );
  await writeJson(planPath, currentPlan);

  const proofGate = await kernel.runGate(revisionChange.id, "outcome-revisions");
  assert.equal(proofGate.status, "passed");
  assert.deepEqual(
    proofGate.gateRuns.find((run) => run.gateId === "outcome-revisions")
      .commandResults.map((result) => result.id),
    ["outcome-revision-proof"]
  );
  const minimumGate = await kernel.runGate(revisionChange.id, "minimum");
  assert.equal(minimumGate.status, "passed");
  assert.deepEqual(
    minimumGate.gateRuns.find((run) => run.gateId === "minimum")
      .commandResults.map((result) => result.id),
    ["project-model-minimum"]
  );
  assert.equal((await kernel.getChange(revisionChange.id)).state, "EvidenceReady");

  await mutateRevisionRationale(planPath, " Acceptance-time tamper.");
  await assert.rejects(
    kernel.acceptChange(revisionChange.id),
    (error) => error.code === "OUTCOME_PLAN_AMENDMENT_COMPILATION_STALE"
  );
  await writeJson(planPath, currentPlan);

  const accepted = await kernel.acceptChange(revisionChange.id);
  assert.equal(accepted.state, "Accepted");
  assert.deepEqual(
    accepted.acceptance.package.outcomePlanAmendmentCompilation,
    compiled.outcomePlanAmendmentCompilation
  );
  assert.equal(Object.hasOwn(accepted.acceptance.package, "outcomeTransitionCompilation"), false);

  await assert.rejects(
    kernel.compileChange(oldCandidate.id),
    (error) => error.code === "GOVERNANCE_BASELINE_STALE"
  );
  const laterCandidate = await kernel.createChange({
    id: "candidate-after-revision",
    title: "Inherit only the Accepted refined Governance Baseline",
    primaryModule: "change-kernel",
    planRefs: ["LGT-018"],
    claims: [{
      id: "change-lifecycle-requires-preconditions",
      statement: "A Change reaches Accepted only after explicit Claims, compiled verification obligations, current direct Evidence, Knowledge Closure, scope compliance, and the required Authority Decision are all present."
    }]
  });
  assert.equal(
    laterCandidate.governanceBaseline.plan.outcomeRevisions.at(-1).id,
    `${OUTCOME_REF}-R1`
  );
});

async function copyFixtureRepository(t) {
  const sourceRoot = path.resolve(import.meta.dirname, "../..");
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "legatura-outcome-amendment-"));
  const repoPath = path.join(fixtureRoot, "repo");
  t.after(() => rm(fixtureRoot, { recursive: true, force: true }));
  await cp(sourceRoot, repoPath, {
    recursive: true,
    filter: (source) => {
      const relative = path.relative(sourceRoot, source);
      return relative === ""
        || (!relative.startsWith(".git")
          && !relative.startsWith(path.join(".legatura", "runtime"))
          && !relative.startsWith("node_modules"));
    }
  });
  await runGit(repoPath, "init", "-q");
  await runGit(repoPath, "config", "user.name", "Legatura Kernel Proof");
  await runGit(repoPath, "config", "user.email", "kernel-proof@legatura.test");
  await runGit(repoPath, "add", ".");
  await runGit(repoPath, "commit", "-qm", "test: initialize kernel proof fixture");
  return repoPath;
}

function normalizedDefinition(outcome) {
  return {
    id: outcome.id,
    stage: outcome.stage,
    outcome: outcome.outcome,
    dependsOn: [...new Set(outcome.dependsOn ?? [])].sort(),
    kind: outcome.kind ?? null,
    allowedChangeKinds: [...new Set(outcome.allowedChangeKinds ?? [])].sort(),
    acceptance: {
      activationCriterionRefs: [...new Set(outcome.acceptance?.activationCriterionRefs ?? [])].sort(),
      criteria: (outcome.acceptance?.criteria ?? []).map((criterion) => ({
        id: criterion.id,
        statement: criterion.statement,
        claimRefs: [...new Set(criterion.claimRefs ?? [])].sort(),
        gapRefs: [...new Set(criterion.gapRefs ?? [])].sort()
      })).sort((left, right) => left.id.localeCompare(right.id)),
      exitCriteria: [...new Set(outcome.acceptance?.exitCriteria ?? [])].sort(),
      claimRefs: [...new Set(outcome.acceptance?.claimRefs ?? [])].sort(),
      gapRefs: [...new Set(outcome.acceptance?.gapRefs ?? [])].sort()
    },
    nonGoals: [...new Set(outcome.nonGoals ?? [])].sort()
  };
}

async function mutateRevisionRationale(planPath, suffix) {
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  plan.outcomeRevisions.at(-1).rationale += suffix;
  await writeJson(planPath, plan);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

async function runGit(repoPath, ...args) {
  return execFileAsync("git", args, { cwd: repoPath });
}
