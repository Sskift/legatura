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
    planRefs: ["LGT-900"]
  });

  assert.deepEqual(compiled.planRefs, ["LGT-900"]);
  assert.deepEqual(compiled.contextCapsule.planOutcomes.map((outcome) => outcome.id), ["LGT-900"]);
  assert.deepEqual(readExpectedAuthorities(compiled.governanceBaseline, compiled), ["module-maintainer"]);
  assert.ok(compiled.contextCapsule.scope.read.include.includes("test/core/**"));
  assert.ok(!compiled.contextCapsule.scope.write.include.includes("test/core/**"));
  assert.deepEqual(compiled.contextCapsule.module.focusedTests, [{
    path: "test/core/**",
    command: "node --test test/core"
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
  const kernel = createKernel({ repoPath: fixture.repoPath });

  const planPath = path.join(fixture.repoPath, ".legatura/plan.json");
  const plan = JSON.parse(await readFile(planPath, "utf8"));
  const historyChange = await kernel.createChange({
    title: "Preserve permanent Outcome identity across amendments",
    changeKind: "plan-amendment",
    primaryModule: "core",
    claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
  });
  assert.deepEqual(readExpectedAuthorities(historyChange.governanceBaseline, historyChange), ["project-maintainer"]);
  const renamedPlan = JSON.parse(JSON.stringify(plan));
  renamedPlan.outcomes.find((outcome) => outcome.id === "LGT-901").id = "LGT-902";
  renamedPlan.stages[0].outcomeRefs = renamedPlan.stages[0].outcomeRefs
    .map((outcomeId) => outcomeId === "LGT-901" ? "LGT-902" : outcomeId);
  await writeJson(planPath, renamedPlan);
  await assert.rejects(
    kernel.compileChange(historyChange.id),
    (error) => error.code === "PLAN_HISTORY_REWRITE_FORBIDDEN"
      && error.details.removedOutcomeIds.includes("LGT-901")
  );
  await writeJson(planPath, plan);

  const amendedPlan = JSON.parse(JSON.stringify(plan));
  amendedPlan.northStar = `${amendedPlan.northStar} Plan amendment under review.`;
  await writeJson(planPath, amendedPlan);
  const planCompiled = await kernel.compileChange(historyChange.id, {
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-amendment",
        refs: [".legatura/plan.json"],
        statement: "The fixture Development Plan records an independently reviewed clarification.",
        rationale: "Future Changes must inherit the clarified North Star from durable project truth."
      }]
    },
    authorityDecision: {
      status: "approved",
      authority: "project-maintainer",
      decidedBy: "maintainer@example.test",
      decisionType: "normative-amendment",
      rationale: "Approve the isolated Development Plan clarification.",
      amendmentRefs: [".legatura/plan.json"]
    }
  });
  assert.equal(planCompiled.state, "Submitted");
  const planGate = await kernel.runGate(historyChange.id, "minimum");
  assert.equal(planGate.change.state, "EvidenceReady");

  await writeFile(path.join(fixture.repoPath, "src/index.mjs"), "export const value = false;\n");
  await assert.rejects(
    kernel.acceptChange(historyChange.id),
    (error) => error.code === "PLAN_AMENDMENT_IMPLEMENTATION_MIXED"
      && error.details.implementationPaths.includes("src/index.mjs")
  );
  await writeFile(path.join(fixture.repoPath, "src/index.mjs"), "export const value = true;\n");
  const acceptedPlan = await kernel.acceptChange(historyChange.id);
  assert.equal(acceptedPlan.state, "Accepted");
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

  const gate = await kernel.runGate(candidate.id);
  assert.equal(gate.status, "passed");
  assert.equal(gate.change.state, "EvidenceReady");
  assert.ok(gate.change.evidence.every((item) => EVIDENCE_FIELDS.every((field) => field in item)));

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

  await kernel.compileChange(change.id, {
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
  const mapped = await kernel.runGate(change.id);
  assert.equal(mapped.change.state, "EvidenceReady");
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
  const invalidated = await kernel.getChange(change.id);

  assert.equal(invalidated.acceptance.valid, false);
  assert.equal(invalidated.state, "Submitted");
  assert.match(invalidated.acceptance.invalidationReason, /content changed/iu);
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
      outcomeRefs: ["LGT-900", "LGT-901", "LGT-999"]
    }],
    outcomes: [
      {
        id: "LGT-900",
        stage: "S1",
        status: "active",
        outcome: "The fixture Change receives only its active capability Outcome.",
        dependsOn: [],
        acceptance: {
          claimRefs: ["behavior-correct"],
          gapRefs: [],
          exitCriteria: ["The active fixture Outcome is injected into the Context Capsule."]
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

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}

function monotonicClock() {
  let current = Date.parse("2026-07-15T00:00:00.000Z");
  return () => new Date(current++);
}
