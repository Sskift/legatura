import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createKernel } from "../../src/core/index.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";

const execFileAsync = promisify(execFile);
const FORBIDDEN_SUMMARY_KEYS = new Set([
  "acceptance",
  "evidence",
  "gateRuns",
  "governanceBaseline",
  "package",
  "stderr",
  "stdout"
]);

test("Change queries observe sources independently of N and keep list bodies bounded and reads pure", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const writer = createKernel({ repoPath: fixture.repoPath });
  const records = [];
  for (const id of ["query-one", "query-two", "query-three"]) {
    records.push(await writer.createChange({
      id,
      title: `${id} ${"bounded ".repeat(80)}`,
      request: `${id} ${"request ".repeat(80)}`,
      primaryModule: "core",
      claims: [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
    }));
  }
  await writer.compileChange(records[1].id, {
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture introduces no durable project knowledge beyond this declared proof."
    }
  });
  await writer.runGate(records[1].id);
  await writer.acceptChange(records[1].id, {
    authority: "module-maintainer",
    decidedBy: "architecture-profile-test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "Seal the exact fixture record before testing a top-level-only tamper."
  });

  const detailPath = changePath(fixture.repoPath, records[0].id);
  const stored = JSON.parse(await readFile(detailPath, "utf8"));
  stored.evidence = [{
    id: "large-evidence",
    stdout: "private-output".repeat(1000),
    provenance: {}
  }];
  stored.gateRuns = [{
    gateId: "large-gate",
    stdout: "private-stdout".repeat(1000),
    stderr: "private-stderr".repeat(1000),
    evidenceBindings: []
  }];
  stored.acceptance = {
    valid: true,
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    package: { body: "private-package".repeat(1000) }
  };
  await writeJson(detailPath, stored);
  const bytesBefore = await readFile(detailPath, "utf8");

  const counted = countingCommandRunner();
  const reader = createKernel({ repoPath: fixture.repoPath, commandRunner: counted.run });
  const summaries = await reader.listChanges();

  assert.equal(counted.observations(), 2, "N records still require exactly two stable source rounds");
  assert.equal(summaries.length, 3);
  assert.ok(JSON.stringify(summaries[0]).length < 3000);
  assert.equal(summaries[0].intent.title.length, 240);
  assert.equal(summaries[0].truncated.title, true);
  assertNoForbiddenSummaryKeys(summaries);
  assert.equal(await readFile(detailPath, "utf8"), bytesBefore, "list must not rewrite runtime records");

  counted.reset();
  const detail = await reader.getChange(records[0].id);
  assert.equal(counted.observations(), 2, "detail also acquires one stable composite snapshot");
  assert.equal(detail.state, stored.state);
  assert.deepEqual(detail.acceptance, stored.acceptance, "historical acceptance is returned without projection mutation");
  assert.equal(detail.evidence[0].stdout.startsWith("private-output"), true);
  assert.equal(detail.gateRuns[0].stderr.startsWith("private-stderr"), true);
  assert.equal(detail.acceptance.package.body.startsWith("private-package"), true);
  assert.deepEqual(detail.observation.seal.problems.includes("package-digest-mismatch"), true);
  assert.equal(detail.observation.evidenceCurrency.invalidIds.includes("large-evidence"), true);
  assert.equal(await readFile(detailPath, "utf8"), bytesBefore, "detail must not rewrite runtime records");

  counted.reset();
  const currentDetail = await reader.getChange(records[1].id);
  assert.equal(counted.observations(), 2);
  assert.equal(currentDetail.observation.evidenceCurrency.currentIds.length, 2);
  assert.deepEqual(currentDetail.observation.evidenceCurrency.invalidIds, []);
  assert.equal(currentDetail.observation.seal.intact, true);
  assert.equal(currentDetail.observation.currentApplicability.status, "current");

  const routeForgedPath = changePath(fixture.repoPath, records[1].id);
  const routeForged = JSON.parse(await readFile(routeForgedPath, "utf8"));
  const gateEvidence = routeForged.evidence.find((item) => item.provenance?.kind === "gate-command");
  gateEvidence.provenance.gateId = "forged-gate";
  const gateRun = routeForged.gateRuns.find((run) => run.evidenceIds?.includes(gateEvidence.id));
  gateRun.evidenceBindings.find((binding) => binding.id === gateEvidence.id).digest = canonicalDigest(gateEvidence);
  await writeJson(routeForgedPath, routeForged);
  const forgedBytes = await readFile(routeForgedPath, "utf8");
  const forgedDetail = await reader.getChange(records[1].id);
  assert.equal(forgedDetail.observation.evidenceCurrency.invalidIds.includes(gateEvidence.id), true);
  assert.equal(forgedDetail.observation.seal.packageIntact, true);
  assert.equal(forgedDetail.observation.seal.recordProjectionIntact, false);
  assert.equal(forgedDetail.observation.seal.intact, false);
  assert.equal(forgedDetail.observation.currentApplicability.status, "invalid");
  assert.equal(
    forgedDetail.acceptance.package.evidence.some((item) => item.provenance?.gateId === "forged-gate"),
    false,
    "the historical package remains distinct from mutable top-level Evidence"
  );
  assert.equal(await readFile(routeForgedPath, "utf8"), forgedBytes);
});

test("bounded stabilization accepts A/B/B and fails closed on A/B/C", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  const c = "c".repeat(40);

  const converging = sequencedGitRunner([a, b, b]);
  const convergingKernel = createKernel({ repoPath: fixture.repoPath, commandRunner: converging.run });
  assert.deepEqual(await convergingKernel.listChanges(), []);
  assert.equal(converging.observations(), 3);

  const projectConverging = sequencedGitRunner([a, b, b]);
  const inspection = await createKernel({
    repoPath: fixture.repoPath,
    commandRunner: projectConverging.run
  }).inspectProject();
  assert.equal(inspection.git.head, b);
  assert.equal(projectConverging.observations(), 3);

  const unstable = sequencedGitRunner([a, b, c]);
  const unstableKernel = createKernel({ repoPath: fixture.repoPath, commandRunner: unstable.run });
  await assert.rejects(
    unstableKernel.listChanges(),
    (error) => error?.code === "CHANGE_QUERY_SNAPSHOT_UNSTABLE"
      && error?.statusCode === 409
      && error.details.observationCount === 3
      && error.details.observedDigests.length === 3
      && new Set(error.details.observedDigests).size === 3
      && Object.keys(error.details).sort().join(",") === "observationCount,observedDigests"
  );
  assert.equal(unstable.observations(), 3);
});

function assertNoForbiddenSummaryKeys(value) {
  if (Array.isArray(value)) {
    for (const item of value) assertNoForbiddenSummaryKeys(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    assert.equal(FORBIDDEN_SUMMARY_KEYS.has(key), false, `summary leaked ${key}`);
    assertNoForbiddenSummaryKeys(item);
  }
}

function countingCommandRunner() {
  let count = 0;
  return {
    async run(specification) {
      if (specification.purpose === "git-binding" && specification.args?.[0] === "rev-parse") {
        count += 1;
      }
      try {
        const result = await execFileAsync(specification.command, specification.args ?? [], {
          cwd: specification.cwd,
          maxBuffer: 2 * 1024 * 1024
        });
        return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
      } catch (error) {
        return {
          exitCode: Number.isInteger(error?.code) ? error.code : 1,
          stdout: typeof error?.stdout === "string" ? error.stdout : "",
          stderr: typeof error?.stderr === "string" ? error.stderr : String(error)
        };
      }
    },
    observations: () => count,
    reset: () => { count = 0; }
  };
}

function sequencedGitRunner(heads) {
  let count = 0;
  let currentHead = heads[0];
  return {
    async run(specification) {
      const operation = specification.args?.[0];
      if (operation === "rev-parse") {
        currentHead = heads[Math.min(count, heads.length - 1)];
        count += 1;
        return commandResult(`${currentHead}\n`);
      }
      if (operation === "branch") return commandResult("main\n");
      if (operation === "status" || operation === "diff" || operation === "ls-files") {
        return commandResult("");
      }
      return { exitCode: 1, stdout: "", stderr: `Unexpected Git command after ${currentHead}.` };
    },
    observations: () => count
  };
}

function commandResult(stdout) {
  return { exitCode: 0, stdout, stderr: "" };
}

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-stable-query-"));
  await mkdir(path.join(repoPath, ".legatura/modules"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/contracts"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/gates"), { recursive: true });
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "stable-query-fixture", name: "Stable Query Fixture" },
    authorities: {
      decision: [{ id: "module-maintainer", may: ["case-decision"] }],
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
    decisionAuthority: "module-maintainer",
    interface: { accepts: ["request"], returns: ["result"] },
    paths: { include: ["src/**"], exclude: [] },
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
      command: [process.execPath, "-e", "process.exit(0)"],
      timeoutMs: 30_000,
      claimRefs: ["behavior-correct"],
      oracle: { kind: "fixture", description: "The fixture command exits zero." },
      applicability: { phase: "acceptance" },
      discriminatoryPower: { rejects: ["A non-zero exit rejects the fixture."] },
      residualUncertainty: ["Only fixture behavior is covered."]
    }]
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), { schemaVersion: 1, gaps: [] });
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const value = true;\n");
  await writeFile(path.join(repoPath, "README.md"), "stable query fixture\n");
  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return { repoPath };
}

function changePath(repoPath, id) {
  return path.join(repoPath, ".legatura/runtime/changes", `${id}.json`);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
