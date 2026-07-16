import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);
const MINIMUM_CLAIM_ID = "minimum-behavior";
const CASE_DECISION = {
  status: "approved",
  authority: "maintainer",
  decidedBy: "trust-invariant-test",
  decisionType: "case-decision",
  rationale: "The exact bounded Change is accepted for this case only."
};
const NO_NEW_KNOWLEDGE = {
  status: "complete",
  noNewKnowledge: true,
  rationale: "The Change discovered no future-relevant project knowledge."
};

test("changing intent after a Gate makes old Evidence stale and returns to Submitted", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  await createAndCompile(kernel, {
    id: "intent-stales-evidence",
    knowledgeClosure: NO_NEW_KNOWLEDGE
  });
  const gateResult = await kernel.runGate("intent-stales-evidence", "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");

  const changed = await kernel.compileChange("intent-stales-evidence", {
    intent: {
      description: "This is a materially different intent introduced after observation."
    }
  });

  assert.equal(
    changed.state,
    "Submitted",
    "Evidence collected for the prior intent must not remain acceptance-ready"
  );
  await assert.rejects(
    () => kernel.acceptChange("intent-stales-evidence", CASE_DECISION),
    (error) => error?.code === "CHANGE_NOT_EVIDENCE_READY"
  );
});

test("Knowledge Closure requires a legal classification, not status complete alone", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  await createAndCompile(kernel, {
    id: "empty-knowledge-closure",
    knowledgeClosure: { status: "complete" }
  });
  const gateResult = await kernel.runGate("empty-knowledge-closure", "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");

  await assert.rejects(
    () => kernel.acceptChange("empty-knowledge-closure", CASE_DECISION),
    (error) => ["KNOWLEDGE_CLOSURE_INVALID", "KNOWLEDGE_CLOSURE_REQUIRED"].includes(error?.code),
    "status complete without entries or an explicit noNewKnowledge rationale must be rejected"
  );
});

test("a Change executes its frozen baseline Gate after the on-disk Gate is weakened", async (t) => {
  const fixture = await createFixture(t, { minimumExitCode: 17 });
  const kernel = createKernel({ repoPath: fixture.repoPath });
  await kernel.createChange(changeInput({
    id: "frozen-governance-baseline",
    knowledgeClosure: NO_NEW_KNOWLEDGE
  }));

  await fixture.writeMinimumGate(0);
  await kernel.compileChange("frozen-governance-baseline");
  const gateResult = await kernel.runGate("frozen-governance-baseline", "minimum");
  const configuredRun = gateResult.gateRuns.find((run) => run.gateId === "minimum");

  assert.ok(configuredRun, "the frozen minimum Gate should execute");
  assert.equal(
    configuredRun.commandResults[0].exitCode,
    17,
    "the post-creation weaker command must not replace the Change's Governance Baseline"
  );
  assert.equal(configuredRun.status, "failed");
  assert.equal(gateResult.status, "failed");
});

async function createAndCompile(kernel, { id, knowledgeClosure }) {
  await kernel.createChange(changeInput({ id, knowledgeClosure }));
  return kernel.compileChange(id);
}

function changeInput({ id, knowledgeClosure }) {
  return {
    id,
    title: `Trust invariant ${id}`,
    primaryModule: "core",
    claims: [{
      id: MINIMUM_CLAIM_ID,
      statement: "The minimum governed behavior remains correct."
    }],
    knowledgeClosure
  };
}

async function createFixture(t, {
  minimumExitCode = 0,
  changePolicy = { defaultGate: "minimum" }
} = {}) {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-trust-"));
  t.after(() => rm(repoPath, { force: true, recursive: true }));
  await Promise.all([
    mkdir(path.join(repoPath, ".legatura", "modules"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "contracts"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "gates"), { recursive: true }),
    mkdir(path.join(repoPath, "src"), { recursive: true })
  ]);

  await Promise.all([
    writeJson(path.join(repoPath, ".legatura", "project.json"), {
      project: { id: "trust-fixture", name: "Trust Fixture" },
      authorities: {
        fact: [{ id: "core-facts" }],
        decision: [{ id: "maintainer" }]
      },
      normativeSources: [{ id: "accepted-requirement" }],
      assuranceBoundary: { governed: ["core"], provisional: [], opaque: [] },
      changePolicy
    }),
    writeJson(path.join(repoPath, ".legatura", "modules", "core.json"), {
      id: "core",
      name: "Core",
      status: "governed",
      paths: { include: ["src/**"] },
      interface: { description: "The governed fixture interface." },
      factAuthority: "core-facts",
      decisionAuthority: "maintainer",
      publicContracts: ["core-api"]
    }),
    writeJson(path.join(repoPath, ".legatura", "contracts", "core-api.json"), {
      id: "core-api",
      name: "Core API",
      owner: "core",
      consumers: [],
      normativeSources: ["accepted-requirement"],
      claims: [
        { id: MINIMUM_CLAIM_ID, statement: "The minimum governed behavior remains correct." }
      ]
    }),
    writeGate(repoPath, "minimum", MINIMUM_CLAIM_ID, minimumExitCode),
    writeFile(path.join(repoPath, "src", "index.mjs"), "export const governed = true;\n")
  ]);

  await execFileAsync("git", ["init", "--quiet"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.name", "Legatura Trust Test"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.email", "trust@example.invalid"], { cwd: repoPath });
  await execFileAsync("git", ["add", "."], { cwd: repoPath });
  await execFileAsync("git", ["commit", "--quiet", "-m", "governance baseline"], { cwd: repoPath });

  return {
    repoPath,
    writeMinimumGate(exitCode) {
      return writeGate(repoPath, "minimum", MINIMUM_CLAIM_ID, exitCode);
    }
  };
}

function writeGate(repoPath, gateId, claimId, exitCode) {
  return writeJson(path.join(repoPath, ".legatura", "gates", `${gateId}.json`), {
    id: gateId,
    name: "Minimum Verification",
    commands: [{
      id: `${gateId}-command`,
      command: [process.execPath, "-e", `process.exit(${exitCode})`],
      claimRefs: [claimId],
      oracle: {
        kind: "deterministic-process-exit",
        description: `${gateId} fixture command must exit successfully.`
      },
      applicability: { phase: gateId === "full" ? "integration" : "acceptance" },
      discriminatoryPower: { rejects: [`non-zero ${gateId} fixture exits`] },
      residualUncertainty: [`The ${gateId} fixture is intentionally bounded.`]
    }]
  });
}

function writeJson(targetPath, value) {
  return writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`);
}
