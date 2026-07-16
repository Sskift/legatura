import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);
const MINIMUM_CLAIM_ID = "minimum-behavior";
const FULL_CLAIM_ID = "full-verification";
const CASE_DECISION = {
  status: "approved",
  authority: "maintainer",
  decidedBy: "integration-assurance-test",
  decisionType: "case-decision",
  rationale: "Accept only this exact bounded Change after its minimum Gate passes."
};
const NO_NEW_KNOWLEDGE = {
  status: "complete",
  noNewKnowledge: true,
  rationale: "The fixture Change discovered no future-relevant project knowledge."
};

test("minimum accepts a Change while full remains a sealed integration assurance step", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "minimum-acceptance-full-integration";

  await createCompiledChange(kernel, changeId);
  const minimum = await kernel.runGate(changeId, "minimum");
  assert.equal(minimum.status, "passed");
  assert.equal(minimum.change.state, "EvidenceReady");

  const accepted = await kernel.acceptChange(changeId, CASE_DECISION);
  assert.equal(accepted.state, "Accepted");
  assert.equal(accepted.acceptance.valid, true);
  const acceptanceDigest = accepted.acceptance.digest;

  const full = await kernel.runGate(changeId, "full");
  assert.equal(full.status, "passed");
  assert.equal(full.change.state, "Accepted");
  assert.equal(full.change.acceptance.valid, true);
  assert.equal(full.change.acceptance.digest, acceptanceDigest);
  assert.equal(full.change.integrationAssurance.valid, true);
  assert.equal(full.change.integrationAssurance.acceptanceDigest, acceptanceDigest);
  assert.match(full.change.integrationAssurance.digest, /^sha256:[a-f0-9]{64}$/u);

  await assert.rejects(
    () => kernel.runGate(changeId, "minimum"),
    (error) => error?.code === "CHANGE_SEALED"
  );
  const stillAccepted = await kernel.getChange(changeId);
  assert.equal(stillAccepted.state, "Accepted");
  assert.equal(stillAccepted.acceptance.valid, true);
  assert.equal(stillAccepted.acceptance.digest, acceptanceDigest);

  const integrated = await kernel.acceptChange(changeId, { integrate: true });
  assert.equal(integrated.state, "Integrated");
  assert.equal(integrated.acceptance.valid, true);
  assert.equal(integrated.integration.acceptanceDigest, acceptanceDigest);
});

test("tampered integration assurance cannot authorize integration", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const attacks = [
    {
      id: "forged-integration-assurance-digest",
      mutate(assurance) {
        assurance.digest = `sha256:${"0".repeat(64)}`;
      }
    },
    {
      id: "forged-integration-assurance-content",
      mutate(assurance) {
        assert.ok(assurance.gateRuns.length > 0);
        assurance.gateRuns[0].status = "failed";
      }
    }
  ];

  for (const attack of attacks) {
    await createCompiledChange(kernel, attack.id);
    await kernel.runGate(attack.id, "minimum");
    const accepted = await kernel.acceptChange(attack.id, CASE_DECISION);
    assert.equal(accepted.state, "Accepted");
    const full = await kernel.runGate(attack.id, "full");
    assert.equal(full.status, "passed");
    assert.equal(full.change.integrationAssurance.valid, true);

    await mutateRuntimeChange(fixture.repoPath, attack.id, (record) => {
      const retainedDigest = record.integrationAssurance.digest;
      attack.mutate(record.integrationAssurance);
      if (attack.id.endsWith("content")) {
        assert.equal(
          record.integrationAssurance.digest,
          retainedDigest,
          "content forgery deliberately retains the previously trusted digest"
        );
      }
    });

    await assert.rejects(
      () => kernel.acceptChange(attack.id, { integrate: true }),
      (error) => error?.code === "FULL_GATE_REQUIRED"
    );
    const refused = await kernel.getChange(attack.id);
    assert.equal(refused.state, "Accepted");
    assert.equal(refused.acceptance.valid, true);
    assert.equal(refused.integration, undefined);
  }
});

async function createCompiledChange(kernel, id) {
  await kernel.createChange({
    id,
    title: `Integration assurance ${id}`,
    primaryModule: "core",
    claims: [{
      id: MINIMUM_CLAIM_ID,
      statement: "The minimum governed behavior remains correct."
    }],
    knowledgeClosure: NO_NEW_KNOWLEDGE
  });
  return kernel.compileChange(id);
}

async function mutateRuntimeChange(repoPath, changeId, mutate) {
  const target = path.join(repoPath, ".legatura", "runtime", "changes", `${changeId}.json`);
  const record = JSON.parse(await readFile(target, "utf8"));
  mutate(record);
  await writeJson(target, record);
}

async function createFixture(t) {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-integration-assurance-"));
  t.after(() => rm(repoPath, { force: true, recursive: true }));
  await Promise.all([
    mkdir(path.join(repoPath, ".legatura", "modules"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "contracts"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "gates"), { recursive: true }),
    mkdir(path.join(repoPath, "src"), { recursive: true })
  ]);

  await Promise.all([
    writeFile(path.join(repoPath, ".legatura", ".gitignore"), "runtime/\n"),
    writeJson(path.join(repoPath, ".legatura", "project.json"), {
      schemaVersion: 1,
      project: { id: "integration-assurance-fixture", name: "Integration Assurance Fixture" },
      authorities: {
        fact: [{ id: "core-facts", module: "core", owns: "Fixture behavior" }],
        decision: [{ id: "maintainer", may: ["case-decision"] }]
      },
      normativeSources: [{ id: "accepted-requirement" }],
      assuranceBoundary: {
        governed: [{ module: "core", reason: "Fixture behavior has explicit Contracts and Gates." }],
        provisional: [],
        opaque: []
      },
      changePolicy: {
        defaultGate: "minimum",
        fullGate: "full",
        fullGateBefore: ["integrated", "release"]
      }
    }),
    writeJson(path.join(repoPath, ".legatura", "modules", "core.json"), {
      schemaVersion: 1,
      id: "core",
      name: "Core",
      status: "governed",
      summary: "A bounded fixture Module.",
      factAuthority: "core-facts",
      decisionAuthority: "maintainer",
      interface: { accepts: ["request"], returns: ["result"] },
      paths: { include: ["src/**"], exclude: [] },
      publicContracts: ["core-api"],
      dependencies: []
    }),
    writeJson(path.join(repoPath, ".legatura", "contracts", "core-api.json"), {
      schemaVersion: 1,
      id: "core-api",
      name: "Core API",
      owner: "core",
      maturity: "governed",
      normativeSources: ["accepted-requirement"],
      claims: [
        { id: MINIMUM_CLAIM_ID, statement: "The minimum governed behavior remains correct." },
        { id: FULL_CLAIM_ID, statement: "The full verification profile remains correct." }
      ],
      consumers: []
    }),
    writeGate(repoPath, {
      id: "minimum",
      name: "Minimum Gate",
      appliesTo: ["core"],
      claimId: MINIMUM_CLAIM_ID
    }),
    writeGate(repoPath, {
      id: "full",
      name: "Full Gate",
      appliesTo: ["integration", "release"],
      claimId: FULL_CLAIM_ID
    }),
    writeJson(path.join(repoPath, ".legatura", "knowledge-gaps.json"), {
      schemaVersion: 1,
      gaps: []
    }),
    writeFile(path.join(repoPath, "src", "index.mjs"), "export const governed = true;\n")
  ]);

  await git(repoPath, "init", "--quiet");
  await git(repoPath, "config", "user.name", "Legatura Integration Test");
  await git(repoPath, "config", "user.email", "integration@example.invalid");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "--quiet", "-m", "integration assurance baseline");
  return { repoPath };
}

function writeGate(repoPath, { id, name, appliesTo, claimId }) {
  return writeJson(path.join(repoPath, ".legatura", "gates", `${id}.json`), {
    schemaVersion: 1,
    id,
    name,
    purpose: `${name} for the integration assurance fixture.`,
    appliesTo,
    commands: [{
      id: `${id}-command`,
      command: [process.execPath, "-e", "process.exit(0)"],
      timeoutMs: 30_000,
      claimRefs: [claimId],
      oracle: {
        kind: "deterministic-process-exit",
        description: `${name} must exit successfully.`
      },
      applicability: { modules: ["core"], phase: id === "full" ? "integration" : "acceptance" },
      discriminatoryPower: { rejects: [`non-zero ${id} process exits`] },
      residualUncertainty: [`The ${id} fixture is intentionally bounded.`]
    }]
  });
}

function writeJson(targetPath, value) {
  return writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
