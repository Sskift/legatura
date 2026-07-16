import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createServer } from "../../src/server.mjs";

const execFileAsync = promisify(execFile);

test("drives a real repository Change from HTTP creation through acceptance", async (t) => {
  const repoPath = await createModeledRepository();
  const app = createServer({ repoPath });
  t.after(async () => {
    await app.close();
    await rm(repoPath, { force: true, recursive: true });
  });
  const address = await app.listen(0);

  const project = await getJson(`${address.url}/api/project`);
  assert.equal(project.validation.valid, true);
  assert.equal(project.project.id, "fixture-project");

  const created = await requestJson(`${address.url}/api/changes`, "POST", {
    id: "change-e2e",
    title: "Prove the local Change lifecycle",
    primaryModule: "core",
    claims: [{
      id: "change-lifecycle-works",
      statement: "A governed Change can be accepted only after its minimum Gate passes."
    }],
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The HTTP fixture introduces no reusable project knowledge."
    }
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.state, "Candidate");

  const compiled = await requestJson(
    `${address.url}/api/changes/change-e2e/compile`,
    "POST",
    {}
  );
  assert.equal(compiled.body.state, "Submitted");

  const gate = await requestJson(
    `${address.url}/api/changes/change-e2e/gates/minimum/run`,
    "POST",
    {}
  );
  assert.equal(gate.body.status, "passed");
  assert.equal(gate.body.change.state, "EvidenceReady");

  const accepted = await requestJson(
    `${address.url}/api/changes/change-e2e/accept`,
    "POST",
    {
      status: "approved",
      authority: "maintainer",
      decidedBy: "test-maintainer",
      decisionType: "case-decision",
      rationale: "Accept the exact fixture Change proven by its configured Gate."
    }
  );
  assert.equal(accepted.body.state, "Accepted");
  assert.equal(accepted.body.acceptance.valid, true);
  assert.match(accepted.body.acceptance.digest, /^sha256:[a-f0-9]{64}$/u);
});

async function getJson(url) {
  const response = await fetch(url);
  assert.equal(response.status, 200);
  return response.json();
}

async function requestJson(url, method, body) {
  const response = await fetch(url, {
    method,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return { response, body: await response.json() };
}

async function createModeledRepository() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-repo-"));
  await Promise.all([
    mkdir(path.join(repoPath, ".legatura", "modules"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "contracts"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "gates"), { recursive: true }),
    mkdir(path.join(repoPath, "src"), { recursive: true })
  ]);
  await Promise.all([
    writeJson(path.join(repoPath, ".legatura", "project.json"), {
      project: { id: "fixture-project", name: "Fixture Project" },
      authorities: {
        fact: [{ id: "core-facts" }],
        decision: [{ id: "maintainer" }]
      },
      normativeSources: [{ id: "accepted-requirement" }],
      assuranceBoundary: { governed: ["core"], provisional: [], opaque: [] },
      changePolicy: { defaultGate: "minimum" }
    }),
    writeJson(path.join(repoPath, ".legatura", "modules", "core.json"), {
      id: "core",
      name: "Core",
      status: "governed",
      paths: { include: ["src/**"] },
      interface: { description: "A deliberately small public core." },
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
      claims: [{
        id: "change-lifecycle-works",
        statement: "A governed Change can be accepted only after its minimum Gate passes."
      }]
    }),
    writeJson(path.join(repoPath, ".legatura", "gates", "minimum.json"), {
      id: "minimum",
      name: "Minimum",
      commands: [{
        id: "deterministic-pass",
        command: [process.execPath, "-e", "process.exit(0)"],
        claimRefs: ["change-lifecycle-works"],
        oracle: {
          kind: "deterministic-process-exit",
          description: "The fixture command must exit successfully."
        },
        applicability: { phase: "acceptance" },
        discriminatoryPower: { rejects: ["non-zero fixture exits"] },
        residualUncertainty: ["The fixture does not exercise an external integration."]
      }]
    }),
    writeFile(path.join(repoPath, "src", "index.mjs"), "export const ready = true;\n")
  ]);

  await execFileAsync("git", ["init", "--quiet"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.name", "Legatura Test"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.email", "legatura@example.invalid"], { cwd: repoPath });
  await execFileAsync("git", ["add", "."], { cwd: repoPath });
  await execFileAsync("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repoPath });
  return repoPath;
}

function writeJson(targetPath, value) {
  return writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`);
}
