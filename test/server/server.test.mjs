import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createServer, LOOPBACK_HOST } from "../../src/server.mjs";

const execFileAsync = promisify(execFile);

test("serves public assets and the complete Change API on loopback", async (t) => {
  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-public-"));
  await writeFile(path.join(publicDir, "index.html"), "<!doctype html><title>Legatura</title>");
  t.after(() => rm(publicDir, { force: true, recursive: true }));

  const calls = [];
  const change = { id: "change-1", title: "Bound the change", status: "framed" };
  const kernel = {
    async inspectProject() {
      calls.push(["inspectProject"]);
      return { name: "fixture", validation: { valid: true } };
    },
    async listChanges() {
      calls.push(["listChanges"]);
      return [change];
    },
    async createChange(input) {
      calls.push(["createChange", input]);
      return { ...change, ...input };
    },
    async getChange(id) {
      calls.push(["getChange", id]);
      return id === change.id ? change : undefined;
    },
    async compileChange(id, patch) {
      calls.push(["compileChange", id, patch]);
      return { ...change, status: "compiled", patch };
    },
    async runGate(id, gateId) {
      calls.push(["runGate", id, gateId]);
      return { ...change, status: "evidence-ready", gateId };
    },
    async acceptChange(id, decision) {
      calls.push(["acceptChange", id, decision]);
      return { ...change, status: "accepted", decision };
    }
  };

  const app = createServer({ kernel, publicDir });
  t.after(() => app.close());
  const address = await app.listen(0);
  assert.equal(address.host, LOOPBACK_HOST);

  const indexResponse = await fetch(`${address.url}/`);
  assert.equal(indexResponse.status, 200);
  assert.match(indexResponse.headers.get("content-type"), /^text\/html/);
  assert.match(indexResponse.headers.get("content-security-policy"), /frame-ancestors 'none'/);
  assert.equal(indexResponse.headers.get("x-frame-options"), "DENY");
  assert.match(await indexResponse.text(), /Legatura/);

  assert.deepEqual(await getJson(`${address.url}/api/project`), {
    name: "fixture",
    validation: { valid: true }
  });
  assert.deepEqual(await getJson(`${address.url}/api/changes`), [change]);

  const created = await requestJson(`${address.url}/api/changes`, "POST", {
    title: "Created through HTTP",
    intent: "Keep intent explicit"
  });
  assert.equal(created.response.status, 201);
  assert.equal(created.body.title, "Created through HTTP");

  assert.deepEqual(await getJson(`${address.url}/api/changes/change-1`), change);

  const compiled = await requestJson(
    `${address.url}/api/changes/change-1/compile`,
    "POST",
    { primaryModule: "core" }
  );
  assert.equal(compiled.body.status, "compiled");
  assert.deepEqual(compiled.body.patch, { primaryModule: "core" });

  const gate = await requestJson(
    `${address.url}/api/changes/change-1/gates/minimum/run`,
    "POST",
    {}
  );
  assert.equal(gate.body.status, "evidence-ready");
  assert.equal(gate.body.gateId, "minimum");

  const accepted = await requestJson(
    `${address.url}/api/changes/change-1/accept`,
    "POST",
    { authority: "maintainer", decidedBy: "human" }
  );
  assert.equal(accepted.body.status, "accepted");
  assert.equal(accepted.body.decision.authority, "maintainer");

  assert.deepEqual(calls, [
    ["inspectProject"],
    ["listChanges"],
    ["createChange", { title: "Created through HTTP", intent: "Keep intent explicit" }],
    ["getChange", "change-1"],
    ["compileChange", "change-1", { primaryModule: "core" }],
    ["runGate", "change-1", "minimum"],
    ["acceptChange", "change-1", { authority: "maintainer", decidedBy: "human" }]
  ]);
});

test("returns bounded structured JSON errors", async (t) => {
  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-public-"));
  await writeFile(path.join(publicDir, "index.html"), "ok");
  t.after(() => rm(publicDir, { force: true, recursive: true }));

  const kernel = {
    async getChange() {
      return undefined;
    }
  };
  const app = createServer({ kernel, publicDir, bodyLimitBytes: 32 });
  t.after(() => app.close());
  const address = await app.listen(0);

  const missing = await fetch(`${address.url}/api/changes/missing`);
  assert.equal(missing.status, 404);
  assert.deepEqual(await missing.json(), {
    error: {
      code: "CHANGE_NOT_FOUND",
      message: "Change missing was not found."
    }
  });

  const malformed = await fetch(`${address.url}/api/changes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{not-json"
  });
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).error.code, "INVALID_JSON");

  const simpleCrossSiteBody = await fetch(`${address.url}/api/changes`, {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: "{}"
  });
  assert.equal(simpleCrossSiteBody.status, 415);
  assert.equal((await simpleCrossSiteBody.json()).error.code, "JSON_CONTENT_TYPE_REQUIRED");

  const foreignOrigin = await fetch(`${address.url}/api/changes`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://attacker.example"
    },
    body: "{}"
  });
  assert.equal(foreignOrigin.status, 403);
  assert.equal((await foreignOrigin.json()).error.code, "ORIGIN_FORBIDDEN");

  const oversized = await fetch(`${address.url}/api/changes`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ intent: "x".repeat(100) })
  });
  assert.equal(oversized.status, 413);
  assert.deepEqual(await oversized.json(), {
    error: {
      code: "BODY_TOO_LARGE",
      message: "The request body exceeds the 32-byte limit.",
      details: { limitBytes: 32 }
    }
  });

  const missingAsset = await fetch(`${address.url}/missing.js`);
  assert.equal(missingAsset.status, 404);
  assert.equal((await missingAsset.json()).error.code, "STATIC_NOT_FOUND");

  const wrongMethod = await fetch(`${address.url}/api/project`, { method: "POST" });
  assert.equal(wrongMethod.status, 405);
  assert.deepEqual((await wrongMethod.json()).error.details.allowed, ["GET"]);
});

test("drives a real repository Change from creation through acceptance", async (t) => {
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
  assert.match(accepted.body.acceptance.digest, /^sha256:[a-f0-9]{64}$/);
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
      assuranceBoundary: {
        governed: ["core"],
        provisional: [],
        opaque: []
      },
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
        applicability: { modules: ["core"] },
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
