import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { createServer, LOOPBACK_HOST } from "../../src/server.mjs";
import { compileArchitectureProfileWindowViewModel } from "../../src/workbench-view-model.mjs";

test("serves public assets and the complete Change API on loopback", async (t) => {
  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-public-"));
  await writeFile(path.join(publicDir, "index.html"), "<!doctype html><title>Legatura</title>");
  t.after(() => rm(publicDir, { force: true, recursive: true }));

  const calls = [];
  const change = { id: "change-1", title: "Bound the change", status: "framed" };
  const inputRequirementsConfirmation = {
    requirementsDigest: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    binding: {
      changeRef: "change-1",
      sourceSnapshotDigest: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
      governanceBaselineDigest: "sha256:3333333333333333333333333333333333333333333333333333333333333333",
      verificationSubjectDigest: "sha256:4444444444444444444444444444444444444444444444444444444444444444"
    }
  };
  const firstProfileWindow = architectureProfileWindowFixture({
    changeIds: ["change-1"],
    hasMore: true,
    cursor: "opaque-window-cursor"
  });
  const secondProfileWindow = architectureProfileWindowFixture({
    changeIds: ["change-2"],
    offset: 1
  });
  const firstProfileWindowViewModel = compileArchitectureProfileWindowViewModel(firstProfileWindow);
  const secondProfileWindowViewModel = compileArchitectureProfileWindowViewModel(secondProfileWindow);
  const workbenchProjection = {
    schemaVersion: 2,
    source: firstProfileWindow.source,
    selection: { changeRef: null },
    authoring: {
      modules: [{
        moduleRef: "core",
        selectableClaims: [{ claimRef: "claim-1", routeRefs: ["route-1"] }]
      }]
    },
    changes: [],
    projectionDigest: "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  };
  const selectedWorkbenchProjection = {
    ...workbenchProjection,
    selection: { changeRef: "change-1" },
    changes: [{
      changeRef: "change-1",
      actions: [{
        actionRef: "accept",
        enabled: false,
        workbenchDisabledReasonCodes: ["CHANGE_NOT_EVIDENCE_READY"]
      }]
    }],
    projectionDigest: "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  };
  const kernel = {
    async inspectProject() {
      calls.push(["inspectProject"]);
      return { name: "fixture", validation: { valid: true } };
    },
    async inspectArchitectureProfileWindow(input) {
      calls.push(["inspectArchitectureProfileWindow", input]);
      return Object.hasOwn(input, "cursor") ? secondProfileWindow : firstProfileWindow;
    },
    async inspectWorkbenchProjection(input) {
      calls.push(["inspectWorkbenchProjection", input]);
      return Object.hasOwn(input, "changeRef")
        ? selectedWorkbenchProjection
        : workbenchProjection;
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
  assert.deepEqual(
    await getJson(`${address.url}/api/architecture-profile?limit=1`),
    firstProfileWindowViewModel
  );
  assert.deepEqual(
    await getJson(`${address.url}/api/architecture-profile?cursor=${encodeURIComponent("opaque-window-cursor")}`),
    secondProfileWindowViewModel
  );
  assert.deepEqual(await getJson(`${address.url}/api/workbench`), workbenchProjection);
  assert.deepEqual(
    await getJson(`${address.url}/api/workbench?changeRef=change-1`),
    selectedWorkbenchProjection
  );
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

  const missingConfirmation = await requestJson(
    `${address.url}/api/changes/change-1/accept`,
    "POST",
    { authority: "maintainer", decidedBy: "human" }
  );
  assert.equal(missingConfirmation.response.status, 409);
  assert.equal(missingConfirmation.body.error.code, "ACCEPTANCE_INPUT_CONFIRMATION_REQUIRED");

  const acceptanceRequest = {
    inputRequirementsConfirmation,
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "No reusable knowledge is introduced by the fixture."
    },
    authorityDecision: { authority: "maintainer", decidedBy: "human" }
  };
  const accepted = await requestJson(
    `${address.url}/api/changes/change-1/accept`,
    "POST",
    acceptanceRequest
  );
  assert.equal(accepted.body.status, "accepted");
  assert.equal(accepted.body.decision.authorityDecision.authority, "maintainer");

  assert.deepEqual(calls, [
    ["inspectProject"],
    ["inspectArchitectureProfileWindow", { limit: 1 }],
    ["inspectArchitectureProfileWindow", { cursor: "opaque-window-cursor" }],
    ["inspectWorkbenchProjection", {}],
    ["inspectWorkbenchProjection", { changeRef: "change-1" }],
    ["listChanges"],
    ["createChange", { title: "Created through HTTP", intent: "Keep intent explicit" }],
    ["getChange", "change-1"],
    ["compileChange", "change-1", { primaryModule: "core" }],
    ["runGate", "change-1", "minimum"],
    ["acceptChange", "change-1", acceptanceRequest]
  ]);
});

test("returns bounded structured JSON errors", async (t) => {
  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-public-"));
  await writeFile(path.join(publicDir, "index.html"), "ok");
  t.after(() => rm(publicDir, { force: true, recursive: true }));

  let rejectedQueryKernelCalls = 0;
  const kernel = {
    async getChange() {
      return undefined;
    },
    async inspectArchitectureProfileWindow() {
      rejectedQueryKernelCalls += 1;
      throw new Error("invalid query reached Kernel");
    },
    async inspectWorkbenchProjection() {
      rejectedQueryKernelCalls += 1;
      throw new Error("invalid query reached Kernel");
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

  for (const query of [
    "unknown=1",
    "limit=1&limit=2",
    "limit=1&cursor=opaque",
    "limit=33",
    "cursor="
  ]) {
    const response = await fetch(`${address.url}/api/architecture-profile?${query}`);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "ARCHITECTURE_PROFILE_WINDOW_INPUT_INVALID");
  }
  for (const query of [
    "unknown=1",
    "changeRef=one&changeRef=two",
    "changeRef="
  ]) {
    const response = await fetch(`${address.url}/api/workbench?${query}`);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "WORKBENCH_PROJECTION_INPUT_INVALID");
  }
  assert.equal(rejectedQueryKernelCalls, 0, "invalid queries must fail before Kernel observation");
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

function architectureProfileWindowFixture({
  changeIds,
  offset = 0,
  limit = 1,
  hasMore = false,
  cursor
}) {
  const page = architectureProfileFixture(changeIds);
  const content = {
    schemaVersion: 1,
    proofVersion: 1,
    kind: "architecture-profile-window",
    source: page.source,
    window: {
      ordering: "change-id-v1",
      offset,
      limit,
      returned: changeIds.length,
      hasMore,
      recordRefs: changeIds.map((id) => ({ id }))
    },
    page
  };
  return {
    ...content,
    windowDigest: canonicalDigest(content),
    continuation: hasMore
      ? {
          cursor,
          expiresAt: "2026-07-18T12:05:00.000Z"
        }
      : null
  };
}

function architectureProfileFixture(changeIds = []) {
  const content = {
    schemaVersion: 1,
    source: {
      snapshotDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      projectModelDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      gitContentDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      changeStoreDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    },
    entities: {
      ...Object.fromEntries([
      "stages",
      "outcomes",
      "criteria",
      "modules",
      "areas",
      "contracts",
      "changes",
      "claims",
      "gates",
      "routes",
      "evidence",
      "residuals",
      "gaps"
      ].map((key) => [key, []])),
      changes: changeIds.map((id) => ({ id }))
    },
    relations: Object.fromEntries([
      "outcomeCriteria",
      "outcomeClaims",
      "outcomeGaps",
      "criterionClaims",
      "criterionGaps",
      "gapProofClaims",
      "gapAffects",
      "contributions",
      "contributionClaims",
      "claimGateRoutes",
      "routeModules",
      "routeResiduals",
      "currentEvidenceClaimAssociations",
      "historicalEvidenceClaimAssociations",
      "evidenceResiduals"
    ].map((key) => [key, []]))
  };
  return { ...content, profileDigest: canonicalDigest(content) };
}
