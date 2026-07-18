import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { parseArgs, runCli } from "../../src/cli.mjs";
import { compileArchitectureProfileWindowViewModel } from "../../src/workbench-view-model.mjs";

const execFileAsync = promisify(execFile);
const CLI_ENTRYPOINT = fileURLToPath(new URL("../../src/cli.mjs", import.meta.url));
const BROWNFIELD_REFERENCE_ROOT = fileURLToPath(
  new URL("../../examples/brownfield-app-apk-relay/", import.meta.url)
);
const AGGREGATE_ASSURANCE_KEYS = new Set([
  "completeness",
  "confidence",
  "greenlight",
  "health",
  "overall",
  "percent",
  "percentage",
  "readiness",
  "ready",
  "score"
]);

test("parses supported commands and rejects ambiguous input", () => {
  assert.deepEqual(parseArgs(["open", "/repo"]), {
    command: "open",
    repo: "/repo",
    port: 4317,
    openBrowser: true
  });
  assert.deepEqual(parseArgs(["open", "--port", "9000", "--no-browser", "/repo"]), {
    command: "open",
    repo: "/repo",
    port: 9000,
    openBrowser: false
  });
  assert.deepEqual(parseArgs(["inspect", "/repo", "--json"]), {
    command: "inspect",
    repo: "/repo",
    json: true
  });
  assert.throws(
    () => parseArgs(["open", "/first", "/second"]),
    (error) => error.code === "UNEXPECTED_ARGUMENT"
  );
  assert.throws(
    () => parseArgs(["open", "/repo", "--port", "0"]),
    (error) => error.code === "INVALID_PORT"
  );
});

test("inspect streams exact Profile windows or bounded orthogonal dimension summaries", async () => {
  const firstWindow = architectureProfileWindowFixture({
    changeIds: ["change-1"],
    hasMore: true,
    cursor: "opaque-next-window"
  });
  const secondWindow = architectureProfileWindowFixture({
    changeIds: ["change-2"],
    offset: 1
  });
  const expectedFirst = compileArchitectureProfileWindowViewModel(firstWindow);
  const expectedSecond = compileArchitectureProfileWindowViewModel(secondWindow);
  const calls = [];
  let instance = 0;
  const kernelFactory = ({ repoPath }) => {
    instance += 1;
    const instanceId = instance;
    calls.push(["kernelFactory", repoPath, instanceId]);
    return {
      async inspectArchitectureProfileWindow(input) {
        calls.push(["inspectArchitectureProfileWindow", instanceId, input]);
        return Object.hasOwn(input, "cursor") ? secondWindow : firstWindow;
      }
    };
  };

  const jsonIo = fixtureIo();
  const result = await runCli(
    ["inspect", "/repo", "--json"],
    jsonIo.io,
    { kernelFactory }
  );
  assert.deepEqual(JSON.parse(jsonIo.stdout()), {
    schemaVersion: 2,
    kind: "architecture-profile-window-stream",
    windows: [expectedFirst, expectedSecond],
    windowCount: 2,
    complete: true,
    error: null
  });
  assert.deepEqual(result, {
    status: "inspected",
    repoPath: "/resolved/repo",
    windowCount: 2,
    lastWindowDigest: expectedSecond.windowDigest
  });
  assert.equal(Object.hasOwn(result, "architectureProfile"), false);

  const textIo = fixtureIo();
  await runCli(["inspect", "/repo"], textIo.io, { kernelFactory });
  assert.equal(textIo.stdout(), [
    "Architecture Profile window 1",
    `Profile: ${expectedFirst.page.profileRef}`,
    "Window: offset 0, returned 1, limit 1, has more yes",
    `Snapshot: ${expectedFirst.source.snapshotDigest}`,
    `Project Model: ${expectedFirst.source.projectModelDigest}`,
    `Git content: ${expectedFirst.source.gitContentDigest}`,
    `Change Store: ${expectedFirst.source.changeStoreDigest}`,
    "Orthogonal dimensions:",
    "  Outcomes: 0",
    "  Criteria: 0",
    "  Claims: 0",
    "  Gates: 0",
    "  Evidence: 0",
    "  Residual uncertainty: 0",
    "  Knowledge gaps: 0",
    "Architecture Profile window 2",
    `Profile: ${expectedSecond.page.profileRef}`,
    "Window: offset 1, returned 1, limit 1, has more no",
    `Snapshot: ${expectedSecond.source.snapshotDigest}`,
    `Project Model: ${expectedSecond.source.projectModelDigest}`,
    `Git content: ${expectedSecond.source.gitContentDigest}`,
    `Change Store: ${expectedSecond.source.changeStoreDigest}`,
    "Orthogonal dimensions:",
    "  Outcomes: 0",
    "  Criteria: 0",
    "  Claims: 0",
    "  Gates: 0",
    "  Evidence: 0",
    "  Residual uncertainty: 0",
    "  Knowledge gaps: 0",
    ""
  ].join("\n"));
  assert.doesNotMatch(
    textIo.stdout(),
    /overall|score|percent|confidence|health|readiness|green.?light|total/iu
  );
  assert.deepEqual(calls, [
    ["kernelFactory", "/resolved/repo", 1],
    ["inspectArchitectureProfileWindow", 1, {}],
    ["inspectArchitectureProfileWindow", 1, { cursor: "opaque-next-window" }],
    ["kernelFactory", "/resolved/repo", 2],
    ["inspectArchitectureProfileWindow", 2, {}],
    ["inspectArchitectureProfileWindow", 2, { cursor: "opaque-next-window" }]
  ]);

  const failureCode = `PROFILE_WINDOW_opaque-next-window_${"X".repeat(160)}`;
  const failureMessage = `The successor\nwindow failed for opaque-next-window: ${"x".repeat(600)}`;
  const failure = Object.assign(new Error(failureMessage), {
    code: failureCode,
    details: {
      cursor: "sensitive-failing-cursor",
      providerOutput: "sensitive-provider-output"
    }
  });
  const failedCalls = [];
  const failureIo = fixtureIo();
  await assert.rejects(
    runCli(
      ["inspect", "/repo", "--json"],
      failureIo.io,
      {
        kernelFactory() {
          return {
            async inspectArchitectureProfileWindow(input) {
              failedCalls.push(structuredClone(input));
              if (Object.hasOwn(input, "cursor")) throw failure;
              return firstWindow;
            }
          };
        }
      }
    ),
    (error) => error === failure
  );
  const failedDocument = JSON.parse(failureIo.stdout());
  assert.deepEqual(failedDocument, {
    schemaVersion: 2,
    kind: "architecture-profile-window-stream",
    windows: [expectedFirst],
    windowCount: 1,
    complete: false,
    error: {
      code: `${failureCode.replace("opaque-next-window", "[opaque continuation]").slice(0, 127)}\u2026`,
      message: `${failureMessage
        .replace("\n", " ")
        .replace("opaque-next-window", "[opaque continuation]")
        .slice(0, 511)}\u2026`
    }
  });
  assert.deepEqual(Object.keys(failedDocument.error), ["code", "message"]);
  assert.doesNotMatch(
    JSON.stringify(failedDocument.error),
    /opaque-next-window|sensitive-failing-cursor|sensitive-provider-output/u
  );
  assert.match(JSON.stringify(failedDocument.error), /\[opaque continuation\]/u);
  assert.deepEqual(failedCalls, [{}, { cursor: "opaque-next-window" }]);
});

test("the real inspect CLI preserves the brownfield reference as orthogonal Profile facts", async (t) => {
  const repoPath = await createBrownfieldReferenceFixture(t);
  const { stdout, stderr } = await execFileAsync(
    process.execPath,
    [CLI_ENTRYPOINT, "inspect", repoPath, "--json"],
    { cwd: repoPath, maxBuffer: 4 * 1024 * 1024 }
  );
  assert.equal(stderr, "");
  const stream = JSON.parse(stdout);
  assert.deepEqual({
    schemaVersion: stream.schemaVersion,
    kind: stream.kind,
    windowCount: stream.windowCount,
    complete: stream.complete,
    error: stream.error
  }, {
    schemaVersion: 2,
    kind: "architecture-profile-window-stream",
    windowCount: 1,
    complete: true,
    error: null
  });
  assert.equal(stream.windows.length, 1);
  const [window] = stream.windows;
  assert.equal(window.kind, "architecture-profile-window");
  assert.deepEqual(window.window, {
    ordering: "change-id-v1",
    offset: 0,
    limit: 20,
    returned: 0,
    hasMore: false,
    recordRefs: []
  });
  assert.equal(window.continuation, null);

  const profile = window.page;
  assert.deepEqual(
    profile.context.modules
      .map(({ id, status }) => ({ id, status }))
      .sort(compareIds),
    [
      { id: "apk", status: "provisional" },
      { id: "app", status: "provisional" },
      { id: "relay", status: "governed" },
      { id: "repository-governance", status: "governed" }
    ]
  );
  assert.equal(
    profile.context.modules.some((module) => module.id === "legacy-device-bridge"),
    false,
    "the opaque legacy dependency remains explicitly unmodeled, not invented as a fifth Module"
  );

  assert.deepEqual(
    profile.context.contracts
      .map(({ id, ownerModuleRef, maturity }) => ({ id, ownerModuleRef, maturity }))
      .sort(compareIds),
    [
      { id: "apk-delivery-port", ownerModuleRef: "apk", maturity: "provisional" },
      { id: "app-relay-request", ownerModuleRef: "app", maturity: "provisional" },
      { id: "relay-routing", ownerModuleRef: "relay", maturity: "governed" }
    ]
  );
  assert.deepEqual(
    profile.dimensions.claims
      .map(({ id, contractRef, ownerModuleRef, statement }) => ({
        id,
        contractRef,
        ownerModuleRef,
        statement
      }))
      .sort(compareIds),
    [
      {
        id: "apk-delivery-port-accepts-envelope",
        contractRef: "apk-delivery-port",
        ownerModuleRef: "apk",
        statement: "The apk delivery port accepts one correlation-bound envelope and returns an acceptance acknowledgement."
      },
      {
        id: "app-relay-request-carries-correlation-id",
        contractRef: "app-relay-request",
        ownerModuleRef: "app",
        statement: "An app relay request carries a non-empty correlation id and an opaque payload."
      },
      {
        id: "relay-preserves-correlation-id",
        contractRef: "relay-routing",
        ownerModuleRef: "relay",
        statement: "Relay preserves the app request correlation id in the delivery envelope and returned acknowledgement."
      }
    ]
  );

  assert.deepEqual(profile.dimensions.gates, [{ id: "minimum", name: "Relay Minimum Gate" }]);
  const relayRelations = profile.relations.claimGateRoutes.filter(
    (relation) => relation.claimRef === "relay-preserves-correlation-id"
  );
  assert.equal(relayRelations.length, 1);
  const relayRoute = profile.context.routes.find(
    (route) => route.id === relayRelations[0].routeRef
  );
  assert.deepEqual({
    claimRef: relayRoute.claimRef,
    gateRef: relayRoute.gateRef,
    commandRef: relayRoute.commandRef,
    timeoutMs: relayRoute.timeoutMs,
    oracleKind: relayRoute.oracle.kind
  }, {
    claimRef: "relay-preserves-correlation-id",
    gateRef: "minimum",
    commandRef: "relay-correlation-proof",
    timeoutMs: 30000,
    oracleKind: "node-test-runner-exit"
  });
  assert.match(relayRoute.commandDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(relayRoute.routeDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.deepEqual(
    profile.relations.routeModules
      .filter((relation) => relation.routeRef === relayRoute.id)
      .map((relation) => relation.moduleRef),
    ["relay"]
  );

  assert.deepEqual(
    profile.dimensions.knowledgeGaps
      .map(({ id, status, statement }) => ({ id, status, statement }))
      .sort(compareIds),
    [
      {
        id: "apk-remains-provisional",
        status: "open",
        statement: "The apk delivery port Contract is modeled, but real device delivery behavior is not yet governed."
      },
      {
        id: "app-remains-provisional",
        status: "open",
        statement: "The app public request Contract is modeled, but broader app implementation behavior is not yet governed."
      },
      {
        id: "legacy-device-bridge-remains-opaque",
        status: "open",
        statement: "The legacy device bridge remains opaque and outside governed Module implementation scope."
      }
    ]
  );
  assert.deepEqual(
    profile.context.areas.find((area) => area.id === "legacy-device-bridge"),
    { id: "legacy-device-bridge", kind: "declared-gap-affect" }
  );
  assert.deepEqual(
    profile.relations.gapAffects.filter((relation) => (
      relation.gapRef === "legacy-device-bridge-remains-opaque"
        && relation.targetRef === "legacy-device-bridge"
    )),
    [{
      gapRef: "legacy-device-bridge-remains-opaque",
      targetKind: "declared-area",
      targetRef: "legacy-device-bridge"
    }],
    "the CLI preserves the explicit unknown without inferring a modeled assurance state"
  );

  assert.throws(
    () => parseArgs(["adopt", repoPath]),
    (error) => error?.code === "UNKNOWN_COMMAND"
  );
  const keyFacts = collectKeyFacts(stream);
  assert.deepEqual(
    keyFacts.filter(({ normalized }) => normalized === "adopt" || normalized === "adoption"),
    [],
    "inspection introduces no special brownfield adoption field"
  );
  assert.deepEqual(
    keyFacts.filter(({ normalized }) => AGGREGATE_ASSURANCE_KEYS.has(normalized)),
    [],
    "Profile keys preserve orthogonal facts and never introduce aggregate assurance"
  );
  assert.deepEqual(
    keyFacts.filter(({ normalized }) => normalized === "complete").map(({ path: keyPath }) => keyPath),
    ["$.complete"],
    "complete is only the CLI stream traversal marker, never a Profile assurance conclusion"
  );
});

test("the packed CLI installs as an executable entrypoint", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "legatura-package-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const repoPath = fileURLToPath(new URL("../..", import.meta.url));
  const packed = await execFileAsync(
    "npm",
    ["pack", "--silent", "--pack-destination", directory],
    { cwd: repoPath }
  );
  const tarball = path.join(directory, packed.stdout.trim().split(/\r?\n/u).at(-1));
  const installRoot = path.join(directory, "install");
  await mkdir(installRoot);
  await execFileAsync("npm", [
    "install",
    "--prefix",
    installRoot,
    tarball,
    "--ignore-scripts",
    "--no-audit",
    "--no-fund",
    "--silent"
  ]);
  const command = path.join(installRoot, "node_modules", ".bin", "legatura");

  const { stdout, stderr } = await execFileAsync(command, ["--help"]);
  assert.equal(stderr, "");
  assert.match(stdout, /^Usage:\n  legatura open/mu);
});

function fixtureIo() {
  let output = "";
  return {
    io: {
      stdout: { write(value) { output += value; } },
      stderr: { write() {} },
      async realpath() {
        return "/resolved/repo";
      },
      async stat() {
        return { isDirectory: () => true };
      }
    },
    stdout: () => output
  };
}

async function createBrownfieldReferenceFixture(t) {
  const fixtureRoot = await mkdtemp(path.join(os.tmpdir(), "legatura-brownfield-cli-"));
  const repoPath = path.join(fixtureRoot, "repo");
  t.after(() => rm(fixtureRoot, { recursive: true, force: true }));
  await cp(BROWNFIELD_REFERENCE_ROOT, repoPath, { recursive: true });
  await runGit(repoPath, "init", "--quiet");
  await runGit(repoPath, "config", "user.name", "Legatura Brownfield Proof");
  await runGit(repoPath, "config", "user.email", "brownfield-proof@legatura.test");
  await runGit(repoPath, "add", ".");
  await runGit(repoPath, "commit", "--quiet", "-m", "fixture: brownfield reference");
  return repoPath;
}

function collectKeyFacts(value, currentPath = "$", facts = []) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectKeyFacts(entry, `${currentPath}[${index}]`, facts));
    return facts;
  }
  if (!value || typeof value !== "object") return facts;
  for (const [key, child] of Object.entries(value)) {
    const keyPath = `${currentPath}.${key}`;
    facts.push({
      path: keyPath,
      normalized: key.toLowerCase().replace(/[^a-z]/gu, "")
    });
    collectKeyFacts(child, keyPath, facts);
  }
  return facts;
}

function compareIds(left, right) {
  return left.id.localeCompare(right.id);
}

function runGit(repoPath, ...args) {
  return execFileAsync("git", args, { cwd: repoPath });
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

export const BROWNFIELD_ADOPTION_LOCAL_WORKBENCH_PROOF_VERSION = 1;
