import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { parseArgs, runCli } from "../../src/cli.mjs";
import { compileArchitectureProfileWindowViewModel } from "../../src/workbench-view-model.mjs";

const execFileAsync = promisify(execFile);

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
