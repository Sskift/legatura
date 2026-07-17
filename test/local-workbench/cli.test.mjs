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
import { compileArchitectureProfileViewModel } from "../../src/workbench-view-model.mjs";

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

test("inspect emits the exact Profile view model or an orthogonal dimension summary", async () => {
  const profile = architectureProfileFixture();
  const expected = compileArchitectureProfileViewModel(profile);
  const calls = [];
  const kernelFactory = ({ repoPath }) => {
    calls.push(["kernelFactory", repoPath]);
    return {
      async inspectArchitectureProfile() {
        calls.push(["inspectArchitectureProfile"]);
        return profile;
      }
    };
  };

  const jsonIo = fixtureIo();
  const result = await runCli(
    ["inspect", "/repo", "--json"],
    jsonIo.io,
    { kernelFactory }
  );
  assert.deepEqual(JSON.parse(jsonIo.stdout()), expected);
  assert.deepEqual(result.architectureProfile, expected);

  const textIo = fixtureIo();
  await runCli(["inspect", "/repo"], textIo.io, { kernelFactory });
  assert.equal(textIo.stdout(), [
    `Architecture Profile: ${expected.profileRef}`,
    `Snapshot: ${expected.sourceRefs.snapshotDigest}`,
    `Project Model: ${expected.sourceRefs.projectModelDigest}`,
    `Git content: ${expected.sourceRefs.gitContentDigest}`,
    `Change Store: ${expected.sourceRefs.changeStoreDigest}`,
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
    ["kernelFactory", "/resolved/repo"],
    ["inspectArchitectureProfile"],
    ["kernelFactory", "/resolved/repo"],
    ["inspectArchitectureProfile"]
  ]);
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

function architectureProfileFixture() {
  const content = {
    schemaVersion: 1,
    source: {
      snapshotDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      projectModelDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      gitContentDigest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      changeStoreDigest: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    },
    entities: Object.fromEntries([
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
