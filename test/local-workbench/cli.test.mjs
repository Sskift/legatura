import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseArgs } from "../../src/cli.mjs";

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
