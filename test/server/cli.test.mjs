import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parseArgs } from "../../src/cli.mjs";

const execFileAsync = promisify(execFile);

test("parses the local workbench command", () => {
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
});

test("parses inspect and rejects ambiguous input", () => {
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

test("the installed-style CLI symlink remains an executable entrypoint", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "legatura-cli-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const target = fileURLToPath(new URL("../../src/cli.mjs", import.meta.url));
  const command = path.join(directory, "legatura");
  await symlink(target, command);

  const { stdout, stderr } = await execFileAsync(command, ["--help"]);
  assert.equal(stderr, "");
  assert.match(stdout, /^Usage:\n  legatura open/mu);
});
