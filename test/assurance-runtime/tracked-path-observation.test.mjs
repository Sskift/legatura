import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { readGitBinding } from "../../src/core/git-binding.mjs";

const execFileAsync = promisify(execFile);

test("tracked-path observation is exact and rejects partial, malformed, duplicate, or over-limit facts", async (t) => {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-tracked-path-proof-"));
  t.after(() => rm(repoPath, { recursive: true, force: true }));
  await git(repoPath, "init", "--quiet");
  await git(repoPath, "config", "user.name", "Legatura Path Proof");
  await git(repoPath, "config", "user.email", "path-proof@example.invalid");
  await mkdir(path.join(repoPath, ".legatura/runtime"), { recursive: true });
  const realPaths = [
    ".legatura/runtime/accident.json",
    "line\nbreak.txt",
    "space name.txt",
    "z.txt"
  ].sort(compareUtf8);
  for (const trackedPath of realPaths) {
    await writeFile(path.join(repoPath, trackedPath), `${JSON.stringify(trackedPath)}\n`);
  }
  await git(repoPath, "add", "--", ".");
  await git(repoPath, "commit", "--quiet", "-m", "tracked path proof");

  const production = await readGitBinding(repoPath);
  assert.equal(production.available, true);
  assert.deepEqual(production.trackedPathFacts, {
    schemaVersion: 1,
    paths: realPaths,
    digest: canonicalDigest({ schemaVersion: 1, paths: realPaths })
  });
  assert.ok(
    production.trackedPathFacts.paths.includes(".legatura/runtime/accident.json"),
    "Assurance Runtime reports facts and does not make governance filtering decisions"
  );

  const paths = ["a.txt", "dir\\file.txt", "line\nbreak.txt", "z/file.mjs"];
  const exact = await readGitBinding(
    "/tmp/legatura-tracked-paths",
    runnerFor("z/file.mjs\0line\nbreak.txt\0dir\\file.txt\0a.txt\0")
  );
  assert.equal(exact.available, true);
  assert.deepEqual(exact.trackedPathFacts, {
    schemaVersion: 1,
    paths,
    digest: canonicalDigest({ schemaVersion: 1, paths })
  });
  const { contentDigest, ...boundContent } = exact;
  assert.equal(contentDigest, canonicalDigest(boundContent));

  const attacks = [
    ["failed command", "a.txt\0", { exitCode: 7, stderr: "inventory failed" }],
    ["runner rejection", "a.txt\0", { throws: true }],
    ["truncated command", "a.txt\0", { truncated: true }],
    ["missing terminator", "a.txt", {}],
    ["empty segment", "a.txt\0\0", {}],
    ["duplicate path", "a.txt\0a.txt\0", {}],
    ["parent traversal", "../escape.txt\0", {}],
    ["dot relative", "./escape.txt\0", {}],
    ["absolute path", "/escape.txt\0", {}],
    ["windows absolute path", "C:/escape.txt\0", {}],
    ["windows UNC path", "\\\\server\\share\0", {}],
    ["invalid UTF-8 replacement", "bad\uFFFDname.txt\0", {}],
    ["unpaired surrogate", `bad\uD800name.txt\0`, {}],
    ["single path limit", `${"x".repeat(4097)}\0`, {}],
    ["path count limit", "x\0".repeat(65_537), {}],
    ["raw byte limit", `${"x".repeat(1024 * 1024)}\0`, {}]
  ];

  for (const [label, stdout, override] of attacks) {
    const observed = await readGitBinding(
      `/tmp/legatura-tracked-paths-${label.replaceAll(" ", "-")}`,
      runnerFor(stdout, override)
    );
    assert.equal(observed.available, false, label);
    assert.equal(observed.trackedPathFacts, null, label);
    assert.match(observed.error, /tracked|incomplete/i, label);
  }
});

function runnerFor(trackedStdout, trackedOverride = {}) {
  return async ({ args }) => {
    const operation = args[0];
    if (operation === "rev-parse") return result("a".repeat(40));
    if (operation === "branch") return result("main\n");
    if (operation === "status" || operation === "diff") return result("");
    if (operation === "ls-files" && args.includes("--others")) return result("");
    if (operation === "ls-files" && args.includes("--cached")) {
      if (trackedOverride.throws) throw new Error("tracked inventory runner rejected");
      return { ...result(trackedStdout), ...trackedOverride };
    }
    return { exitCode: 1, stdout: "", stderr: "unexpected command" };
  };
}

function result(stdout) {
  return { exitCode: 0, stdout, stderr: "", truncated: false };
}

function git(cwd, ...args) {
  return execFileAsync("git", args, { cwd });
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
