import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { readGitBinding } from "../../src/core/git-binding.mjs";

const execFileAsync = promisify(execFile);

test("Git binding captures exact content and fails closed on incomplete observations", async (t) => {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-git-binding-"));
  t.after(() => rm(repoPath, { recursive: true, force: true }));
  await git(repoPath, "init", "--quiet");
  await git(repoPath, "config", "user.name", "Legatura Assurance Test");
  await git(repoPath, "config", "user.email", "assurance@example.invalid");
  await writeFile(path.join(repoPath, "tracked.txt"), "baseline\n");
  await git(repoPath, "add", "tracked.txt");
  await git(repoPath, "commit", "--quiet", "-m", "binding baseline");

  const trackedContent = "changed tracked content\n";
  const untrackedContent = "untracked content\n";
  await writeFile(path.join(repoPath, "tracked.txt"), trackedContent);
  await writeFile(path.join(repoPath, "untracked.txt"), untrackedContent);
  const head = (await git(repoPath, "rev-parse", "--verify", "HEAD")).stdout.trim();
  const diff = (await git(
    repoPath,
    "diff",
    "--binary",
    "HEAD",
    "--",
    ".",
    ":(exclude).legatura/runtime/**"
  )).stdout;

  const exact = await readGitBinding(repoPath);
  assert.equal(exact.available, true);
  assert.equal(exact.head, head);
  assert.equal(exact.dirty, true);
  assert.ok(exact.status.includes(" M tracked.txt"));
  assert.equal(exact.trackedDiffDigest, canonicalDigest(diff));
  assert.deepEqual(exact.untracked, [{
    path: "untracked.txt",
    kind: "file",
    size: Buffer.byteLength(untrackedContent),
    digest: canonicalDigest(Buffer.from(untrackedContent).toString("base64"))
  }]);
  const { contentDigest, ...boundContent } = exact;
  assert.equal(contentDigest, canonicalDigest(boundContent));

  for (const fault of ["truncated", "failed"]) {
    const commandRunner = async ({ args }) => {
      const operation = args[0];
      if (operation === "rev-parse") return result("a".repeat(40));
      if (operation === "branch") return result("main\n");
      if (operation === "status") return result(" M src/index.mjs\n");
      if (operation === "diff" && fault === "truncated") {
        return { ...result("partial diff"), truncated: true };
      }
      if (operation === "diff") {
        return { exitCode: 1, stdout: "", stderr: "diff failed" };
      }
      if (operation === "ls-files") return result("");
      return { exitCode: 1, stdout: "", stderr: "unexpected command" };
    };

    const binding = await readGitBinding(`/tmp/legatura-${fault}-fixture`, commandRunner);
    assert.equal(binding.available, false);
    assert.match(binding.error, fault === "truncated" ? /truncated/i : /diff \(exit 1\)/i);
    assert.equal(binding.dirty, true);
  }
});

function git(cwd, ...args) {
  return execFileAsync("git", args, { cwd });
}

function result(stdout) {
  return { exitCode: 0, stdout, stderr: "", truncated: false };
}
