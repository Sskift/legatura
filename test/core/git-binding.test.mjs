import assert from "node:assert/strict";
import test from "node:test";

import { readGitBinding } from "../../src/core/git-binding.mjs";

test("Git binding fails closed when any exact-binding output is truncated", async () => {
  const commandRunner = async ({ args }) => {
    const operation = args[0];
    if (operation === "rev-parse") return result("a".repeat(40));
    if (operation === "branch") return result("main\n");
    if (operation === "status") return result(" M src/index.mjs\n");
    if (operation === "diff") return { ...result("partial diff"), truncated: true };
    if (operation === "ls-files") return result("");
    return { exitCode: 1, stdout: "", stderr: "unexpected command" };
  };

  const binding = await readGitBinding("/tmp/legatura-truncated-fixture", commandRunner);
  assert.equal(binding.available, false);
  assert.match(binding.error, /truncated/i);
  assert.equal(binding.dirty, true);
});

function result(stdout) {
  return { exitCode: 0, stdout, stderr: "", truncated: false };
}
