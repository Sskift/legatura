import assert from "node:assert/strict";
import test from "node:test";

import { executeCommand } from "../../src/core/command-runner.mjs";

test("command observations expose process outcomes and report truncated output", async () => {
  const failed = await executeCommand(undefined, {
    command: process.execPath,
    args: ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.exit(7)"]
  });
  assert.deepEqual(failed, { exitCode: 7, stdout: "out", stderr: "err" });

  const signaled = await executeCommand(undefined, {
    command: process.execPath,
    args: ["-e", "process.kill(process.pid, 'SIGTERM')"]
  });
  assert.equal(signaled.signal, "SIGTERM");

  const truncated = await executeCommand(undefined, {
    command: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(1024 * 1024 + 1))"]
  });
  assert.equal(truncated.exitCode, 0);
  assert.equal(truncated.truncated, true);
  assert.equal(Buffer.byteLength(truncated.stdout), 1024 * 1024);
});
