import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  COMMAND_OBSERVATION_PROOF_VERSION,
  createLocalCommandObserver,
  executeCommand,
  isSuccessfulCommandObservation,
  observeCommand,
  readCommandUtf8Stream
} from "../../src/core/command-runner.mjs";

const NODE_SPECIFICATION = Object.freeze({
  command: process.execPath,
  args: ["--version"],
  timeoutMs: 2_000
});

test("Command Observer keeps support, terminal state, and raw stream facts orthogonal", async () => {
  assert.equal(COMMAND_OBSERVATION_PROOF_VERSION, 1);
  const observer = createLocalCommandObserver({ captureBytesPerStream: 4 });

  const failed = await observer({
    command: process.execPath,
    args: ["-e", "process.stdout.write('out'); process.stderr.write('err'); process.exit(7)"],
    timeoutMs: 2_000
  });
  assert.equal(failed.support.status, "supported");
  assert.equal(failed.control.kind, "none");
  assert.deepEqual(failed.termination, {
    kind: "exited",
    exitCode: 7,
    signal: null,
    error: null,
    closeConfirmed: true
  });
  assert.deepEqual(readCommandUtf8Stream(failed, "stdout"), { available: true, value: "out" });
  assert.deepEqual(readCommandUtf8Stream(failed, "stderr"), { available: true, value: "err" });
  assert.equal(isSuccessfulCommandObservation(failed), false);

  const signaled = await observer({
    command: process.execPath,
    args: ["-e", "process.kill(process.pid, 'SIGTERM')"],
    timeoutMs: 2_000
  });
  assert.equal(signaled.termination.kind, "signaled");
  assert.equal(signaled.termination.exitCode, null);
  assert.equal(signaled.termination.signal, "SIGTERM");
  assert.equal(signaled.termination.closeConfirmed, true);

  const rawBytes = Buffer.from([0xff, 0x61, 0x62, 0x63, 0x64, 0x65]);
  const truncated = await observer({
    command: process.execPath,
    args: ["-e", `process.stdout.write(Buffer.from('${rawBytes.toString("base64")}', 'base64'))`],
    timeoutMs: 2_000
  });
  assert.equal(truncated.termination.kind, "exited");
  assert.equal(truncated.streams.stdout.capturedBytes, 4);
  assert.equal(truncated.streams.stdout.observedBytes, rawBytes.byteLength);
  assert.equal(truncated.streams.stdout.truncated, true);
  assert.equal(truncated.streams.stdout.complete, true);
  assert.equal(truncated.streams.stdout.utf8Validity, "invalid");
  assert.equal(truncated.streams.stdout.observedDigest, digest(rawBytes));
  assert.equal(readCommandUtf8Stream(truncated, "stdout").reasonCode, "stream-truncated");
  assert.equal(isSuccessfulCommandObservation(truncated), true);
  assert.equal(Object.isFrozen(truncated.streams.stdout), true);
  assert.equal(
    isSuccessfulCommandObservation(structuredClone(truncated)),
    false,
    "unverifiable truncated facts cannot regain live-observer authority after serialization"
  );

  let unsupportedSpawnCalls = 0;
  const unsupportedObserver = createLocalCommandObserver({
    platform: "win32",
    spawnProcess() {
      unsupportedSpawnCalls += 1;
      throw new Error("must not spawn");
    }
  });
  const unsupported = await unsupportedObserver(NODE_SPECIFICATION);
  assert.equal(unsupported.support.status, "unsupported");
  assert.equal(unsupported.support.reasonCode, "platform-unsupported");
  assert.equal(unsupported.termination.kind, "not-started");
  assert.equal(unsupportedSpawnCalls, 0);
  assert.equal(isSuccessfulCommandObservation(unsupported), false);

  for (const forged of [
    { ok: true },
    { exitCode: 0, signal: "SIGTERM", stdout: "", stderr: "" },
    { exitCode: 0, stdout: "partial", stderr: "", truncated: true },
    failed
  ]) {
    const rejected = await observeCommand(async () => forged, NODE_SPECIFICATION);
    assert.equal(rejected.termination.kind, "unconfirmed");
    assert.equal(rejected.termination.closeConfirmed, false);
    assert.equal(isSuccessfulCommandObservation(rejected), false);
  }
  assert.throws(
    () => createLocalCommandObserver({ captureBytesPerStream: 1024 * 1024 + 1 }),
    /cannot exceed/u
  );

  const legacy = await executeCommand(undefined, {
    command: process.execPath,
    args: ["-e", "process.stdout.write('x'.repeat(1024 * 1024 + 1))"],
    timeoutMs: 2_000
  });
  assert.equal(legacy.exitCode, 0);
  assert.equal(legacy.truncated, true);
  assert.equal(Buffer.byteLength(legacy.stdout), 1024 * 1024);
});

test("timeout and cancellation settle the process group before returning", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "legatura-command-observer-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const observer = createLocalCommandObserver({
    terminationGraceMs: 40,
    settlementGraceMs: 200
  });

  const timeoutMarker = path.join(directory, "timeout-late.txt");
  const timedOut = await observer(longRunningSpecification(timeoutMarker, { timeoutMs: 120 }));
  assert.equal(timedOut.control.kind, "timeout");
  assert.equal(timedOut.control.signalAttempts[0]?.signal, "SIGTERM");
  assert.equal(timedOut.termination.kind, "signaled");
  assert.ok(["SIGTERM", "SIGKILL"].includes(timedOut.termination.signal));
  assert.ok(timedOut.control.signalAttempts.some((attempt) => (
    attempt.signal === timedOut.termination.signal && attempt.delivered
  )));
  assert.equal(timedOut.termination.closeConfirmed, true);
  assert.equal(readCommandUtf8Stream(timedOut, "stdout").value, "before");
  assert.equal(isSuccessfulCommandObservation(timedOut), false);

  const controller = new AbortController();
  const cancellationMarker = path.join(directory, "cancel-late.txt");
  const cancellation = observer(longRunningSpecification(cancellationMarker, {
    timeoutMs: 2_000,
    signal: controller.signal
  }));
  setTimeout(() => controller.abort(), 120);
  const cancelled = await cancellation;
  assert.equal(cancelled.control.kind, "cancelled");
  assert.equal(cancelled.control.signalAttempts[0]?.signal, "SIGTERM");
  assert.equal(cancelled.termination.kind, "signaled");
  assert.ok(["SIGTERM", "SIGKILL"].includes(cancelled.termination.signal));
  assert.ok(cancelled.control.signalAttempts.some((attempt) => (
    attempt.signal === cancelled.termination.signal && attempt.delivered
  )));
  assert.equal(cancelled.termination.closeConfirmed, true);
  assert.equal(readCommandUtf8Stream(cancelled, "stdout").value, "before");
  assert.equal(isSuccessfulCommandObservation(cancelled), false);

  await new Promise((resolve) => setTimeout(resolve, 400));
  await assert.rejects(access(timeoutMarker), { code: "ENOENT" });
  await assert.rejects(access(cancellationMarker), { code: "ENOENT" });

  const unconfirmed = await observeCommand(
    async () => new Promise(() => {}),
    { ...NODE_SPECIFICATION, timeoutMs: 20 }
  );
  assert.equal(unconfirmed.control.kind, "timeout");
  assert.equal(unconfirmed.control.signalDelivered, false);
  assert.equal(unconfirmed.termination.kind, "unconfirmed");
  assert.equal(isSuccessfulCommandObservation(unconfirmed), false);
});

function longRunningSpecification(markerPath, { timeoutMs, signal } = {}) {
  const script = [
    "const { writeFileSync } = require('node:fs');",
    "process.on('SIGTERM', () => {});",
    "process.stdout.write('before');",
    `setTimeout(() => writeFileSync(${JSON.stringify(markerPath)}, 'late'), 350);`,
    "setInterval(() => {}, 50);"
  ].join("\n");
  return {
    command: process.execPath,
    args: ["-e", script],
    timeoutMs,
    ...(signal ? { signal } : {})
  };
}

function digest(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}
