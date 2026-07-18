import { isUtf8 } from "node:buffer";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";

export const COMMAND_OBSERVATION_SCHEMA_VERSION = 2;
export const COMMAND_OBSERVATION_PROOF_VERSION = 1;

const LOCAL_SUPPORT_PROFILE = "local-direct-node-posix-v1";
const SUPPORTED_PLATFORMS = new Set(["darwin", "linux"]);
const SUPPORTED_NODE_MAJORS = new Set([22, 24, 25]);
const MAX_CAPTURE_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 300_000;
const DEFAULT_TERMINATION_GRACE_MS = 1_000;
const DEFAULT_SETTLEMENT_GRACE_MS = 1_000;
const MAX_GRACE_MS = 60_000;
const MAX_TIMER_MS = 2_147_483_647;
const MAX_ERROR_BYTES = 4 * 1024;
const INTERNAL_OBSERVATION = Symbol("legatura.command-observation");

const DEFAULT_LOCAL_OBSERVER = createLocalCommandObserver();

/**
 * Observe one command through either the declared local adapter or a strict
 * injected adapter. The returned v2 object is the only authoritative process
 * fact; executeCommand() below is a temporary one-way compatibility view.
 */
export async function observeCommand(commandRunner, specification) {
  const normalized = normalizeCommandSpecification(specification);
  if (!normalized.valid) {
    return invalidSpecificationObservation(normalized);
  }
  if (commandRunner == null) {
    return DEFAULT_LOCAL_OBSERVER(normalized.value);
  }
  if (typeof commandRunner !== "function") {
    return invalidAdapterObservation(normalized.value, "Command runner must be a function.");
  }
  return observeInjectedCommand(commandRunner, normalized.value);
}

/**
 * Build the production local observer with explicit runtime facts. Runtime
 * injection exists for deterministic support-boundary tests, not for callers
 * to broaden the production support profile.
 */
export function createLocalCommandObserver({
  platform = process.platform,
  arch = process.arch,
  nodeVersion = process.versions.node,
  spawnProcess = spawn,
  captureBytesPerStream = MAX_CAPTURE_BYTES,
  terminationGraceMs = DEFAULT_TERMINATION_GRACE_MS,
  settlementGraceMs = DEFAULT_SETTLEMENT_GRACE_MS
} = {}) {
  const runtime = Object.freeze({
    platform: requireRuntimeString(platform, "platform"),
    arch: requireRuntimeString(arch, "arch"),
    nodeVersion: requireRuntimeString(nodeVersion, "nodeVersion"),
    spawnProcess: requireFunction(spawnProcess, "spawnProcess"),
    captureBytesPerStream: requireCaptureLimit(
      captureBytesPerStream,
      "captureBytesPerStream"
    ),
    terminationGraceMs: requireGrace(terminationGraceMs, "terminationGraceMs"),
    settlementGraceMs: requireGrace(settlementGraceMs, "settlementGraceMs")
  });
  return async function localCommandObserver(specification) {
    const normalized = normalizeCommandSpecification(specification);
    if (!normalized.valid) return invalidSpecificationObservation(normalized, runtime);
    return observeLocalCommand(normalized.value, runtime);
  };
}

export function isSuccessfulCommandObservation(value) {
  if (!isCanonicalCommandObservation(value)) return false;
  return value.support.status === "supported"
    && value.control.kind === "none"
    && value.termination.closeConfirmed === true
    && value.termination.kind === "exited"
    && value.termination.exitCode === 0
    && value.streams.stdout.complete === true
    && value.streams.stderr.complete === true;
}

/**
 * Strict UTF-8 is a read projection over authoritative raw bytes. Consumers
 * such as Git may additionally require the captured bytes to be complete.
 */
export function readCommandUtf8Stream(
  observation,
  streamName,
  { requireUntruncated = true } = {}
) {
  if (!isCanonicalCommandObservation(observation)) {
    return unavailableText("observation-invalid", "Command Observation v2 is invalid.");
  }
  if (streamName !== "stdout" && streamName !== "stderr") {
    return unavailableText("stream-unknown", `Unknown command stream: ${String(streamName)}.`);
  }
  const stream = observation.streams[streamName];
  if (!stream.complete) {
    return unavailableText("stream-incomplete", `${streamName} did not reach confirmed close.`);
  }
  if (requireUntruncated && stream.truncated) {
    return unavailableText("stream-truncated", `${streamName} capture was truncated.`);
  }
  if (stream.utf8Validity !== "valid") {
    return unavailableText("stream-not-utf8", `${streamName} is not strict UTF-8.`);
  }
  const bytes = Buffer.from(stream.contentBase64, "base64");
  if (bytes.byteLength !== stream.capturedBytes || !isUtf8(bytes)) {
    return unavailableText("stream-content-invalid", `${streamName} capture does not match its byte facts.`);
  }
  return { available: true, value: bytes.toString("utf8") };
}

/**
 * Legacy result projection for consumers that have not yet adopted v2. No
 * legacy input is allowed to override the canonical observation.
 */
export async function executeCommand(commandRunner, specification) {
  return projectLegacyCommandResult(await observeCommand(commandRunner, specification));
}

export function normalizeGateCommand(value) {
  if (typeof value === "string" && value.trim()) {
    return {
      command: "/bin/sh",
      args: ["-lc", value.trim()],
      display: value.trim(),
      mode: "posix-shell"
    };
  }

  if (Array.isArray(value) && value.length > 0 && value.every((part) => typeof part === "string")) {
    const [command, ...args] = value;
    if (!command.trim()) return undefined;
    return { command, args, display: value.join(" "), mode: "direct" };
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const command = readString(value.command) ?? readString(value.program);
    const hasArgs = Object.hasOwn(value, "args");
    if (hasArgs && (!Array.isArray(value.args)
      || !value.args.every((part) => typeof part === "string"))) {
      return undefined;
    }
    const args = hasArgs ? [...value.args] : [];
    if (command) {
      return {
        command,
        args,
        display: readString(value.display) ?? [command, ...args].join(" "),
        mode: readString(value.mode) ?? "direct"
      };
    }
  }

  return undefined;
}

async function observeLocalCommand(specification, runtime) {
  const support = compileLocalSupport(specification, runtime);
  const limits = commandLimits(specification, runtime);
  if (support.status === "unsupported") {
    return notStartedObservation({ support, limits, controlKind: "none" });
  }
  if (specification.signal?.aborted === true) {
    return notStartedObservation({ support, limits, controlKind: "cancelled" });
  }

  return new Promise((resolve) => {
    const stdout = createStreamAccumulator(limits.captureBytesPerStream);
    const stderr = createStreamAccumulator(limits.captureBytesPerStream);
    let child;
    let closed = false;
    let resolved = false;
    let spawnError = null;
    let controlKind = "none";
    let requestedSignal = null;
    let signalDelivered = false;
    const signalAttempts = [];
    let timeoutTimer;
    let escalationTimer;
    let settlementTimer;
    let spawnErrorTimer;

    const cleanup = () => {
      clearTimeout(timeoutTimer);
      clearTimeout(escalationTimer);
      clearTimeout(settlementTimer);
      clearTimeout(spawnErrorTimer);
      specification.signal?.removeEventListener?.("abort", onAbort);
    };
    const finish = ({ exitCode = null, signal = null, closeConfirmed, forcedKind } = {}) => {
      if (resolved) return;
      resolved = true;
      cleanup();
      const termination = compileTermination({
        exitCode,
        signal,
        spawnError,
        closeConfirmed,
        forcedKind
      });
      resolve(createObservation({
        support,
        limits,
        control: {
          kind: controlKind,
          timeoutMs: limits.timeoutMs,
          requestedSignal,
          signalDelivered,
          signalAttempts: signalAttempts.map((attempt) => ({ ...attempt }))
        },
        termination,
        stdout: stdout.finish(closeConfirmed === true),
        stderr: stderr.finish(closeConfirmed === true)
      }));
    };
    const sendSignal = (signalName) => {
      if (!child?.pid) return false;
      try {
        process.kill(-child.pid, signalName);
        return true;
      } catch {
        try {
          return child.kill(signalName);
        } catch {
          return false;
        }
      }
    };
    const requestControl = (kind) => {
      if (resolved || closed || controlKind !== "none") return;
      controlKind = kind;
      requestedSignal = "SIGTERM";
      signalDelivered = sendSignal(requestedSignal);
      signalAttempts.push({ signal: requestedSignal, delivered: signalDelivered });
      escalationTimer = setTimeout(() => {
        if (resolved || closed) return;
        requestedSignal = "SIGKILL";
        signalDelivered = sendSignal(requestedSignal);
        signalAttempts.push({ signal: requestedSignal, delivered: signalDelivered });
        settlementTimer = setTimeout(() => {
          if (!resolved && !closed) {
            finish({ closeConfirmed: false, forcedKind: "unconfirmed" });
          }
        }, limits.settlementGraceMs);
      }, limits.terminationGraceMs);
    };
    const onAbort = () => requestControl("cancelled");

    try {
      child = runtime.spawnProcess(specification.command, specification.args, {
        cwd: specification.cwd,
        env: specification.env ? { ...process.env, ...specification.env } : process.env,
        detached: true,
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      spawnError = error;
      finish({ closeConfirmed: true, forcedKind: "start-failed" });
      return;
    }

    child.stdout?.on("data", (chunk) => stdout.write(chunk));
    child.stderr?.on("data", (chunk) => stderr.write(chunk));
    child.once("error", (error) => {
      spawnError = error;
      if (!child?.pid) {
        spawnErrorTimer = setTimeout(() => {
          if (!closed) finish({ closeConfirmed: false, forcedKind: "unconfirmed" });
        }, limits.settlementGraceMs);
      }
    });
    child.once("close", (exitCode, signal) => {
      closed = true;
      finish({ exitCode, signal, closeConfirmed: true });
    });
    specification.signal?.addEventListener?.("abort", onAbort, { once: true });
    if (specification.signal?.aborted === true) onAbort();
    timeoutTimer = setTimeout(() => requestControl("timeout"), limits.timeoutMs);
  });
}

async function observeInjectedCommand(commandRunner, specification) {
  const runtime = {
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node,
    captureBytesPerStream: MAX_CAPTURE_BYTES,
    terminationGraceMs: DEFAULT_TERMINATION_GRACE_MS,
    settlementGraceMs: DEFAULT_SETTLEMENT_GRACE_MS
  };
  const support = compileLocalSupport(specification, runtime);
  const limits = commandLimits(specification, runtime);
  if (support.status === "unsupported") {
    return notStartedObservation({ support, limits, controlKind: "none" });
  }
  if (specification.signal?.aborted === true) {
    return notStartedObservation({ support, limits, controlKind: "cancelled" });
  }

  const controller = new AbortController();
  let controlKind = "none";
  let timeoutTimer;
  let resolveControl;
  const controlled = new Promise((resolve) => { resolveControl = resolve; });
  const requestControl = (kind) => {
    if (controlKind !== "none") return;
    controlKind = kind;
    controller.abort();
    resolveControl(invalidAdapterObservation(
      specification,
      `Injected runner did not provide confirmed settlement after ${kind}.`,
      { support, limits, controlKind: kind }
    ));
  };
  const onAbort = () => requestControl("cancelled");
  specification.signal?.addEventListener?.("abort", onAbort, { once: true });
  if (specification.signal?.aborted === true) onAbort();
  timeoutTimer = setTimeout(() => requestControl("timeout"), limits.timeoutMs);

  try {
    const observed = await Promise.race([
      Promise.resolve().then(() => commandRunner({
        ...specification,
        signal: controller.signal,
        timeoutMs: limits.timeoutMs
      })).then(
        (value) => controlKind === "none"
          ? normalizeInjectedObservation(value, specification, { support, limits })
          : invalidAdapterObservation(
              specification,
              `Injected runner settled only after ${controlKind} was requested.`,
              { support, limits, controlKind }
            ),
        (error) => invalidAdapterObservation(specification, boundedErrorMessage(error), {
          support,
          limits,
          controlKind
        })
      ),
      controlled
    ]);
    return observed;
  } finally {
    clearTimeout(timeoutTimer);
    specification.signal?.removeEventListener?.("abort", onAbort);
  }
}

function normalizeInjectedObservation(value, specification, { support, limits }) {
  if (value?.schemaVersion === COMMAND_OBSERVATION_SCHEMA_VERSION) {
    return invalidAdapterObservation(
      specification,
      "A legacy injected runner cannot supply authoritative Command Observation v2 facts.",
      { support, limits }
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return invalidAdapterObservation(specification, "Injected runner returned no exact result.", {
      support,
      limits
    });
  }
  const allowed = new Set(["code", "exitCode", "signal", "stderr", "stdout", "truncated"]);
  if (value.truncated === true) {
    return invalidAdapterObservation(
      specification,
      "Injected legacy output reported truncation without exact raw-byte facts.",
      {
        support,
        limits,
        errorCode: "COMMAND_ADAPTER_TRUNCATION_UNPROVABLE",
        reportedTruncated: true
      }
    );
  }
  if (Object.keys(value).some((key) => !allowed.has(key))
    || (Object.hasOwn(value, "code") && Object.hasOwn(value, "exitCode"))
    || (Object.hasOwn(value, "truncated") && value.truncated !== false)
    || (Object.hasOwn(value, "stdout") && typeof value.stdout !== "string")
    || (Object.hasOwn(value, "stderr") && typeof value.stderr !== "string")) {
    return invalidAdapterObservation(specification, "Injected legacy result shape is ambiguous or incomplete.", {
      support,
      limits
    });
  }
  if (Buffer.byteLength(value.stdout ?? "", "utf8") > limits.captureBytesPerStream
    || Buffer.byteLength(value.stderr ?? "", "utf8") > limits.captureBytesPerStream) {
    return invalidAdapterObservation(
      specification,
      "Injected legacy output exceeded the exact bounded capture contract.",
      { support, limits }
    );
  }
  const exitCode = Object.hasOwn(value, "exitCode") ? value.exitCode : value.code;
  const signal = readString(value.signal) ?? null;
  if ((Number.isInteger(exitCode) && signal !== null)
    || (!Number.isInteger(exitCode) && signal === null)) {
    return invalidAdapterObservation(specification, "Injected legacy result must report exactly one exit code or signal.", {
      support,
      limits
    });
  }
  return createObservation({
    support: { ...support, adapter: "injected-legacy-v1" },
    limits,
    control: {
      kind: "none",
      timeoutMs: limits.timeoutMs,
      requestedSignal: null,
      signalDelivered: false,
      signalAttempts: []
    },
    termination: compileTermination({ exitCode, signal, closeConfirmed: true }),
    stdout: streamFromKnownBytes(Buffer.from(value.stdout ?? "", "utf8"), limits.captureBytesPerStream),
    stderr: streamFromKnownBytes(Buffer.from(value.stderr ?? "", "utf8"), limits.captureBytesPerStream)
  });
}

function createStreamAccumulator(captureLimit) {
  const chunks = [];
  const capturedHash = createHash("sha256");
  const observedHash = createHash("sha256");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let capturedBytes = 0;
  let observedBytes = 0;
  let utf8Valid = true;
  let finished = false;
  return {
    write(value) {
      if (finished) return;
      const buffer = Buffer.isBuffer(value) ? value : Buffer.from(value);
      observedBytes = safeByteSum(observedBytes, buffer.byteLength);
      observedHash.update(buffer);
      if (utf8Valid) {
        try {
          decoder.decode(buffer, { stream: true });
        } catch {
          utf8Valid = false;
        }
      }
      const remaining = Math.max(0, captureLimit - capturedBytes);
      const captured = buffer.subarray(0, remaining);
      if (captured.byteLength > 0) {
        chunks.push(captured);
        capturedHash.update(captured);
        capturedBytes += captured.byteLength;
      }
    },
    finish(complete) {
      if (finished) throw new Error("Command stream was finalized more than once.");
      finished = true;
      if (utf8Valid) {
        try {
          decoder.decode();
        } catch {
          utf8Valid = false;
        }
      }
      const content = Buffer.concat(chunks, capturedBytes);
      return {
        contentBase64: content.toString("base64"),
        capturedBytes,
        observedBytes,
        capturedDigest: `sha256:${capturedHash.digest("hex")}`,
        observedDigest: `sha256:${observedHash.digest("hex")}`,
        truncated: observedBytes > capturedBytes,
        complete,
        utf8Validity: complete ? (utf8Valid ? "valid" : "invalid") : "unconfirmed"
      };
    }
  };
}

function streamFromKnownBytes(bytes, captureLimit) {
  const accumulator = createStreamAccumulator(captureLimit);
  accumulator.write(bytes);
  return accumulator.finish(true);
}

function emptyStream(complete = true) {
  const accumulator = createStreamAccumulator(1);
  return accumulator.finish(complete);
}

function createObservation({ support, limits, control, termination, stdout, stderr }) {
  const observation = {
    schemaVersion: COMMAND_OBSERVATION_SCHEMA_VERSION,
    support,
    limits,
    control,
    termination,
    streams: { stdout, stderr }
  };
  Object.defineProperty(observation, INTERNAL_OBSERVATION, { value: true });
  return deepFreeze(observation);
}

function notStartedObservation({ support, limits, controlKind }) {
  return createObservation({
    support,
    limits,
    control: {
      kind: controlKind,
      timeoutMs: limits.timeoutMs,
      requestedSignal: null,
      signalDelivered: false,
      signalAttempts: []
    },
    termination: {
      kind: "not-started",
      exitCode: null,
      signal: null,
      error: null,
      closeConfirmed: true
    },
    stdout: emptyStream(),
    stderr: emptyStream()
  });
}

function invalidSpecificationObservation(validation, runtime = {}) {
  const specification = validation?.value ?? {};
  const support = unsupportedSupport(specification, runtime, "specification-invalid", validation?.reason);
  const limits = fallbackLimits(specification, runtime);
  return notStartedObservation({ support, limits, controlKind: "none" });
}

function invalidAdapterObservation(
  specification,
  message,
  {
    support,
    limits,
    controlKind = "none",
    errorCode = "COMMAND_ADAPTER_OBSERVATION_INVALID",
    reportedTruncated = false
  } = {}
) {
  const actualSupport = support ?? compileLocalSupport(specification, {
    platform: process.platform,
    arch: process.arch,
    nodeVersion: process.versions.node
  });
  const actualLimits = limits ?? fallbackLimits(specification, {});
  return createObservation({
    support: { ...actualSupport, adapter: "injected-invalid" },
    limits: actualLimits,
    control: {
      kind: controlKind,
      timeoutMs: actualLimits.timeoutMs,
      requestedSignal: null,
      signalDelivered: false,
      signalAttempts: []
    },
    termination: {
      kind: "unconfirmed",
      exitCode: null,
      signal: null,
      error: {
        code: errorCode,
        message: boundedText(message, MAX_ERROR_BYTES),
        ...(reportedTruncated ? { reportedTruncated: true } : {})
      },
      closeConfirmed: false
    },
    stdout: emptyStream(false),
    stderr: emptyStream(false)
  });
}

function compileLocalSupport(specification, runtime) {
  const nodeMajor = parseNodeMajor(runtime.nodeVersion);
  const base = {
    status: "supported",
    profile: LOCAL_SUPPORT_PROFILE,
    adapter: "local-node-spawn",
    platform: runtime.platform,
    arch: runtime.arch,
    nodeVersion: runtime.nodeVersion,
    nodeMajor,
    mode: specification.mode,
    reasonCode: null,
    reason: null
  };
  if (specification.mode !== "direct") {
    return { ...base, status: "unsupported", reasonCode: "execution-mode-unsupported", reason: "Only direct argv execution is supported." };
  }
  if (!SUPPORTED_PLATFORMS.has(runtime.platform)) {
    return { ...base, status: "unsupported", reasonCode: "platform-unsupported", reason: `Platform ${runtime.platform} is outside the declared profile.` };
  }
  if (!SUPPORTED_NODE_MAJORS.has(nodeMajor)) {
    return { ...base, status: "unsupported", reasonCode: "node-major-unsupported", reason: `Node major ${String(nodeMajor)} is outside the declared profile.` };
  }
  return base;
}

function unsupportedSupport(specification, runtime, reasonCode, reason) {
  return {
    status: "unsupported",
    profile: LOCAL_SUPPORT_PROFILE,
    adapter: "local-node-spawn",
    platform: runtime.platform ?? process.platform,
    arch: runtime.arch ?? process.arch,
    nodeVersion: runtime.nodeVersion ?? process.versions.node,
    nodeMajor: parseNodeMajor(runtime.nodeVersion ?? process.versions.node),
    mode: specification.mode ?? null,
    reasonCode,
    reason: boundedText(reason ?? "Command specification is invalid.", MAX_ERROR_BYTES)
  };
}

function commandLimits(specification, runtime) {
  return {
    timeoutMs: specification.timeoutMs,
    terminationGraceMs: runtime.terminationGraceMs,
    settlementGraceMs: runtime.settlementGraceMs,
    captureBytesPerStream: runtime.captureBytesPerStream,
    initialSignal: "SIGTERM",
    escalationSignal: "SIGKILL"
  };
}

function fallbackLimits(specification, runtime) {
  return {
    timeoutMs: validTimer(specification.timeoutMs) ? specification.timeoutMs : DEFAULT_TIMEOUT_MS,
    terminationGraceMs: validTimer(runtime.terminationGraceMs)
      ? runtime.terminationGraceMs : DEFAULT_TERMINATION_GRACE_MS,
    settlementGraceMs: validTimer(runtime.settlementGraceMs)
      ? runtime.settlementGraceMs : DEFAULT_SETTLEMENT_GRACE_MS,
    captureBytesPerStream: Number.isSafeInteger(runtime.captureBytesPerStream)
      && runtime.captureBytesPerStream > 0 ? runtime.captureBytesPerStream : MAX_CAPTURE_BYTES,
    initialSignal: "SIGTERM",
    escalationSignal: "SIGKILL"
  };
}

function compileTermination({ exitCode, signal, spawnError, closeConfirmed, forcedKind }) {
  if (forcedKind === "start-failed" || (spawnError && !Number.isInteger(exitCode) && !readString(signal))) {
    return {
      kind: "start-failed",
      exitCode: null,
      signal: null,
      error: normalizedProcessError(spawnError),
      closeConfirmed
    };
  }
  if (forcedKind === "unconfirmed" || closeConfirmed !== true) {
    return {
      kind: "unconfirmed",
      exitCode: null,
      signal: null,
      error: spawnError ? normalizedProcessError(spawnError) : null,
      closeConfirmed: false
    };
  }
  if (Number.isInteger(exitCode) && signal == null) {
    return { kind: "exited", exitCode, signal: null, error: null, closeConfirmed: true };
  }
  const signalName = readString(signal);
  if (exitCode == null && signalName) {
    return { kind: "signaled", exitCode: null, signal: signalName, error: null, closeConfirmed: true };
  }
  return {
    kind: "unconfirmed",
    exitCode: null,
    signal: null,
    error: { code: "COMMAND_TERMINATION_AMBIGUOUS", message: "Close did not report exactly one exit code or signal." },
    closeConfirmed: false
  };
}

function normalizeCommandSpecification(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, value: {}, reason: "Command specification must be an object." };
  }
  const command = readString(value.command);
  if (!command) {
    return { valid: false, value: { ...value }, reason: "Command specification requires command." };
  }
  if (!Array.isArray(value.args) || !value.args.every((part) => typeof part === "string")) {
    return { valid: false, value: { ...value, command }, reason: "Command args must be an exact string array." };
  }
  const mode = readString(value.mode) ?? "direct";
  const timeoutMs = value.timeoutMs === undefined ? DEFAULT_TIMEOUT_MS : value.timeoutMs;
  if (!validTimer(timeoutMs)) {
    return { valid: false, value: { ...value, command, mode }, reason: "timeoutMs must be a positive safe timer integer." };
  }
  if (value.env !== undefined && (!value.env || typeof value.env !== "object" || Array.isArray(value.env)
    || Object.values(value.env).some((entry) => typeof entry !== "string"))) {
    return { valid: false, value: { ...value, command, mode }, reason: "Command env must contain only string values." };
  }
  return {
    valid: true,
    value: {
      ...value,
      command,
      args: [...value.args],
      mode,
      timeoutMs,
      ...(value.env ? { env: { ...value.env } } : {})
    }
  };
}

function isCanonicalCommandObservation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.schemaVersion !== COMMAND_OBSERVATION_SCHEMA_VERSION) return false;
  const support = value.support;
  const limits = value.limits;
  const control = value.control;
  const termination = value.termination;
  const streams = value.streams;
  if (!support || !["supported", "unsupported"].includes(support.status)
    || typeof support.profile !== "string" || typeof support.platform !== "string"
    || typeof support.nodeVersion !== "string" || typeof support.mode !== "string"
    || typeof support.adapter !== "string") return false;
  if (support.profile !== LOCAL_SUPPORT_PROFILE) return false;
  if (support.status === "supported"
    && (support.mode !== "direct"
      || !SUPPORTED_PLATFORMS.has(support.platform)
      || !SUPPORTED_NODE_MAJORS.has(parseNodeMajor(support.nodeVersion))
      || support.nodeMajor !== parseNodeMajor(support.nodeVersion)
      || support.reasonCode !== null
      || support.reason !== null)) return false;
  if (!limits || !validTimer(limits.timeoutMs)
    || !validTimer(limits.terminationGraceMs)
    || !validTimer(limits.settlementGraceMs)
    || limits.terminationGraceMs > MAX_GRACE_MS
    || limits.settlementGraceMs > MAX_GRACE_MS
    || !Number.isSafeInteger(limits.captureBytesPerStream)
    || limits.captureBytesPerStream < 1
    || limits.captureBytesPerStream > MAX_CAPTURE_BYTES) return false;
  if (!control || !["none", "timeout", "cancelled"].includes(control.kind)
    || control.timeoutMs !== limits.timeoutMs
    || ![null, "SIGTERM", "SIGKILL"].includes(control.requestedSignal)
    || typeof control.signalDelivered !== "boolean"
    || !Array.isArray(control.signalAttempts)
    || control.signalAttempts.some((attempt) => (
      !attempt || !["SIGTERM", "SIGKILL"].includes(attempt.signal)
      || typeof attempt.delivered !== "boolean"
    ))) return false;
  if (!termination || !["exited", "signaled", "start-failed", "not-started", "unconfirmed"].includes(termination.kind)
    || typeof termination.closeConfirmed !== "boolean") return false;
  if (termination.kind === "exited" && (!Number.isInteger(termination.exitCode) || termination.signal !== null)) return false;
  if (termination.kind === "signaled" && (termination.exitCode !== null || !readString(termination.signal))) return false;
  if (!["exited", "signaled"].includes(termination.kind)
    && (termination.exitCode !== null || termination.signal !== null)) return false;
  if (termination.closeConfirmed !== (termination.kind !== "unconfirmed")) return false;
  const internallyObserved = value[INTERNAL_OBSERVATION] === true;
  if (!streams || !validStream(streams.stdout, limits.captureBytesPerStream, internallyObserved)
    || !validStream(streams.stderr, limits.captureBytesPerStream, internallyObserved)) return false;
  if (streams.stdout.complete !== termination.closeConfirmed
    || streams.stderr.complete !== termination.closeConfirmed) return false;
  if (control.kind === "none"
    && (control.requestedSignal !== null || control.signalDelivered !== false
      || control.signalAttempts.length !== 0)) return false;
  if (control.signalAttempts.length > 0) {
    const lastAttempt = control.signalAttempts.at(-1);
    if (control.requestedSignal !== lastAttempt.signal
      || control.signalDelivered !== lastAttempt.delivered) return false;
  } else if (control.requestedSignal !== null || control.signalDelivered !== false) return false;
  if (support.status === "unsupported" && termination.kind !== "not-started") return false;
  return true;
}

function validStream(stream, captureLimit, internallyObserved) {
  if (!stream || typeof stream !== "object" || Array.isArray(stream)
    || typeof stream.contentBase64 !== "string"
    || !Number.isSafeInteger(stream.capturedBytes) || stream.capturedBytes < 0
    || !Number.isSafeInteger(stream.observedBytes) || stream.observedBytes < stream.capturedBytes
    || stream.capturedBytes > captureLimit
    || typeof stream.capturedDigest !== "string"
    || typeof stream.observedDigest !== "string"
    || !/^sha256:[a-f0-9]{64}$/u.test(stream.capturedDigest)
    || !/^sha256:[a-f0-9]{64}$/u.test(stream.observedDigest)
    || typeof stream.truncated !== "boolean"
    || stream.truncated !== (stream.observedBytes > stream.capturedBytes)
    || typeof stream.complete !== "boolean"
    || !["valid", "invalid", "unconfirmed"].includes(stream.utf8Validity)) return false;
  const bytes = Buffer.from(stream.contentBase64, "base64");
  if (bytes.byteLength !== stream.capturedBytes
    || bytes.toString("base64") !== stream.contentBase64
    || rawDigest(bytes) !== stream.capturedDigest
    || (stream.complete && stream.utf8Validity === "unconfirmed")
    || (!stream.complete && stream.utf8Validity !== "unconfirmed")) return false;
  if (!stream.truncated) {
    if (stream.observedDigest !== stream.capturedDigest) return false;
    if (stream.complete
      && stream.utf8Validity !== (isUtf8(bytes) ? "valid" : "invalid")) return false;
  }
  if (stream.truncated && !internallyObserved) return false;
  return true;
}

function projectLegacyCommandResult(observation) {
  const stdout = readCommandUtf8Stream(observation, "stdout", { requireUntruncated: false });
  const stderr = readCommandUtf8Stream(observation, "stderr", { requireUntruncated: false });
  return {
    exitCode: observation.termination.kind === "exited"
      ? observation.termination.exitCode : null,
    stdout: stdout.available ? stdout.value : "",
    stderr: stderr.available ? stderr.value : observation.termination.error?.message ?? "",
    ...(observation.termination.kind === "signaled"
      ? { signal: observation.termination.signal } : {}),
    ...((observation.streams.stdout.truncated || observation.streams.stderr.truncated)
      ? { truncated: true } : {}),
    ...(observation.termination.error?.reportedTruncated === true
      ? { truncated: true } : {})
  };
}

function normalizedProcessError(error) {
  if (!error) return { code: "COMMAND_START_FAILED", message: "Command could not be started." };
  return {
    code: readString(error.code) ?? "COMMAND_START_FAILED",
    message: boundedErrorMessage(error),
    ...(readString(error.syscall) ? { syscall: error.syscall.trim() } : {})
  };
}

function boundedErrorMessage(error) {
  return boundedText(error instanceof Error ? error.message : String(error), MAX_ERROR_BYTES);
}

function boundedText(value, limit) {
  const text = typeof value === "string" ? value : String(value);
  const bytes = Buffer.from(text, "utf8");
  if (bytes.byteLength <= limit) return text;
  return `${bytes.subarray(0, Math.max(0, limit - 3)).toString("utf8")}...`;
}

function unavailableText(reasonCode, reason) {
  return { available: false, reasonCode, reason };
}

function rawDigest(value) {
  return `sha256:${createHash("sha256").update(value).digest("hex")}`;
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const entry of Object.values(value)) deepFreeze(entry);
  return Object.freeze(value);
}

function safeByteSum(current, added) {
  const next = current + added;
  if (!Number.isSafeInteger(next)) throw new RangeError("Observed command stream exceeded safe byte accounting.");
  return next;
}

function parseNodeMajor(value) {
  const match = /^(\d+)\./u.exec(value ?? "");
  return match ? Number.parseInt(match[1], 10) : null;
}

function validTimer(value) {
  return Number.isSafeInteger(value) && value > 0 && value <= MAX_TIMER_MS;
}

function requireTimer(value, label) {
  if (!validTimer(value)) throw new TypeError(`${label} must be a positive safe timer integer.`);
  return value;
}

function requirePositiveSafeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${label} must be a positive safe integer.`);
  }
  return value;
}

function requireCaptureLimit(value, label) {
  const limit = requirePositiveSafeInteger(value, label);
  if (limit > MAX_CAPTURE_BYTES) {
    throw new TypeError(`${label} cannot exceed ${MAX_CAPTURE_BYTES} bytes.`);
  }
  return limit;
}

function requireGrace(value, label) {
  const grace = requireTimer(value, label);
  if (grace > MAX_GRACE_MS) {
    throw new TypeError(`${label} cannot exceed ${MAX_GRACE_MS}ms.`);
  }
  return grace;
}

function requireRuntimeString(value, label) {
  const text = readString(value);
  if (!text) throw new TypeError(`${label} must be a non-empty string.`);
  return text;
}

function requireFunction(value, label) {
  if (typeof value !== "function") throw new TypeError(`${label} must be a function.`);
  return value;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
