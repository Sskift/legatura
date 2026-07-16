import { spawn } from "node:child_process";

const MAX_CAPTURE_BYTES = 1024 * 1024;

export async function executeCommand(commandRunner, specification) {
  const result = await (commandRunner ?? defaultCommandRunner)(specification);
  return normalizeCommandResult(result);
}

export function normalizeGateCommand(value) {
  if (typeof value === "string" && value.trim()) {
    return {
      command: "/bin/sh",
      args: ["-lc", value.trim()],
      display: value.trim()
    };
  }

  if (Array.isArray(value) && value.length > 0 && value.every((part) => typeof part === "string")) {
    const [command, ...args] = value;
    if (!command.trim()) {
      return undefined;
    }
    return { command, args, display: value.join(" ") };
  }

  if (value && typeof value === "object" && !Array.isArray(value)) {
    const command = readString(value.command) ?? readString(value.program);
    const args = Array.isArray(value.args) && value.args.every((part) => typeof part === "string")
      ? [...value.args]
      : [];
    if (command) {
      return {
        command,
        args,
        display: readString(value.display) ?? [command, ...args].join(" ")
      };
    }
  }

  return undefined;
}

async function defaultCommandRunner({ command, args = [], cwd, env, signal }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      env: env ? { ...process.env, ...env } : process.env,
      signal,
      stdio: ["ignore", "pipe", "pipe"]
    });
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let overflow = false;

    child.stdout.on("data", (chunk) => {
      const capture = captureChunk(stdoutChunks, stdoutBytes, chunk);
      stdoutBytes = capture.capturedBytes;
      overflow ||= capture.truncated;
    });
    child.stderr.on("data", (chunk) => {
      const capture = captureChunk(stderrChunks, stderrBytes, chunk);
      stderrBytes = capture.capturedBytes;
      overflow ||= capture.truncated;
    });
    child.on("error", reject);
    child.on("close", (exitCode, signalName) => {
      resolve({
        exitCode: exitCode ?? 1,
        stdout: Buffer.concat(stdoutChunks, stdoutBytes).toString("utf8"),
        stderr: Buffer.concat(stderrChunks, stderrBytes).toString("utf8"),
        ...(signalName ? { signal: signalName } : {}),
        truncated: overflow
      });
    });
  });
}

function captureChunk(chunks, capturedBytes, chunk) {
  const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
  const remainingBytes = Math.max(0, MAX_CAPTURE_BYTES - capturedBytes);
  const captured = buffer.subarray(0, remainingBytes);
  if (captured.byteLength > 0) {
    chunks.push(captured);
  }
  return {
    capturedBytes: capturedBytes + captured.byteLength,
    truncated: buffer.byteLength > remainingBytes
  };
}

function normalizeCommandResult(value) {
  if (typeof value === "number") {
    return { exitCode: value, stdout: "", stderr: "" };
  }

  if (!value || typeof value !== "object") {
    return { exitCode: 1, stdout: "", stderr: "Command runner returned no result." };
  }

  const exitCode = Number.isInteger(value.exitCode)
    ? value.exitCode
    : Number.isInteger(value.code) ? value.code : value.ok === true ? 0 : 1;
  return {
    exitCode,
    stdout: typeof value.stdout === "string" ? value.stdout : "",
    stderr: typeof value.stderr === "string" ? value.stderr : "",
    ...(typeof value.signal === "string" ? { signal: value.signal } : {}),
    ...(value.truncated === true ? { truncated: true } : {})
  };
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}
