#!/usr/bin/env node

import { spawn } from "node:child_process";
import { realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { createKernel } from "./core/index.mjs";
import { DEFAULT_PORT, startServer } from "./server.mjs";
import { compileArchitectureProfileWindowViewModel } from "./workbench-view-model.mjs";

const HELP_TEXT = `Usage:
  legatura open <repo> [--port ${DEFAULT_PORT}] [--no-browser]
  legatura inspect <repo> [--json]

Commands:
  open       Start the local Change workbench for a repository.
  inspect    Compile and print the repository Architecture Profile.
`;

const PROFILE_DIMENSIONS = Object.freeze([
  ["outcomes", "Outcomes"],
  ["criteria", "Criteria"],
  ["claims", "Claims"],
  ["gates", "Gates"],
  ["evidence", "Evidence"],
  ["residualUncertainty", "Residual uncertainty"],
  ["knowledgeGaps", "Knowledge gaps"]
]);

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!command || command === "--help" || command === "-h" || command === "help") {
    return { command: "help" };
  }

  if (command === "open") {
    return parseOpenArgs(rest);
  }
  if (command === "inspect") {
    return parseInspectArgs(rest);
  }
  throw cliError("UNKNOWN_COMMAND", `Unknown command: ${command}`, { command });
}

export async function runCli(
  argv,
  io = defaultIo(),
  { kernelFactory = createKernel } = {}
) {
  const options = parseArgs(argv);
  if (options.command === "help") {
    io.stdout.write(HELP_TEXT);
    return { status: "help" };
  }

  const repoPath = await resolveRepositoryPath(options.repo, io);
  if (options.command === "inspect") {
    return inspectArchitectureProfileWindows({
      repoPath,
      json: options.json,
      io,
      kernel: kernelFactory({ repoPath })
    });
  }

  const app = await startServer({ repoPath, port: options.port });
  io.stdout.write(`Legatura is governing ${repoPath}\n${app.address.url}\n`);

  if (options.openBrowser) {
    try {
      await io.openBrowser(app.address.url);
    } catch (error) {
      writeStructuredError(io.stderr, cliError(
        "BROWSER_OPEN_FAILED",
        `The workbench is running, but the browser could not be opened: ${error.message}`
      ));
    }
  }

  const close = async () => {
    await app.close();
  };
  io.onSignal?.("SIGINT", close);
  io.onSignal?.("SIGTERM", close);
  return { status: "listening", repoPath, address: app.address, close };
}

function parseOpenArgs(argv) {
  let repo;
  let port = DEFAULT_PORT;
  let openBrowser = true;

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--port") {
      const value = argv[index + 1];
      if (value === undefined) {
        throw cliError("MISSING_OPTION_VALUE", "--port requires a value.");
      }
      port = parseCliPort(value);
      index += 1;
    } else if (arg === "--no-browser") {
      openBrowser = false;
    } else if (arg === "--help" || arg === "-h") {
      return { command: "help" };
    } else if (arg.startsWith("-")) {
      throw cliError("UNKNOWN_OPTION", `Unknown option for open: ${arg}`, { option: arg });
    } else if (repo === undefined) {
      repo = arg;
    } else {
      throw cliError("UNEXPECTED_ARGUMENT", `Unexpected argument: ${arg}`, { argument: arg });
    }
  }

  if (!repo) {
    throw cliError("REPOSITORY_REQUIRED", "open requires a repository path.");
  }
  return { command: "open", repo, port, openBrowser };
}

function parseInspectArgs(argv) {
  let repo;
  let json = false;

  for (const arg of argv) {
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      return { command: "help" };
    } else if (arg.startsWith("-")) {
      throw cliError("UNKNOWN_OPTION", `Unknown option for inspect: ${arg}`, { option: arg });
    } else if (repo === undefined) {
      repo = arg;
    } else {
      throw cliError("UNEXPECTED_ARGUMENT", `Unexpected argument: ${arg}`, { argument: arg });
    }
  }

  if (!repo) {
    throw cliError("REPOSITORY_REQUIRED", "inspect requires a repository path.");
  }
  return { command: "inspect", repo, json };
}

function parseCliPort(value) {
  if (!/^\d+$/.test(value)) {
    throw cliError("INVALID_PORT", `Invalid port: ${value}`);
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw cliError("INVALID_PORT", `Port must be between 1 and 65535: ${value}`);
  }
  return port;
}

async function resolveRepositoryPath(value, io) {
  const candidate = path.resolve(value);
  let resolved;
  try {
    resolved = await io.realpath(candidate);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw cliError("REPOSITORY_NOT_FOUND", `Repository path does not exist: ${candidate}`);
    }
    throw error;
  }

  const metadata = await io.stat(resolved);
  if (!metadata.isDirectory()) {
    throw cliError("REPOSITORY_NOT_DIRECTORY", `Repository path is not a directory: ${resolved}`);
  }
  return resolved;
}

async function inspectArchitectureProfileWindows({ repoPath, json, io, kernel }) {
  let request = {};
  let windowCount = 0;
  let lastWindowDigest = null;
  if (json) {
    await writeOutput(
      io.stdout,
      '{"schemaVersion":1,"kind":"architecture-profile-window-stream","windows":['
    );
  }

  while (request !== null) {
    const profileWindow = await kernel.inspectArchitectureProfileWindow(request);
    const viewModel = compileArchitectureProfileWindowViewModel(profileWindow);
    if (json) {
      await writeOutput(io.stdout, `${windowCount === 0 ? "" : ","}${JSON.stringify(viewModel)}`);
    } else {
      await writeOutput(io.stdout, renderArchitectureProfileWindowSummary(viewModel, windowCount + 1));
    }
    windowCount += 1;
    lastWindowDigest = viewModel.windowDigest;
    request = readContinuationRequest(viewModel.continuation);
  }

  if (json) {
    await writeOutput(io.stdout, `],"windowCount":${windowCount}}\n`);
  }
  return { status: "inspected", repoPath, windowCount, lastWindowDigest };
}

function renderArchitectureProfileWindowSummary(viewModel, sequence) {
  const sourceRefs = viewModel.source;
  const lines = [
    `Architecture Profile window ${sequence}`,
    `Profile: ${viewModel.page.profileRef}`,
    `Window: offset ${viewModel.window.offset}, returned ${viewModel.window.returned}, limit ${viewModel.window.limit}, has more ${viewModel.window.hasMore ? "yes" : "no"}`,
    `Snapshot: ${sourceRefs.snapshotDigest}`,
    `Project Model: ${sourceRefs.projectModelDigest}`,
    `Git content: ${sourceRefs.gitContentDigest}`,
    `Change Store: ${sourceRefs.changeStoreDigest}`,
    "Orthogonal dimensions:"
  ];
  for (const [field, label] of PROFILE_DIMENSIONS) {
    lines.push(`  ${label}: ${viewModel.page.dimensions[field].length}`);
  }
  return `${lines.join("\n")}\n`;
}

function readContinuationRequest(continuation) {
  if (continuation === null) return null;
  if (!continuation
    || typeof continuation !== "object"
    || Array.isArray(continuation)
    || typeof continuation.cursor !== "string"
    || continuation.cursor.length === 0) {
    throw cliError(
      "ARCHITECTURE_PROFILE_CONTINUATION_INVALID",
      "Architecture Profile window did not provide an opaque continuation cursor."
    );
  }
  return { cursor: continuation.cursor };
}

function writeOutput(stream, value) {
  if (stream.write(value) !== false || typeof stream.once !== "function") {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    const onDrain = () => {
      stream.off?.("error", onError);
      resolve();
    };
    const onError = (error) => {
      stream.off?.("drain", onDrain);
      reject(error);
    };
    stream.once("drain", onDrain);
    stream.once("error", onError);
  });
}

function cliError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function writeStructuredError(stream, error) {
  stream.write(`${JSON.stringify({
    error: {
      code: typeof error?.code === "string" ? error.code : "CLI_ERROR",
      message: error instanceof Error ? error.message : "The command failed.",
      ...(error?.details === undefined ? {} : { details: error.details })
    }
  })}\n`);
}

function defaultIo() {
  return {
    stdout: process.stdout,
    stderr: process.stderr,
    realpath,
    stat,
    openBrowser,
    onSignal(signal, handler) {
      process.once(signal, () => {
        Promise.resolve(handler()).finally(() => {
          process.exitCode = 0;
        });
      });
    }
  };
}

function openBrowser(url) {
  const invocation = process.platform === "darwin"
    ? { command: "open", args: [url] }
    : process.platform === "win32"
      ? { command: "cmd", args: ["/c", "start", "", url] }
      : { command: "xdg-open", args: [url] };

  return new Promise((resolve, reject) => {
    const child = spawn(invocation.command, invocation.args, {
      detached: true,
      stdio: "ignore"
    });
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}

async function main() {
  try {
    await runCli(process.argv.slice(2));
  } catch (error) {
    writeStructuredError(process.stderr, error);
    process.exitCode = 1;
  }
}

const entrypointPath = process.argv[1]
  ? await realpath(process.argv[1]).catch(() => path.resolve(process.argv[1]))
  : null;
const isEntrypoint = entrypointPath === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  await main();
}
