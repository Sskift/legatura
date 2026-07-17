import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { canonicalDigest } from "./canonical.mjs";
import { executeCommand } from "./command-runner.mjs";

const RUNTIME_PREFIX = ".legatura/runtime/";
const TRACKED_PATH_LIMITS = Object.freeze({
  paths: 65_536,
  totalBytes: 1024 * 1024,
  pathBytes: 4096
});

export async function readGitBinding(repoPath, commandRunner) {
  const base = { cwd: repoPath, purpose: "git-binding" };
  const headResult = await executeGitCommand(commandRunner, {
    ...base,
    command: "git",
    args: ["rev-parse", "--verify", "HEAD"]
  });
  if (headResult.exitCode !== 0 || headResult.truncated) {
    const error = headResult.truncated
      ? "Git HEAD output was truncated."
      : headResult.stderr || headResult.stdout;
    return unavailableBinding(error, null, false);
  }

  const [branchResult, statusResult, diffResult, untrackedResult, trackedResult] = await Promise.all([
    executeGitCommand(commandRunner, { ...base, command: "git", args: ["branch", "--show-current"] }),
    executeGitCommand(commandRunner, { ...base, command: "git", args: ["status", "--porcelain=v1", "--untracked-files=all"] }),
    executeGitCommand(commandRunner, { ...base, command: "git", args: ["diff", "--binary", "HEAD", "--", ".", ":(exclude).legatura/runtime/**"] }),
    executeGitCommand(commandRunner, { ...base, command: "git", args: ["ls-files", "--others", "--exclude-standard"] }),
    executeGitCommand(commandRunner, { ...base, command: "git", args: ["ls-files", "--cached", "--full-name", "-z", "--"] })
  ]);

  const commandObservations = [
    ["branch", branchResult],
    ["status", statusResult],
    ["diff", diffResult],
    ["untracked", untrackedResult],
    ["tracked", trackedResult]
  ];
  const failedCommands = commandObservations
    .filter(([, result]) => result.exitCode !== 0)
    .map(([name, result]) => `${name} (exit ${result.exitCode})`);
  const truncatedCommands = commandObservations
    .filter(([, result]) => result.truncated)
    .map(([name]) => name);
  if (failedCommands.length > 0 || truncatedCommands.length > 0) {
    const failures = [
      ...(failedCommands.length > 0 ? [`failed commands: ${failedCommands.join(", ")}`] : []),
      ...(truncatedCommands.length > 0 ? [`truncated output: ${truncatedCommands.join(", ")}`] : [])
    ];
    const error = `Git binding observations were incomplete (${failures.join("; ")}).`;
    return unavailableBinding(error, headResult.stdout.trim());
  }

  const trackedObservation = parseTrackedPaths(trackedResult.stdout);
  if (!trackedObservation.valid) {
    return unavailableBinding(trackedObservation.error, headResult.stdout.trim());
  }

  const status = splitLines(statusResult.stdout)
    .filter((line) => !lineReferencesRuntime(line))
    .sort();
  const untrackedPaths = splitLines(untrackedResult.stdout)
    .map(normalizeGitPath)
    .filter((filePath) => filePath && !filePath.startsWith(RUNTIME_PREFIX))
    .sort();
  const untracked = [];
  for (const relativePath of untrackedPaths) {
    untracked.push(await summarizeUntrackedFile(repoPath, relativePath));
  }

  const binding = {
    available: true,
    head: headResult.stdout.trim(),
    branch: branchResult.stdout.trim() || "DETACHED",
    dirty: status.length > 0,
    status,
    trackedDiffDigest: canonicalDigest(diffResult.stdout),
    trackedPathFacts: trackedObservation.facts,
    untracked
  };
  return {
    ...binding,
    contentDigest: canonicalDigest(binding)
  };
}

function parseTrackedPaths(stdout) {
  const totalBytes = Buffer.byteLength(stdout, "utf8");
  if (totalBytes > TRACKED_PATH_LIMITS.totalBytes) {
    return invalidTrackedPaths(
      `Tracked path observation exceeded ${TRACKED_PATH_LIMITS.totalBytes} bytes.`
    );
  }
  if (stdout === "") {
    return validTrackedPaths([]);
  }
  if (!stdout.endsWith("\0")) {
    return invalidTrackedPaths("Tracked path observation was not NUL-terminated.");
  }

  const pathCount = countNulTerminators(stdout);
  if (pathCount > TRACKED_PATH_LIMITS.paths) {
    return invalidTrackedPaths(
      `Tracked path observation exceeded ${TRACKED_PATH_LIMITS.paths} paths.`
    );
  }
  const paths = stdout.slice(0, -1).split("\0");

  const seen = new Set();
  for (const trackedPath of paths) {
    const issue = trackedPathIssue(trackedPath);
    if (issue) return invalidTrackedPaths(issue);
    if (seen.has(trackedPath)) {
      return invalidTrackedPaths(`Tracked path observation repeated path: ${trackedPath}.`);
    }
    seen.add(trackedPath);
  }
  return validTrackedPaths([...seen].sort(compareUtf8Paths));
}

function trackedPathIssue(trackedPath) {
  if (!trackedPath) return "Tracked path observation contained an empty path.";
  const pathBytes = Buffer.byteLength(trackedPath, "utf8");
  if (pathBytes > TRACKED_PATH_LIMITS.pathBytes) {
    return `Tracked path exceeded ${TRACKED_PATH_LIMITS.pathBytes} bytes.`;
  }
  if (!trackedPath.isWellFormed() || trackedPath.includes("\uFFFD")) {
    return `Tracked path was not a canonical UTF-8 repository path: ${JSON.stringify(trackedPath)}.`;
  }
  if (path.posix.isAbsolute(trackedPath)
    || /^[A-Za-z]:\//u.test(trackedPath)
    || trackedPath.startsWith("\\\\")
    || trackedPath === "."
    || trackedPath === ".."
    || trackedPath.startsWith("./")
    || trackedPath.endsWith("/")
    || trackedPath.includes("//")
    || trackedPath.split("/").some((part) => part === "." || part === "..")
    || path.posix.normalize(trackedPath) !== trackedPath) {
    return `Tracked path was not canonical repository-relative form: ${JSON.stringify(trackedPath)}.`;
  }
  return null;
}

function validTrackedPaths(paths) {
  const facts = {
    schemaVersion: 1,
    paths
  };
  return {
    valid: true,
    facts: {
      ...facts,
      digest: canonicalDigest(facts)
    }
  };
}

function invalidTrackedPaths(message) {
  return {
    valid: false,
    error: `Git tracked path observation was incomplete (${message})`
  };
}

function unavailableBinding(error, head = null, dirty = true) {
  return {
    available: false,
    head: head || null,
    branch: null,
    dirty,
    status: [],
    trackedPathFacts: null,
    untracked: [],
    error,
    contentDigest: canonicalDigest({ available: false, error })
  };
}

async function executeGitCommand(commandRunner, specification) {
  try {
    return await executeCommand(commandRunner, specification);
  } catch (error) {
    return {
      exitCode: 1,
      stdout: "",
      stderr: error instanceof Error ? error.message : String(error)
    };
  }
}

function countNulTerminators(value) {
  let count = 0;
  for (let index = value.indexOf("\0"); index !== -1; index = value.indexOf("\0", index + 1)) {
    count += 1;
    if (count > TRACKED_PATH_LIMITS.paths) return count;
  }
  return count;
}

function compareUtf8Paths(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

async function summarizeUntrackedFile(repoPath, relativePath) {
  const fullPath = path.join(repoPath, relativePath);
  try {
    const metadata = await stat(fullPath);
    if (!metadata.isFile()) {
      return { path: relativePath, kind: "non-file" };
    }
    const content = await readFile(fullPath);
    return {
      path: relativePath,
      kind: "file",
      size: content.byteLength,
      digest: canonicalDigest(content.toString("base64"))
    };
  } catch (error) {
    return {
      path: relativePath,
      kind: "unreadable",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

function lineReferencesRuntime(line) {
  return line.includes(RUNTIME_PREFIX) || line.includes(".legatura/runtime");
}

function splitLines(value) {
  return value.split(/\r?\n/u).map((line) => line.trimEnd()).filter(Boolean);
}

function normalizeGitPath(value) {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}
