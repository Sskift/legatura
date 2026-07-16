import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { canonicalDigest } from "./canonical.mjs";
import { executeCommand } from "./command-runner.mjs";

const RUNTIME_PREFIX = ".legatura/runtime/";

export async function readGitBinding(repoPath, commandRunner) {
  const base = { cwd: repoPath, purpose: "git-binding" };
  const headResult = await executeCommand(commandRunner, {
    ...base,
    command: "git",
    args: ["rev-parse", "--verify", "HEAD"]
  });
  if (headResult.exitCode !== 0 || headResult.truncated) {
    return {
      available: false,
      head: null,
      branch: null,
      dirty: false,
      status: [],
      untracked: [],
      error: headResult.truncated ? "Git HEAD output was truncated." : headResult.stderr || headResult.stdout,
      contentDigest: canonicalDigest({
        available: false,
        error: headResult.truncated ? "Git HEAD output was truncated." : headResult.stderr || headResult.stdout
      })
    };
  }

  const [branchResult, statusResult, diffResult, untrackedResult] = await Promise.all([
    executeCommand(commandRunner, { ...base, command: "git", args: ["branch", "--show-current"] }),
    executeCommand(commandRunner, { ...base, command: "git", args: ["status", "--porcelain=v1", "--untracked-files=all"] }),
    executeCommand(commandRunner, { ...base, command: "git", args: ["diff", "--binary", "HEAD", "--", ".", ":(exclude).legatura/runtime/**"] }),
    executeCommand(commandRunner, { ...base, command: "git", args: ["ls-files", "--others", "--exclude-standard"] })
  ]);

  const commandObservations = [
    ["branch", branchResult],
    ["status", statusResult],
    ["diff", diffResult],
    ["untracked", untrackedResult]
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
    return {
      available: false,
      head: headResult.stdout.trim(),
      branch: null,
      dirty: true,
      status: [],
      untracked: [],
      error,
      contentDigest: canonicalDigest({ available: false, error })
    };
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
    untracked
  };
  return {
    ...binding,
    contentDigest: canonicalDigest(binding)
  };
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
