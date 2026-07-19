import { constants as fsConstants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { types as utilTypes } from "node:util";

import { canonicalDigest } from "./canonical.mjs";
import { readGitBinding } from "./git-binding.mjs";

export const REPOSITORY_SOURCE_PRODUCT_PROOF_VERSION = 1;

export const REPOSITORY_SOURCE_PRODUCT_LIMITS = deepFreeze({
  schemaVersion: 1,
  rounds: 3,
  pathRefs: 1_024,
  pathBytes: 4_096,
  fileBytes: 4 * 1024 * 1024,
  totalBytes: 16 * 1024 * 1024
});

const SOURCE_PRODUCTS = new WeakMap();
const SOURCE_ERRORS = new WeakSet();
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/u;
const REQUEST_KEYS = new Set([
  "gitContentDigest",
  "pathRefs",
  "schemaVersion",
  "trackedPathFactsDigest"
]);
const EXPECTATION_KEYS = new Set([...REQUEST_KEYS, "repoPath"]);
const OPTION_KEYS = new Set(["commandRunner", "limits"]);
const LIMIT_KEYS = new Set(["fileBytes", "pathBytes", "pathRefs", "totalBytes"]);
const ERROR_MESSAGES = Object.freeze({
  EXPECTATION_MISMATCH: "Repository source expectations do not match the product.",
  LIMIT_EXCEEDED: "Repository source input exceeded a configured hard limit.",
  OBSERVATION_UNAVAILABLE: "An exact repository source observation is unavailable.",
  PRODUCT_INVALID: "A live Repository Source Product is required.",
  REPOSITORY_SOURCE_INPUT_INVALID: "Repository source input is incomplete or invalid.",
  UNSTABLE: "Repository source observations did not stabilize within the bounded window."
});

/**
 * Observe one exact, tracked-only source request. A live product is issued only
 * when two adjacent rounds have the same complete composite digest.
 */
export async function observeStableRepositorySource(repoPath, request, options = {}) {
  try {
    const normalizedOptions = normalizeOptions(options);
    const normalizedRequest = normalizeSourceRequest(request, normalizedOptions.limits);
    const requestedRepoPath = normalizeRepoPath(repoPath, "REPOSITORY_SOURCE_INPUT_INVALID");
    let previousRound = null;

    for (let roundIndex = 0;
      roundIndex < REPOSITORY_SOURCE_PRODUCT_LIMITS.rounds;
      roundIndex += 1) {
      const observed = await observeSourceRound(
        requestedRepoPath,
        normalizedRequest,
        normalizedOptions
      );
      if (previousRound?.compositeDigest === observed.compositeDigest) {
        return issueSourceProduct(observed);
      }
      previousRound = observed;
    }
    throw repositorySourceError("UNSTABLE");
  } catch (error) {
    throw closedError(error, "OBSERVATION_UNAVAILABLE");
  }
}

/**
 * Project only reproducible body-free facts. Every expectation is mandatory,
 * including the caller-known repository path, which is re-identified here but
 * never copied into the result.
 */
export async function projectRepositorySourceProduct(sourceProduct, expectations) {
  try {
    const state = requireLiveProduct(sourceProduct);
    const normalized = normalizeExpectations(expectations);
    if (normalized.repoPath !== state.repoPath
      || normalized.gitContentDigest !== state.gitContentDigest
      || normalized.trackedPathFactsDigest !== state.trackedPathFactsDigest
      || !sameStrings(normalized.pathRefs, state.pathRefs)) {
      throw repositorySourceError("EXPECTATION_MISMATCH");
    }

    const currentIdentity = await observeRepositoryIdentity(normalized.repoPath);
    if (currentIdentity.digest !== state.repositoryIdentityDigest) {
      throw repositorySourceError("EXPECTATION_MISMATCH");
    }

    return deepFreeze({
      schemaVersion: 1,
      repositoryIdentityDigest: state.repositoryIdentityDigest,
      gitContentDigest: state.gitContentDigest,
      trackedPathFactsDigest: state.trackedPathFactsDigest,
      pathSetDigest: state.pathSetDigest,
      manifestDigest: state.manifestDigest,
      productDigest: state.productDigest,
      manifest: state.manifest.map((entry) => ({ ...entry }))
    });
  } catch (error) {
    throw closedError(error, "PRODUCT_INVALID");
  }
}

/** Return a fresh copy of bytes captured by the stable observation. */
export function readRepositorySourceBytes(sourceProduct, pathRef) {
  try {
    const state = requireLiveProduct(sourceProduct);
    const normalizedPathRef = normalizeSinglePathRef(
      pathRef,
      "REPOSITORY_SOURCE_INPUT_INVALID",
      REPOSITORY_SOURCE_PRODUCT_LIMITS
    );
    const bytes = state.bytesByPathRef.get(normalizedPathRef);
    if (!bytes) throw repositorySourceError("EXPECTATION_MISMATCH");
    return Buffer.from(bytes);
  } catch (error) {
    throw closedError(error, "PRODUCT_INVALID");
  }
}

async function observeSourceRound(repoPath, request, { commandRunner, limits }) {
  const identityBefore = await observeRepositoryIdentity(repoPath);
  const git = await readGitBinding(identityBefore.realRoot, commandRunner);
  const binding = validateGitBinding(git);
  if (binding.gitContentDigest !== request.gitContentDigest
    || binding.trackedPathFactsDigest !== request.trackedPathFactsDigest) {
    throw repositorySourceError("OBSERVATION_UNAVAILABLE");
  }

  const tracked = new Set(binding.trackedPathRefs);
  if (request.pathRefs.some((pathRef) => !tracked.has(pathRef))) {
    throw repositorySourceError("OBSERVATION_UNAVAILABLE");
  }

  let totalBytes = 0;
  const entries = [];
  const bytesByPathRef = new Map();
  for (const pathRef of request.pathRefs) {
    const remainingBytes = limits.totalBytes - totalBytes;
    const bytes = await readExactRegularFile(identityBefore.realRoot, pathRef, remainingBytes, limits);
    totalBytes += bytes.byteLength;
    const entry = Object.freeze({
      pathRef,
      byteLength: bytes.byteLength,
      contentDigest: canonicalDigest(bytes.toString("base64"))
    });
    entries.push(entry);
    bytesByPathRef.set(pathRef, Buffer.from(bytes));
  }

  const identityAfter = await observeRepositoryIdentity(repoPath);
  if (identityBefore.digest !== identityAfter.digest) {
    throw repositorySourceError("OBSERVATION_UNAVAILABLE");
  }

  const pathSetDigest = canonicalDigest({ schemaVersion: 1, paths: request.pathRefs });
  const manifestDigest = canonicalDigest({ schemaVersion: 1, entries });
  const productFacts = {
    schemaVersion: 1,
    repositoryIdentityDigest: identityBefore.digest,
    gitContentDigest: binding.gitContentDigest,
    trackedPathFactsDigest: binding.trackedPathFactsDigest,
    pathSetDigest,
    manifestDigest
  };
  const productDigest = canonicalDigest(productFacts);
  const compositeDigest = canonicalDigest({
    schemaVersion: 1,
    proofVersion: REPOSITORY_SOURCE_PRODUCT_PROOF_VERSION,
    ...productFacts,
    productDigest
  });

  return {
    compositeDigest,
    repoPath,
    repositoryIdentityDigest: identityBefore.digest,
    gitContentDigest: binding.gitContentDigest,
    trackedPathFactsDigest: binding.trackedPathFactsDigest,
    pathRefs: [...request.pathRefs],
    pathSetDigest,
    manifestDigest,
    productDigest,
    manifest: entries,
    bytesByPathRef
  };
}

function issueSourceProduct(round) {
  const sourceProduct = Object.freeze(Object.create(null));
  const state = Object.freeze({
    repoPath: round.repoPath,
    repositoryIdentityDigest: round.repositoryIdentityDigest,
    gitContentDigest: round.gitContentDigest,
    trackedPathFactsDigest: round.trackedPathFactsDigest,
    pathRefs: Object.freeze([...round.pathRefs]),
    pathSetDigest: round.pathSetDigest,
    manifestDigest: round.manifestDigest,
    productDigest: round.productDigest,
    manifest: Object.freeze(round.manifest.map((entry) => Object.freeze({ ...entry }))),
    bytesByPathRef: new Map(
      [...round.bytesByPathRef].map(([pathRef, bytes]) => [pathRef, Buffer.from(bytes)])
    )
  });
  SOURCE_PRODUCTS.set(sourceProduct, state);
  return sourceProduct;
}

function requireLiveProduct(value) {
  if ((typeof value !== "object" && typeof value !== "function") || value === null) {
    throw repositorySourceError("PRODUCT_INVALID");
  }
  const state = SOURCE_PRODUCTS.get(value);
  if (!state) throw repositorySourceError("PRODUCT_INVALID");
  return state;
}

function normalizeSourceRequest(value, limits) {
  const record = readExactDataRecord(value, REQUEST_KEYS);
  if (!record
    || record.schemaVersion !== 1
    || !isDigest(record.gitContentDigest)
    || !isDigest(record.trackedPathFactsDigest)) {
    throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
  }
  return Object.freeze({
    schemaVersion: 1,
    gitContentDigest: record.gitContentDigest,
    trackedPathFactsDigest: record.trackedPathFactsDigest,
    pathRefs: Object.freeze(normalizePathRefs(
      record.pathRefs,
      "REPOSITORY_SOURCE_INPUT_INVALID",
      limits
    ))
  });
}

function normalizeExpectations(value) {
  const record = readExactDataRecord(value, EXPECTATION_KEYS);
  if (!record
    || record.schemaVersion !== 1
    || !isDigest(record.gitContentDigest)
    || !isDigest(record.trackedPathFactsDigest)) {
    throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
  }
  return Object.freeze({
    schemaVersion: 1,
    repoPath: normalizeRepoPath(record.repoPath, "REPOSITORY_SOURCE_INPUT_INVALID"),
    gitContentDigest: record.gitContentDigest,
    trackedPathFactsDigest: record.trackedPathFactsDigest,
    pathRefs: Object.freeze(normalizePathRefs(
      record.pathRefs,
      "REPOSITORY_SOURCE_INPUT_INVALID",
      REPOSITORY_SOURCE_PRODUCT_LIMITS
    ))
  });
}

function normalizeOptions(value) {
  const record = readExactDataRecord(value, OPTION_KEYS, { optional: true });
  if (!record) {
    throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
  }
  if (record.commandRunner !== undefined && typeof record.commandRunner !== "function") {
    throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
  }
  return Object.freeze({
    commandRunner: record.commandRunner,
    limits: normalizeLimits(record.limits)
  });
}

function normalizeLimits(value) {
  if (value === undefined) {
    return Object.freeze({
      pathRefs: REPOSITORY_SOURCE_PRODUCT_LIMITS.pathRefs,
      pathBytes: REPOSITORY_SOURCE_PRODUCT_LIMITS.pathBytes,
      fileBytes: REPOSITORY_SOURCE_PRODUCT_LIMITS.fileBytes,
      totalBytes: REPOSITORY_SOURCE_PRODUCT_LIMITS.totalBytes
    });
  }
  const record = readExactDataRecord(value, LIMIT_KEYS, { optional: true });
  if (!record) throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
  const limits = {};
  for (const key of LIMIT_KEYS) {
    const configured = record[key] ?? REPOSITORY_SOURCE_PRODUCT_LIMITS[key];
    if (!Number.isSafeInteger(configured)
      || configured < 1
      || configured > REPOSITORY_SOURCE_PRODUCT_LIMITS[key]) {
      throw repositorySourceError("REPOSITORY_SOURCE_INPUT_INVALID");
    }
    limits[key] = configured;
  }
  return Object.freeze(limits);
}

function normalizePathRefs(value, errorCode, limits) {
  const values = readDensePlainArray(value, limits.pathRefs, "LIMIT_EXCEEDED");
  if (!values) throw repositorySourceError(errorCode);
  const normalized = [];
  const seen = new Set();
  for (const pathRef of values) {
    const exact = normalizeSinglePathRef(pathRef, errorCode, limits);
    if (seen.has(exact)) throw repositorySourceError(errorCode);
    seen.add(exact);
    normalized.push(exact);
  }
  const sorted = [...normalized].sort(compareUtf8);
  if (!sameStrings(sorted, normalized)) {
    throw repositorySourceError(errorCode);
  }
  return normalized;
}

function normalizeSinglePathRef(value, errorCode, limits) {
  if (typeof value !== "string"
    || value.length === 0
    || !value.isWellFormed()
    || value.includes("\uFFFD")
    || value.includes("\0")
    || path.posix.isAbsolute(value)
    || /^[A-Za-z]:\//u.test(value)
    || value.startsWith("\\\\")
    || value === "."
    || value === ".."
    || value.startsWith("./")
    || value.endsWith("/")
    || value.includes("//")
    || value.split("/").some((part) => part === "." || part === "..")
    || path.posix.normalize(value) !== value) {
    throw repositorySourceError(errorCode);
  }
  if (Buffer.byteLength(value, "utf8") > limits.pathBytes) {
    throw repositorySourceError("LIMIT_EXCEEDED");
  }
  return value;
}

function normalizeRepoPath(value, errorCode) {
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw repositorySourceError(errorCode);
  }
  return path.resolve(value);
}

async function observeRepositoryIdentity(repoPath) {
  try {
    const realRoot = await realpath(repoPath);
    const rootMetadata = await lstat(realRoot, { bigint: true });
    const gitMarker = await lstat(path.join(realRoot, ".git"), { bigint: true });
    if (!rootMetadata.isDirectory()
      || rootMetadata.isSymbolicLink()
      || gitMarker.isSymbolicLink()
      || (!gitMarker.isDirectory() && !gitMarker.isFile())) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    const facts = {
      schemaVersion: 1,
      realRoot,
      rootDevice: rootMetadata.dev.toString(),
      rootInode: rootMetadata.ino.toString(),
      gitMarkerDevice: gitMarker.dev.toString(),
      gitMarkerInode: gitMarker.ino.toString(),
      gitMarkerKind: gitMarker.isDirectory() ? "directory" : "file"
    };
    return { realRoot, digest: canonicalDigest(facts) };
  } catch (error) {
    throw closedError(error, "OBSERVATION_UNAVAILABLE");
  }
}

function validateGitBinding(value) {
  try {
    if (!isRecord(value) || value.available !== true || !isDigest(value.contentDigest)) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    const { contentDigest, ...content } = value;
    if (canonicalDigest(content) !== contentDigest) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    const tracked = readExactDataRecord(
      value.trackedPathFacts,
      new Set(["digest", "paths", "schemaVersion"])
    );
    if (!tracked
      || tracked.schemaVersion !== 1
      || !isDigest(tracked.digest)) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    const normalized = normalizeTrackedPathRefs(tracked.paths);
    if (canonicalDigest({ schemaVersion: 1, paths: normalized }) !== tracked.digest) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    return {
      gitContentDigest: contentDigest,
      trackedPathFactsDigest: tracked.digest,
      trackedPathRefs: normalized
    };
  } catch (error) {
    throw closedError(error, "OBSERVATION_UNAVAILABLE");
  }
}

function normalizeTrackedPathRefs(values) {
  const denseValues = readDensePlainArray(values, 65_536, "OBSERVATION_UNAVAILABLE");
  if (!denseValues) {
    throw repositorySourceError("OBSERVATION_UNAVAILABLE");
  }
  const seen = new Set();
  const normalized = [];
  for (const value of denseValues) {
    const pathRef = normalizeSinglePathRef(
      value,
      "OBSERVATION_UNAVAILABLE",
      REPOSITORY_SOURCE_PRODUCT_LIMITS
    );
    if (seen.has(pathRef)) throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    seen.add(pathRef);
    normalized.push(pathRef);
  }
  const sorted = [...normalized].sort(compareUtf8);
  if (!sameStrings(sorted, normalized)) {
    throw repositorySourceError("OBSERVATION_UNAVAILABLE");
  }
  return normalized;
}

async function readExactRegularFile(realRoot, pathRef, remainingBytes, limits) {
  if (remainingBytes < 0) throw repositorySourceError("LIMIT_EXCEEDED");
  const fullPath = path.join(realRoot, ...pathRef.split("/"));
  let handle;
  try {
    if (!Number.isInteger(fsConstants.O_NOFOLLOW) || fsConstants.O_NOFOLLOW === 0) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    await validatePathChain(realRoot, pathRef);
    const canonicalBefore = await realpath(fullPath);
    if (canonicalBefore !== fullPath) throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    const pathBefore = await lstat(fullPath, { bigint: true });
    if (pathBefore.isSymbolicLink() || !pathBefore.isFile()) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }

    handle = await open(fullPath, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    const handleBefore = await handle.stat({ bigint: true });
    if (!sameFileIdentity(pathBefore, handleBefore) || !handleBefore.isFile()) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    if (handleBefore.size > BigInt(limits.fileBytes)
      || handleBefore.size > BigInt(remainingBytes)) {
      throw repositorySourceError("LIMIT_EXCEEDED");
    }

    const byteLength = Number(handleBefore.size);
    const bytes = Buffer.alloc(byteLength);
    let offset = 0;
    while (offset < byteLength) {
      const length = Math.min(64 * 1024, byteLength - offset);
      const { bytesRead } = await handle.read(bytes, offset, length, offset);
      if (bytesRead === 0) throw repositorySourceError("OBSERVATION_UNAVAILABLE");
      offset += bytesRead;
    }
    const extra = Buffer.allocUnsafe(1);
    const extraRead = await handle.read(extra, 0, 1, byteLength);
    if (extraRead.bytesRead !== 0) throw repositorySourceError("OBSERVATION_UNAVAILABLE");

    const handleAfter = await handle.stat({ bigint: true });
    const pathAfter = await lstat(fullPath, { bigint: true });
    const canonicalAfter = await realpath(fullPath);
    await validatePathChain(realRoot, pathRef);
    if (canonicalAfter !== fullPath
      || !sameFileSnapshot(handleBefore, handleAfter)
      || !sameFileIdentity(handleAfter, pathAfter)
      || pathAfter.isSymbolicLink()
      || !pathAfter.isFile()) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
    return bytes;
  } catch (error) {
    throw closedError(error, "OBSERVATION_UNAVAILABLE");
  } finally {
    await handle?.close().catch(() => {});
  }
}

async function validatePathChain(realRoot, pathRef) {
  const parts = pathRef.split("/");
  let current = realRoot;
  for (const part of parts.slice(0, -1)) {
    current = path.join(current, part);
    const metadata = await lstat(current, { bigint: true });
    if (metadata.isSymbolicLink() || !metadata.isDirectory()) {
      throw repositorySourceError("OBSERVATION_UNAVAILABLE");
    }
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.uid === right.uid
    && left.gid === right.gid
    && left.rdev === right.rdev;
}

function sameFileSnapshot(left, right) {
  return sameFileIdentity(left, right)
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs;
}

function sameStrings(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function isDigest(value) {
  return typeof value === "string" && DIGEST_PATTERN.test(value);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readExactDataRecord(value, keys, { optional = false } = {}) {
  if (!isRecord(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Object.prototype) {
    return null;
  }
  const actualKeys = Reflect.ownKeys(value);
  if (actualKeys.some((key) => typeof key !== "string" || !keys.has(key))) return null;
  if (!optional && actualKeys.length !== keys.size) return null;
  const record = Object.create(null);
  for (const key of actualKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) return null;
    record[key] = descriptor.value;
  }
  return record;
}

function readDensePlainArray(value, maxLength, limitErrorCode) {
  if (!Array.isArray(value)
    || utilTypes.isProxy(value)
    || Object.getPrototypeOf(value) !== Array.prototype) {
    return null;
  }
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (!lengthDescriptor || !("value" in lengthDescriptor)) return null;
  const length = lengthDescriptor.value;
  if (!Number.isSafeInteger(length) || length < 0) return null;
  if (length > maxLength) throw repositorySourceError(limitErrorCode);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== "string") || ownKeys.length !== length + 1) {
    return null;
  }
  const values = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) return null;
    values.push(descriptor.value);
  }
  if (ownKeys.some((key) => key !== "length"
    && (!/^(0|[1-9][0-9]*)$/u.test(key) || Number(key) >= length))) {
    return null;
  }
  return values;
}

function repositorySourceError(code) {
  const error = new Error(ERROR_MESSAGES[code] ?? ERROR_MESSAGES.OBSERVATION_UNAVAILABLE);
  error.name = "RepositorySourceError";
  error.code = code;
  error.stack = `${error.name}: ${error.message}`;
  SOURCE_ERRORS.add(error);
  return error;
}

function closedError(error, fallbackCode) {
  if ((typeof error === "object" || typeof error === "function")
    && error !== null
    && SOURCE_ERRORS.has(error)) {
    return error;
  }
  return repositorySourceError(fallbackCode);
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}
