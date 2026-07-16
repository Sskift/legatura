import { randomUUID } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import {
  lstat,
  mkdir,
  open,
  opendir,
  realpath,
  rename,
  rm
} from "node:fs/promises";
import path from "node:path";
import { types as utilTypes } from "node:util";

import { canonicalDigest, cloneJson } from "./canonical.mjs";

export const CHANGE_STORE_LIMITS = Object.freeze({
  directoryEntries: 4096,
  records: 2048,
  changeIdBytes: 128,
  fileBytes: 16 * 1024 * 1024,
  totalBytes: 64 * 1024 * 1024,
  depth: 64,
  nodesPerRecord: 262_144,
  // Aggregate parsing budget for snapshot(); save() preserves it for Store-owned writes.
  // get() parses one target and therefore applies nodesPerRecord without scanning every body.
  totalNodes: 4_194_304
});

const STORE_SNAPSHOT_ATTEMPT_LIMIT = 3;
// Store-owned writes are serialized across every Store instance in this process.
// Multi-process writers are outside the current local single-writer assurance boundary.
const STORE_WRITE_QUEUES = new Map();

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true });
const READ_NOFOLLOW = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0);
const WRITE_EXCLUSIVE_NOFOLLOW = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0);

export function createChangeStore(repoPath) {
  const locations = storeLocations(repoPath);
  const { directory } = locations;

  return {
    async snapshot() {
      return readStableStoreSnapshot(locations);
    },

    async list() {
      return (await readStableStoreSnapshot(locations)).records;
    },

    async get(id) {
      const name = `${requireChangeId(id, { statusCode: 400 })}.json`;
      for (let attempt = 1; attempt <= STORE_SNAPSHOT_ATTEMPT_LIMIT; attempt += 1) {
        try {
          const manifest = await inspectSnapshotManifest(locations);
          if (!manifest) {
            await assertStoreStillAbsent(locations);
            return undefined;
          }
          const source = manifest.sources.find((entry) => entry.name === name);
          if (!source) {
            await assertManifestStillCurrent(locations, manifest);
            return undefined;
          }
          const record = await readManifestSource(source, { totalNodeBudget: { observed: 0 } });
          await assertManifestStillCurrent(locations, manifest);
          return record;
        } catch (error) {
          if (error?.code !== "CHANGE_STORE_SOURCE_CHANGED") throw error;
          if (attempt === STORE_SNAPSHOT_ATTEMPT_LIMIT) throw snapshotUnstableError(attempt);
        }
      }
      return undefined;
    },

    async save(change) {
      const id = requireChangeId(change?.id, { statusCode: 400 });
      return enqueueStoreWrite(directory, async () => {
        const serialized = serializeChange(change, `${id}.json`);
        await ensureStoreDirectory(locations);
        const currentSnapshot = await readStableStoreSnapshot(locations);
        const previous = currentSnapshot.records.find((record) => record.id === id);
        const previousNodes = previous
          ? assertBoundedJson(previous, `${id}.json`, { observed: 0 })
          : 0;
        assertLimit(
          "totalNodes",
          CHANGE_STORE_LIMITS.totalNodes,
          currentSnapshot.observed.totalNodes - previousNodes + serialized.nodeCount
        );
        await assertSaveFitsStore(directory, `${id}.json`, serialized.bytes.byteLength);
        const target = changePath(directory, id);
        const temporary = path.join(
          locations.runtime,
          `.change-${process.pid}-${randomUUID()}.tmp`
        );
        let temporaryHandle;
        try {
          temporaryHandle = await open(temporary, WRITE_EXCLUSIVE_NOFOLLOW, 0o600);
          await temporaryHandle.writeFile(serialized.bytes);
          await temporaryHandle.close();
          temporaryHandle = undefined;
          await rename(temporary, target);
        } finally {
          await temporaryHandle?.close().catch(() => undefined);
          await rm(temporary, { force: true }).catch(() => undefined);
        }
        return cloneJson(serialized.record);
      });
    }
  };
}

function emptySnapshot() {
  const content = { schemaVersion: 1, entries: [] };
  return {
    schemaVersion: 1,
    digest: canonicalDigest(content),
    records: [],
    observed: {
      directoryEntries: 0,
      recordCount: 0,
      totalBytes: 0,
      totalNodes: 0
    }
  };
}

function enqueueStoreWrite(directory, operation) {
  const preceding = STORE_WRITE_QUEUES.get(directory) ?? Promise.resolve();
  const result = preceding.then(operation, operation);
  const tail = result.catch(() => undefined);
  STORE_WRITE_QUEUES.set(directory, tail);
  tail.then(() => {
    if (STORE_WRITE_QUEUES.get(directory) === tail) STORE_WRITE_QUEUES.delete(directory);
  });
  return result;
}

async function readStableStoreSnapshot(locations) {
  for (let attempt = 1; attempt <= STORE_SNAPSHOT_ATTEMPT_LIMIT; attempt += 1) {
    try {
      return await readStoreSnapshotOnce(locations);
    } catch (error) {
      if (error?.code !== "CHANGE_STORE_SOURCE_CHANGED") throw error;
      if (attempt === STORE_SNAPSHOT_ATTEMPT_LIMIT) throw snapshotUnstableError(attempt);
    }
  }
  throw snapshotUnstableError(STORE_SNAPSHOT_ATTEMPT_LIMIT);
}

async function readStoreSnapshotOnce(locations) {
  const manifest = await inspectSnapshotManifest(locations);
  if (!manifest) {
    await assertStoreStillAbsent(locations);
    return emptySnapshot();
  }
  const records = [];
  const entries = [];
  const totalNodeBudget = { observed: 0 };
  for (const source of manifest.sources) {
    const record = await readManifestSource(source, { totalNodeBudget });
    records.push(record);
    entries.push({
      name: source.name,
      changeId: record.id,
      recordDigest: canonicalDigest(record)
    });
  }
  await assertManifestStillCurrent(locations, manifest);
  return {
    schemaVersion: 1,
    digest: canonicalDigest({ schemaVersion: 1, entries }),
    records,
    observed: {
      directoryEntries: manifest.directoryEntries,
      recordCount: records.length,
      totalBytes: manifest.totalBytes,
      totalNodes: totalNodeBudget.observed
    }
  };
}

async function inspectSnapshotManifest(locations) {
  const { directory } = locations;
  const directoryIdentity = await readDirectoryIdentity(locations);
  if (!directoryIdentity) return null;
  const { names, entryCount: directoryEntries } = await readRecordDirectory(directory);
  assertLimit("records", CHANGE_STORE_LIMITS.records, names.length);
  const sources = [];
  let totalBytes = 0;
  for (const name of names) {
    const filePath = path.join(directory, name);
    let metadata;
    try {
      metadata = await lstat(filePath, { bigint: true });
    } catch (error) {
      throw sourceChangedError(name, error?.code ?? "entry-unavailable");
    }
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      throw entryTypeError(name);
    }
    const size = safeMetadataNumber(metadata.size, name);
    assertLimit(`fileBytes:${name}`, CHANGE_STORE_LIMITS.fileBytes, size);
    totalBytes += size;
    assertLimit("totalBytes", CHANGE_STORE_LIMITS.totalBytes, totalBytes);
    sources.push({ name, filePath, size, identity: sourceIdentity(metadata) });
  }
  return { directoryIdentity, directoryEntries, names, sources, totalBytes };
}

async function assertStoreStillAbsent(locations) {
  const identity = await readDirectoryIdentity(locations);
  if (identity) throw sourceChangedError("changes", "store-created-during-absence-check");
}

async function readManifestSource(source, { totalNodeBudget }) {
  let handle;
  try {
    handle = await open(source.filePath, READ_NOFOLLOW);
  } catch (error) {
    if (["ENOENT", "ELOOP", "EMLINK"].includes(error?.code)) {
      throw sourceChangedError(source.name, error.code);
    }
    throw error;
  }
  try {
    const beforeRead = await handle.stat({ bigint: true });
    if (!beforeRead.isFile()
      || !sameSourceIdentity(source.identity, sourceIdentity(beforeRead))) {
      throw sourceChangedError(source.name, "entry-identity-changed-before-read");
    }
    const bytes = await readDeclaredBytes(handle, source);
    const afterRead = await handle.stat({ bigint: true });
    assertSourceIdentityUnchanged(source, afterRead, bytes.byteLength);
    await assertPathStillNamesSource(source);
    return parseBoundedChangeRecord(bytes, source.name, source.name, { totalNodeBudget });
  } finally {
    await handle.close().catch(() => undefined);
  }
}

async function readDeclaredBytes(handle, source) {
  const buffer = Buffer.allocUnsafe(source.size + 1);
  let offset = 0;
  while (offset < buffer.length) {
    const { bytesRead } = await handle.read(
      buffer,
      offset,
      buffer.length - offset,
      offset
    );
    if (bytesRead === 0) break;
    offset += bytesRead;
  }
  if (offset !== source.size) {
    throw sourceChangedError(source.name, "entry-size-changed-during-read");
  }
  return buffer.subarray(0, source.size);
}

function storeLocations(repoPath) {
  const repo = path.resolve(repoPath);
  const legatura = path.join(repo, ".legatura");
  const runtime = path.join(legatura, "runtime");
  return { repo, legatura, runtime, directory: path.join(runtime, "changes") };
}

async function readDirectoryIdentity(locations) {
  let directoryIdentity = null;
  for (const [label, location] of storeLocationEntries(locations)) {
    let metadata;
    try {
      metadata = await lstat(location, { bigint: true });
    } catch (error) {
      if (error?.code === "ENOENT" && ["runtime", "changes"].includes(label)) return null;
      if (error?.code === "ENOENT" && label === "legatura") return null;
      throw error;
    }
    assertRealStoreDirectory(metadata, label);
    if (label === "changes") directoryIdentity = sourceIdentity(metadata);
  }
  try {
    await assertRealContainment(locations);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw sourceChangedError("changes", "directory-changed-before-containment-check");
    }
    throw error;
  }
  return directoryIdentity;
}

async function ensureStoreDirectory(locations) {
  for (const [label, location] of storeLocationEntries(locations)) {
    let metadata;
    try {
      metadata = await lstat(location, { bigint: true });
    } catch (error) {
      if (error?.code !== "ENOENT" || !["runtime", "changes"].includes(label)) throw error;
      await mkdir(location, { mode: 0o700 }).catch((mkdirError) => {
        if (mkdirError?.code !== "EEXIST") throw mkdirError;
      });
      metadata = await lstat(location, { bigint: true });
    }
    assertRealStoreDirectory(metadata, label);
  }
  await assertRealContainment(locations);
}

function storeLocationEntries(locations) {
  return [
    ["repo", locations.repo],
    ["legatura", locations.legatura],
    ["runtime", locations.runtime],
    ["changes", locations.directory]
  ];
}

function assertRealStoreDirectory(metadata, location) {
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw storeError(
      "CHANGE_STORE_DIRECTORY_INVALID",
      "Every Change Store path component must be a real directory and cannot be a symbolic link.",
      422,
      { location }
    );
  }
}

async function assertRealContainment(locations) {
  const [repoReal, changesReal] = await Promise.all([
    realpath(locations.repo),
    realpath(locations.directory)
  ]);
  const relative = path.relative(repoReal, changesReal);
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    throw storeError(
      "CHANGE_STORE_DIRECTORY_INVALID",
      "Change Store directory must remain contained by the repository root.",
      422,
      { location: "changes" }
    );
  }
}

async function readRecordDirectory(directory) {
  let handle;
  try {
    handle = await opendir(directory);
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw sourceChangedError("changes", "directory-unavailable-during-enumeration");
    }
    throw error;
  }
  const names = [];
  let entryCount = 0;
  for await (const entry of handle) {
    entryCount += 1;
    assertLimit("directoryEntries", CHANGE_STORE_LIMITS.directoryEntries, entryCount);
    if (!entry.name.endsWith(".json")) continue;
    if (!entry.isFile()) throw entryTypeError(entry.name);
    requireSnapshotFileName(entry.name);
    names.push(entry.name);
    assertLimit("records", CHANGE_STORE_LIMITS.records, names.length);
  }
  return { names: names.sort(), entryCount };
}

async function assertManifestStillCurrent(locations, manifest) {
  const directoryIdentity = await readDirectoryIdentity(locations).catch((error) => {
    if (["CHANGE_STORE_DIRECTORY_INVALID", "CHANGE_STORE_LIMIT_EXCEEDED"].includes(error?.code)) {
      throw error;
    }
    throw sourceChangedError("changes", error?.code ?? "directory-unavailable");
  });
  if (!directoryIdentity
    || !sameSourceIdentity(manifest.directoryIdentity, directoryIdentity)) {
    throw sourceChangedError("changes", "directory-identity-changed");
  }
  const { names, entryCount } = await readRecordDirectory(locations.directory);
  if (entryCount !== manifest.directoryEntries
    || canonicalDigest(names) !== canonicalDigest(manifest.names)) {
    throw sourceChangedError("changes", "directory-entry-set-changed");
  }
  for (const source of manifest.sources) await assertPathStillNamesSource(source);
}

async function assertPathStillNamesSource(source) {
  let metadata;
  try {
    metadata = await lstat(source.filePath, { bigint: true });
  } catch (error) {
    throw sourceChangedError(source.name, error?.code ?? "entry-unavailable");
  }
  if (metadata.isSymbolicLink()
    || !metadata.isFile()
    || !sameSourceIdentity(source.identity, sourceIdentity(metadata))) {
    throw sourceChangedError(source.name, "entry-identity-changed");
  }
}

function assertSourceIdentityUnchanged(source, metadata, observedBytes) {
  if (observedBytes !== source.size
    || !sameSourceIdentity(source.identity, sourceIdentity(metadata))) {
    throw sourceChangedError(source.name, "entry-changed-during-read");
  }
}

function sourceIdentity(metadata) {
  return {
    device: metadata.dev,
    inode: metadata.ino,
    size: metadata.size,
    modifiedAt: metadata.mtimeNs,
    changedAt: metadata.ctimeNs
  };
}

function sameSourceIdentity(left, right) {
  return left.device === right.device
    && left.inode === right.inode
    && left.size === right.size
    && left.modifiedAt === right.modifiedAt
    && left.changedAt === right.changedAt;
}

function parseBoundedChangeRecord(
  bytes,
  name,
  filePath,
  { totalNodeBudget, observation } = {}
) {
  let text;
  try {
    text = UTF8_DECODER.decode(bytes);
  } catch {
    throw invalidRecordError(filePath, "record is not canonical UTF-8 text");
  }
  let record;
  try {
    record = JSON.parse(text);
  } catch {
    throw invalidRecordError(filePath, "record is not valid JSON");
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw invalidRecordError(filePath, "record root must be an object");
  }
  const expectedId = name.slice(0, -".json".length);
  const observedId = requireChangeId(record.id, { filePath });
  if (observedId !== expectedId) {
    throw invalidRecordError(filePath, `record id ${observedId} does not match filename ${name}`);
  }
  const recordNodes = assertBoundedJson(record, filePath, totalNodeBudget);
  if (observation) observation.recordNodes = recordNodes;
  return record;
}

function serializeChange(change, name) {
  const input = inspectSerializableJson(change, name);
  let text;
  try {
    text = `${JSON.stringify(change, null, 2)}\n`;
  } catch {
    throw storeError(
      "CHANGE_RECORD_INVALID",
      "Change record cannot be serialized as bounded JSON data.",
      422
    );
  }
  const bytes = Buffer.from(text, "utf8");
  assertLimit(`fileBytes:${name}`, CHANGE_STORE_LIMITS.fileBytes, bytes.byteLength);
  const observation = {};
  const record = parseBoundedChangeRecord(bytes, name, name, {
    totalNodeBudget: { observed: 0 },
    observation
  });
  if (observation.recordNodes !== input.nodeCount) {
    throw invalidSaveInputError("serialized record changed its JSON node identity");
  }
  return { bytes, nodeCount: input.nodeCount, record };
}

function inspectSerializableJson(root, location) {
  const stack = [{ value: root, depth: 0, entered: false }];
  const active = new WeakSet();
  const byteBudget = { observed: 1 };
  let nodeCount = 0;
  while (stack.length > 0) {
    const frame = stack.at(-1);
    const { value, depth } = frame;
    if (!frame.entered) {
      nodeCount += 1;
      assertLimit(
        `nodes:${path.basename(location)}`,
        CHANGE_STORE_LIMITS.nodesPerRecord,
        nodeCount
      );
      assertLimit(`depth:${path.basename(location)}`, CHANGE_STORE_LIMITS.depth, depth);
      if (value === null) {
        addJsonBytes(byteBudget, 4, location);
        stack.pop();
        continue;
      }
      if (typeof value === "string") {
        addJsonStringBytes(byteBudget, value, location);
        stack.pop();
        continue;
      }
      if (typeof value === "boolean") {
        addJsonBytes(byteBudget, value ? 4 : 5, location);
        stack.pop();
        continue;
      }
      if (typeof value === "number") {
        if (!Number.isFinite(value)
          || Object.is(value, -0)
          || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
          throw invalidSaveInputError("numbers must be finite, safe, and must not use negative zero");
        }
        addJsonBytes(byteBudget, String(value).length, location);
        stack.pop();
        continue;
      }
      if (!value || typeof value !== "object") {
        throw invalidSaveInputError("values must use exact JSON data types without omission");
      }
      if (utilTypes.isProxy(value)) {
        throw invalidSaveInputError("proxy containers cannot be persisted as JSON");
      }
      if (active.has(value)) {
        throw invalidSaveInputError("records must be acyclic JSON data");
      }
      const array = Array.isArray(value);
      const prototype = Object.getPrototypeOf(value);
      if (prototype !== (array ? Array.prototype : Object.prototype) && prototype !== null) {
        throw invalidSaveInputError("containers must be plain JSON objects or arrays");
      }
      const toJson = Object.getOwnPropertyDescriptor(value, "toJSON");
      if (toJson && (!Object.hasOwn(toJson, "value") || typeof toJson.value === "function")) {
        throw invalidSaveInputError("containers cannot customize JSON serialization");
      }
      if (array) {
        assertLimit(
          `nodes:${path.basename(location)}`,
          CHANGE_STORE_LIMITS.nodesPerRecord,
          nodeCount + value.length
        );
      }
      active.add(value);
      frame.array = array;
      frame.childCount = 0;
      frame.entered = true;
      frame.iterator = iterateSerializableEntries(value, array);
      addJsonBytes(byteBudget, 2, location);
      continue;
    }

    const next = frame.iterator.next();
    if (next.done) {
      if (frame.childCount > 0) {
        addJsonBytes(byteBudget, 1 + (2 * depth), location);
      }
      active.delete(value);
      stack.pop();
      continue;
    }
    const child = next.value;
    if (frame.childCount > 0) addJsonBytes(byteBudget, 1, location);
    frame.childCount += 1;
    addJsonBytes(byteBudget, 1 + (2 * (depth + 1)), location);
    if (!frame.array) {
      addJsonStringBytes(byteBudget, child.key, location);
      addJsonBytes(byteBudget, 2, location);
    }
    stack.push({ value: child.value, depth: depth + 1, entered: false });
  }
  return { byteCount: byteBudget.observed, nodeCount };
}

function* iterateSerializableEntries(value, array) {
  let childCount = 0;
  for (const key in value) {
    if (!Object.hasOwn(value, key)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, "value") || descriptor.enumerable !== true) {
      throw invalidSaveInputError("records cannot contain enumerable accessors");
    }
    if (array && key !== String(childCount)) {
      throw invalidSaveInputError("arrays must be dense and cannot contain named fields");
    }
    childCount += 1;
    yield { key, value: descriptor.value };
  }
  if (array && childCount !== value.length) {
    throw invalidSaveInputError("arrays must be dense and cannot contain hidden elements");
  }
}

function addJsonBytes(budget, bytes, location) {
  budget.observed += bytes;
  assertLimit(`fileBytes:${path.basename(location)}`, CHANGE_STORE_LIMITS.fileBytes, budget.observed);
}

function addJsonStringBytes(budget, value, location) {
  let observed = budget.observed + 2;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22 || code === 0x5c || [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(code)) {
      observed += 2;
    } else if (code < 0x20) {
      observed += 6;
    } else if (code < 0x80) {
      observed += 1;
    } else if (code < 0x800) {
      observed += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const following = value.charCodeAt(index + 1);
      if (following >= 0xdc00 && following <= 0xdfff) {
        observed += 4;
        index += 1;
      } else {
        observed += 6;
      }
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      observed += 6;
    } else {
      observed += 3;
    }
    if (observed > CHANGE_STORE_LIMITS.fileBytes) {
      assertLimit(
        `fileBytes:${path.basename(location)}`,
        CHANGE_STORE_LIMITS.fileBytes,
        observed
      );
    }
  }
  budget.observed = observed;
}

function assertBoundedJson(root, filePath, totalNodeBudget) {
  const stack = [{ value: root, depth: 0, entered: false }];
  let recordNodes = 0;
  while (stack.length > 0) {
    const frame = stack.at(-1);
    const { value, depth } = frame;
    if (!frame.entered) {
      recordNodes += 1;
      totalNodeBudget.observed += 1;
      assertLimit(`nodes:${path.basename(filePath)}`, CHANGE_STORE_LIMITS.nodesPerRecord, recordNodes);
      assertLimit("totalNodes", CHANGE_STORE_LIMITS.totalNodes, totalNodeBudget.observed);
      assertLimit(`depth:${path.basename(filePath)}`, CHANGE_STORE_LIMITS.depth, depth);
      if (typeof value === "number"
        && (!Number.isFinite(value)
          || Object.is(value, -0)
          || (Number.isInteger(value) && !Number.isSafeInteger(value)))) {
        throw invalidRecordError(
          filePath,
          "record contains a non-finite, negative-zero, or unsafe integer number"
        );
      }
      if (!value || typeof value !== "object") {
        stack.pop();
        continue;
      }
      frame.entered = true;
      frame.iterator = iterateJsonChildren(value);
      continue;
    }
    const next = frame.iterator.next();
    if (next.done) {
      stack.pop();
      continue;
    }
    stack.push({ value: next.value, depth: depth + 1, entered: false });
  }
  return recordNodes;
}

function* iterateJsonChildren(value) {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) yield value[index];
    return;
  }
  for (const key in value) {
    if (Object.hasOwn(value, key)) yield value[key];
  }
}

async function assertSaveFitsStore(directory, targetName, nextBytes) {
  const { names, entryCount } = await readRecordDirectory(directory);
  const replacing = names.includes(targetName);
  const nextRecordCount = replacing ? names.length : names.length + 1;
  assertLimit("records", CHANGE_STORE_LIMITS.records, nextRecordCount);
  assertLimit(
    "directoryEntries",
    CHANGE_STORE_LIMITS.directoryEntries,
    replacing ? entryCount : entryCount + 1
  );
  let totalBytes = nextBytes;
  for (const name of names) {
    if (name === targetName) continue;
    const metadata = await lstat(path.join(directory, name), { bigint: true });
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw entryTypeError(name);
    }
    const size = safeMetadataNumber(metadata.size, name);
    assertLimit(`fileBytes:${name}`, CHANGE_STORE_LIMITS.fileBytes, size);
    totalBytes += size;
    assertLimit("totalBytes", CHANGE_STORE_LIMITS.totalBytes, totalBytes);
  }
}

function requireSnapshotFileName(name) {
  const id = name.endsWith(".json") ? name.slice(0, -".json".length) : "";
  try {
    requireChangeId(id, { statusCode: 500 });
  } catch {
    throw storeError(
      "CHANGE_STORE_ENTRY_INVALID",
      "Change Store JSON filename contains an unsupported Change id.",
      422,
      { name }
    );
  }
  return id;
}

function requireChangeId(value, { statusCode = 500, filePath } = {}) {
  if (typeof value !== "string"
    || Buffer.byteLength(value, "utf8") > CHANGE_STORE_LIMITS.changeIdBytes
    || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)) {
    if (filePath) {
      throw invalidRecordError(
        filePath,
        "record id contains unsupported characters or exceeds its byte bound"
      );
    }
    throw storeError(
      "CHANGE_ID_INVALID",
      "Change id contains unsupported characters or exceeds its byte bound.",
      statusCode,
      { limitBytes: CHANGE_STORE_LIMITS.changeIdBytes }
    );
  }
  return value;
}

function changePath(directory, id) {
  return path.join(directory, `${requireChangeId(id, { statusCode: 400 })}.json`);
}

function safeMetadataNumber(value, filePath) {
  const observed = Number(value);
  if (!Number.isSafeInteger(observed) || observed < 0) {
    throw storeError(
      "CHANGE_STORE_ENTRY_INVALID",
      "Change Store entry has an unsupported file size.",
      422,
      { file: path.basename(filePath) }
    );
  }
  return observed;
}

function assertLimit(location, limit, observed) {
  if (observed <= limit) return;
  throw storeError(
    "CHANGE_STORE_LIMIT_EXCEEDED",
    "Change Store input exceeded a declared hard bound.",
    413,
    { location, limit, observed }
  );
}

function invalidRecordError(filePath, reason) {
  const file = path.basename(filePath);
  return storeError(
    "CHANGE_RECORD_INVALID",
    `Invalid Change record JSON in ${file}: ${reason}`,
    500,
    { file }
  );
}

function invalidSaveInputError(reason) {
  return storeError(
    "CHANGE_RECORD_INVALID",
    `Change record cannot be persisted as exact bounded JSON data: ${reason}.`,
    422
  );
}

function sourceChangedError(source, reason) {
  return storeError(
    "CHANGE_STORE_SOURCE_CHANGED",
    "Change Store source changed while a bounded snapshot was being read.",
    409,
    { source, reason }
  );
}

function entryTypeError(name) {
  return storeError(
    "CHANGE_STORE_ENTRY_INVALID",
    "Change Store JSON entries must be regular files and cannot be symbolic links.",
    422,
    { file: path.basename(name) }
  );
}

function snapshotUnstableError(observationCount) {
  return storeError(
    "CHANGE_STORE_SNAPSHOT_UNSTABLE",
    "Change Store sources did not stabilize within the bounded observation window.",
    409,
    { observationCount }
  );
}

function storeError(code, message, statusCode, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details !== undefined) error.details = details;
  return error;
}
