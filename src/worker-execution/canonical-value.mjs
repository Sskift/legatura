import { createHash } from "node:crypto";

export const WORKER_EXECUTION_SCHEMA_VERSION = 1;
export const WORKER_EXECUTION_INTERFACE_PROOF_VERSION = 1;

export const WORKER_EXECUTION_LIMITS = Object.freeze({
  workSpecificationBytes: 128 * 1024,
  contextExpansionRequestBytes: 128 * 1024,
  workerReportBytes: 256 * 1024,
  workerObservationBytes: 128 * 1024,
  executionRecordBytes: 1024 * 1024,
  textBytes: 8 * 1024,
  pathBytes: 1024,
  identifierBytes: 128,
  planRefs: 64,
  claimRefs: 256,
  paths: 512,
  expansionRequests: 64,
  artifactRefs: 256,
  reportItems: 256,
  relatedRefs: 64,
  events: 256
});

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const IDENTIFIER_PATTERN = /^[a-zA-Z0-9](?:[a-zA-Z0-9._:-]*[a-zA-Z0-9])?$/u;
function assertSchemaAndKind(value, kind, location) {
  if (value.schemaVersion !== WORKER_EXECUTION_SCHEMA_VERSION || value.kind !== kind) {
    throw protocolError(
      "WORKER_EXECUTION_SCHEMA_INVALID",
      `${location} must use schemaVersion 1 and kind ${kind}.`
    );
  }
}

function normalizeIdentifier(value, location) {
  const text = normalizeText(value, location, {
    minimumBytes: 1,
    maximumBytes: WORKER_EXECUTION_LIMITS.identifierBytes
  });
  if (!IDENTIFIER_PATTERN.test(text)) {
    throw protocolError("WORKER_EXECUTION_IDENTIFIER_INVALID", `${location} is not canonical.`);
  }
  return text;
}

function normalizeDigest(value, location) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw protocolError("WORKER_EXECUTION_DIGEST_INVALID", `${location} must be a sha256 digest.`);
  }
  return value;
}

function normalizePath(value, location) {
  const path = normalizeText(value, location, {
    minimumBytes: 1,
    maximumBytes: WORKER_EXECUTION_LIMITS.pathBytes
  });
  if (path.startsWith("/")
    || path.includes("\\")
    || path.includes("\0")
    || path.split("/").some((segment) => !segment || segment === "." || segment === "..")) {
    throw protocolError("WORKER_EXECUTION_PATH_INVALID", `${location} is not repository-relative.`);
  }
  return path;
}

function normalizeText(value, location, {
  minimumBytes = 0,
  maximumBytes = WORKER_EXECUTION_LIMITS.textBytes
} = {}) {
  if (typeof value !== "string" || value !== value.trim() || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)) {
    throw protocolError("WORKER_EXECUTION_TEXT_INVALID", `${location} must be canonical text.`);
  }
  const bytes = Buffer.byteLength(value, "utf8");
  if (bytes < minimumBytes || bytes > maximumBytes) {
    throw protocolError(
      "WORKER_EXECUTION_LIMIT_EXCEEDED",
      `${location} must contain between ${minimumBytes} and ${maximumBytes} UTF-8 bytes.`
    );
  }
  return value;
}

function normalizeInteger(value, location, { minimum, maximum }) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw protocolError(
      "WORKER_EXECUTION_NUMBER_INVALID",
      `${location} must be an integer between ${minimum} and ${maximum}.`
    );
  }
  return value;
}

function normalizeStringSet(value, location, {
  minimum = 0,
  maximum,
  item
}) {
  const entries = normalizeDenseArray(value, location, { minimum, maximum })
    .map((entry, index) => item(entry, `${location}[${index}]`))
    .sort(compareUtf8);
  assertUnique(entries, location);
  return entries;
}

function normalizeDenseArray(value, location, { minimum = 0, maximum }) {
  if (!Array.isArray(value)) {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} must be an array.`);
  }
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key === "symbol")
    || ownKeys.some((key) => key !== "length" && !/^\d+$/u.test(key))
    || value.length < minimum
    || value.length > maximum
    || !Array.from({ length: value.length }, (_, index) => Object.hasOwn(value, index)).every(Boolean)) {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} must be dense and bounded.`);
  }
  return value;
}

function assertPlainObject(value, location) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} must be an object.`);
  }
  let prototype;
  let descriptors;
  try {
    prototype = Object.getPrototypeOf(value);
    descriptors = Object.getOwnPropertyDescriptors(value);
  } catch {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} cannot be inspected safely.`);
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} must be a plain object.`);
  }
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (!("value" in descriptor) || descriptor.enumerable !== true) {
      throw protocolError(
        "WORKER_EXECUTION_INPUT_INVALID",
        `${location}.${key} must be an enumerable data property.`
      );
    }
  }
  if (Reflect.ownKeys(value).some((key) => typeof key === "symbol")) {
    throw protocolError("WORKER_EXECUTION_INPUT_INVALID", `${location} cannot contain symbol keys.`);
  }
}

function assertExactKeys(value, expected, location) {
  const actual = Object.keys(value).sort(compareUtf8);
  const canonicalExpected = [...expected].sort(compareUtf8);
  if (canonicalStringify(actual) !== canonicalStringify(canonicalExpected)) {
    const expectedSet = new Set(canonicalExpected);
    const actualSet = new Set(actual);
    throw protocolError(
      "WORKER_EXECUTION_FIELDS_INVALID",
      `${location} has missing or unknown fields.`,
      {
        missing: canonicalExpected.filter((key) => !actualSet.has(key)),
        unknown: actual.filter((key) => !expectedSet.has(key))
      }
    );
  }
}

function assertUnique(values, location) {
  const seen = new Set();
  for (const value of values) {
    if (seen.has(value)) {
      throw protocolError("WORKER_EXECUTION_DUPLICATE", `${location} contains duplicate values.`);
    }
    seen.add(value);
  }
}

function withoutKeys(value, keys) {
  assertPlainObject(value, "object");
  const omitted = new Set(keys);
  return Object.fromEntries(Object.entries(value).filter(([candidate]) => !omitted.has(candidate)));
}

function sealDocument(content, digestField) {
  return { ...content, [digestField]: canonicalDigest(content) };
}

function assertDocumentSeal(value, content, digestField) {
  const expected = sealDocument(content, digestField);
  if (value[digestField] !== expected[digestField]
    || canonicalStringify(value) !== canonicalStringify(expected)) {
    throw protocolError(
      "WORKER_EXECUTION_DIGEST_INVALID",
      `${digestField} does not bind the canonical document content.`
    );
  }
  return expected;
}

function canonicalDigest(value) {
  return `sha256:${createHash("sha256").update(canonicalStringify(value), "utf8").digest("hex")}`;
}

function canonicalStringify(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw protocolError("WORKER_EXECUTION_NUMBER_INVALID", "Canonical values require safe integers.");
    }
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(",")}]`;
  assertPlainObject(value, "canonicalValue");
  return `{${Object.keys(value).sort(compareUtf8).map((key) => (
    `${JSON.stringify(key)}:${canonicalStringify(value[key])}`
  )).join(",")}}`;
}

function assertDocumentBytes(value, maximum, label) {
  const observed = Buffer.byteLength(canonicalStringify(value), "utf8");
  if (observed > maximum) {
    throw protocolError(
      "WORKER_EXECUTION_LIMIT_EXCEEDED",
      `${label} exceeds its ${maximum}-byte canonical limit.`,
      { maximum, observed }
    );
  }
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(String(left), "utf8"), Buffer.from(String(right), "utf8"));
}

function deepFreeze(value) {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) return value;
  for (const item of Object.values(value)) deepFreeze(item);
  return Object.freeze(value);
}

function protocolError(code, message, details = undefined) {
  const error = new Error(message);
  error.code = code;
  if (details !== undefined) error.details = details;
  return error;
}

export {
  assertDocumentBytes,
  assertDocumentSeal,
  assertExactKeys,
  assertPlainObject,
  assertSchemaAndKind,
  assertUnique,
  canonicalDigest,
  canonicalStringify,
  compareUtf8,
  deepFreeze,
  normalizeDenseArray,
  normalizeDigest,
  normalizeIdentifier,
  normalizeInteger,
  normalizePath,
  normalizeStringSet,
  normalizeText,
  protocolError,
  sealDocument,
  withoutKeys
};
