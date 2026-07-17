import { Buffer } from "node:buffer";
import { types as utilTypes } from "node:util";

import { ARCHITECTURE_PROFILE_LIMITS } from "./core/architecture-profile.mjs";
import { canonicalDigest } from "./core/canonical.mjs";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const EVIDENCE_CURRENCIES = new Set([
  "current",
  "stale",
  "invalid",
  "sealed-historical"
]);

const ENTITY_COLLECTIONS = Object.freeze({
  stages: 256,
  outcomes: 256,
  criteria: 2048,
  modules: 2048,
  areas: 2048,
  contracts: 4096,
  changes: 2048,
  claims: 4096,
  gates: 2048,
  routes: 8192,
  evidence: 32768,
  residuals: 32768,
  gaps: 2048
});

const RELATION_COLLECTIONS = Object.freeze([
  "outcomeCriteria",
  "outcomeClaims",
  "outcomeGaps",
  "criterionClaims",
  "criterionGaps",
  "gapProofClaims",
  "gapAffects",
  "contributions",
  "contributionClaims",
  "claimGateRoutes",
  "routeModules",
  "routeResiduals",
  "currentEvidenceClaimAssociations",
  "historicalEvidenceClaimAssociations",
  "evidenceResiduals"
]);

const SOURCE_REF_FIELDS = Object.freeze([
  "snapshotDigest",
  "projectModelDigest",
  "gitContentDigest",
  "changeStoreDigest"
]);

const FORBIDDEN_KEYS = new Set([
  "acceptedpackage",
  "body",
  "commandoutput",
  "confidence",
  "coverage",
  "evidencebody",
  "greenlight",
  "health",
  "observationbody",
  "overall",
  "output",
  "package",
  "percentage",
  "progress",
  "ready",
  "satisfied",
  "score",
  "sourcebody",
  "stderr",
  "stdout"
]);

const VIEW_MODEL_ENVELOPE_BYTES = ARCHITECTURE_PROFILE_LIMITS.profileBytes + (4 * 1024);

export const ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS = Object.freeze({
  inputBytes: VIEW_MODEL_ENVELOPE_BYTES,
  outputBytes: VIEW_MODEL_ENVELOPE_BYTES,
  nodes: VIEW_MODEL_ENVELOPE_BYTES,
  relations: 65536,
  depth: 64,
  textBytes: 16 * 1024
});

/**
 * Compile the Kernel's exact Architecture Acceptance Profile into the one
 * browser/CLI shape owned by Local Workbench. This is a projection only: it
 * preserves orthogonal facts and relations and never derives assurance.
 */
export function compileArchitectureProfileViewModel(profile) {
  preflightPlainJson(profile, {
    byteLimit: ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.inputBytes,
    root: "profile"
  });
  assertProfileShape(profile);

  const safeProfile = JSON.parse(JSON.stringify(profile));
  const { profileDigest, ...profileContent } = safeProfile;
  const expectedProfileDigest = canonicalDigest(profileContent);
  if (profileDigest !== expectedProfileDigest) {
    throw viewModelError(
      "ARCHITECTURE_PROFILE_VIEW_DIGEST_INVALID",
      "Architecture Profile content does not match profileDigest.",
      { expectedProfileDigest, observedProfileDigest: profileDigest }
    );
  }

  const content = {
    schemaVersion: 1,
    profileRef: profileDigest,
    sourceRefs: safeProfile.source,
    dimensions: {
      outcomes: safeProfile.entities.outcomes,
      criteria: safeProfile.entities.criteria,
      claims: safeProfile.entities.claims,
      gates: safeProfile.entities.gates,
      evidence: safeProfile.entities.evidence,
      residualUncertainty: safeProfile.entities.residuals,
      knowledgeGaps: safeProfile.entities.gaps
    },
    context: {
      stages: safeProfile.entities.stages,
      modules: safeProfile.entities.modules,
      areas: safeProfile.entities.areas,
      contracts: safeProfile.entities.contracts,
      changes: safeProfile.entities.changes,
      routes: safeProfile.entities.routes
    },
    relations: safeProfile.relations
  };
  const result = { ...content, viewModelDigest: canonicalDigest(content) };
  const observedBytes = Buffer.byteLength(JSON.stringify(result), "utf8");
  if (observedBytes > ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.outputBytes) {
    throw limitError("outputBytes", observedBytes, "viewModel");
  }
  return result;
}

function assertProfileShape(profile) {
  assertRecord(profile, "profile");
  assertExactKeys(
    profile,
    ["schemaVersion", "source", "entities", "relations", "profileDigest"],
    "profile"
  );
  if (profile.schemaVersion !== 1) {
    throw invalidInput("Architecture Profile schemaVersion must be 1.", {
      location: "profile.schemaVersion",
      observed: profile.schemaVersion
    });
  }
  requireDigest(profile.profileDigest, "profile.profileDigest");

  assertRecord(profile.source, "profile.source");
  assertExactKeys(profile.source, SOURCE_REF_FIELDS, "profile.source");
  for (const field of SOURCE_REF_FIELDS) {
    requireDigest(profile.source[field], `profile.source.${field}`);
  }

  assertRecord(profile.entities, "profile.entities");
  assertExactKeys(profile.entities, Object.keys(ENTITY_COLLECTIONS), "profile.entities");
  for (const [collection, limit] of Object.entries(ENTITY_COLLECTIONS)) {
    const entities = profile.entities[collection];
    assertArray(entities, `profile.entities.${collection}`);
    if (entities.length > limit) {
      throw limitError(collection, entities.length, `profile.entities.${collection}`, limit);
    }
    assertUniqueEntityIds(entities, collection);
  }

  for (const [index, evidence] of profile.entities.evidence.entries()) {
    if (!EVIDENCE_CURRENCIES.has(evidence.currency)) {
      throw invalidInput("Architecture Profile Evidence has an unsupported currency.", {
        location: `profile.entities.evidence.${index}.currency`,
        observed: evidence.currency,
        allowed: [...EVIDENCE_CURRENCIES]
      });
    }
  }

  assertRecord(profile.relations, "profile.relations");
  assertExactKeys(profile.relations, RELATION_COLLECTIONS, "profile.relations");
  let relationCount = 0;
  for (const collection of RELATION_COLLECTIONS) {
    const relations = profile.relations[collection];
    assertArray(relations, `profile.relations.${collection}`);
    relationCount += relations.length;
    if (relationCount > ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.relations) {
      throw limitError("relations", relationCount, `profile.relations.${collection}`);
    }
    for (const [index, relation] of relations.entries()) {
      assertRecord(relation, `profile.relations.${collection}.${index}`);
    }
  }
}

function assertUniqueEntityIds(entities, collection) {
  const seen = new Set();
  for (const [index, entity] of entities.entries()) {
    const location = `profile.entities.${collection}.${index}`;
    assertRecord(entity, location);
    if (typeof entity.id !== "string" || entity.id.length === 0) {
      throw invalidInput("Architecture Profile entities require non-empty string ids.", {
        location: `${location}.id`
      });
    }
    if (seen.has(entity.id)) {
      throw invalidInput("Architecture Profile entity ids must be unique within a dimension.", {
        location: `${location}.id`,
        collection,
        id: entity.id
      });
    }
    seen.add(entity.id);
  }
}

function preflightPlainJson(value, { byteLimit, root }) {
  const budget = { bytes: 0, nodes: 0 };
  const ancestors = new WeakSet();
  visit(value, root, 0);

  function visit(item, location, depth) {
    if (depth > ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.depth) {
      throw limitError("depth", depth, location);
    }
    budget.nodes += 1;
    if (budget.nodes > ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.nodes) {
      throw limitError("nodes", budget.nodes, location);
    }

    if (item === null || typeof item === "boolean") {
      consumeBytes(Buffer.byteLength(JSON.stringify(item), "utf8"), location);
      return;
    }
    if (typeof item === "number") {
      if (!Number.isFinite(item)) {
        throw invalidInput("Architecture Profile view input must contain finite JSON numbers.", {
          location
        });
      }
      consumeBytes(Buffer.byteLength(JSON.stringify(item), "utf8"), location);
      return;
    }
    if (typeof item === "string") {
      const textBytes = Buffer.byteLength(item, "utf8");
      if (textBytes > ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.textBytes) {
        throw limitError("textBytes", textBytes, location);
      }
      consumeBytes(Buffer.byteLength(JSON.stringify(item), "utf8"), location);
      return;
    }
    if (!item || typeof item !== "object") {
      throw invalidInput("Architecture Profile view input must be strict plain JSON.", { location });
    }
    if (utilTypes.isProxy(item)) {
      throw invalidInput("Architecture Profile view input cannot contain Proxy values.", { location });
    }
    if (ancestors.has(item)) {
      throw invalidInput("Architecture Profile view input cannot contain cycles.", { location });
    }

    const prototype = Object.getPrototypeOf(item);
    if (Array.isArray(item)) {
      if (prototype !== Array.prototype) {
        throw invalidInput("Architecture Profile arrays must use the plain Array prototype.", {
          location
        });
      }
      assertDensePlainArray(item, location);
      consumeBytes(2 + Math.max(0, item.length - 1), location);
      ancestors.add(item);
      for (let index = 0; index < item.length; index += 1) {
        visit(Object.getOwnPropertyDescriptor(item, String(index)).value, `${location}.${index}`, depth + 1);
      }
      ancestors.delete(item);
      return;
    }

    if (prototype !== Object.prototype && prototype !== null) {
      throw invalidInput("Architecture Profile objects must use a plain JSON prototype.", { location });
    }
    const keys = assertPlainObjectProperties(item, location);
    consumeBytes(2 + Math.max(0, keys.length - 1), location);
    ancestors.add(item);
    for (const key of keys) {
      assertAllowedKey(key, location);
      consumeBytes(Buffer.byteLength(JSON.stringify(key), "utf8") + 1, `${location}.${key}`);
      visit(Object.getOwnPropertyDescriptor(item, key).value, `${location}.${key}`, depth + 1);
    }
    ancestors.delete(item);
  }

  function consumeBytes(bytes, location) {
    budget.bytes += bytes;
    if (budget.bytes > byteLimit) {
      throw limitError("inputBytes", budget.bytes, location, byteLimit);
    }
  }
}

function assertDensePlainArray(value, location) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key === "symbol")) {
    throw invalidInput("Architecture Profile arrays cannot contain symbol keys.", { location });
  }
  const dataKeys = keys.filter((key) => key !== "length");
  if (dataKeys.length !== value.length) {
    throw invalidInput("Architecture Profile arrays must be dense and contain no extra fields.", {
      location
    });
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw invalidInput("Architecture Profile arrays require enumerable data elements.", {
        location: `${location}.${index}`
      });
    }
  }
  if (dataKeys.some((key) => !/^(0|[1-9]\d*)$/u.test(key) || Number(key) >= value.length)) {
    throw invalidInput("Architecture Profile arrays cannot contain extra fields.", { location });
  }
}

function assertPlainObjectProperties(value, location) {
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key === "symbol")) {
    throw invalidInput("Architecture Profile objects cannot contain symbol keys.", { location });
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || descriptor.enumerable !== true) {
      throw invalidInput("Architecture Profile objects require enumerable data properties.", {
        location: `${location}.${key}`
      });
    }
  }
  return keys;
}

function assertAllowedKey(key, location) {
  const normalized = key.toLowerCase().replace(/[^a-z]/gu, "");
  if (FORBIDDEN_KEYS.has(normalized)) {
    throw viewModelError(
      "ARCHITECTURE_PROFILE_VIEW_AGGREGATE_FORBIDDEN",
      "Local Workbench cannot project aggregate assurance conclusions or output bodies.",
      { location, key }
    );
  }
}

function assertExactKeys(value, expected, location) {
  const observed = Object.keys(value).sort();
  const exact = [...expected].sort();
  if (observed.length !== exact.length || observed.some((key, index) => key !== exact[index])) {
    throw invalidInput("Architecture Profile view input has an unsupported shape.", {
      location,
      expected: exact,
      observed
    });
  }
}

function assertRecord(value, location) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalidInput("Architecture Profile view input requires an object.", { location });
  }
}

function assertArray(value, location) {
  if (!Array.isArray(value)) {
    throw invalidInput("Architecture Profile view input requires an array.", { location });
  }
}

function requireDigest(value, location) {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) {
    throw invalidInput("Architecture Profile view input requires a canonical digest.", {
      location,
      observed: value ?? null
    });
  }
}

function invalidInput(message, details) {
  return viewModelError("ARCHITECTURE_PROFILE_VIEW_INPUT_INVALID", message, details);
}

function limitError(dimension, observed, location, suppliedLimit) {
  const limit = suppliedLimit
    ?? ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS[dimension]
    ?? ENTITY_COLLECTIONS[dimension];
  return viewModelError(
    "ARCHITECTURE_PROFILE_VIEW_LIMIT_EXCEEDED",
    "Architecture Profile view input exceeded a hard resource limit.",
    { dimension, limit, observed, location },
    413
  );
}

function viewModelError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  error.details = details;
  return error;
}
