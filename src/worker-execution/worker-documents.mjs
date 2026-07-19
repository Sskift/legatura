import {
  WORKER_EXECUTION_LIMITS,
  WORKER_EXECUTION_SCHEMA_VERSION,
  assertDocumentBytes,
  assertDocumentSeal,
  assertExactKeys,
  assertPlainObject,
  assertSchemaAndKind,
  assertUnique,
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
} from "./canonical-value.mjs";

const MEDIA_TYPE_PATTERN = /^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u;
const CAPABILITY_REFS = Object.freeze([
  "filesystem-read",
  "filesystem-write",
  "network",
  "process",
  "secrets"
]);
const CONTROL_KEYS = Object.freeze([
  "filesystemRead",
  "filesystemWrite",
  "network",
  "process",
  "secrets"
]);
const CONTROL_MODES = new Set(["observed-only", "unsupported"]);
const CAPABILITY_OUTCOMES = new Set(["allowed", "denied", "not-observed"]);
const REPORT_DISPOSITIONS = Object.freeze(["blocked", "completed", "failed", "partial"]);
const PROCESS_TERMINATION_KINDS = new Set([
  "exited",
  "not-started",
  "signaled",
  "start-failed",
  "unconfirmed"
]);
export const EVENT_KINDS = new Set([
  "context-expansion-requested",
  "execution-started",
  "worker-observation-recorded",
  "worker-report-submitted"
]);
const FORBIDDEN_REPORT_SEMANTICS = Object.freeze([
  "acceptance",
  "authority-decision",
  "claim-satisfaction",
  "evidence-sufficiency",
  "knowledge-closure",
  "verification-waiver"
]);

export function compileWorkSpecification(input) {
  assertPlainObject(input, "workSpecificationInput");
  assertExactKeys(input, [
    "attempt",
    "capabilityProfile",
    "change",
    "context",
    "executionId",
    "intent"
  ], "workSpecificationInput");

  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-work-specification",
    executionId: normalizeIdentifier(input.executionId, "executionId"),
    attempt: normalizeInteger(input.attempt, "attempt", { minimum: 1, maximum: 1_000_000 }),
    change: normalizeChangeBinding(input.change),
    intent: normalizeIntent(input.intent),
    context: normalizeContextBinding(input.context),
    capabilityProfile: normalizeCapabilityProfile(input.capabilityProfile),
    reportContract: {
      dispositions: [...REPORT_DISPOSITIONS],
      forbiddenSemantics: [...FORBIDDEN_REPORT_SEMANTICS]
    }
  };
  const result = sealDocument(content, "workSpecificationDigest");
  assertDocumentBytes(result, WORKER_EXECUTION_LIMITS.workSpecificationBytes, "Work Specification");
  return deepFreeze(result);
}

function normalizeChangeBinding(value) {
  assertPlainObject(value, "change");
  assertExactKeys(value, [
    "baselineGitContentDigest",
    "changeKind",
    "claimRefs",
    "compilationDigest",
    "governanceBaselineDigest",
    "id",
    "planRefs",
    "primaryModuleRef"
  ], "change");
  return {
    id: normalizeIdentifier(value.id, "change.id"),
    primaryModuleRef: normalizeIdentifier(value.primaryModuleRef, "change.primaryModuleRef"),
    changeKind: normalizeIdentifier(value.changeKind, "change.changeKind"),
    planRefs: normalizeStringSet(value.planRefs, "change.planRefs", {
      maximum: WORKER_EXECUTION_LIMITS.planRefs,
      item: normalizeIdentifier
    }),
    claimRefs: normalizeStringSet(value.claimRefs, "change.claimRefs", {
      maximum: WORKER_EXECUTION_LIMITS.claimRefs,
      item: normalizeIdentifier
    }),
    governanceBaselineDigest: normalizeDigest(
      value.governanceBaselineDigest,
      "change.governanceBaselineDigest"
    ),
    baselineGitContentDigest: normalizeDigest(
      value.baselineGitContentDigest,
      "change.baselineGitContentDigest"
    ),
    compilationDigest: normalizeDigest(value.compilationDigest, "change.compilationDigest")
  };
}

function normalizeIntent(value) {
  assertPlainObject(value, "intent");
  assertExactKeys(value, ["nonGoals", "request", "title"], "intent");
  return {
    title: normalizeText(value.title, "intent.title", { minimumBytes: 1 }),
    request: normalizeText(value.request, "intent.request", { minimumBytes: 1 }),
    nonGoals: normalizeStringSet(value.nonGoals, "intent.nonGoals", {
      maximum: 64,
      item: (item, location) => normalizeText(item, location, { minimumBytes: 1 })
    })
  };
}

function normalizeContextBinding(value) {
  assertPlainObject(value, "context");
  assertExactKeys(value, ["capsuleDigest", "readScopeDigest", "writeScopeDigest"], "context");
  return {
    capsuleDigest: normalizeDigest(value.capsuleDigest, "context.capsuleDigest"),
    readScopeDigest: normalizeDigest(value.readScopeDigest, "context.readScopeDigest"),
    writeScopeDigest: normalizeDigest(value.writeScopeDigest, "context.writeScopeDigest")
  };
}

function normalizeCapabilityProfile(value) {
  assertPlainObject(value, "capabilityProfile");
  assertExactKeys(
    value,
    ["controls", "limits", "ref", "requested", "sourceDigest"],
    "capabilityProfile"
  );
  const requested = normalizeStringSet(value.requested, "capabilityProfile.requested", {
    maximum: CAPABILITY_REFS.length,
    item: (item, location) => {
      const ref = normalizeIdentifier(item, location);
      if (!CAPABILITY_REFS.includes(ref)) {
        throw protocolError("WORKER_EXECUTION_CAPABILITY_INVALID", `Unknown capability: ${ref}.`);
      }
      return ref;
    }
  });
  assertPlainObject(value.controls, "capabilityProfile.controls");
  assertExactKeys(value.controls, CONTROL_KEYS, "capabilityProfile.controls");
  const controls = Object.fromEntries(CONTROL_KEYS.map((key) => {
    const mode = normalizeIdentifier(value.controls[key], `capabilityProfile.controls.${key}`);
    if (mode === "enforced") {
      throw protocolError(
        "CAPABILITY_ENFORCEMENT_PROOF_REQUIRED",
        "LGT-020 cannot construct an enforced capability fact without an independent controller proof."
      );
    }
    if (!CONTROL_MODES.has(mode)) {
      throw protocolError(
        "WORKER_EXECUTION_CONTROL_MODE_INVALID",
        `Unsupported capability control mode: ${mode}.`
      );
    }
    return [key, mode];
  }));
  assertPlainObject(value.limits, "capabilityProfile.limits");
  assertExactKeys(value.limits, [
    "artifactRefs",
    "expansionRequests",
    "reportBytes",
    "wallTimeMs"
  ], "capabilityProfile.limits");
  const content = {
    ref: normalizeIdentifier(value.ref, "capabilityProfile.ref"),
    sourceDigest: normalizeDigest(value.sourceDigest, "capabilityProfile.sourceDigest"),
    requested,
    controls,
    limits: {
      wallTimeMs: normalizeInteger(value.limits.wallTimeMs, "capabilityProfile.limits.wallTimeMs", {
        minimum: 1,
        maximum: 3_600_000
      }),
      expansionRequests: normalizeInteger(
        value.limits.expansionRequests,
        "capabilityProfile.limits.expansionRequests",
        { minimum: 0, maximum: WORKER_EXECUTION_LIMITS.expansionRequests }
      ),
      artifactRefs: normalizeInteger(
        value.limits.artifactRefs,
        "capabilityProfile.limits.artifactRefs",
        { minimum: 0, maximum: WORKER_EXECUTION_LIMITS.artifactRefs }
      ),
      reportBytes: normalizeInteger(value.limits.reportBytes, "capabilityProfile.limits.reportBytes", {
        minimum: 1,
        maximum: WORKER_EXECUTION_LIMITS.workerReportBytes
      })
    },
    acceptanceAuthority: false
  };
  return sealDocument(content, "digest");
}

export function normalizeWorkSpecificationDocument(value) {
  assertPlainObject(value, "workSpecification");
  assertExactKeys(value, [
    "attempt",
    "capabilityProfile",
    "change",
    "context",
    "executionId",
    "intent",
    "kind",
    "reportContract",
    "schemaVersion",
    "workSpecificationDigest"
  ], "workSpecification");
  assertSchemaAndKind(value, "worker-work-specification", "workSpecification");
  assertPlainObject(value.reportContract, "workSpecification.reportContract");
  assertExactKeys(
    value.reportContract,
    ["dispositions", "forbiddenSemantics"],
    "workSpecification.reportContract"
  );
  const normalized = compileWorkSpecification({
    executionId: value.executionId,
    attempt: value.attempt,
    change: value.change,
    intent: value.intent,
    context: value.context,
    capabilityProfile: withoutKeys(value.capabilityProfile, ["acceptanceAuthority", "digest"])
  });
  if (canonicalStringify(value) !== canonicalStringify(normalized)) {
    throw protocolError(
      "WORKER_EXECUTION_DIGEST_INVALID",
      "Work Specification content or digest is not canonical."
    );
  }
  return normalized;
}
export function compileEvent(workSpecification, input) {
  assertPlainObject(input, "event");
  const kind = normalizeIdentifier(input.kind, "event.kind");
  if (!EVENT_KINDS.has(kind)) {
    throw protocolError("WORKER_EXECUTION_EVENT_KIND_INVALID", `Unsupported event kind: ${kind}.`);
  }
  const payloadKey = {
    "context-expansion-requested": "request",
    "execution-started": null,
    "worker-observation-recorded": "observation",
    "worker-report-submitted": "report"
  }[kind];
  assertExactKeys(input, [
    "eventId",
    "executionRef",
    "kind",
    "priorRecordDigest",
    "schemaVersion",
    "sequence",
    ...(payloadKey ? [payloadKey] : [])
  ], "event");
  if (input.schemaVersion !== WORKER_EXECUTION_SCHEMA_VERSION) {
    throw protocolError("WORKER_EXECUTION_SCHEMA_INVALID", "Event schemaVersion must be 1.");
  }
  const common = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind,
    eventId: normalizeIdentifier(input.eventId, "event.eventId"),
    executionRef: normalizeIdentifier(input.executionRef, "event.executionRef"),
    sequence: normalizeInteger(input.sequence, "event.sequence", {
      minimum: 1,
      maximum: WORKER_EXECUTION_LIMITS.events
    }),
    priorRecordDigest: normalizeDigest(input.priorRecordDigest, "event.priorRecordDigest")
  };
  let content = common;
  if (kind === "context-expansion-requested") {
    content = { ...common, request: compileExpansionRequest(workSpecification, common, input.request) };
  } else if (kind === "worker-report-submitted") {
    content = { ...common, report: compileWorkerReport(workSpecification, input.report) };
  } else if (kind === "worker-observation-recorded") {
    content = { ...common, observation: compileWorkerObservation(workSpecification, input.observation) };
  }
  return sealDocument(content, "eventDigest");
}

function compileExpansionRequest(workSpecification, event, value) {
  assertPlainObject(value, "event.request");
  assertExactKeys(value, ["expectedKnowledge", "id", "reason", "requestedPaths"], "event.request");
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "context-expansion-request",
    id: normalizeIdentifier(value.id, "event.request.id"),
    executionRef: workSpecification.executionId,
    sequence: event.sequence,
    priorRecordDigest: event.priorRecordDigest,
    workSpecificationDigest: workSpecification.workSpecificationDigest,
    currentContextCapsuleDigest: workSpecification.context.capsuleDigest,
    currentCapabilityProfileDigest: workSpecification.capabilityProfile.digest,
    requestedPaths: normalizeStringSet(value.requestedPaths, "event.request.requestedPaths", {
      minimum: 1,
      maximum: WORKER_EXECUTION_LIMITS.paths,
      item: normalizePath
    }),
    reason: normalizeText(value.reason, "event.request.reason", { minimumBytes: 1 }),
    expectedKnowledge: normalizeText(value.expectedKnowledge, "event.request.expectedKnowledge", {
      minimumBytes: 1
    })
  };
  const result = sealDocument(content, "contextExpansionRequestDigest");
  assertDocumentBytes(
    result,
    WORKER_EXECUTION_LIMITS.contextExpansionRequestBytes,
    "Context Expansion Request"
  );
  return result;
}

function compileWorkerReport(workSpecification, value) {
  assertPlainObject(value, "event.report");
  assertExactKeys(value, [
    "artifactRefs",
    "blockers",
    "contextExpansionRequestDigests",
    "decisions",
    "deltas",
    "disposition",
    "finalCapabilityProfileDigest",
    "finalContextCapsuleDigest",
    "risks",
    "summary"
  ], "event.report");
  const disposition = normalizeIdentifier(value.disposition, "event.report.disposition");
  if (!REPORT_DISPOSITIONS.includes(disposition)) {
    throw protocolError("WORKER_EXECUTION_REPORT_INVALID", `Unsupported report disposition: ${disposition}.`);
  }
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-report",
    executionRef: workSpecification.executionId,
    workSpecificationDigest: workSpecification.workSpecificationDigest,
    finalContextCapsuleDigest: normalizeDigest(
      value.finalContextCapsuleDigest,
      "event.report.finalContextCapsuleDigest"
    ),
    finalCapabilityProfileDigest: normalizeDigest(
      value.finalCapabilityProfileDigest,
      "event.report.finalCapabilityProfileDigest"
    ),
    disposition,
    summary: normalizeText(value.summary, "event.report.summary", { minimumBytes: 1 }),
    deltas: normalizeDeltas(value.deltas),
    decisions: normalizeReportStatements(value.decisions, "event.report.decisions"),
    blockers: normalizeReportStatements(value.blockers, "event.report.blockers"),
    risks: normalizeReportStatements(value.risks, "event.report.risks"),
    artifactRefs: normalizeArtifactRefs(value.artifactRefs),
    contextExpansionRequestDigests: normalizeStringSet(
      value.contextExpansionRequestDigests,
      "event.report.contextExpansionRequestDigests",
      {
        maximum: WORKER_EXECUTION_LIMITS.expansionRequests,
        item: normalizeDigest
      }
    ),
    acceptanceAuthority: false
  };
  assertReportDispositionConsistency(content);
  const result = sealDocument(content, "workerReportDigest");
  const maximum = Math.min(
    WORKER_EXECUTION_LIMITS.workerReportBytes,
    workSpecification.capabilityProfile.limits.reportBytes
  );
  assertDocumentBytes(result, maximum, "Worker Report");
  return result;
}

function compileWorkerObservation(workSpecification, value) {
  assertPlainObject(value, "event.observation");
  assertExactKeys(value, [
    "capabilityObservations",
    "reportDigest",
    "runtime",
    "workspace"
  ], "event.observation");
  const runtime = normalizeRuntimeObservation(value.runtime);
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-observation",
    executionRef: workSpecification.executionId,
    workSpecificationDigest: workSpecification.workSpecificationDigest,
    capabilityProfileRef: workSpecification.capabilityProfile.ref,
    capabilityProfileDigest: workSpecification.capabilityProfile.digest,
    runtime,
    capabilityObservations: normalizeCapabilityObservations(value.capabilityObservations),
    workspace: normalizeWorkspaceObservation(value.workspace),
    reportDigest: value.reportDigest === null
      ? null
      : normalizeDigest(value.reportDigest, "event.observation.reportDigest"),
    factAuthority: false,
    acceptanceAuthority: false
  };
  const result = sealDocument(content, "workerObservationDigest");
  assertDocumentBytes(result, WORKER_EXECUTION_LIMITS.workerObservationBytes, "Worker Observation");
  return result;
}
export function normalizeCompiledEvent(value) {
  assertPlainObject(value, "compiledEvent");
  const kind = normalizeIdentifier(value.kind, "compiledEvent.kind");
  if (!EVENT_KINDS.has(kind)) {
    throw protocolError("WORKER_EXECUTION_EVENT_KIND_INVALID", `Unsupported event kind: ${kind}.`);
  }
  const payloadKey = {
    "context-expansion-requested": "request",
    "execution-started": null,
    "worker-observation-recorded": "observation",
    "worker-report-submitted": "report"
  }[kind];
  assertExactKeys(value, [
    "eventDigest",
    "eventId",
    "executionRef",
    "kind",
    "priorRecordDigest",
    "schemaVersion",
    "sequence",
    ...(payloadKey ? [payloadKey] : [])
  ], "compiledEvent");
  assertSchemaAndKind(value, kind, "compiledEvent");
  let content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind,
    eventId: normalizeIdentifier(value.eventId, "compiledEvent.eventId"),
    executionRef: normalizeIdentifier(value.executionRef, "compiledEvent.executionRef"),
    sequence: normalizeInteger(value.sequence, "compiledEvent.sequence", {
      minimum: 1,
      maximum: WORKER_EXECUTION_LIMITS.events
    }),
    priorRecordDigest: normalizeDigest(value.priorRecordDigest, "compiledEvent.priorRecordDigest")
  };
  if (kind === "context-expansion-requested") {
    content = { ...content, request: normalizeExpansionRequestDocument(value.request) };
  } else if (kind === "worker-report-submitted") {
    content = { ...content, report: normalizeWorkerReportDocument(value.report) };
  } else if (kind === "worker-observation-recorded") {
    content = { ...content, observation: normalizeWorkerObservationDocument(value.observation) };
  }
  const expected = sealDocument(content, "eventDigest");
  if (value.eventDigest !== expected.eventDigest) {
    throw protocolError("WORKER_EXECUTION_DIGEST_INVALID", "Execution event digest is invalid.");
  }
  return expected;
}

export function normalizeExpansionRequestDocument(value) {
  assertPlainObject(value, "contextExpansionRequest");
  assertExactKeys(value, [
    "contextExpansionRequestDigest",
    "currentCapabilityProfileDigest",
    "currentContextCapsuleDigest",
    "executionRef",
    "expectedKnowledge",
    "id",
    "kind",
    "priorRecordDigest",
    "reason",
    "requestedPaths",
    "schemaVersion",
    "sequence",
    "workSpecificationDigest"
  ], "contextExpansionRequest");
  assertSchemaAndKind(value, "context-expansion-request", "contextExpansionRequest");
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "context-expansion-request",
    id: normalizeIdentifier(value.id, "contextExpansionRequest.id"),
    executionRef: normalizeIdentifier(value.executionRef, "contextExpansionRequest.executionRef"),
    sequence: normalizeInteger(value.sequence, "contextExpansionRequest.sequence", {
      minimum: 1,
      maximum: WORKER_EXECUTION_LIMITS.events
    }),
    priorRecordDigest: normalizeDigest(
      value.priorRecordDigest,
      "contextExpansionRequest.priorRecordDigest"
    ),
    workSpecificationDigest: normalizeDigest(
      value.workSpecificationDigest,
      "contextExpansionRequest.workSpecificationDigest"
    ),
    currentContextCapsuleDigest: normalizeDigest(
      value.currentContextCapsuleDigest,
      "contextExpansionRequest.currentContextCapsuleDigest"
    ),
    currentCapabilityProfileDigest: normalizeDigest(
      value.currentCapabilityProfileDigest,
      "contextExpansionRequest.currentCapabilityProfileDigest"
    ),
    requestedPaths: normalizeStringSet(value.requestedPaths, "contextExpansionRequest.requestedPaths", {
      minimum: 1,
      maximum: WORKER_EXECUTION_LIMITS.paths,
      item: normalizePath
    }),
    reason: normalizeText(value.reason, "contextExpansionRequest.reason", { minimumBytes: 1 }),
    expectedKnowledge: normalizeText(
      value.expectedKnowledge,
      "contextExpansionRequest.expectedKnowledge",
      { minimumBytes: 1 }
    )
  };
  const result = assertDocumentSeal(value, content, "contextExpansionRequestDigest");
  assertDocumentBytes(
    result,
    WORKER_EXECUTION_LIMITS.contextExpansionRequestBytes,
    "Context Expansion Request"
  );
  return result;
}

export function normalizeWorkerReportDocument(value) {
  assertPlainObject(value, "workerReport");
  assertExactKeys(value, [
    "acceptanceAuthority",
    "artifactRefs",
    "blockers",
    "contextExpansionRequestDigests",
    "decisions",
    "deltas",
    "disposition",
    "executionRef",
    "finalCapabilityProfileDigest",
    "finalContextCapsuleDigest",
    "kind",
    "risks",
    "schemaVersion",
    "summary",
    "workSpecificationDigest",
    "workerReportDigest"
  ], "workerReport");
  assertSchemaAndKind(value, "worker-report", "workerReport");
  if (value.acceptanceAuthority !== false) {
    throw protocolError("WORKER_EXECUTION_AUTHORITY_FORBIDDEN", "Worker Reports are not authoritative.");
  }
  const disposition = normalizeIdentifier(value.disposition, "workerReport.disposition");
  if (!REPORT_DISPOSITIONS.includes(disposition)) {
    throw protocolError("WORKER_EXECUTION_REPORT_INVALID", `Unsupported report disposition: ${disposition}.`);
  }
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-report",
    executionRef: normalizeIdentifier(value.executionRef, "workerReport.executionRef"),
    workSpecificationDigest: normalizeDigest(
      value.workSpecificationDigest,
      "workerReport.workSpecificationDigest"
    ),
    finalContextCapsuleDigest: normalizeDigest(
      value.finalContextCapsuleDigest,
      "workerReport.finalContextCapsuleDigest"
    ),
    finalCapabilityProfileDigest: normalizeDigest(
      value.finalCapabilityProfileDigest,
      "workerReport.finalCapabilityProfileDigest"
    ),
    disposition,
    summary: normalizeText(value.summary, "workerReport.summary", { minimumBytes: 1 }),
    deltas: normalizeDeltas(value.deltas),
    decisions: normalizeReportStatements(value.decisions, "workerReport.decisions"),
    blockers: normalizeReportStatements(value.blockers, "workerReport.blockers"),
    risks: normalizeReportStatements(value.risks, "workerReport.risks"),
    artifactRefs: normalizeArtifactRefs(value.artifactRefs),
    contextExpansionRequestDigests: normalizeStringSet(
      value.contextExpansionRequestDigests,
      "workerReport.contextExpansionRequestDigests",
      { maximum: WORKER_EXECUTION_LIMITS.expansionRequests, item: normalizeDigest }
    ),
    acceptanceAuthority: false
  };
  assertReportDispositionConsistency(content);
  const result = assertDocumentSeal(value, content, "workerReportDigest");
  assertDocumentBytes(result, WORKER_EXECUTION_LIMITS.workerReportBytes, "Worker Report");
  return result;
}

function assertReportDispositionConsistency(report) {
  if (new Set(["completed", "partial"]).has(report.disposition) && report.blockers.length > 0) {
    throw protocolError(
      "WORKER_EXECUTION_REPORT_CONTRADICTORY",
      `${report.disposition} Worker Reports cannot declare blockers.`
    );
  }
  if (report.disposition === "blocked" && report.blockers.length === 0) {
    throw protocolError(
      "WORKER_EXECUTION_REPORT_CONTRADICTORY",
      "A blocked Worker Report must declare at least one blocker."
    );
  }
}

export function normalizeWorkerObservationDocument(value) {
  assertPlainObject(value, "workerObservation");
  assertExactKeys(value, [
    "acceptanceAuthority",
    "capabilityObservations",
    "capabilityProfileDigest",
    "capabilityProfileRef",
    "executionRef",
    "factAuthority",
    "kind",
    "reportDigest",
    "runtime",
    "schemaVersion",
    "workSpecificationDigest",
    "workerObservationDigest",
    "workspace"
  ], "workerObservation");
  assertSchemaAndKind(value, "worker-observation", "workerObservation");
  if (value.acceptanceAuthority !== false || value.factAuthority !== false) {
    throw protocolError(
      "WORKER_EXECUTION_AUTHORITY_FORBIDDEN",
      "Serialized Worker Observations carry neither fact nor acceptance authority."
    );
  }
  const runtime = normalizeRuntimeObservation(value.runtime);
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-observation",
    executionRef: normalizeIdentifier(value.executionRef, "workerObservation.executionRef"),
    workSpecificationDigest: normalizeDigest(
      value.workSpecificationDigest,
      "workerObservation.workSpecificationDigest"
    ),
    capabilityProfileRef: normalizeIdentifier(
      value.capabilityProfileRef,
      "workerObservation.capabilityProfileRef"
    ),
    capabilityProfileDigest: normalizeDigest(
      value.capabilityProfileDigest,
      "workerObservation.capabilityProfileDigest"
    ),
    runtime,
    capabilityObservations: normalizeCapabilityObservations(value.capabilityObservations),
    workspace: normalizeWorkspaceObservation(value.workspace),
    reportDigest: value.reportDigest === null
      ? null
      : normalizeDigest(value.reportDigest, "workerObservation.reportDigest"),
    factAuthority: false,
    acceptanceAuthority: false
  };
  const result = assertDocumentSeal(value, content, "workerObservationDigest");
  assertDocumentBytes(
    result,
    WORKER_EXECUTION_LIMITS.workerObservationBytes,
    "Worker Observation"
  );
  return result;
}

function normalizeDeltas(value) {
  const entries = normalizeDenseArray(value, "workerReport.deltas", {
    maximum: WORKER_EXECUTION_LIMITS.reportItems
  }).map((entry, index) => {
    const location = `workerReport.deltas[${index}]`;
    assertPlainObject(entry, location);
    assertExactKeys(entry, ["kind", "path"], location);
    const kind = normalizeIdentifier(entry.kind, `${location}.kind`);
    if (!new Set(["added", "deleted", "modified"]).has(kind)) {
      throw protocolError("WORKER_EXECUTION_REPORT_INVALID", `Unsupported delta kind: ${kind}.`);
    }
    return { path: normalizePath(entry.path, `${location}.path`), kind };
  }).sort((left, right) => compareUtf8(left.path, right.path));
  assertUnique(entries.map((entry) => entry.path), "workerReport.deltas");
  return entries;
}

function normalizeReportStatements(value, location) {
  const entries = normalizeDenseArray(value, location, {
    maximum: WORKER_EXECUTION_LIMITS.reportItems
  }).map((entry, index) => {
    const itemLocation = `${location}[${index}]`;
    assertPlainObject(entry, itemLocation);
    assertExactKeys(entry, ["id", "relatedRefs", "statement"], itemLocation);
    return {
      id: normalizeIdentifier(entry.id, `${itemLocation}.id`),
      statement: normalizeText(entry.statement, `${itemLocation}.statement`, { minimumBytes: 1 }),
      relatedRefs: normalizeStringSet(entry.relatedRefs, `${itemLocation}.relatedRefs`, {
        maximum: WORKER_EXECUTION_LIMITS.relatedRefs,
        item: normalizeIdentifier
      })
    };
  }).sort((left, right) => compareUtf8(left.id, right.id));
  assertUnique(entries.map((entry) => entry.id), location);
  return entries;
}

function normalizeArtifactRefs(value) {
  const entries = normalizeDenseArray(value, "workerReport.artifactRefs", {
    maximum: WORKER_EXECUTION_LIMITS.artifactRefs
  }).map((entry, index) => {
    const location = `workerReport.artifactRefs[${index}]`;
    assertPlainObject(entry, location);
    assertExactKeys(entry, ["bytes", "digest", "id", "mediaType"], location);
    const mediaType = normalizeText(entry.mediaType, `${location}.mediaType`, {
      minimumBytes: 3,
      maximumBytes: 256
    });
    if (!MEDIA_TYPE_PATTERN.test(mediaType)) {
      throw protocolError("WORKER_EXECUTION_REPORT_INVALID", `Invalid media type: ${mediaType}.`);
    }
    return {
      id: normalizeIdentifier(entry.id, `${location}.id`),
      digest: normalizeDigest(entry.digest, `${location}.digest`),
      mediaType,
      bytes: normalizeInteger(entry.bytes, `${location}.bytes`, {
        minimum: 0,
        maximum: Number.MAX_SAFE_INTEGER
      })
    };
  }).sort((left, right) => compareUtf8(left.id, right.id));
  assertUnique(entries.map((entry) => entry.id), "workerReport.artifactRefs");
  return entries;
}

function normalizeRuntimeObservation(value) {
  assertPlainObject(value, "workerObservation.runtime");
  const kind = normalizeIdentifier(value.kind, "workerObservation.runtime.kind");
  if (kind !== "process-observation-reference-v1") {
    throw protocolError("WORKER_EXECUTION_OBSERVATION_INVALID", `Unsupported runtime kind: ${kind}.`);
  }
  assertExactKeys(value, [
    "controlKind",
    "kind",
    "observationDigest",
    "stderr",
    "stdout",
    "supportStatus",
    "termination"
  ], "workerObservation.runtime");
  const supportStatus = normalizeIdentifier(value.supportStatus, "workerObservation.runtime.supportStatus");
  if (!new Set(["supported", "unsupported"]).has(supportStatus)) {
    throw protocolError("WORKER_EXECUTION_OBSERVATION_INVALID", "Invalid runtime supportStatus.");
  }
  const controlKind = normalizeIdentifier(value.controlKind, "workerObservation.runtime.controlKind");
  if (!new Set(["cancelled", "none", "timeout"]).has(controlKind)) {
    throw protocolError("WORKER_EXECUTION_OBSERVATION_INVALID", "Invalid runtime controlKind.");
  }
  const termination = normalizeProcessTermination(value.termination);
  const stdout = normalizeStreamFacts(value.stdout, "workerObservation.runtime.stdout");
  const stderr = normalizeStreamFacts(value.stderr, "workerObservation.runtime.stderr");
  if (stdout.complete !== termination.closeConfirmed
    || stderr.complete !== termination.closeConfirmed) {
    throw protocolError(
      "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
      "Process close and stream-completion facts must remain aligned."
    );
  }
  if (supportStatus === "unsupported" && termination.kind !== "not-started") {
    throw protocolError(
      "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
      "An unsupported process profile must remain not-started."
    );
  }
  return {
    kind,
    observationDigest: normalizeDigest(
      value.observationDigest,
      "workerObservation.runtime.observationDigest"
    ),
    supportStatus,
    controlKind,
    termination,
    stdout,
    stderr
  };
}

function normalizeProcessTermination(value) {
  assertPlainObject(value, "workerObservation.runtime.termination");
  assertExactKeys(
    value,
    ["closeConfirmed", "exitCode", "kind", "signal"],
    "workerObservation.runtime.termination"
  );
  const kind = normalizeIdentifier(value.kind, "workerObservation.runtime.termination.kind");
  if (!PROCESS_TERMINATION_KINDS.has(kind)) {
    throw protocolError("WORKER_EXECUTION_OBSERVATION_INVALID", `Unsupported termination kind: ${kind}.`);
  }
  if (typeof value.closeConfirmed !== "boolean") {
    throw protocolError(
      "WORKER_EXECUTION_OBSERVATION_INVALID",
      "runtime.termination.closeConfirmed must be boolean."
    );
  }
  const closeExpected = kind !== "unconfirmed";
  if (value.closeConfirmed !== closeExpected) {
    throw protocolError(
      "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
      `Process termination ${kind} requires closeConfirmed=${closeExpected}.`
    );
  }
  let exitCode = null;
  let signal = null;
  if (kind === "exited") {
    exitCode = normalizeInteger(value.exitCode, "workerObservation.runtime.termination.exitCode", {
      minimum: Number.MIN_SAFE_INTEGER,
      maximum: Number.MAX_SAFE_INTEGER
    });
    if (value.signal !== null) {
      throw protocolError(
        "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
        "An exited process cannot also name a signal."
      );
    }
  } else if (kind === "signaled") {
    if (value.exitCode !== null) {
      throw protocolError(
        "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
        "A signaled process cannot also name an exit code."
      );
    }
    signal = normalizeIdentifier(value.signal, "workerObservation.runtime.termination.signal");
  } else if (value.exitCode !== null || value.signal !== null) {
    throw protocolError(
      "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY",
      `Process termination ${kind} cannot name an exit code or signal.`
    );
  }
  return { kind, exitCode, signal, closeConfirmed: value.closeConfirmed };
}

function normalizeStreamFacts(value, location) {
  assertPlainObject(value, location);
  assertExactKeys(value, ["complete", "observedBytes", "observedDigest", "truncated"], location);
  if (typeof value.truncated !== "boolean" || typeof value.complete !== "boolean") {
    throw protocolError("WORKER_EXECUTION_OBSERVATION_INVALID", `${location} flags must be boolean.`);
  }
  return {
    observedBytes: normalizeInteger(value.observedBytes, `${location}.observedBytes`, {
      minimum: 0,
      maximum: Number.MAX_SAFE_INTEGER
    }),
    observedDigest: normalizeDigest(value.observedDigest, `${location}.observedDigest`),
    truncated: value.truncated,
    complete: value.complete
  };
}

function normalizeCapabilityObservations(value) {
  const entries = normalizeDenseArray(value, "workerObservation.capabilityObservations", {
    maximum: CAPABILITY_REFS.length
  }).map((entry, index) => {
    const location = `workerObservation.capabilityObservations[${index}]`;
    assertPlainObject(entry, location);
    assertExactKeys(entry, ["capabilityRef", "outcome"], location);
    const capabilityRef = normalizeIdentifier(entry.capabilityRef, `${location}.capabilityRef`);
    if (!CAPABILITY_REFS.includes(capabilityRef)) {
      throw protocolError("WORKER_EXECUTION_CAPABILITY_INVALID", `Unknown capability: ${capabilityRef}.`);
    }
    const outcome = normalizeIdentifier(entry.outcome, `${location}.outcome`);
    if (!CAPABILITY_OUTCOMES.has(outcome)) {
      throw protocolError("WORKER_EXECUTION_CAPABILITY_INVALID", `Unknown outcome: ${outcome}.`);
    }
    return { capabilityRef, outcome };
  }).sort((left, right) => compareUtf8(left.capabilityRef, right.capabilityRef));
  assertUnique(entries.map((entry) => entry.capabilityRef), "workerObservation.capabilityObservations");
  return entries;
}

function normalizeWorkspaceObservation(value) {
  assertPlainObject(value, "workerObservation.workspace");
  assertExactKeys(
    value,
    ["afterGitContentDigest", "beforeGitContentDigest"],
    "workerObservation.workspace"
  );
  return {
    beforeGitContentDigest: normalizeDigest(
      value.beforeGitContentDigest,
      "workerObservation.workspace.beforeGitContentDigest"
    ),
    afterGitContentDigest: normalizeDigest(
      value.afterGitContentDigest,
      "workerObservation.workspace.afterGitContentDigest"
    )
  };
}
