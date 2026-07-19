import {
  WORKER_EXECUTION_LIMITS,
  WORKER_EXECUTION_SCHEMA_VERSION,
  assertDocumentBytes,
  assertExactKeys,
  assertPlainObject,
  assertSchemaAndKind,
  canonicalStringify,
  compareUtf8,
  deepFreeze,
  normalizeDenseArray,
  protocolError,
  sealDocument
} from "./canonical-value.mjs";
import {
  compileEvent,
  normalizeCompiledEvent,
  normalizeWorkSpecificationDocument
} from "./worker-documents.mjs";

const CONTROL_KEY_BY_CAPABILITY = Object.freeze({
  "filesystem-read": "filesystemRead",
  "filesystem-write": "filesystemWrite",
  network: "network",
  process: "process",
  secrets: "secrets"
});
const TERMINAL_STATES = new Set([
  "blocked",
  "cancelled",
  "completed",
  "failed",
  "lost",
  "partial",
  "timed-out",
  "unsupported"
]);
export function createExecutionRecord(workSpecification) {
  const normalized = normalizeWorkSpecificationDocument(workSpecification);
  return deepFreeze(createInitialExecutionRecord(normalized));
}

export function applyExecutionEvent(record, eventInput) {
  const current = normalizeExecutionRecord(record);
  const event = compileEvent(current.workSpecification, eventInput);
  if (isExactEventReplay(current, event)) return current;
  assertEventEnvelope(current, event);
  return deepFreeze(appendCompiledEvent(current, event));
}

function createInitialExecutionRecord(workSpecification) {
  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-execution-record",
    executionId: workSpecification.executionId,
    state: "prepared",
    workSpecification,
    currentBindings: {
      contextCapsuleDigest: workSpecification.context.capsuleDigest,
      capabilityProfileDigest: workSpecification.capabilityProfile.digest
    },
    events: [],
    eventCount: 0,
    nextSequence: 1,
    lastEventDigest: null,
    pendingExpansionRequestDigests: [],
    workerReport: null,
    workerObservation: null,
    acceptanceAuthority: false
  };
  const record = sealDocument(content, "executionRecordDigest");
  assertDocumentBytes(record, WORKER_EXECUTION_LIMITS.executionRecordBytes, "Execution Record");
  return record;
}
function assertEventEnvelope(record, event) {
  if (event.executionRef !== record.executionId) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Event executionRef does not match the Execution Record."
    );
  }
  if (event.sequence !== record.nextSequence) {
    throw protocolError(
      "WORKER_EXECUTION_EVENT_SEQUENCE_INVALID",
      `Expected event sequence ${record.nextSequence}, received ${event.sequence}.`
    );
  }
  if (event.priorRecordDigest !== record.executionRecordDigest) {
    throw protocolError(
      "WORKER_EXECUTION_RECORD_STALE",
      "Event priorRecordDigest does not match the current Execution Record."
    );
  }
  if (record.eventCount >= WORKER_EXECUTION_LIMITS.events) {
    throw protocolError("WORKER_EXECUTION_LIMIT_EXCEEDED", "Execution Record event limit exceeded.");
  }
}

function appendCompiledEvent(record, event) {
  if (isExactEventReplay(record, event)) return record;
  assertEventEnvelope(record, event);
  if (TERMINAL_STATES.has(record.state)) {
    throw protocolError(
      "WORKER_EXECUTION_TERMINAL",
      `Execution Record is terminal in state ${record.state}.`
    );
  }
  let state = record.state;
  let pendingExpansionRequestDigests = [...record.pendingExpansionRequestDigests];
  let workerReport = record.workerReport;
  let workerObservation = record.workerObservation;

  if (event.kind === "execution-started") {
    if (state !== "prepared") {
      throw protocolError("WORKER_EXECUTION_STATE_INVALID", "Execution can start only from prepared.");
    }
    state = "running";
  } else if (event.kind === "context-expansion-requested") {
    if (!new Set(["running", "awaiting-context"]).has(state) || workerReport) {
      throw protocolError(
        "WORKER_EXECUTION_STATE_INVALID",
        "Context Expansion can be requested only while running and before a Worker Report."
      );
    }
    const profileLimit = record.workSpecification.capabilityProfile.limits.expansionRequests;
    if (pendingExpansionRequestDigests.length >= profileLimit) {
      throw protocolError(
        "WORKER_EXECUTION_LIMIT_EXCEEDED",
        "Context Expansion Request limit exceeded."
      );
    }
    assertExpansionRequestBindings(record, event);
    if (record.events.some((candidate) => (
      candidate.kind === "context-expansion-requested"
      && candidate.request.id === event.request.id
    ))) {
      throw protocolError(
        "WORKER_EXECUTION_DUPLICATE",
        `Context Expansion Request id ${event.request.id} is already present.`
      );
    }
    pendingExpansionRequestDigests.push(event.request.contextExpansionRequestDigest);
    pendingExpansionRequestDigests.sort(compareUtf8);
    state = "awaiting-context";
  } else if (event.kind === "worker-report-submitted") {
    if (!new Set(["running", "awaiting-context"]).has(state) || workerReport) {
      throw protocolError(
        "WORKER_EXECUTION_STATE_INVALID",
        "Exactly one Worker Report may be submitted before terminal observation."
      );
    }
    assertReportBindings(record, event.report);
    if (state === "awaiting-context" && !new Set(["blocked", "failed"]).has(event.report.disposition)) {
      throw protocolError(
        "WORKER_EXECUTION_CONTEXT_EXPANSION_PENDING",
        "A Worker cannot report completed or partial while Context Expansion remains unresolved."
      );
    }
    workerReport = event.report;
  } else if (event.kind === "worker-observation-recorded") {
    if (state === "prepared"
      && !(event.observation.runtime.supportStatus === "unsupported"
        && event.observation.runtime.termination.kind === "not-started")) {
      throw protocolError(
        "WORKER_EXECUTION_STATE_INVALID",
        "Only an unsupported terminal observation may precede execution start."
      );
    }
    if (!new Set(["prepared", "running", "awaiting-context"]).has(state) || workerObservation) {
      throw protocolError(
        "WORKER_EXECUTION_STATE_INVALID",
        "Exactly one terminal Worker Observation may close an open Execution Record."
      );
    }
    assertObservationBindings(record, event.observation, workerReport);
    state = deriveTerminalState(event.observation, workerReport);
    workerObservation = event.observation;
  }

  const content = {
    schemaVersion: WORKER_EXECUTION_SCHEMA_VERSION,
    kind: "worker-execution-record",
    executionId: record.executionId,
    state,
    workSpecification: record.workSpecification,
    currentBindings: record.currentBindings,
    events: [...record.events, event],
    eventCount: record.eventCount + 1,
    nextSequence: record.nextSequence + 1,
    lastEventDigest: event.eventDigest,
    pendingExpansionRequestDigests,
    workerReport,
    workerObservation,
    acceptanceAuthority: false
  };
  const next = sealDocument(content, "executionRecordDigest");
  assertDocumentBytes(next, WORKER_EXECUTION_LIMITS.executionRecordBytes, "Execution Record");
  return next;
}

function isExactEventReplay(record, event) {
  const replayed = record.events.find((candidate) => candidate.eventId === event.eventId);
  if (!replayed) return false;
  if (canonicalStringify(replayed) !== canonicalStringify(event)) {
    throw protocolError(
      "WORKER_EXECUTION_EVENT_REPLAY_CONFLICT",
      `Event ${event.eventId} was replayed with different content.`
    );
  }
  return true;
}

function assertExpansionRequestBindings(record, event) {
  const request = event.request;
  if (request.executionRef !== record.executionId
    || request.sequence !== event.sequence
    || request.priorRecordDigest !== event.priorRecordDigest
    || request.workSpecificationDigest !== record.workSpecification.workSpecificationDigest
    || request.currentContextCapsuleDigest !== record.currentBindings.contextCapsuleDigest
    || request.currentCapabilityProfileDigest !== record.currentBindings.capabilityProfileDigest) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Context Expansion Request does not bind the current Execution Record sources."
    );
  }
}

function assertReportBindings(record, report) {
  if (report.executionRef !== record.executionId
    || report.workSpecificationDigest !== record.workSpecification.workSpecificationDigest
    || report.finalContextCapsuleDigest !== record.currentBindings.contextCapsuleDigest
    || report.finalCapabilityProfileDigest !== record.currentBindings.capabilityProfileDigest) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Report does not bind the current Work Specification, Context, and capability profile."
    );
  }
  const allRequestDigests = record.events
    .filter((event) => event.kind === "context-expansion-requested")
    .map((event) => event.request.contextExpansionRequestDigest)
    .sort(compareUtf8);
  if (canonicalStringify(report.contextExpansionRequestDigests) !== canonicalStringify(allRequestDigests)) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Report must name every Context Expansion Request exactly."
    );
  }
  if (report.artifactRefs.length > record.workSpecification.capabilityProfile.limits.artifactRefs) {
    throw protocolError("WORKER_EXECUTION_LIMIT_EXCEEDED", "Worker Report artifact limit exceeded.");
  }
  const maximumBytes = Math.min(
    WORKER_EXECUTION_LIMITS.workerReportBytes,
    record.workSpecification.capabilityProfile.limits.reportBytes
  );
  assertDocumentBytes(report, maximumBytes, "Worker Report");
}

function assertObservationBindings(record, observation, workerReport) {
  if (observation.executionRef !== record.executionId
    || observation.workSpecificationDigest !== record.workSpecification.workSpecificationDigest
    || observation.capabilityProfileRef !== record.workSpecification.capabilityProfile.ref
    || observation.capabilityProfileDigest !== record.currentBindings.capabilityProfileDigest) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Observation does not bind the current execution sources."
    );
  }
  const expectedReportDigest = workerReport?.workerReportDigest ?? null;
  if (observation.reportDigest !== expectedReportDigest) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Observation reportDigest does not match the recorded Worker Report."
    );
  }
  if (observation.workspace.beforeGitContentDigest
    !== record.workSpecification.change.baselineGitContentDigest) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Observation before-Git binding does not match the Work Specification baseline."
    );
  }
  const expectedCapabilities = [...record.workSpecification.capabilityProfile.requested].sort(compareUtf8);
  const observedCapabilities = observation.capabilityObservations
    .map((entry) => entry.capabilityRef)
    .sort(compareUtf8);
  if (canonicalStringify(expectedCapabilities) !== canonicalStringify(observedCapabilities)) {
    throw protocolError(
      "WORKER_EXECUTION_BINDING_MISMATCH",
      "Worker Observation must report each requested capability exactly once."
    );
  }
  for (const entry of observation.capabilityObservations) {
    const controlKey = CONTROL_KEY_BY_CAPABILITY[entry.capabilityRef];
    const mode = record.workSpecification.capabilityProfile.controls[controlKey];
    if (mode === "unsupported" && entry.outcome !== "not-observed") {
      throw protocolError(
        "WORKER_EXECUTION_CAPABILITY_CONTRADICTORY",
        `Unsupported capability ${entry.capabilityRef} cannot be reported as ${entry.outcome}.`
      );
    }
  }
}

function deriveTerminalState(observation, report) {
  const runtime = observation.runtime;
  if (runtime.supportStatus === "unsupported") return "unsupported";
  if (runtime.controlKind === "timeout") return "timed-out";
  if (runtime.controlKind === "cancelled") return "cancelled";
  if (runtime.termination.kind === "unconfirmed") return "lost";
  if (runtime.termination.kind !== "exited" || runtime.termination.exitCode !== 0) return "failed";
  return report?.disposition ?? "failed";
}

export function normalizeExecutionRecord(value) {
  assertPlainObject(value, "executionRecord");
  assertExactKeys(value, [
    "acceptanceAuthority",
    "currentBindings",
    "eventCount",
    "events",
    "executionId",
    "executionRecordDigest",
    "kind",
    "lastEventDigest",
    "nextSequence",
    "pendingExpansionRequestDigests",
    "schemaVersion",
    "state",
    "workerObservation",
    "workerReport",
    "workSpecification"
  ], "executionRecord");
  assertSchemaAndKind(value, "worker-execution-record", "executionRecord");
  if (value.acceptanceAuthority !== false) {
    throw protocolError(
      "WORKER_EXECUTION_AUTHORITY_FORBIDDEN",
      "Execution Records never carry acceptance authority."
    );
  }
  const workSpecification = normalizeWorkSpecificationDocument(value.workSpecification);
  if (value.executionId !== workSpecification.executionId) {
    throw protocolError("WORKER_EXECUTION_BINDING_MISMATCH", "Execution Record id is not source-bound.");
  }
  const events = normalizeDenseArray(value.events, "executionRecord.events", {
    maximum: WORKER_EXECUTION_LIMITS.events
  }).map((event) => normalizeCompiledEvent(event));
  let expected = createInitialExecutionRecord(workSpecification);
  for (const event of events) expected = appendCompiledEvent(expected, event);
  if (canonicalStringify(value) !== canonicalStringify(expected)) {
    throw protocolError(
      "WORKER_EXECUTION_RECORD_INVALID",
      "Execution Record content, derived lifecycle, or digest chain is not canonical."
    );
  }
  assertDocumentBytes(expected, WORKER_EXECUTION_LIMITS.executionRecordBytes, "Execution Record");
  return deepFreeze(expected);
}
