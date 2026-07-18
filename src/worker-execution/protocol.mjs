import {
  WORKER_EXECUTION_INTERFACE_PROOF_VERSION,
  WORKER_EXECUTION_LIMITS,
  WORKER_EXECUTION_SCHEMA_VERSION,
  assertPlainObject,
  deepFreeze,
  protocolError
} from "./canonical-value.mjs";
import {
  EVENT_KINDS,
  compileWorkSpecification,
  normalizeCompiledEvent,
  normalizeExpansionRequestDocument,
  normalizeWorkSpecificationDocument,
  normalizeWorkerObservationDocument,
  normalizeWorkerReportDocument
} from "./worker-documents.mjs";
import {
  applyExecutionEvent,
  createExecutionRecord,
  normalizeExecutionRecord
} from "./execution-record.mjs";

export {
  WORKER_EXECUTION_INTERFACE_PROOF_VERSION,
  WORKER_EXECUTION_LIMITS,
  WORKER_EXECUTION_SCHEMA_VERSION,
  applyExecutionEvent,
  compileWorkSpecification,
  createExecutionRecord
};

export function validateWorkerExecutionDocument(value) {
  assertPlainObject(value, "document");
  switch (value.kind) {
    case "worker-work-specification":
      return normalizeWorkSpecificationDocument(value);
    case "context-expansion-request":
      return deepFreeze(normalizeExpansionRequestDocument(value));
    case "worker-report":
      return deepFreeze(normalizeWorkerReportDocument(value));
    case "worker-observation":
      return deepFreeze(normalizeWorkerObservationDocument(value));
    case "worker-execution-record":
      return normalizeExecutionRecord(value);
    default:
      if (EVENT_KINDS.has(value.kind)) return deepFreeze(normalizeCompiledEvent(value));
      throw protocolError(
        "WORKER_EXECUTION_DOCUMENT_KIND_INVALID",
        "Worker Execution document kind is missing or unsupported."
      );
  }
}
