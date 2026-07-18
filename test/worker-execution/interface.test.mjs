import assert from "node:assert/strict";
import test from "node:test";

import {
  WORKER_EXECUTION_INTERFACE_PROOF_VERSION,
  applyExecutionEvent,
  compileWorkSpecification,
  createExecutionRecord,
  validateWorkerExecutionDocument
} from "../../src/worker-execution/protocol.mjs";

const digest = (character) => `sha256:${character.repeat(64)}`;
const DIGESTS = Object.freeze({
  governance: digest("1"),
  baselineGit: digest("2"),
  compilation: digest("3"),
  context: digest("4"),
  readScope: digest("5"),
  writeScope: digest("6"),
  capabilityProfile: digest("7"),
  runtimeObservation: digest("8"),
  stdout: digest("9"),
  stderr: digest("a"),
  afterGit: digest("b"),
  artifact: digest("c"),
  attack: digest("f")
});

export const WORKER_EXECUTION_CONFORMANCE_PROOF_VERSION = 1;

test("Worker Execution protocol is deterministic, bounded, and never self-authorizing", () => {
  assert.equal(WORKER_EXECUTION_INTERFACE_PROOF_VERSION, 1);
  assert.equal(WORKER_EXECUTION_CONFORMANCE_PROOF_VERSION, 1);

  const specificationInput = validSpecificationInput();
  const workSpecification = compileWorkSpecification(specificationInput);
  assertCanonicalDocument(workSpecification);
  assert.equal(workSpecification.executionId, specificationInput.executionId);
  assert.equal(workSpecification.attempt, specificationInput.attempt);
  assert.equal(workSpecification.capabilityProfile.controls.filesystemRead, "observed-only");
  assert.equal(workSpecification.capabilityProfile.controls.network, "unsupported");
  assert.notEqual(
    workSpecification.capabilityProfile.digest,
    workSpecification.capabilityProfile.sourceDigest,
    "the inline capability projection has its own canonical digest"
  );

  const prepared = createExecutionRecord(workSpecification);
  assertCanonicalDocument(prepared);
  assert.equal(prepared.state, "prepared");
  assert.equal(prepared.acceptanceAuthority, false);
  assert.equal(prepared.eventCount, 0);
  assert.equal(prepared.nextSequence, 1);

  const startedEvent = eventFor(prepared, {
    eventId: "event-started",
    kind: "execution-started"
  });
  const running = applyExecutionEvent(prepared, startedEvent);
  assertCanonicalDocument(running);
  assert.equal(running.state, "running");
  assert.equal(running.eventCount, 1);
  assert.equal(running.nextSequence, 2);

  const exactReplay = applyExecutionEvent(running, structuredClone(startedEvent));
  assert.deepEqual(exactReplay, running, "an exact event replay is a byte-stable no-op");

  const reportEvent = eventFor(running, {
    eventId: "event-report",
    kind: "worker-report-submitted",
    report: validWorkerReport(workSpecification)
  });
  const reported = applyExecutionEvent(running, reportEvent);
  assertCanonicalDocument(reported);
  assert.equal(reported.state, "running", "a Worker Report cannot terminate execution itself");
  assert.equal(reported.acceptanceAuthority, false);
  assert.ok(reported.workerReport);
  assert.equal(reported.workerObservation, null);

  const observationEvent = eventFor(reported, {
    eventId: "event-observation",
    kind: "worker-observation-recorded",
    observation: validWorkerObservation({
      workSpecification,
      reportDigest: reported.workerReport.workerReportDigest
    })
  });
  const completed = applyExecutionEvent(reported, observationEvent);
  assertCanonicalDocument(completed);
  assert.equal(completed.state, "completed");
  assert.equal(completed.acceptanceAuthority, false);
  assert.equal(completed.workerObservation.factAuthority, false);
  assert.equal(completed.eventCount, 3);
  assert.equal(completed.nextSequence, 4);
  assert.deepEqual(completed.pendingExpansionRequestDigests, []);
  assert.equal(completed.workerObservation.reportDigest, completed.workerReport.workerReportDigest);
  assert.equal(
    completed.workerObservation.workspace.beforeGitContentDigest,
    workSpecification.change.baselineGitContentDigest
  );
  assert.equal(completed.workerObservation.workspace.afterGitContentDigest, DIGESTS.afterGit);

  for (const field of [
    "messages",
    "model",
    "provider",
    "session",
    "sourceBody",
    "toolCalls",
    "transcript"
  ]) {
    const specificationAttack = structuredClone(specificationInput);
    specificationAttack[field] = `forged-${field}`;
    assertProtocolRefusal(
      () => compileWorkSpecification(specificationAttack),
      `Work Specification rejects provider detail ${field}`,
      "WORKER_EXECUTION_FIELDS_INVALID"
    );

    const reportAttack = validWorkerReport(workSpecification);
    reportAttack[field] = `forged-${field}`;
    assertProtocolRefusal(
      () => applyExecutionEvent(running, eventFor(running, {
        eventId: `event-report-${field}`,
        kind: "worker-report-submitted",
        report: reportAttack
      })),
      `Worker Report rejects provider detail ${field}`,
      "WORKER_EXECUTION_FIELDS_INVALID"
    );
  }

  for (const control of ["filesystemRead", "filesystemWrite", "process", "network", "secrets"]) {
    const enforcedAttack = structuredClone(specificationInput);
    enforcedAttack.capabilityProfile.controls[control] = "enforced";
    assertProtocolRefusal(
      () => compileWorkSpecification(enforcedAttack),
      `an unproved enforced ${control} control fails closed`,
      "CAPABILITY_ENFORCEMENT_PROOF_REQUIRED"
    );
  }
  const changedProjectionInput = structuredClone(specificationInput);
  changedProjectionInput.capabilityProfile.controls.network = "observed-only";
  const changedProjection = compileWorkSpecification(changedProjectionInput);
  assert.equal(
    changedProjection.capabilityProfile.sourceDigest,
    workSpecification.capabilityProfile.sourceDigest
  );
  assert.notEqual(
    changedProjection.capabilityProfile.digest,
    workSpecification.capabilityProfile.digest,
    "different control semantics cannot retain the same projection digest"
  );

  const expansionRequest = {
    id: "expansion-core-internals",
    requestedPaths: ["src/core/internal.mjs"],
    reason: "Inspect one implementation detail needed to explain the blocker.",
    expectedKnowledge: "Whether the private implementation violates the public Contract."
  };
  const validExpansion = applyExecutionEvent(running, eventFor(running, {
    eventId: "event-expansion",
    kind: "context-expansion-requested",
    request: expansionRequest
  }));
  assert.equal(validExpansion.state, "awaiting-context");
  assert.equal(validExpansion.pendingExpansionRequestDigests.length, 1);
  assert.equal(
    Object.hasOwn(validExpansion.events.at(-1).request, "granted"),
    false,
    "an expansion remains a request, never a self-issued grant"
  );
  for (const selfGrant of [
    { granted: true },
    { disposition: "granted" },
    { resultingContextCapsuleDigest: DIGESTS.attack },
    { resultingCapabilityProfileDigest: DIGESTS.attack }
  ]) {
    assertProtocolRefusal(
      () => applyExecutionEvent(running, eventFor(running, {
        eventId: `event-self-grant-${Object.keys(selfGrant)[0]}`,
        kind: "context-expansion-requested",
        request: { ...expansionRequest, ...selfGrant }
      })),
      `Context Expansion Request rejects ${Object.keys(selfGrant)[0]}`,
      "WORKER_EXECUTION_FIELDS_INVALID"
    );
  }
  assertProtocolRefusal(
    () => applyExecutionEvent(validExpansion, eventFor(validExpansion, {
      eventId: "event-duplicate-expansion-id",
      kind: "context-expansion-requested",
      request: { ...expansionRequest, requestedPaths: ["src/other/internal.mjs"] }
    })),
    "Context Expansion business ids are unique inside one execution",
    "WORKER_EXECUTION_DUPLICATE"
  );

  const bypassReport = validWorkerReport(workSpecification);
  bypassReport.contextExpansionRequestDigests = [
    validExpansion.pendingExpansionRequestDigests[0]
  ];
  assertProtocolRefusal(
    () => applyExecutionEvent(validExpansion, eventFor(validExpansion, {
      eventId: "event-expansion-bypass",
      kind: "worker-report-submitted",
      report: bypassReport
    })),
    "a Worker cannot report completion while Context Expansion remains unresolved",
    "WORKER_EXECUTION_CONTEXT_EXPANSION_PENDING"
  );

  for (const field of [
    "acceptance",
    "accepted",
    "authorityDecision",
    "claimSatisfaction",
    "confidence",
    "evidence",
    "greenLight",
    "knowledgeClosure",
    "percentage",
    "score"
  ]) {
    const reportAttack = validWorkerReport(workSpecification);
    reportAttack[field] = field === "score" ? 100 : { status: "approved" };
    assertProtocolRefusal(
      () => applyExecutionEvent(running, eventFor(running, {
        eventId: `event-authority-${field}`,
        kind: "worker-report-submitted",
        report: reportAttack
      })),
      `Worker Report rejects self-authorizing field ${field}`,
      "WORKER_EXECUTION_FIELDS_INVALID"
    );
  }
  const contradictoryCompleted = validWorkerReport(workSpecification);
  contradictoryCompleted.blockers = [{
    id: "blocker-contradiction",
    statement: "This contradicts completed disposition.",
    relatedRefs: []
  }];
  assertProtocolRefusal(
    () => applyExecutionEvent(running, eventFor(running, {
      eventId: "event-contradictory-completed-report",
      kind: "worker-report-submitted",
      report: contradictoryCompleted
    })),
    "completed Worker Reports cannot conceal blockers",
    "WORKER_EXECUTION_REPORT_CONTRADICTORY"
  );

  assertProtocolRefusal(
    () => applyExecutionEvent(running, {
      ...eventFor(running, { eventId: "event-sequence-gap", kind: "worker-report-submitted" }),
      sequence: running.nextSequence + 1,
      report: validWorkerReport(workSpecification)
    }),
    "event sequence gaps fail closed",
    "WORKER_EXECUTION_EVENT_SEQUENCE_INVALID"
  );
  assertProtocolRefusal(
    () => applyExecutionEvent(running, {
      ...eventFor(running, { eventId: "event-stale-record", kind: "worker-report-submitted" }),
      priorRecordDigest: prepared.executionRecordDigest,
      report: validWorkerReport(workSpecification)
    }),
    "a stale prior Record digest fails closed",
    "WORKER_EXECUTION_RECORD_STALE"
  );
  assertProtocolRefusal(
    () => applyExecutionEvent(running, {
      ...eventFor(running, { eventId: "event-cross-execution", kind: "worker-report-submitted" }),
      executionRef: "execution-other",
      report: validWorkerReport(workSpecification)
    }),
    "a cross-Execution event fails closed",
    "WORKER_EXECUTION_BINDING_MISMATCH"
  );
  assertProtocolRefusal(
    () => applyExecutionEvent(running, {
      ...startedEvent,
      sequence: running.nextSequence
    }),
    "the same event id with altered content is a replay conflict",
    "WORKER_EXECUTION_EVENT_REPLAY_CONFLICT"
  );

  for (const [label, field] of [
    ["Context Capsule", "finalContextCapsuleDigest"],
    ["Capability Profile", "finalCapabilityProfileDigest"]
  ]) {
    const reportAttack = validWorkerReport(workSpecification);
    reportAttack[field] = DIGESTS.attack;
    assertProtocolRefusal(
      () => applyExecutionEvent(running, eventFor(running, {
        eventId: `event-stale-${field}`,
        kind: "worker-report-submitted",
        report: reportAttack
      })),
      `Worker Report cannot substitute its final ${label} binding`,
      "WORKER_EXECUTION_BINDING_MISMATCH"
    );
  }

  const tamperedReportRecord = structuredClone(reported);
  tamperedReportRecord.workerReport.summary = "Tampered while retaining the old Report digest.";
  assertProtocolRefusal(
    () => validateWorkerExecutionDocument(tamperedReportRecord),
    "Report content cannot retain an old digest",
    "WORKER_EXECUTION_DIGEST_INVALID"
  );
  const tamperedContextRecord = structuredClone(completed);
  tamperedContextRecord.workSpecification.context.capsuleDigest = DIGESTS.attack;
  assertProtocolRefusal(
    () => validateWorkerExecutionDocument(tamperedContextRecord),
    "Context content cannot retain an old Work Specification or Record digest",
    "WORKER_EXECUTION_DIGEST_INVALID"
  );

  const truncatedObservation = validWorkerObservation({
    workSpecification,
    reportDigest: reported.workerReport.workerReportDigest
  });
  truncatedObservation.runtime.stdout.truncated = true;
  const truncatedRecord = applyExecutionEvent(reported, eventFor(reported, {
    eventId: "event-truncated-complete-stream",
    kind: "worker-observation-recorded",
    observation: truncatedObservation
  }));
  assert.equal(truncatedRecord.state, "completed");
  assert.equal(truncatedRecord.workerObservation.runtime.stdout.complete, true);
  assert.equal(truncatedRecord.workerObservation.runtime.stdout.truncated, true);

  for (const [index, mutate] of [
    (observation) => { observation.runtime.termination.closeConfirmed = false; },
    (observation) => { observation.runtime.stdout.complete = false; },
    (observation) => { observation.runtime.termination.kind = "signaled"; }
  ].entries()) {
    const observation = validWorkerObservation({
      workSpecification,
      reportDigest: reported.workerReport.workerReportDigest
    });
    mutate(observation);
    assertProtocolRefusal(
      () => applyExecutionEvent(reported, eventFor(reported, {
        eventId: `event-stream-contradiction-${index + 1}`,
        kind: "worker-observation-recorded",
        observation
      })),
      "contradictory runtime stream or termination facts fail closed",
      "WORKER_EXECUTION_OBSERVATION_CONTRADICTORY"
    );
  }

  const wrongWorkspace = validWorkerObservation({
    workSpecification,
    reportDigest: reported.workerReport.workerReportDigest
  });
  wrongWorkspace.workspace.beforeGitContentDigest = DIGESTS.attack;
  assertProtocolRefusal(
    () => applyExecutionEvent(reported, eventFor(reported, {
      eventId: "event-wrong-workspace-baseline",
      kind: "worker-observation-recorded",
      observation: wrongWorkspace
    })),
    "a Worker Observation cannot substitute the workspace baseline",
    "WORKER_EXECUTION_BINDING_MISMATCH"
  );

  const unsupportedRequestedInput = structuredClone(specificationInput);
  unsupportedRequestedInput.executionId = "execution-unsupported-requested";
  unsupportedRequestedInput.capabilityProfile.requested.push("network");
  const unsupportedSpecification = compileWorkSpecification(unsupportedRequestedInput);
  const unsupportedPrepared = createExecutionRecord(unsupportedSpecification);
  const unsupportedRunning = applyExecutionEvent(unsupportedPrepared, eventFor(unsupportedPrepared, {
    eventId: "event-unsupported-started",
    kind: "execution-started"
  }));
  const unsupportedReported = applyExecutionEvent(unsupportedRunning, eventFor(unsupportedRunning, {
    eventId: "event-unsupported-report",
    kind: "worker-report-submitted",
    report: validWorkerReport(unsupportedSpecification)
  }));
  const unsupportedAllowed = validWorkerObservation({
    workSpecification: unsupportedSpecification,
    reportDigest: unsupportedReported.workerReport.workerReportDigest
  });
  assertProtocolRefusal(
    () => applyExecutionEvent(unsupportedReported, eventFor(unsupportedReported, {
      eventId: "event-unsupported-allowed",
      kind: "worker-observation-recorded",
      observation: unsupportedAllowed
    })),
    "an unsupported capability cannot be reported as allowed",
    "WORKER_EXECUTION_CAPABILITY_CONTRADICTORY"
  );

  assertProtocolRefusal(
    () => applyExecutionEvent(completed, eventFor(completed, {
      eventId: "event-after-terminal",
      kind: "context-expansion-requested",
      request: expansionRequest
    })),
    "a terminal Execution Record rejects late events",
    "WORKER_EXECUTION_TERMINAL"
  );

  const oversizedReport = validWorkerReport(workSpecification);
  oversizedReport.summary = "x".repeat(specificationInput.capabilityProfile.limits.reportBytes + 1);
  assertProtocolRefusal(
    () => applyExecutionEvent(running, eventFor(running, {
      eventId: "event-oversized-report",
      kind: "worker-report-submitted",
      report: oversizedReport
    })),
    "the declared Report byte limit is enforced",
    "WORKER_EXECUTION_LIMIT_EXCEEDED"
  );
  const tooManyArtifacts = validWorkerReport(workSpecification);
  tooManyArtifacts.artifactRefs = [
    artifactRef("artifact-1", DIGESTS.artifact),
    artifactRef("artifact-2", DIGESTS.afterGit),
    artifactRef("artifact-3", DIGESTS.attack)
  ];
  assertProtocolRefusal(
    () => applyExecutionEvent(running, eventFor(running, {
      eventId: "event-too-many-artifacts",
      kind: "worker-report-submitted",
      report: tooManyArtifacts
    })),
    "the declared artifact reference limit is enforced",
    "WORKER_EXECUTION_LIMIT_EXCEEDED"
  );
});

function validSpecificationInput() {
  return {
    executionId: "execution-conformance-1",
    attempt: 1,
    change: {
      id: "change-worker-interface",
      primaryModuleRef: "worker-execution",
      changeKind: "implementation",
      planRefs: ["LGT-020"],
      claimRefs: ["worker-execution-conformance-is-deterministic-and-fail-closed"],
      governanceBaselineDigest: DIGESTS.governance,
      baselineGitContentDigest: DIGESTS.baselineGit,
      compilationDigest: DIGESTS.compilation
    },
    intent: {
      title: "Exercise one bounded Worker Execution",
      request: "Produce one structured Worker Report under an observed-only capability profile.",
      nonGoals: ["Acceptance", "Provider transcript persistence"]
    },
    context: {
      capsuleDigest: DIGESTS.context,
      readScopeDigest: DIGESTS.readScope,
      writeScopeDigest: DIGESTS.writeScope
    },
    capabilityProfile: {
      ref: "local-observed-only-v1",
      sourceDigest: DIGESTS.capabilityProfile,
      requested: ["filesystem-read", "filesystem-write", "process"],
      controls: {
        filesystemRead: "observed-only",
        filesystemWrite: "observed-only",
        process: "observed-only",
        network: "unsupported",
        secrets: "unsupported"
      },
      limits: {
        wallTimeMs: 60_000,
        expansionRequests: 2,
        artifactRefs: 2,
        reportBytes: 16 * 1024
      }
    }
  };
}

function validWorkerReport(workSpecification) {
  return {
    disposition: "completed",
    summary: "The bounded change was implemented and is ready for independent verification.",
    deltas: [{ path: "src/worker-execution/protocol.mjs", kind: "modified" }],
    decisions: [],
    blockers: [],
    risks: [{
      id: "risk-self-ratification",
      statement: "Worker-reported completion is not acceptance Evidence.",
      relatedRefs: []
    }],
    artifactRefs: [artifactRef("artifact-patch", DIGESTS.artifact)],
    contextExpansionRequestDigests: [],
    finalContextCapsuleDigest: workSpecification.context.capsuleDigest,
    finalCapabilityProfileDigest: workSpecification.capabilityProfile.digest
  };
}

function validWorkerObservation({ workSpecification, reportDigest }) {
  return {
    runtime: {
      kind: "process-observation-reference-v1",
      observationDigest: DIGESTS.runtimeObservation,
      supportStatus: "supported",
      controlKind: "none",
      termination: {
        kind: "exited",
        exitCode: 0,
        signal: null,
        closeConfirmed: true
      },
      stdout: {
        observedBytes: 128,
        observedDigest: DIGESTS.stdout,
        truncated: false,
        complete: true
      },
      stderr: {
        observedBytes: 0,
        observedDigest: DIGESTS.stderr,
        truncated: false,
        complete: true
      }
    },
    capabilityObservations: workSpecification.capabilityProfile.requested.map((capabilityRef) => ({
      capabilityRef,
      outcome: "allowed"
    })),
    workspace: {
      beforeGitContentDigest: workSpecification.change.baselineGitContentDigest,
      afterGitContentDigest: DIGESTS.afterGit
    },
    reportDigest
  };
}

function artifactRef(id, digestValue) {
  return {
    id,
    digest: digestValue,
    mediaType: "application/json",
    bytes: 128
  };
}

function eventFor(record, value) {
  return {
    schemaVersion: 1,
    eventId: value.eventId,
    executionRef: record.executionId,
    sequence: record.nextSequence,
    priorRecordDigest: record.executionRecordDigest,
    ...value
  };
}

function assertCanonicalDocument(value) {
  const canonical = validateWorkerExecutionDocument(value);
  assert.deepEqual(canonical, value);
  assert.equal(Object.isFrozen(canonical), true);
  return canonical;
}

function assertProtocolRefusal(operation, message, expectedCode) {
  assert.throws(
    operation,
    (error) => error?.code === expectedCode,
    message
  );
}
