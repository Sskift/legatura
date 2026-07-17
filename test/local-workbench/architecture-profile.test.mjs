import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { ARCHITECTURE_PROFILE_LIMITS } from "../../src/core/architecture-profile.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import { runCli } from "../../src/cli.mjs";
import { createServer } from "../../src/server.mjs";
import {
  ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS,
  compileArchitectureProfileViewModel
} from "../../src/workbench-view-model.mjs";
import {
  architectureProfileDimension,
  receiveArchitectureProfileViewModel,
  receiveWorkbenchProjection,
  refreshAfterMutation,
  selectWorkbenchAction,
  selectWorkbenchAuthoringModules
} from "../../public/workbench-adapter.js";

test("Local Workbench projects exact Profile dimensions and preserves Kernel Workbench actions", async (t) => {
  const profile = createProfile();
  const original = structuredClone(profile);
  const view = compileArchitectureProfileViewModel(profile);
  const repeated = compileArchitectureProfileViewModel(profile);

  assert.deepEqual(profile, original, "pure projection does not mutate Kernel facts");
  assert.deepEqual(repeated, view, "the same exact Profile has one deterministic view");
  assert.equal(view.schemaVersion, 1);
  assert.equal(view.profileRef, profile.profileDigest);
  assert.deepEqual(view.sourceRefs, profile.source);
  assert.deepEqual(Object.keys(view.dimensions), [
    "outcomes",
    "criteria",
    "claims",
    "gates",
    "evidence",
    "residualUncertainty",
    "knowledgeGaps"
  ]);
  assert.deepEqual(Object.keys(view.context), [
    "stages",
    "modules",
    "areas",
    "contracts",
    "changes",
    "routes"
  ]);
  assert.deepEqual(view.dimensions.outcomes.map(({ id }) => id), ["outcome-1"]);
  assert.deepEqual(view.dimensions.criteria.map(({ id }) => id), ["criterion-1"]);
  assert.deepEqual(view.dimensions.claims.map(({ id }) => id), ["claim-1"]);
  assert.deepEqual(view.dimensions.gates.map(({ id }) => id), ["gate-1"]);
  assert.deepEqual(
    view.dimensions.evidence.map(({ id, currency }) => ({ id, currency })),
    [
      { id: "evidence-current", currency: "current" },
      { id: "evidence-invalid", currency: "invalid" },
      { id: "evidence-sealed", currency: "sealed-historical" },
      { id: "evidence-stale", currency: "stale" }
    ]
  );
  assert.deepEqual(view.dimensions.residualUncertainty.map(({ id }) => id), ["residual-1"]);
  assert.deepEqual(view.dimensions.knowledgeGaps.map(({ id }) => id), ["gap-1"]);
  assert.deepEqual(view.context.routes.map(({ id }) => id), ["route-1"]);
  assert.deepEqual(
    view.context.routes[0].oracle,
    profile.entities.routes[0].oracle,
    "the adapter preserves compiler-accepted metadata instead of inventing a stricter policy"
  );
  assert.deepEqual(view.relations, profile.relations);

  const { viewModelDigest, ...content } = view;
  assert.equal(viewModelDigest, canonicalDigest(content));
  const inputEntityIds = Object.values(profile.entities).flat().map(({ id }) => id).sort();
  const outputEntityIds = [
    ...Object.values(view.dimensions),
    ...Object.values(view.context)
  ].flat().map(({ id }) => id).sort();
  assert.deepEqual(outputEntityIds, inputEntityIds, "every entity occurs in exactly one view collection");

  const serialized = JSON.stringify(view);
  for (const forbidden of [
    '"overall"',
    '"score"',
    '"percentage"',
    '"confidence"',
    '"greenLight"',
    '"health"',
    '"coverage"',
    '"package"',
    '"stdout"',
    '"stderr"',
    '"output"'
  ]) {
    assert.equal(serialized.includes(forbidden), false, `view leaked ${forbidden}`);
  }

  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-profile-view-"));
  await writeFile(path.join(publicDir, "index.html"), "<!doctype html><title>Legatura</title>");
  t.after(() => rm(publicDir, { recursive: true, force: true }));
  const workbench = createWorkbenchProjection(profile.source);
  const calls = [];
  const server = createServer({
    publicDir,
    kernel: {
      async inspectArchitectureProfile() {
        calls.push("inspectArchitectureProfile");
        return profile;
      },
      async inspectWorkbenchProjection() {
        calls.push("inspectWorkbenchProjection");
        return workbench;
      }
    }
  });
  t.after(() => server.close());
  const address = await server.listen(0);
  const profileResponse = await fetch(`${address.url}/api/architecture-profile`);
  const workbenchResponse = await fetch(`${address.url}/api/workbench`);
  assert.equal(profileResponse.status, 200);
  assert.equal(workbenchResponse.status, 200);
  const profilePayload = await profileResponse.json();
  const workbenchPayload = await workbenchResponse.json();
  assert.deepEqual(profilePayload, repeated);
  assert.deepEqual(
    workbenchPayload,
    workbench,
    "HTTP preserves selectable Claims, exact routes, actions, and disabled reasons without recompilation"
  );
  assert.deepEqual(calls, ["inspectArchitectureProfile", "inspectWorkbenchProjection"]);

  const browserProfile = receiveArchitectureProfileViewModel(profilePayload);
  const browserWorkbench = receiveWorkbenchProjection(workbenchPayload);
  assert.strictEqual(
    architectureProfileDimension(browserProfile, "evidence"),
    browserProfile.dimensions.evidence,
    "the browser adapter selects the exact canonical dimension"
  );
  assert.strictEqual(
    selectWorkbenchAuthoringModules(browserWorkbench),
    browserWorkbench.authoring.modules,
    "the browser adapter preserves every authoring fact and its order"
  );
  const matchingChange = {
    id: "change-1",
    observation: { sourceSnapshotDigest: browserWorkbench.source.snapshotDigest }
  };
  assert.strictEqual(
    selectWorkbenchAction(browserWorkbench, matchingChange, "gates"),
    browserWorkbench.changes[0].actions.gates,
    "the browser adapter returns the Kernel action object without rebuilding eligibility"
  );
  const mismatchedChange = structuredClone(matchingChange);
  mismatchedChange.observation.sourceSnapshotDigest = canonicalDigest("other-snapshot");
  assert.equal(
    selectWorkbenchAction(browserWorkbench, mismatchedChange, "accept"),
    null,
    "independently stable but mismatched detail and Workbench snapshots fail closed"
  );

  const refreshCalls = [];
  await refreshAfterMutation({
    async loadChangeDetail(id) { refreshCalls.push(["detail", id]); },
    async loadChanges(options) { refreshCalls.push(["changes", options]); },
    async loadWorkbench() { refreshCalls.push(["workbench"]); },
    async loadArchitectureProfile() { refreshCalls.push(["profile"]); },
    async loadProject() { refreshCalls.push(["project"]); }
  }, { detailId: "change-1", includeProject: true, preserveSelection: false });
  assert.deepEqual(refreshCalls, [
    ["detail", "change-1"],
    ["changes", { preserveSelection: false }],
    ["workbench"],
    ["profile"],
    ["project"]
  ]);

  let cliOutput = "";
  await runCli(
    ["inspect", publicDir, "--json"],
    {
      stdout: { write(value) { cliOutput += value; } },
      stderr: { write() {} },
      async realpath() { return publicDir; },
      async stat() { return { isDirectory: () => true }; }
    },
    {
      kernelFactory() {
        return { async inspectArchitectureProfile() { return profile; } };
      }
    }
  );
  assert.deepEqual(JSON.parse(cliOutput), repeated, "CLI emits the same exact bounded view model");

  const [browserSource, browserAdapterSource, browserMarkup, browserStyles] = await Promise.all([
    readFile(new URL("../../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/workbench-adapter.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../../public/styles.css", import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(
    `${browserSource}\n${browserAdapterSource}\n${browserMarkup}\n${browserStyles}`,
    /\b(?:overall|score|percentage|confidence|green.?light|health|readiness)\b|\/100/iu
  );
  assert.doesNotMatch(
    browserSource,
    /publicContracts|\.appliesTo|\.claimRefs|canCompile|canAccept|\.runnable|integrationGateIds/u,
    "browser source cannot regain raw Contract, Gate, or lifecycle compiler inputs"
  );
  assert.match(browserSource, /selectWorkbenchAction/u);
  assert.match(browserSource, /refreshCanonicalStateAfterMutation/u);

  view.dimensions.outcomes[0].statement = "caller mutation";
  view.relations.outcomeClaims.length = 0;
  assert.deepEqual(profile, original, "returned view does not alias caller-owned Profile facts");
});

test("Local Workbench rejects forged, ambiguous, non-JSON, or unbounded Profiles", () => {
  const forged = createProfile();
  forged.entities.outcomes[0].statement = "forged without rebinding the Profile digest";
  assert.throws(
    () => compileArchitectureProfileViewModel(forged),
    hasCode("ARCHITECTURE_PROFILE_VIEW_DIGEST_INVALID")
  );

  const duplicate = createProfile();
  duplicate.entities.claims.push(structuredClone(duplicate.entities.claims[0]));
  reseal(duplicate);
  assert.throws(
    () => compileArchitectureProfileViewModel(duplicate),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_INPUT_INVALID"
      && error?.details?.collection === "claims"
  );

  const aggregate = createProfile();
  aggregate.entities.evidence[0].overall = "green";
  reseal(aggregate);
  assert.throws(
    () => compileArchitectureProfileViewModel(aggregate),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_AGGREGATE_FORBIDDEN"
      && error?.details?.key === "overall"
  );

  const outputBody = createProfile();
  outputBody.entities.routes[0].observationBody = { detail: "private command output" };
  reseal(outputBody);
  assert.throws(
    () => compileArchitectureProfileViewModel(outputBody),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_AGGREGATE_FORBIDDEN"
      && error?.details?.key === "observationBody"
  );

  const unknownCurrency = createProfile();
  unknownCurrency.entities.evidence[0].currency = "probably-current";
  reseal(unknownCurrency);
  assert.throws(
    () => compileArchitectureProfileViewModel(unknownCurrency),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_INPUT_INVALID"
      && error?.details?.location.endsWith("currency")
  );

  const tooManyOutcomes = createProfile();
  tooManyOutcomes.entities.outcomes = Array.from({ length: 257 }, (_, index) => ({
    id: `outcome-${index}`,
    stageRef: "stage-1",
    status: "active",
    statement: `Outcome ${index}`
  }));
  reseal(tooManyOutcomes);
  assert.throws(
    () => compileArchitectureProfileViewModel(tooManyOutcomes),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_LIMIT_EXCEEDED"
      && error?.statusCode === 413
      && error?.details?.dimension === "outcomes"
      && error?.details?.limit === 256
  );

  const oversizedText = createProfile();
  oversizedText.entities.outcomes[0].statement = "x".repeat(
    ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS.textBytes + 1
  );
  reseal(oversizedText);
  assert.throws(
    () => compileArchitectureProfileViewModel(oversizedText),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_LIMIT_EXCEEDED"
      && error?.details?.dimension === "textBytes"
  );

  const accessor = createProfile();
  Object.defineProperty(accessor.entities.outcomes[0], "statement", {
    enumerable: true,
    get() {
      throw new Error("must not execute");
    }
  });
  assert.throws(
    () => compileArchitectureProfileViewModel(accessor),
    hasCode("ARCHITECTURE_PROFILE_VIEW_INPUT_INVALID")
  );

  const minimal = createProfile({ empty: true });
  assert.doesNotThrow(() => compileArchitectureProfileViewModel(minimal));

  const nearCeiling = createProfile({ empty: true });
  fillProfileContentToBytes(nearCeiling, ARCHITECTURE_PROFILE_LIMITS.profileBytes);
  reseal(nearCeiling);
  assert.ok(
    Buffer.byteLength(JSON.stringify(nearCeiling), "utf8")
      > ARCHITECTURE_PROFILE_LIMITS.profileBytes,
    "a legal core content ceiling gains a digest envelope before reaching Local Workbench"
  );
  assert.doesNotThrow(
    () => compileArchitectureProfileViewModel(nearCeiling),
    "Local Workbench reserves bounded space for the Kernel digest and view wrapper"
  );
});

function createProfile({ empty = false } = {}) {
  const source = {
    snapshotDigest: canonicalDigest("snapshot"),
    projectModelDigest: canonicalDigest("project-model"),
    gitContentDigest: canonicalDigest("git-content"),
    changeStoreDigest: canonicalDigest("change-store")
  };
  const entities = empty ? emptyEntities() : {
    stages: [{ id: "stage-1", name: "Stage One", status: "active" }],
    outcomes: [{
      id: "outcome-1",
      stageRef: "stage-1",
      status: "active",
      statement: "The exact capability is available."
    }],
    criteria: [{
      id: "criterion-1",
      outcomeRef: "outcome-1",
      statement: "The exact Claim has discriminating Evidence."
    }],
    modules: [{ id: "module-1", name: "Module One", status: "governed" }],
    areas: [{ id: "external-area", kind: "declared-gap-affect" }],
    contracts: [{
      id: "contract-1",
      name: "Contract One",
      ownerModuleRef: "module-1",
      maturity: "governed"
    }],
    changes: [{ id: "change-1", state: "Accepted", primaryModuleRef: "module-1" }],
    claims: [{
      id: "claim-1",
      contractRef: "contract-1",
      ownerModuleRef: "module-1",
      statement: "The governed behavior remains exact."
    }],
    gates: [{ id: "gate-1", name: "Exact Gate" }],
    routes: [{
      id: "route-1",
      claimRef: "claim-1",
      gateRef: "gate-1",
      commandRef: "exact-command",
      commandDigest: canonicalDigest("command"),
      routeDigest: canonicalDigest("route"),
      oracle: {
        kind: "exit",
        description: "A non-zero exit rejects the Claim.",
        command: "declared-command-label",
        observation: "declared-observation-shape",
        readiness: "declared-local-precondition"
      }
    }],
    evidence: [
      evidence("evidence-current", "current"),
      evidence("evidence-invalid", "invalid"),
      evidence("evidence-sealed", "sealed-historical"),
      evidence("evidence-stale", "stale")
    ],
    residuals: [{
      id: "residual-1",
      ownerKind: "evidence",
      ownerRef: "evidence-current",
      ordinal: 0,
      value: "Only the declared applicability was observed."
    }],
    gaps: [{
      id: "gap-1",
      status: "open",
      ownerRef: "module-maintainer",
      statement: "One durable uncertainty remains open."
    }]
  };
  const relations = empty ? emptyRelations() : {
    ...emptyRelations(),
    outcomeCriteria: [{ outcomeRef: "outcome-1", criterionRef: "criterion-1" }],
    outcomeClaims: [{ outcomeRef: "outcome-1", claimRef: "claim-1" }],
    outcomeGaps: [{ outcomeRef: "outcome-1", gapRef: "gap-1" }],
    criterionClaims: [{ criterionRef: "criterion-1", claimRef: "claim-1" }],
    criterionGaps: [{ criterionRef: "criterion-1", gapRef: "gap-1" }],
    gapProofClaims: [{ gapRef: "gap-1", claimRef: "claim-1" }],
    gapAffects: [{ gapRef: "gap-1", targetKind: "module", targetRef: "module-1" }],
    claimGateRoutes: [{ claimRef: "claim-1", routeRef: "route-1" }],
    routeModules: [{ routeRef: "route-1", moduleRef: "module-1" }],
    routeResiduals: [{ routeRef: "route-1", residualRef: "residual-1" }],
    currentEvidenceClaimAssociations: [{
      evidenceRef: "evidence-current",
      targetClaimRef: "claim-1",
      sourceClaimRef: "claim-1",
      routeRef: "route-1",
      associationKind: "direct",
      obligationRef: "verify-claim-1",
      obligationDigest: canonicalDigest("obligation")
    }],
    evidenceResiduals: [{ evidenceRef: "evidence-current", residualRef: "residual-1" }]
  };
  const content = { schemaVersion: 1, source, entities, relations };
  return { ...content, profileDigest: canonicalDigest(content) };
}

function evidence(id, currency) {
  return {
    id,
    evidenceRef: `source-${id}`,
    evidenceDigest: canonicalDigest(id),
    changeRef: "change-1",
    origin: currency === "sealed-historical" ? "sealed-package" : "current-record",
    currency,
    observationStatus: "passed",
    provenance: {
      kind: "gate-command",
      gateId: "gate-1",
      commandId: "exact-command"
    },
    claimEnvelopeRefs: ["claim-1"]
  };
}

function createWorkbenchProjection(source) {
  const content = {
    schemaVersion: 1,
    source: structuredClone(source),
    authoring: {
      modules: [{
        id: "module-1",
        name: "Module One",
        governanceStatus: "governed",
        selectable: true,
        disabledReasonCodes: [],
        claims: [{
          id: "claim-1",
          statement: "The governed behavior remains exact.",
          contractRef: "contract-1",
          visibilityKinds: ["owned"],
          selectable: true,
          disabledReasonCodes: [],
          acceptanceRoutes: [{
            gateId: "gate-1",
            commandId: "exact-command",
            routeRef: "route-1",
            routeDigest: canonicalDigest("route")
          }]
        }]
      }]
    },
    changes: [{
      id: "change-1",
      state: "Candidate",
      primaryModule: "module-1",
      governanceBaselineDigest: canonicalDigest("baseline"),
      actions: {
        compile: { kind: "compile", enabled: true, disabledReasonCodes: [] },
        gates: [{
          kind: "gate",
          gateId: "gate-1",
          name: "Exact Gate",
          enabled: false,
          disabledReasonCodes: ["CHANGE_NOT_COMPILED"],
          selectedCommandIds: ["exact-command"],
          skippedCommandIds: [],
          claimRouteAnnotations: []
        }],
        accept: {
          kind: "accept",
          enabled: false,
          disabledReasonCodes: ["CHANGE_NOT_COMPILED", "CHANGE_NOT_EVIDENCE_READY"]
        }
      }
    }]
  };
  return { ...content, projectionDigest: canonicalDigest(content) };
}

function emptyEntities() {
  return {
    stages: [],
    outcomes: [],
    criteria: [],
    modules: [],
    areas: [],
    contracts: [],
    changes: [],
    claims: [],
    gates: [],
    routes: [],
    evidence: [],
    residuals: [],
    gaps: []
  };
}

function emptyRelations() {
  return {
    outcomeCriteria: [],
    outcomeClaims: [],
    outcomeGaps: [],
    criterionClaims: [],
    criterionGaps: [],
    gapProofClaims: [],
    gapAffects: [],
    contributions: [],
    contributionClaims: [],
    claimGateRoutes: [],
    routeModules: [],
    routeResiduals: [],
    currentEvidenceClaimAssociations: [],
    historicalEvidenceClaimAssociations: [],
    evidenceResiduals: []
  };
}

function reseal(profile) {
  const { profileDigest: ignored, ...content } = profile;
  profile.profileDigest = canonicalDigest(content);
}

function fillProfileContentToBytes(profile, targetBytes) {
  let ordinal = 0;
  while (profileContentBytes(profile) < targetBytes - 4100) {
    profile.entities.areas.push({ id: `area-${ordinal}`, kind: "x".repeat(3000) });
    ordinal += 1;
  }
  const tail = { id: `area-${ordinal}`, kind: "" };
  profile.entities.areas.push(tail);
  const remaining = targetBytes - profileContentBytes(profile);
  assert.ok(remaining >= 0 && remaining <= 4096, `unexpected profile padding ${remaining}`);
  tail.kind = "x".repeat(remaining);
  assert.equal(profileContentBytes(profile), targetBytes);
}

function profileContentBytes(profile) {
  const { profileDigest: ignored, ...content } = profile;
  return Buffer.byteLength(JSON.stringify(content), "utf8");
}

function hasCode(code) {
  return (error) => error?.code === code;
}
