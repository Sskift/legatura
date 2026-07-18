import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { parseHTML } from "linkedom";

import { ARCHITECTURE_PROFILE_LIMITS } from "../../src/core/architecture-profile.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import { createServer } from "../../src/server.mjs";
import {
  ARCHITECTURE_PROFILE_VIEW_MODEL_LIMITS,
  compileArchitectureProfileWindowViewModel,
  compileArchitectureProfileViewModel
} from "../../src/workbench-view-model.mjs";
import {
  createProfileWindowController,
  receiveArchitectureProfileWindowViewModel
} from "../../public/profile-window-controller.js";
import {
  architectureProfileDimension,
  compileWorkbenchAcceptanceRequest,
  receiveArchitectureProfileViewModel,
  receiveWorkbenchProjection,
  refreshAfterMutation,
  selectWorkbenchAction,
  selectWorkbenchAcceptanceInputRequirements,
  selectWorkbenchAuthoringModules,
  selectWorkbenchClaimOptions,
  selectWorkbenchChangeKindAuthoring,
  selectWorkbenchChangeKinds,
  selectWorkbenchPlanOutcomes,
  WORKBENCH_BROWSER_PROJECTION_INTEGRITY_PROOF_VERSION
} from "../../public/workbench-adapter.js";

export const ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION = 1;
export const WORKBENCH_INPUT_REQUIREMENTS_PROOF_VERSION = 1;
export { WORKBENCH_BROWSER_PROJECTION_INTEGRITY_PROOF_VERSION };

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

  const secondProfile = structuredClone(profile);
  secondProfile.entities.changes[0].id = "change-2";
  for (const item of secondProfile.entities.evidence) item.changeRef = "change-2";
  reseal(secondProfile);
  const opaqueCursor = "opaque/profile-window?proof=secret-sentinel";
  const firstWindow = createProfileWindow(profile, {
    offset: 0,
    hasMore: true,
    cursor: opaqueCursor
  });
  const secondWindow = createProfileWindow(secondProfile, { offset: 1 });
  const mismatchedProfile = structuredClone(secondProfile);
  mismatchedProfile.source.changeStoreDigest = canonicalDigest("mismatched-change-store");
  reseal(mismatchedProfile);
  const mismatchedWindow = createProfileWindow(mismatchedProfile, { offset: 1 });
  const expectedFirstWindow = compileArchitectureProfileWindowViewModel(firstWindow);
  const expectedSecondWindow = compileArchitectureProfileWindowViewModel(secondWindow);

  const publicDir = await mkdtemp(path.join(os.tmpdir(), "legatura-profile-view-"));
  await writeFile(path.join(publicDir, "index.html"), "<!doctype html><title>Legatura</title>");
  t.after(() => rm(publicDir, { recursive: true, force: true }));
  const authoringWorkbench = createWorkbenchProjection(profile.source);
  const selectedWorkbench = createWorkbenchProjection(profile.source, "change-1");
  const calls = [];
  let profileMode = "normal";
  const server = createServer({
    publicDir,
    kernel: {
      async inspectArchitectureProfileWindow(input) {
        calls.push(["inspectArchitectureProfileWindow", structuredClone(input)]);
        if (!Object.hasOwn(input, "cursor") && profileMode === "initial-failure") {
          const error = new Error("Initial Profile source is unavailable.");
          error.code = "ARCHITECTURE_PROFILE_SOURCE_UNSTABLE";
          error.statusCode = 409;
          throw error;
        }
        if (!Object.hasOwn(input, "cursor")) return firstWindow;
        assert.equal(input.cursor, opaqueCursor, "HTTP forwards the continuation as one opaque value");
        if (profileMode === "mismatched-source") return mismatchedWindow;
        if (profileMode === "stale-cursor") {
          const error = new Error(`Continuation expired: ${opaqueCursor}`);
          error.code = `ARCHITECTURE_PROFILE_CURSOR_EXPIRED_${opaqueCursor}`;
          error.statusCode = 410;
          error.details = { cursor: opaqueCursor, private: "must not render" };
          throw error;
        }
        return secondWindow;
      },
      async inspectWorkbenchProjection(input) {
        calls.push(["inspectWorkbenchProjection", structuredClone(input)]);
        return input.changeRef === "change-1" ? selectedWorkbench : authoringWorkbench;
      }
    }
  });
  t.after(() => server.close());
  const address = await server.listen(0);
  const profilePayload = await requestJson(address.url, "/api/architecture-profile");
  const authoringPayload = await requestJson(address.url, "/api/workbench");
  const selectedPayload = await requestJson(address.url, "/api/workbench?changeRef=change-1");
  assert.deepEqual(profilePayload, expectedFirstWindow);
  assert.deepEqual(authoringPayload, authoringWorkbench);
  assert.deepEqual(
    selectedPayload,
    selectedWorkbench,
    "HTTP preserves selectable Claims, exact routes, actions, and disabled reasons without recompilation"
  );
  assert.deepEqual(calls.slice(0, 3), [
    ["inspectArchitectureProfileWindow", {}],
    ["inspectWorkbenchProjection", {}],
    ["inspectWorkbenchProjection", { changeRef: "change-1" }]
  ]);

  assert.equal(WORKBENCH_BROWSER_PROJECTION_INTEGRITY_PROOF_VERSION, 1);
  const browserWindow = await receiveArchitectureProfileWindowViewModel(profilePayload);
  const browserProfile = browserWindow.page;
  const browserAuthoring = await receiveWorkbenchProjection(authoringPayload);
  const browserWorkbench = await receiveWorkbenchProjection(selectedPayload);
  assert.strictEqual(
    architectureProfileDimension(browserProfile, "evidence"),
    browserProfile.dimensions.evidence,
    "the browser adapter selects the exact canonical dimension"
  );
  assert.strictEqual(
    selectWorkbenchAuthoringModules(browserAuthoring),
    browserAuthoring.authoring.modules,
    "the browser adapter preserves every authoring fact and its order"
  );
  assert.strictEqual(
    selectWorkbenchPlanOutcomes(browserAuthoring),
    browserAuthoring.authoring.planOutcomes,
    "Plan Outcomes cross the receiver seam without browser reconstruction"
  );
  assert.strictEqual(
    selectWorkbenchChangeKinds(browserAuthoring),
    browserAuthoring.authoring.changeKinds,
    "the closed Change-kind collection is preserved as one Kernel-owned value"
  );
  assert.strictEqual(
    selectWorkbenchChangeKindAuthoring(browserAuthoring, "implementation"),
    browserAuthoring.authoring.changeKinds[0],
    "Change-kind cardinality and eligibility remain Kernel-owned"
  );
  const implementationClaimOptions = selectWorkbenchClaimOptions(browserAuthoring, {
    changeKind: "implementation",
    planRefs: ["LGT-001", "LGT-099"],
    moduleRef: "module-1"
  });
  assert.strictEqual(
    implementationClaimOptions,
    browserAuthoring.authoring.claimSelectionRoutes.find((route) => (
      route.changeKindRef === "implementation"
        && route.outcomeRef === null
        && route.moduleRef === "module-1"
    )).claimOptions,
    "non-integrity authoring selects the exact Kernel null-Outcome route without merging Plan facts"
  );
  const integrityClaimOptions = selectWorkbenchClaimOptions(browserAuthoring, {
    changeKind: "regression-repair",
    planRefs: ["LGT-099"],
    moduleRef: "module-1"
  });
  assert.strictEqual(
    integrityClaimOptions,
    browserAuthoring.authoring.claimSelectionRoutes.find((route) => (
      route.changeKindRef === "regression-repair"
        && route.outcomeRef === "LGT-099"
        && route.moduleRef === "module-1"
    )).claimOptions,
    "integrity authoring returns the exact source-bound Claim option collection"
  );
  assert.deepEqual(integrityClaimOptions[1], {
    claimRef: "claim-2",
    selectable: false,
    disabledReasonCodes: ["CLAIM_NOT_PROTECTED_BY_SELECTED_OUTCOME"]
  });
  assert.equal(selectWorkbenchClaimOptions(browserAuthoring, {
    changeKind: "regression-repair",
    planRefs: [],
    moduleRef: "module-1"
  }), null, "an incomplete integrity key fails closed instead of combining routes");
  const matchingChange = {
    id: "change-1",
    observation: { sourceSnapshotDigest: browserWorkbench.source.snapshotDigest }
  };
  assert.strictEqual(
    selectWorkbenchAction(browserWorkbench, matchingChange, "gates"),
    browserWorkbench.changes[0].actions.gates,
    "the browser adapter returns the Kernel action object without rebuilding eligibility"
  );
  assert.strictEqual(
    selectWorkbenchAcceptanceInputRequirements(browserWorkbench, matchingChange),
    browserWorkbench.changes[0].actions.accept.inputRequirements,
    "acceptance fields and bindings cross the receiver seam as one canonical object"
  );
  assert.equal(Object.isFrozen(browserAuthoring.authoring.modules[0].claims[0].acceptanceRoutes[0]), true);
  assert.throws(
    () => { browserAuthoring.authoring.modules[0].claims[0].selectable = false; },
    TypeError,
    "validated Workbench semantics cannot be rewritten after the receiver seam"
  );
  const readyProjection = createWorkbenchProjection(profile.source, "change-1");
  const readyAccept = readyProjection.changes[0].actions.accept;
  readyAccept.enabled = true;
  readyAccept.disabledReasonCodes = [];
  const readyRequirements = readyAccept.inputRequirements;
  readyRequirements.available = true;
  readyRequirements.disabledReasonCodes = [];
  readyRequirements.binding.verificationSubjectDigest = canonicalDigest("verification-subject");
  readyRequirements.knowledgeClosure.allowedModes = ["entries"];
  readyRequirements.knowledgeClosure.requiredModelAmendmentRefs = [
    ".legatura/knowledge-gaps.json"
  ];
  readyRequirements.knowledgeClosure.selectableKnowledgeGapRefs = ["gap-1"];
  readyRequirements.authorityDecision.decisionOptions = [{
    authorityRef: "module-maintainer",
    decisionType: "normative-amendment",
    requiredFields: ["amendmentRefs", "decidedBy", "rationale"]
  }];
  readyRequirements.authorityDecision.requiredAmendmentRefs = [
    ".legatura/knowledge-gaps.json"
  ];
  const { requirementsDigest: _requirementsDigest, ...readyRequirementContent } = readyRequirements;
  readyRequirements.requirementsDigest = canonicalDigest(readyRequirementContent);
  resealWorkbenchProjection(readyProjection);
  const readyWorkbench = await receiveWorkbenchProjection(readyProjection);
  const acceptanceRequest = compileWorkbenchAcceptanceRequest(
    readyWorkbench.changes[0].actions.accept.inputRequirements,
    {
      confirmed: true,
      decisionOptionIndex: 0,
      decidedBy: "actual-maintainer",
      decisionReason: "Approve the exact modeled amendment.",
      amendmentRefs: [],
      expiresAt: "",
      scope: "",
      compensatingControls: [],
      closureMode: "entries",
      closureRationale: "The new Gap is durable Project Model knowledge.",
      knowledgeGapRefs: ["gap-1"],
      ephemeralStatements: ["One bounded request-local observation."]
    }
  );
  assert.deepEqual(acceptanceRequest, {
    inputRequirementsConfirmation: {
      requirementsDigest: readyRequirements.requirementsDigest,
      binding: structuredClone(readyRequirements.binding),
    },
    knowledgeClosure: {
      status: "complete",
      entries: [
        {
          kind: "model-amendment",
          refs: [".legatura/knowledge-gaps.json"],
          rationale: "The new Gap is durable Project Model knowledge."
        },
        {
          kind: "model-gap",
          refs: ["gap-1"],
          rationale: "The new Gap is durable Project Model knowledge."
        },
        {
          kind: "ephemeral",
          statement: "One bounded request-local observation.",
          rationale: "The new Gap is durable Project Model knowledge."
        }
      ]
    },
    authorityDecision: {
      status: "approved",
      authority: "module-maintainer",
      decidedBy: "actual-maintainer",
      decisionType: "normative-amendment",
      rationale: "Approve the exact modeled amendment.",
      amendmentRefs: [".legatura/knowledge-gaps.json"]
    }
  });
  const mismatchedChange = structuredClone(matchingChange);
  mismatchedChange.observation.sourceSnapshotDigest = canonicalDigest("other-snapshot");
  assert.equal(
    selectWorkbenchAction(browserWorkbench, mismatchedChange, "accept"),
    null,
    "independently stable but mismatched detail and Workbench snapshots fail closed"
  );
  assert.equal(
    selectWorkbenchAcceptanceInputRequirements(browserWorkbench, mismatchedChange),
    null,
    "acceptance input requirements share the same source-matching fail-closed seam"
  );
  assert.throws(
    () => selectWorkbenchChangeKindAuthoring(browserAuthoring, "invented-kind"),
    hasCode("BROWSER_PROJECTION_INVALID")
  );

  const workbenchAttacks = [
    ["stale digest after Claim mutation", false, (value) => {
      value.authoring.modules[0].claims[0].statement = "mutated after the Kernel sealed it";
    }],
    ["missing Claim selection route after reseal", false, (value) => {
      value.authoring.claimSelectionRoutes.pop();
      resealWorkbenchProjection(value);
    }],
    ["missing Plan collection", false, (value) => { delete value.authoring.planOutcomes; }],
    ["missing closed Change kind", false, (value) => { value.authoring.changeKinds.pop(); }],
    ["unknown Change kind", false, (value) => { value.authoring.changeKinds[0].id = "feature"; }],
    ["forged nested Claim route", false, (value) => {
      value.authoring.modules[0].claims[0].acceptanceRoutes[0].routeDigest = "sha256:short";
    }],
    ["inconsistent compile action", true, (value) => {
      value.changes[0].actions.compile.enabled = false;
    }],
    ["overlapping Gate command partition", true, (value) => {
      value.changes[0].actions.gates[0].skippedCommandIds = ["exact-command"];
    }],
    ["unknown acceptance field", true, (value) => {
      value.changes[0].actions.accept.inputRequirements.browserGuess = true;
    }],
    ["forged source binding", true, (value) => {
      value.changes[0].actions.accept.inputRequirements.binding.sourceSnapshotDigest = canonicalDigest("forged");
    }],
    ["unknown Closure mode", true, (value) => {
      value.changes[0].actions.accept.inputRequirements.knowledgeClosure.allowedModes.push("assume");
    }],
    ["unknown Decision type", true, (value) => {
      value.changes[0].actions.accept.inputRequirements.authorityDecision
        .decisionOptions[0].decisionType = "green-light";
    }],
    ["invalid requirements digest", true, (value) => {
      value.changes[0].actions.accept.inputRequirements.requirementsDigest = "sha256:short";
    }]
  ];
  for (const [label, selected, mutate] of workbenchAttacks) {
    const attacked = createWorkbenchProjection(profile.source, selected ? "change-1" : null);
    mutate(attacked);
    await assert.rejects(
      receiveWorkbenchProjection(attacked),
      hasCode("BROWSER_PROJECTION_INVALID"),
      label
    );
  }

  const { document, window } = parseHTML(`<!doctype html><body>
    <ol id="profile-page"></ol>
    <span id="profile-status"></span>
    <span id="profile-error" hidden></span>
    <button id="profile-next" type="button">Next</button>
  </body>`);
  const pageElement = document.querySelector("#profile-page");
  const statusElement = document.querySelector("#profile-status");
  const errorElement = document.querySelector("#profile-error");
  const nextElement = document.querySelector("#profile-next");
  const controller = createProfileWindowController({
    fetchJson: (url) => requestJson(address.url, url),
    renderPage(page) {
      pageElement.replaceChildren(...page.context.changes.map((change) => {
        const item = document.createElement("li");
        item.textContent = change.id;
        return item;
      }));
    },
    clearPage() {
      pageElement.replaceChildren();
    },
    elements: { status: statusElement, error: errorElement, next: nextElement }
  });
  let pendingClick;
  nextElement.addEventListener("click", () => { pendingClick = controller.next(); });

  assert.equal((await controller.refresh()).status, "rendered");
  assert.equal(pageElement.textContent, "change-1");
  assert.equal(nextElement.disabled, false);
  nextElement.dispatchEvent(new window.Event("click"));
  await pendingClick;
  assert.equal(
    pageElement.textContent,
    "change-2",
    "the successor replaces the current DOM page instead of accumulating records"
  );
  assert.equal(pageElement.querySelectorAll("li").length, 1);
  assert.equal(nextElement.hidden, true);
  assert.equal(controller.snapshot().current.windowDigest, expectedSecondWindow.windowDigest);

  profileMode = "mismatched-source";
  await controller.refresh();
  const mismatchedResult = await controller.next();
  assert.equal(mismatchedResult.status, "failed");
  assert.equal(pageElement.textContent, "change-1", "a mismatched successor leaves the prior page intact");
  assert.match(errorElement.textContent, /BROWSER_PROFILE_WINDOW_INVALID/u);

  profileMode = "normal";
  await controller.refresh();
  profileMode = "stale-cursor";
  const staleResult = await controller.next();
  assert.equal(staleResult.status, "failed");
  assert.equal(pageElement.textContent, "change-1");
  assert.doesNotMatch(errorElement.textContent, /secret-sentinel|private/u);
  assert.match(errorElement.textContent, /\[opaque continuation\]/u);
  await controller.refresh();
  assert.deepEqual(
    calls.at(-1),
    ["inspectArchitectureProfileWindow", {}],
    "refresh starts from the first window and never reuses a continuation"
  );
  profileMode = "initial-failure";
  const initialFailure = await controller.refresh();
  assert.equal(initialFailure.status, "failed");
  assert.equal(pageElement.textContent, "", "a failed initial refresh cannot leave stale Profile DOM");
  assert.equal(controller.snapshot().current, null);
  profileMode = "normal";

  const deferred = [];
  const renderedByGeneration = [];
  const guardedController = createProfileWindowController({
    fetchJson() {
      return new Promise((resolve) => deferred.push(resolve));
    },
    renderPage(page) {
      renderedByGeneration.push(page.context.changes[0].id);
    }
  });
  const lateRequest = guardedController.refresh();
  const currentRequest = guardedController.refresh();
  const replacementFirstWindow = compileArchitectureProfileWindowViewModel(
    createProfileWindow(secondProfile, { offset: 0 })
  );
  deferred[1](replacementFirstWindow);
  assert.equal((await currentRequest).status, "rendered");
  deferred[0](expectedFirstWindow);
  assert.equal((await lateRequest).status, "discarded");
  assert.deepEqual(renderedByGeneration, ["change-2"], "late responses cannot replace a newer page");

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

  const [browserSource, controllerSource, browserMarkup, browserStyles] = await Promise.all([
    readFile(new URL("../../public/app.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/profile-window-controller.js", import.meta.url), "utf8"),
    readFile(new URL("../../public/index.html", import.meta.url), "utf8"),
    readFile(new URL("../../public/styles.css", import.meta.url), "utf8")
  ]);
  assert.doesNotMatch(
    `${browserSource}\n${controllerSource}\n${browserMarkup}\n${browserStyles}`,
    /\b(?:overall|score|percentage|confidence|green.?light|health|readiness)\b|\/100/iu
  );
  assert.doesNotMatch(
    browserSource,
    /publicContracts|\.appliesTo|canCompile|canAccept|\.runnable|integrationGateIds/u,
    "browser source cannot regain raw Contract, Gate, or lifecycle compiler inputs"
  );
  assert.doesNotMatch(
    browserSource,
    /requirePlanRefs|allowedChangeKinds|activePlanOutcomes|selectablePlanOutcomes|outcomeRequired|integrityChangeKinds/u,
    "browser source cannot reconstruct Plan, Change-kind, or integrity eligibility"
  );
  assert.match(browserSource, /selectWorkbenchAction/u);
  assert.match(browserSource, /selectWorkbenchClaimOptions/u);
  assert.match(browserSource, /selectWorkbenchChangeKindAuthoring/u);
  assert.match(browserSource, /selectWorkbenchAcceptanceInputRequirements/u);
  assert.match(browserSource, /body:\s*JSON\.stringify\(acceptanceRequest\)/u);
  assert.doesNotMatch(browserSource, /decidedBy:\s*authority\b/u);
  assert.match(browserSource, /refreshCanonicalStateAfterMutation/u);
  assert.match(browserSource, /workbench\?changeRef=/u);
  assert.match(browserSource, /createProfileWindowController/u);
  assert.match(controllerSource, /clearPage\(\);/u);
  assert.doesNotMatch(browserSource, /protectedClaimRefs|protectedForIncident/u);
  assert.match(browserMarkup, /accept-decision-option/u);
  assert.match(browserMarkup, /accept-closure-mode/u);
  assert.doesNotMatch(controllerSource, /\b(?:atob|btoa)\b|base64|JSON\.parse\([^)]*cursor/iu);

  view.dimensions.outcomes[0].statement = "caller mutation";
  view.relations.outcomeClaims.length = 0;
  assert.deepEqual(profile, original, "returned view does not alias caller-owned Profile facts");
});

test("Local Workbench rejects forged, ambiguous, non-JSON, or unbounded Profiles", async () => {
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

  const resealedAggregateView = compileArchitectureProfileViewModel(createProfile());
  resealedAggregateView.dimensions.evidence[0].overall = "green";
  resealViewModel(resealedAggregateView);
  await assert.rejects(
    receiveArchitectureProfileViewModel(resealedAggregateView),
    hasCode("BROWSER_PROJECTION_INVALID"),
    "a digest-valid nested aggregate still fails at the browser receiver"
  );

  const windowAggregateProfile = createProfile();
  windowAggregateProfile.entities.evidence[0].confidence = 0.99;
  reseal(windowAggregateProfile);
  assert.throws(
    () => compileArchitectureProfileWindowViewModel(
      createProfileWindow(windowAggregateProfile)
    ),
    (error) => error?.code === "ARCHITECTURE_PROFILE_VIEW_AGGREGATE_FORBIDDEN"
      && error?.details?.key === "confidence",
    "the bounded window seam cannot reintroduce aggregate assurance"
  );

  const canonicalWindow = compileArchitectureProfileWindowViewModel(
    createProfileWindow(createProfile(), {
      hasMore: true,
      cursor: "opaque-attack-table-cursor"
    })
  );
  const differentlyOrderedProfile = createProfile();
  differentlyOrderedProfile.entities.changes.push({
    id: "change-2",
    state: "Candidate",
    primaryModuleRef: "module-1"
  });
  reseal(differentlyOrderedProfile);
  const differentlyOrderedWindow = createProfileWindow(differentlyOrderedProfile, { limit: 2 });
  differentlyOrderedWindow.window.recordRefs.reverse();
  const {
    windowDigest: _oldWindowDigest,
    continuation: _continuation,
    ...differentlyOrderedContent
  } = differentlyOrderedWindow;
  differentlyOrderedWindow.windowDigest = canonicalDigest(differentlyOrderedContent);
  await assert.doesNotReject(receiveArchitectureProfileWindowViewModel(
    compileArchitectureProfileWindowViewModel(differentlyOrderedWindow)
  ), "Profile canonical entity order need not duplicate the Kernel record-window order");
  const browserEnvelopeAttacks = [
    ["aggregate envelope", (value) => { value.score = 100; }],
    ["mismatched source", (value) => {
      value.source.changeStoreDigest = canonicalDigest("forged-source");
    }],
    ["mismatched record", (value) => { value.window.recordRefs[0].id = "other-change"; }],
    ["non-canonical expiry", (value) => {
      value.continuation.expiresAt = "2026-07-18T12:05:00Z";
    }]
  ];
  for (const [label, mutate] of browserEnvelopeAttacks) {
    const attacked = structuredClone(canonicalWindow);
    mutate(attacked);
    await assert.rejects(
      receiveArchitectureProfileWindowViewModel(attacked),
      hasCode("BROWSER_PROFILE_WINDOW_INVALID"),
      label
    );
  }

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

function createProfileWindow(profile, {
  offset = 0,
  limit = 1,
  hasMore = false,
  cursor = null
} = {}) {
  const content = {
    schemaVersion: 1,
    proofVersion: ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION,
    kind: "architecture-profile-window",
    source: structuredClone(profile.source),
    window: {
      ordering: "change-id-v1",
      offset,
      limit,
      returned: profile.entities.changes.length,
      hasMore,
      recordRefs: profile.entities.changes.map(({ id }) => ({ id }))
    },
    page: structuredClone(profile)
  };
  return {
    ...content,
    windowDigest: canonicalDigest(content),
    continuation: hasMore
      ? { cursor, expiresAt: "2026-07-18T12:05:00.000Z" }
      : null
  };
}

async function requestJson(origin, requestPath) {
  const response = await fetch(new URL(requestPath, origin));
  const payload = await response.json();
  if (!response.ok) {
    const error = new Error(payload?.error?.message ?? `HTTP ${response.status}`);
    error.code = payload?.error?.code ?? response.status;
    error.details = payload?.error?.details;
    throw error;
  }
  return payload;
}

function createWorkbenchProjection(source, changeRef = null) {
  const planAuthoring = createWorkbenchPlanAuthoring();
  const claimSelectionRoutes = createWorkbenchClaimSelectionRoutes(planAuthoring);
  const content = {
    schemaVersion: 3,
    source: structuredClone(source),
    selection: { changeRef },
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
          acceptanceRoutes: [{
            gateId: "gate-1",
            commandId: "exact-command",
            routeRef: "route-1",
            routeDigest: canonicalDigest("route")
          }]
        }, {
          id: "claim-2",
          statement: "A second exact behavior remains governed.",
          contractRef: "contract-1",
          visibilityKinds: ["owned"],
          acceptanceRoutes: [{
            gateId: "gate-1",
            commandId: "second-command",
            routeRef: "route-2",
            routeDigest: canonicalDigest("second-route")
          }]
        }]
      }],
      ...planAuthoring,
      claimSelectionRoutes
    },
    changes: changeRef === null ? [] : [{
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
          disabledReasonCodes: ["CHANGE_NOT_COMPILED", "CHANGE_NOT_EVIDENCE_READY"],
          inputRequirements: createWorkbenchAcceptanceInputRequirements({
            changeRef,
            source,
            governanceBaselineDigest: canonicalDigest("baseline")
          })
        }
      }
    }]
  };
  return { ...content, projectionDigest: canonicalDigest(content) };
}

function createWorkbenchPlanAuthoring() {
  const changeKind = ({
    id,
    selectable = true,
    selectableOutcomeRefs = [],
    minRefs = 1,
    maxRefs = 1,
    integrityRequired = false,
    protectedClaimRefsByOutcome = []
  }) => ({
    id,
    selectable,
    disabledReasonCodes: selectable ? [] : ["PLAN_OUTCOME_UNAVAILABLE"],
    planSelection: { minRefs, maxRefs, selectableOutcomeRefs },
    integrityIncident: { required: integrityRequired },
    protectedClaimRefsByOutcome
  });
  const internalChangeKinds = [
    changeKind({
      id: "implementation",
      minRefs: 1,
      maxRefs: 64,
      selectableOutcomeRefs: ["LGT-001"]
    }),
    changeKind({ id: "plan-amendment", minRefs: 0, maxRefs: 0 }),
    changeKind({
      id: "regression-repair",
      selectableOutcomeRefs: ["LGT-099"],
      integrityRequired: true,
      protectedClaimRefsByOutcome: [{
        outcomeRef: "LGT-099",
        claimRefs: ["claim-1"]
      }]
    }),
    ...[
      "security-containment",
      "data-integrity-repair",
      "acceptance-integrity-repair",
      "entrypoint-restoration"
    ].map((id) => changeKind({ id, selectable: false, integrityRequired: true }))
  ];
  return {
    schemaVersion: 2,
    planOutcomes: [
      { outcomeRef: "LGT-001", statement: "Implement one bounded fixture capability." },
      { outcomeRef: "LGT-099", statement: "Restore one protected fixture Claim." }
    ],
    changeKinds: internalChangeKinds.map(({ protectedClaimRefsByOutcome: ignored, ...kind }) => kind),
    protectionByChangeKind: new Map(internalChangeKinds.map((kind) => [
      kind.id,
      kind.protectedClaimRefsByOutcome
    ]))
  };
}

function createWorkbenchClaimSelectionRoutes(planAuthoring) {
  const routes = [];
  for (const changeKind of planAuthoring.changeKinds) {
    const protections = changeKind.integrityIncident.required
      ? planAuthoring.protectionByChangeKind.get(changeKind.id)
      : [{ outcomeRef: null, claimRefs: null }];
    for (const protection of protections) {
      const protectedRefs = protection.claimRefs === null ? null : new Set(protection.claimRefs);
      routes.push({
        changeKindRef: changeKind.id,
        outcomeRef: protection.outcomeRef,
        moduleRef: "module-1",
        claimOptions: ["claim-1", "claim-2"].map((claimRef) => {
          const disabledReasonCodes = protectedRefs === null || protectedRefs.has(claimRef)
            ? []
            : ["CLAIM_NOT_PROTECTED_BY_SELECTED_OUTCOME"];
          return {
            claimRef,
            selectable: disabledReasonCodes.length === 0,
            disabledReasonCodes
          };
        })
      });
    }
  }
  delete planAuthoring.protectionByChangeKind;
  return routes.sort((left, right) => [
    left.changeKindRef,
    left.outcomeRef ?? "",
    left.moduleRef
  ].join("\u0000").localeCompare([
    right.changeKindRef,
    right.outcomeRef ?? "",
    right.moduleRef
  ].join("\u0000")));
}

function createWorkbenchAcceptanceInputRequirements({
  changeRef,
  source,
  governanceBaselineDigest
}) {
  const content = {
    schemaVersion: 1,
    binding: {
      changeRef,
      sourceSnapshotDigest: source.snapshotDigest,
      governanceBaselineDigest,
      verificationSubjectDigest: null
    },
    available: false,
    disabledReasonCodes: ["CHANGE_NOT_COMPILED"],
    knowledgeClosure: {
      required: true,
      allowedModes: ["no-new-knowledge", "entries"],
      entryKinds: ["model-amendment", "model-gap", "ephemeral"],
      requiredModelAmendmentRefs: [],
      selectableKnowledgeGapRefs: [],
      requiredEntryFields: ["rationale"],
      referenceOrStatementRequired: true
    },
    authorityDecision: {
      required: true,
      decisionOptions: [{
        authorityRef: "module-maintainer",
        decisionType: "case-decision",
        requiredFields: ["decidedBy", "rationale"]
      }],
      requiredAmendmentRefs: [],
      requiredAdoptedChangePaths: [],
      requiredApprovedObligationIds: [],
      outOfScopePaths: []
    },
    confirmation: {
      required: true,
      bindingFields: [
        "changeRef",
        "sourceSnapshotDigest",
        "governanceBaselineDigest",
        "verificationSubjectDigest"
      ]
    }
  };
  return { ...content, requirementsDigest: canonicalDigest(content) };
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

function resealViewModel(viewModel) {
  const { viewModelDigest: ignored, ...content } = viewModel;
  viewModel.viewModelDigest = canonicalDigest(content);
}

function resealWorkbenchProjection(projection) {
  const { projectionDigest: ignored, ...content } = projection;
  projection.projectionDigest = canonicalDigest(content);
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
