import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import {
  createKernel,
  WORKBENCH_DISABLED_REASON_CODES
} from "../../src/core/index.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";

const execFileAsync = promisify(execFile);
const PRIVATE_OUTPUT = "workbench-private-gate-output";

test("Kernel compiles one bounded canonical Workbench semantic projection", async (t) => {
  const repoPath = await createFixture();
  t.after(() => rm(repoPath, { recursive: true, force: true }));

  const writer = createKernel({ repoPath });
  const ready = await writer.createChange({
    id: "ready-change",
    title: "Prove core behavior",
    primaryModule: "core",
    claims: [{ id: "core-correct", statement: "Core behavior remains correct." }]
  });
  await writer.compileChange(ready.id, {
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The deterministic fixture introduces no durable project knowledge."
    }
  });
  const legacyGateResult = await writer.runGate(ready.id, "legacy");
  const legacyRun = legacyGateResult.gateRuns.find((run) => run?.gateId === "legacy");
  assert.equal(legacyRun?.status, "passed");
  assert.deepEqual(legacyRun?.selection?.selectedCommandIds, ["legacy"]);
  const gateResult = await writer.runGate(ready.id);
  assert.equal(gateResult.change.state, "EvidenceReady");

  // Persisted state is intentionally behind the pure current readiness projection.
  const readyPath = path.join(repoPath, ".legatura/runtime/changes/ready-change.json");
  const behind = JSON.parse(await readFile(readyPath, "utf8"));
  behind.state = "Submitted";
  await writeJson(readyPath, behind);

  await writer.createChange({
    id: "claimless-change",
    title: "Await a falsifiable Claim",
    primaryModule: "core",
    claims: []
  });

  const storeBefore = await snapshotStore(repoPath);
  const counted = countingCommandRunner();
  const projection = await createKernel({ repoPath, commandRunner: counted.run })
    .inspectWorkbenchProjection();

  assert.equal(counted.observations(), 2, "N Changes share one two-round stabilized source query");
  assert.deepEqual(await snapshotStore(repoPath), storeBefore, "Workbench inspection is read-only");
  assert.equal(Object.hasOwn(projection, "architectureProfile"), false);
  assert.deepEqual(Object.keys(projection.source).sort(), [
    "changeStoreDigest",
    "gitContentDigest",
    "projectModelDigest",
    "snapshotDigest"
  ]);
  for (const digest of [...Object.values(projection.source), projection.projectionDigest]) {
    assert.match(digest, /^sha256:[a-f0-9]{64}$/u);
  }
  const { projectionDigest, ...projectionContent } = projection;
  assert.equal(projectionDigest, canonicalDigest(projectionContent));

  const core = findById(projection.authoring.modules, "core");
  const consumer = findById(projection.authoring.modules, "consumer");
  const preview = findById(projection.authoring.modules, "preview");
  assert.deepEqual(core.claims.map((claim) => claim.id), ["core-correct", "core-unrouted"]);
  assert.deepEqual(
    consumer.claims.map((claim) => claim.id),
    ["consumer-correct", "core-correct", "core-unrouted"],
    "dependency Claims are visible exactly through dependencies[*].via"
  );
  assert.equal(
    core.claims.some((claim) => claim.id === "owner-only-hidden"),
    false,
    "Contract owner alone does not widen public authoring visibility"
  );
  assert.deepEqual(findById(consumer.claims, "core-correct").visibilityKinds, ["dependency"]);

  const coreCorrect = findById(core.claims, "core-correct");
  assert.equal(coreCorrect.selectable, true);
  assert.deepEqual(coreCorrect.disabledReasonCodes, []);
  assert.deepEqual(coreCorrect.acceptanceRoutes.map((route) => route.gateId), ["legacy", "minimum"]);
  assert.equal(
    coreCorrect.acceptanceRoutes.some((route) => route.gateId === "full"),
    false,
    "integration-only full Gate is not an acceptance authoring route"
  );
  assert.deepEqual(findById(core.claims, "core-unrouted").disabledReasonCodes, [
    "CLAIM_ACCEPTANCE_ROUTE_MISSING"
  ]);
  assert.deepEqual(findById(preview.claims, "preview-unrouted").disabledReasonCodes, [
    "MODULE_NOT_GOVERNED",
    "CLAIM_ACCEPTANCE_ROUTE_MISSING"
  ]);

  const readyActions = findById(projection.changes, "ready-change").actions;
  assert.deepEqual(readyActions.gates.map((gate) => gate.gateId), [
    "diagnostic",
    "foreign",
    "full",
    "legacy",
    "minimum"
  ]);
  assert.equal(readyActions.accept.enabled, true, "current readiness, not stale persisted state, selects accept");
  assert.deepEqual(readyActions.accept.disabledReasonCodes, []);
  const minimum = findGate(readyActions.gates, "minimum");
  assert.equal(minimum.enabled, true);
  assert.equal(minimum.claimRouteAnnotations.length, 1);
  assert.equal(minimum.claimRouteAnnotations[0].sourceClaimRef, "core-correct");
  const minimumAuthoringRoute = coreCorrect.acceptanceRoutes.find((route) => route.gateId === "minimum");
  assert.ok(minimumAuthoringRoute);
  assert.equal(
    minimum.claimRouteAnnotations[0].routeDigest,
    minimumAuthoringRoute.routeDigest,
    "frozen Verification Plan annotation and current authoring option share exact route semantics"
  );
  const profile = await createKernel({ repoPath }).inspectArchitectureProfile();
  const profileRoute = profile.entities.routes.find((route) => (
    route.claimRef === "core-correct"
      && route.gateRef === "minimum"
      && route.commandRef === "core-proof"
  ));
  assert.ok(profileRoute);
  assert.equal(
    minimumAuthoringRoute.routeDigest,
    profileRoute.routeDigest,
    "Workbench authoring and Architecture Profile use the same current route-product seam"
  );
  const diagnostic = findGate(readyActions.gates, "diagnostic");
  assert.equal(diagnostic.enabled, true, "runnable Gates are not pruned for lacking Claim annotations");
  assert.deepEqual(diagnostic.claimRouteAnnotations, []);
  const legacy = findGate(readyActions.gates, "legacy");
  assert.equal(legacy.enabled, true);
  assert.deepEqual(legacy.selectedCommandIds, ["legacy"]);
  assert.equal(legacy.claimRouteAnnotations[0]?.commandId, "legacy");
  assert.deepEqual(
    findGate(readyActions.gates, "full").claimRouteAnnotations,
    [],
    "raw full-Gate claimRefs cannot invent an annotation absent from the Verification Plan"
  );
  assert.deepEqual(findGate(readyActions.gates, "foreign").disabledReasonCodes, [
    "GATE_NOT_APPLICABLE",
    "GATE_COMMAND_NOT_APPLICABLE"
  ]);

  const claimless = findById(projection.changes, "claimless-change").actions;
  assert.deepEqual(claimless.accept.disabledReasonCodes, [
    "CHANGE_CLAIM_REQUIRED",
    "CHANGE_NOT_COMPILED",
    "CHANGE_NOT_EVIDENCE_READY"
  ]);
  assertWorkbenchReasonDiscipline(projection);

  const storeBeforeDrift = await snapshotStore(repoPath);
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const fixture = false;\n");
  const drifted = await createKernel({ repoPath }).inspectWorkbenchProjection();
  assert.deepEqual(
    findById(drifted.changes, "ready-change").actions.accept.disabledReasonCodes,
    ["CHANGE_NOT_EVIDENCE_READY"],
    "current Git drift overrides a persisted Submitted record whose old Evidence was once ready"
  );
  assert.deepEqual(await snapshotStore(repoPath), storeBeforeDrift, "readiness drift projection never saves");
  assertWorkbenchReasonDiscipline(drifted);

  const attacked = JSON.parse(await readFile(readyPath, "utf8"));
  const forgedFullRoute = { gateId: "full", commandId: "full-proof" };
  attacked.verificationPlan.obligations[0].mapping.routes.push(forgedFullRoute);
  attacked.verificationObligations[0].mapping.routes.push(forgedFullRoute);
  await writeJson(readyPath, attacked);
  const storeBeforeRejectedQuery = await snapshotStore(repoPath);
  await assert.rejects(
    createKernel({ repoPath }).inspectWorkbenchProjection(),
    (error) => error?.code === "WORKBENCH_VERIFICATION_PLAN_INVALID"
      && error?.statusCode === 422
  );
  assert.deepEqual(
    await snapshotStore(repoPath),
    storeBeforeRejectedQuery,
    "a forged Verification Plan fails closed without rewriting Store records"
  );
  const hidden = structuredClone(behind);
  const forgedUnmapped = {
    status: "unmapped",
    kind: "unmapped",
    reason: "No exact Contract Claim Gate mapping is declared; independent Evidence is required."
  };
  hidden.verificationPlan.obligations[0].mapping = forgedUnmapped;
  hidden.verificationObligations[0].mapping = forgedUnmapped;
  await writeJson(readyPath, hidden);
  const storeBeforeHiddenRouteQuery = await snapshotStore(repoPath);
  await assert.rejects(
    createKernel({ repoPath }).inspectWorkbenchProjection(),
    (error) => error?.code === "WORKBENCH_VERIFICATION_PLAN_INVALID"
  );
  assert.deepEqual(
    await snapshotStore(repoPath),
    storeBeforeHiddenRouteQuery,
    "an unmapped projection cannot hide an existing frozen acceptance route"
  );

  const serialized = JSON.stringify([projection, drifted]);
  for (const forbidden of [
    PRIVATE_OUTPUT,
    '"evidence":',
    '"package":',
    '"stdout":',
    '"stderr":',
    '"score":',
    '"percentage":',
    '"greenLight":',
    '"overall":',
    '"confidence":',
    '"health":',
    '"readiness":',
    '"command":',
    '"oracle":',
    '"observation":',
    '"output":'
  ]) {
    assert.equal(serialized.includes(forbidden), false, `projection leaked ${forbidden}`);
  }
  assert.ok(Buffer.byteLength(serialized, "utf8") < 128 * 1024);
});

function assertWorkbenchReasonDiscipline(value) {
  if (Array.isArray(value)) {
    for (const item of value) assertWorkbenchReasonDiscipline(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  if (Object.hasOwn(value, "disabledReasonCodes")) {
    assert.equal(Array.isArray(value.disabledReasonCodes), true);
    assert.equal(new Set(value.disabledReasonCodes).size, value.disabledReasonCodes.length);
    assert.deepEqual(
      value.disabledReasonCodes,
      WORKBENCH_DISABLED_REASON_CODES.filter((code) => value.disabledReasonCodes.includes(code))
    );
    if (value.enabled === false || value.selectable === false) {
      assert.ok(value.disabledReasonCodes.length > 0);
    } else {
      assert.deepEqual(value.disabledReasonCodes, []);
    }
  }
  for (const item of Object.values(value)) assertWorkbenchReasonDiscipline(item);
}

function findById(values, id) {
  const value = values.find((item) => item.id === id);
  assert.ok(value, `missing ${id}`);
  return value;
}

function findGate(values, gateId) {
  const value = values.find((item) => item.gateId === gateId);
  assert.ok(value, `missing Gate ${gateId}`);
  return value;
}

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-workbench-"));
  for (const directory of ["modules", "contracts", "gates"]) {
    await mkdir(path.join(repoPath, ".legatura", directory), { recursive: true });
  }
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "workbench-fixture", name: "Workbench Fixture" },
    authorities: {
      decision: [{ id: "module-maintainer", may: ["case-decision"] }],
      fact: [
        { id: "core-facts", module: "core", owns: "Core facts" },
        { id: "consumer-facts", module: "consumer", owns: "Consumer facts" },
        { id: "preview-facts", module: "preview", owns: "Preview facts" }
      ]
    },
    assuranceBoundary: {
      governed: [
        { module: "core", reason: "Fixture" },
        { module: "consumer", reason: "Fixture" }
      ],
      provisional: [{ module: "preview", reason: "Fixture" }],
      opaque: []
    },
    changePolicy: {
      defaultGate: "minimum",
      fullGate: "full",
      fullGateBefore: ["integrated"]
    }
  });
  await writeJson(path.join(repoPath, ".legatura/modules/core.json"), moduleDocument({
    id: "core",
    status: "governed",
    factAuthority: "core-facts",
    publicContracts: ["core-behavior"]
  }));
  await writeJson(path.join(repoPath, ".legatura/modules/consumer.json"), moduleDocument({
    id: "consumer",
    status: "governed",
    factAuthority: "consumer-facts",
    publicContracts: ["consumer-behavior"],
    dependencies: [{ module: "core", via: "core-behavior", access: "interface-only" }]
  }));
  await writeJson(path.join(repoPath, ".legatura/modules/preview.json"), moduleDocument({
    id: "preview",
    status: "provisional",
    factAuthority: "preview-facts",
    publicContracts: ["preview-behavior"]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/core-behavior.json"), contractDocument({
    id: "core-behavior",
    owner: "core",
    consumers: ["consumer"],
    claims: [
      { id: "core-correct", statement: "Core behavior remains correct." },
      { id: "core-unrouted", statement: "Core unrouted behavior is explicit." }
    ]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/consumer-behavior.json"), contractDocument({
    id: "consumer-behavior",
    owner: "consumer",
    claims: [{ id: "consumer-correct", statement: "Consumer behavior remains correct." }]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/preview-behavior.json"), contractDocument({
    id: "preview-behavior",
    owner: "preview",
    claims: [{ id: "preview-unrouted", statement: "Preview uncertainty stays explicit." }]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/owner-only.json"), contractDocument({
    id: "owner-only",
    owner: "core",
    claims: [{ id: "owner-only-hidden", statement: "Ownership alone does not expose this Claim." }]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/minimum.json"), gateDocument({
    id: "minimum",
    appliesTo: ["core", "consumer"],
    commands: [
      commandDocument("core-proof", ["core", "consumer"], ["core-correct"], PRIVATE_OUTPUT),
      commandDocument("consumer-proof", ["consumer"], ["consumer-correct"])
    ]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/diagnostic.json"), gateDocument({
    id: "diagnostic",
    appliesTo: ["core"],
    commands: [commandDocument("diagnose", ["core"], ["consumer-correct"])]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/foreign.json"), gateDocument({
    id: "foreign",
    appliesTo: ["consumer"],
    commands: [commandDocument("foreign-proof", ["consumer"], ["consumer-correct"])]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/full.json"), gateDocument({
    id: "full",
    appliesTo: "integration",
    commands: [{
      ...commandDocument("full-proof", ["core"], ["core-correct"]),
      applicability: { phase: "integration" }
    }]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/legacy.json"), {
    schemaVersion: 1,
    name: "legacy",
    purpose: "Legacy top-level Gate command fixture.",
    ...commandDocument("legacy", ["core"], ["core-correct"])
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), {
    schemaVersion: 1,
    gaps: []
  });
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const fixture = true;\n");
  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return repoPath;
}

function moduleDocument({ id, status, factAuthority, publicContracts, dependencies = [] }) {
  return {
    schemaVersion: 1,
    id,
    name: id,
    status,
    summary: `${id} fixture Module.`,
    factAuthority,
    decisionAuthority: "module-maintainer",
    interface: { accepts: ["request"], returns: ["result"] },
    paths: { include: [`src/${id}/**`], exclude: [] },
    publicContracts,
    dependencies
  };
}

function contractDocument({ id, owner, claims, consumers = [] }) {
  return {
    schemaVersion: 1,
    id,
    name: id,
    owner,
    maturity: "governed",
    normativeSources: [],
    claims,
    consumers
  };
}

function gateDocument({ id, appliesTo, commands }) {
  return {
    schemaVersion: 1,
    id,
    name: id,
    purpose: `${id} fixture Gate.`,
    appliesTo,
    commands
  };
}

function commandDocument(id, appliesTo, claimRefs, output = "") {
  return {
    id,
    appliesTo,
    command: [process.execPath, "-e", `process.stdout.write(${JSON.stringify(output)})`],
    timeoutMs: 30_000,
    claimRefs,
    oracle: { kind: "fixture", description: `${id} exits zero.` },
    applicability: { phase: "acceptance" },
    discriminatoryPower: { rejects: [`A non-zero exit rejects ${id}.`] },
    residualUncertainty: ["Only deterministic fixture behavior is observed."]
  };
}

function countingCommandRunner() {
  let observations = 0;
  return {
    async run(specification) {
      if (specification.purpose === "git-binding" && specification.args?.[0] === "rev-parse") {
        observations += 1;
      }
      try {
        const result = await execFileAsync(specification.command, specification.args ?? [], {
          cwd: specification.cwd,
          maxBuffer: 2 * 1024 * 1024
        });
        return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
      } catch (error) {
        return {
          exitCode: Number.isInteger(error?.code) ? error.code : 1,
          stdout: typeof error?.stdout === "string" ? error.stdout : "",
          stderr: typeof error?.stderr === "string" ? error.stderr : String(error)
        };
      }
    },
    observations: () => observations
  };
}

async function snapshotStore(repoPath) {
  const directory = path.join(repoPath, ".legatura/runtime/changes");
  const names = (await readdir(directory)).sort();
  return Promise.all(names.map(async (name) => {
    const filePath = path.join(directory, name);
    const [bytes, metadata] = await Promise.all([readFile(filePath, "utf8"), stat(filePath)]);
    return { name, bytes, modifiedAt: metadata.mtimeMs };
  }));
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
