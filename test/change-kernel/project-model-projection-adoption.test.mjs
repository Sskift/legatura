import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import inspector from "node:inspector/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { createKernel } from "../../src/core/index.mjs";
import {
  compileClaimGateRouteIndex,
  loadProjectModel,
  projectCompiledModuleClaimGateIndex,
  publicProjectModel
} from "../../src/core/project-model.mjs";

const execFileAsync = promisify(execFile);
const V1_OUTPUT = "frozen-v1-route";
const V2_OUTPUT = "current-v2-route";

test("Kernel consumes one Project Model Module Claim/Gate projection per stable source", async (t) => {
  const repoPath = await createFixture();
  t.after(() => rm(repoPath, { recursive: true, force: true }));

  const writer = createKernel({ repoPath });
  const exactCandidate = await writer.createChange({
    id: "frozen-exact",
    title: "Preserve the exact governed behavior",
    primaryModule: "core",
    claims: [{
      id: "exact-behavior",
      statement: "The exact governed behavior remains stable."
    }]
  });
  const exactCompiled = await writer.compileChange(exactCandidate.id, {
    knowledgeClosure: completeKnowledgeClosure()
  });

  const crossCandidate = await writer.createChange({
    id: "frozen-cross-source",
    title: "Use one explicit governed source route",
    primaryModule: "core",
    claims: [{
      id: "cross-target",
      statement: "The known unrouted behavior has an explicit source mapping."
    }]
  });
  const crossCompiled = await writer.compileChange(crossCandidate.id, {
    verificationObligations: [{
      id: "verify-cross-target",
      claimId: "cross-target",
      gateClaimRefs: ["source-behavior"],
      mappingRationale: "The fixture deliberately binds this target to one frozen deterministic source route.",
      applicability: "Only this fixture's Core Module and frozen source route.",
      discriminatoryPower: "A non-zero source command exit rejects the mapped target Claim."
    }],
    authorityDecision: {
      status: "approved",
      authority: "module-maintainer",
      decidedBy: "project-model-projection-adoption-test",
      decisionType: "case-decision",
      rationale: "Approve the exact fixture-only cross-Claim mapping.",
      approvedObligationIds: ["verify-cross-target"]
    },
    knowledgeClosure: completeKnowledgeClosure()
  });
  assert.equal(
    exactCompiled.governanceBaseline.digest,
    crossCompiled.governanceBaseline.digest,
    "N Changes share one frozen Governance Baseline"
  );

  await installCurrentV2(repoPath);
  await writer.createChange({
    id: "claimless-current",
    title: "Await a falsifiable Claim",
    primaryModule: "core",
    claims: []
  });

  const frozenModel = exactCompiled.governanceBaseline;
  const currentModel = publicProjectModel(await loadProjectModel(repoPath));
  const frozenProjection = directProjection(frozenModel, {
    moduleRefs: [],
    routeSelections: [{
      moduleRef: "core",
      claimRefs: ["cross-target", "exact-behavior", "source-behavior"]
    }]
  });
  const currentProjection = directProjection(currentModel, {
    moduleRefs: ["consumer", "core"],
    routeSelections: []
  });
  const frozenExactRoute = findRoute(frozenProjection, "core", "exact-behavior", "exact-proof");
  const frozenSourceRoute = findRoute(frozenProjection, "core", "source-behavior", "source-proof");
  const currentExactRoute = findRoute(currentProjection, "core", "exact-behavior", "exact-proof");
  const currentSourceRoute = findRoute(currentProjection, "core", "source-behavior", "source-proof");
  assert.notEqual(canonicalDigest(frozenExactRoute), canonicalDigest(currentExactRoute));
  assert.notEqual(canonicalDigest(frozenSourceRoute), canonicalDigest(currentSourceRoute));

  const counted = countingCommandRunner();
  const { value: projection, coverage } = await capturePreciseCoverage(() => (
    createKernel({ repoPath, commandRunner: counted.run }).inspectWorkbenchProjection({
      changeRef: exactCandidate.id
    })
  ));

  assert.equal(counted.observations(), 2, "one selected record shares one stable source query");
  assert.equal(
    functionCalls(coverage, "/src/core/change-compiler.mjs", "compileClaimGateRouteIndex"),
    2,
    "one current and one selected frozen product are compiled"
  );
  assert.equal(
    functionCalls(
      coverage,
      "/src/core/change-compiler.mjs",
      "projectCompiledModuleClaimGateIndex"
    ),
    2,
    "one current and one selected frozen Module projection serve the requested Change"
  );
  for (const obsoleteFunction of [
    "compileWorkbenchAcceptanceGateScopeIndex",
    "workbenchAcceptanceGateSelectsModule",
    "selectWorkbenchAcceptanceRoutes"
  ]) {
    assert.equal(
      functionCalls(coverage, "/src/core/kernel.mjs", obsoleteFunction),
      0,
      `${obsoleteFunction} must not recompile Project Model governance semantics`
    );
  }

  const coreAuthoring = findById(projection.authoring.modules, "core");
  const consumerAuthoring = findById(projection.authoring.modules, "consumer");
  assert.deepEqual(
    coreAuthoring.claims.map(projectWorkbenchClaimDescriptor),
    currentProjection.claimsByModule.get("core").map(projectModelClaimDescriptor),
    "current authoring visibility comes from the current Project Model projection"
  );
  assert.deepEqual(
    consumerAuthoring.claims.map(projectWorkbenchClaimDescriptor),
    currentProjection.claimsByModule.get("consumer").map(projectModelClaimDescriptor),
    "a removed dependency cannot remain visible through a Kernel-side Contract traversal"
  );
  assert.deepEqual(consumerAuthoring.claims.map((claim) => claim.id), ["consumer-behavior"]);

  const exactAuthoring = findById(coreAuthoring.claims, "exact-behavior");
  assert.deepEqual(
    exactAuthoring.acceptanceRoutes,
    currentProjection.routesByModule.get("core").get("exact-behavior")
      .map((route) => workbenchRoute("exact-behavior", route)),
    "route shape, order, and digest are adapted from the current Module projection"
  );
  assert.deepEqual(exactAuthoring.acceptanceRoutes.map((route) => route.gateId), ["minimum"]);
  assert.equal(
    exactAuthoring.acceptanceRoutes.some((route) => ["conflict", "full"].includes(route.gateId)),
    false,
    "parent/command conflicts and integration-only full routes cannot leak into authoring"
  );

  const exactActions = findById(projection.changes, exactCandidate.id).actions;
  const exactAnnotations = exactActions.gates.flatMap((gate) => gate.claimRouteAnnotations);
  assert.deepEqual(exactAnnotations, [{
    obligationRef: "verify-exact-behavior",
    targetClaimRef: "exact-behavior",
    sourceClaimRef: "exact-behavior",
    mappingKind: "exact-contract-claim",
    gateId: "minimum",
    commandId: "exact-proof",
    routeDigest: canonicalDigest(frozenExactRoute)
  }]);
  assert.notEqual(exactAnnotations[0].routeDigest, canonicalDigest(currentExactRoute));

  const crossProjection = await createKernel({ repoPath }).inspectWorkbenchProjection({
    changeRef: crossCandidate.id
  });
  const crossActions = findById(crossProjection.changes, crossCandidate.id).actions;
  const crossAnnotations = crossActions.gates.flatMap((gate) => gate.claimRouteAnnotations);
  assert.deepEqual(crossAnnotations, [{
    obligationRef: "verify-cross-target",
    targetClaimRef: "cross-target",
    sourceClaimRef: "source-behavior",
    mappingKind: "cross-claim",
    gateId: "minimum",
    commandId: "source-proof",
    routeDigest: canonicalDigest(frozenSourceRoute)
  }]);
  assert.notEqual(crossAnnotations[0].routeDigest, canonicalDigest(currentSourceRoute));

  assert.equal(exactActions.compile.enabled, true);
  assert.deepEqual(exactActions.compile.disabledReasonCodes, []);
  assert.equal(exactActions.accept.enabled, false);
  assert.deepEqual(exactActions.accept.disabledReasonCodes, ["CHANGE_NOT_EVIDENCE_READY"]);
  const claimlessProjection = await createKernel({ repoPath }).inspectWorkbenchProjection({
    changeRef: "claimless-current"
  });
  const claimlessActions = findById(claimlessProjection.changes, "claimless-current").actions;
  assert.deepEqual(claimlessActions.compile.disabledReasonCodes, ["CHANGE_CLAIM_REQUIRED"]);
  assert.deepEqual(claimlessActions.accept.disabledReasonCodes, [
    "CHANGE_CLAIM_REQUIRED",
    "CHANGE_NOT_COMPILED",
    "CHANGE_NOT_EVIDENCE_READY"
  ]);
});

function directProjection(model, options) {
  const claimRefs = model.contracts
    .flatMap((contract) => contract.claims)
    .map((claim) => claim.id);
  const product = compileClaimGateRouteIndex(model, { claimRefs });
  return projectCompiledModuleClaimGateIndex(product, { model, ...options });
}

function findRoute(projection, moduleRef, claimRef, commandId) {
  const route = projection.routesByModule.get(moduleRef).get(claimRef)
    .find((candidate) => candidate.commandId === commandId);
  assert.ok(route, `missing ${moduleRef}/${claimRef}/${commandId}`);
  return route;
}

function workbenchRoute(claimRef, route) {
  return {
    gateId: route.gateId,
    commandId: route.commandId,
    routeRef: `route-${canonicalDigest({
      claimRef,
      gateRef: route.gateId,
      commandRef: route.commandId
    }).slice(7)}`,
    routeDigest: canonicalDigest(route)
  };
}

function projectWorkbenchClaimDescriptor(claim) {
  return {
    claimRef: claim.id,
    statement: claim.statement,
    contractRef: claim.contractRef,
    visibilityKinds: claim.visibilityKinds
  };
}

function projectModelClaimDescriptor(claim) {
  return {
    claimRef: claim.claimRef,
    statement: claim.statement,
    contractRef: claim.contractRef,
    visibilityKinds: claim.visibilityKinds
  };
}

function findById(values, id) {
  const value = values.find((item) => item.id === id);
  assert.ok(value, `missing ${id}`);
  return value;
}

async function capturePreciseCoverage(operation) {
  const session = new inspector.Session();
  session.connect();
  let started = false;
  try {
    await session.post("Profiler.enable");
    await session.post("Profiler.startPreciseCoverage", { callCount: true, detailed: true });
    started = true;
    const value = await operation();
    const { result: coverage } = await session.post("Profiler.takePreciseCoverage");
    return { value, coverage };
  } finally {
    if (started) await session.post("Profiler.stopPreciseCoverage");
    await session.post("Profiler.disable");
    session.disconnect();
  }
}

function functionCalls(coverage, scriptSuffix, functionName) {
  const script = coverage.find((entry) => entry.url.endsWith(scriptSuffix));
  assert.ok(script, `missing precise coverage for ${scriptSuffix}`);
  return script.functions
    .filter((entry) => entry.functionName === functionName)
    .reduce((count, entry) => count + (entry.ranges[0]?.count ?? 0), 0);
}

function completeKnowledgeClosure() {
  return {
    status: "complete",
    noNewKnowledge: true,
    rationale: "The deterministic fixture introduces no durable project knowledge."
  };
}

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-pm-adoption-"));
  for (const directory of ["modules", "contracts", "gates"]) {
    await mkdir(path.join(repoPath, ".legatura", directory), { recursive: true });
  }
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "project-model-adoption-fixture", name: "Project Model Adoption Fixture" },
    authorities: {
      decision: [{ id: "module-maintainer", may: ["case-decision"] }],
      fact: [
        { id: "core-facts", module: "core", owns: "Core fixture facts" },
        { id: "consumer-facts", module: "consumer", owns: "Consumer fixture facts" }
      ]
    },
    assuranceBoundary: {
      governed: [
        { module: "core", reason: "Fixture" },
        { module: "consumer", reason: "Fixture" }
      ],
      provisional: [],
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
    factAuthority: "core-facts",
    publicContracts: ["core-behavior"]
  }));
  await writeJson(path.join(repoPath, ".legatura/modules/consumer.json"), moduleDocument({
    id: "consumer",
    factAuthority: "consumer-facts",
    publicContracts: ["consumer-contract"],
    dependencies: [{ module: "core", via: "core-behavior", access: "interface-only" }]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/core-behavior.json"), contractDocument({
    id: "core-behavior",
    owner: "core",
    consumers: ["consumer"],
    claims: [
      ["exact-behavior", "The exact governed behavior remains stable."],
      ["cross-target", "The known unrouted behavior has an explicit source mapping."],
      ["source-behavior", "The governed source behavior remains stable."]
    ]
  }));
  await writeJson(path.join(repoPath, ".legatura/contracts/consumer-contract.json"), contractDocument({
    id: "consumer-contract",
    owner: "consumer",
    claims: [["consumer-behavior", "The consumer behavior remains stable."]]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/minimum.json"), gateDocument({
    id: "minimum",
    appliesTo: ["core", "consumer"],
    commands: [
      commandDocument("exact-proof", ["core"], ["exact-behavior"], V1_OUTPUT),
      commandDocument("source-proof", ["core"], ["source-behavior"], V1_OUTPUT)
    ]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/conflict.json"), gateDocument({
    id: "conflict",
    appliesTo: ["consumer"],
    commands: [commandDocument("parent-excludes-core", ["core"], ["exact-behavior"])]
  }));
  await writeJson(path.join(repoPath, ".legatura/gates/full.json"), gateDocument({
    id: "full",
    appliesTo: "integration",
    commands: [{
      ...commandDocument("full-proof", ["core"], ["exact-behavior"]),
      applicability: { phase: "integration" }
    }]
  }));
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

async function installCurrentV2(repoPath) {
  const gatePath = path.join(repoPath, ".legatura/gates/minimum.json");
  const minimum = JSON.parse(await readFile(gatePath, "utf8"));
  for (const command of minimum.commands) {
    command.command = [process.execPath, "-e", `process.stdout.write(${JSON.stringify(V2_OUTPUT)})`];
    command.oracle = {
      kind: "fixture",
      description: `${command.id} observes the current V2 route.`
    };
  }
  await writeJson(gatePath, minimum);

  const consumerPath = path.join(repoPath, ".legatura/modules/consumer.json");
  const consumer = JSON.parse(await readFile(consumerPath, "utf8"));
  consumer.dependencies = [];
  await writeJson(consumerPath, consumer);
}

function moduleDocument({ id, factAuthority, publicContracts, dependencies = [] }) {
  return {
    schemaVersion: 1,
    id,
    name: id,
    status: "governed",
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
    claims: claims.map(([claimId, statement]) => ({ id: claimId, statement })),
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

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
