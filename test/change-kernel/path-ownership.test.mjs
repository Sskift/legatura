import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";

import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);
const CLAIM = {
  id: "feature-behavior-correct",
  statement: "The governed feature behavior remains correct."
};
const NARROWED_WRITE_SCOPE = {
  include: ["src/core/feature/**"],
  exclude: []
};
const SOURCE_BINDING_KEYS = [
  "assignmentDigest",
  "modelDigest",
  "ownershipPolicyDigest",
  "productDigest",
  "schemaVersion",
  "trackedPathFactsDigest"
];

test("Kernel enforces one digest-bound ownership product through a narrowed governed lifecycle", async (t) => {
  const repoPath = await createGovernedFixture();
  t.after(() => rm(repoPath, { recursive: true, force: true }));
  const commands = countingCommandRunner();
  const kernel = createKernel({ repoPath, commandRunner: commands.run });

  const createRound = commands.bindingRounds();
  const candidate = await kernel.createChange({
    id: "governed-lifecycle",
    title: "Change only the governed feature slice",
    primaryModule: "core",
    claims: [CLAIM],
    contextCapsule: { scope: { write: NARROWED_WRITE_SCOPE } },
    knowledgeClosure: completeKnowledgeClosure()
  });
  assert.equal(commands.bindingRounds() - createRound, 2, "create uses one stable two-round source snapshot");

  await writeFile(
    path.join(repoPath, "src/core/feature/tracked.mjs"),
    "export const tracked = 'changed';\n"
  );
  await writeFile(
    path.join(repoPath, "src/core/feature/prospective.mjs"),
    "export const prospective = true;\n"
  );

  const compileRound = commands.bindingRounds();
  const compiled = await kernel.compileChange(candidate.id);
  assert.equal(commands.bindingRounds() - compileRound, 2, "compile uses one stable two-round source snapshot");
  assert.deepEqual(compiled.contextCapsule.scope.write, NARROWED_WRITE_SCOPE);
  assert.deepEqual(
    Object.keys(compiled.baseline.pathOwnership).sort(),
    SOURCE_BINDING_KEYS
  );
  assert.deepEqual(
    Object.keys(compiled.contextCapsule.compiledFrom.pathOwnership).sort(),
    [...SOURCE_BINDING_KEYS, "effectiveScopeDigest", "scopeDigest"].sort()
  );

  const compiledDecisions = decisionIndex(compiled);
  assert.deepEqual(compiledDecisions.get("src/core/feature/tracked.mjs"), {
    classification: "owned-by-requested-module",
    dispositionRef: null,
    ownerModuleRef: "core",
    ownershipAllowsWrite: true,
    path: "src/core/feature/tracked.mjs",
    scopeAllowsWrite: true,
    writeAllowed: true
  });
  assert.deepEqual(compiledDecisions.get("src/core/feature/prospective.mjs"), {
    classification: "owned-by-requested-module",
    dispositionRef: null,
    ownerModuleRef: "core",
    ownershipAllowsWrite: true,
    path: "src/core/feature/prospective.mjs",
    scopeAllowsWrite: true,
    writeAllowed: true
  }, "the same product classifies a prospective untracked path without broadening scope");

  const gateRound = commands.bindingRounds();
  const gateExecutions = commands.gateExecutions();
  const gate = await kernel.runGate(candidate.id, "minimum");
  assert.equal(gate.status, "passed");
  assert.equal(commands.bindingRounds() - gateRound, 3, "Gate adds exactly one post-execution Git probe");
  assert.equal(commands.gateExecutions() - gateExecutions, 1);

  const acceptRound = commands.bindingRounds();
  const accepted = await kernel.acceptChange(candidate.id, {
    authority: "module-maintainer",
    decidedBy: "path-ownership-test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "The exact narrowed Core paths and their bound Gate Evidence are accepted."
  });
  assert.equal(commands.bindingRounds() - acceptRound, 2, "accept uses one stable two-round source snapshot");
  assert.equal(accepted.state, "Accepted");

  const stored = JSON.parse(await readFile(
    path.join(repoPath, ".legatura/runtime/changes/governed-lifecycle.json"),
    "utf8"
  ));
  const packageContent = accepted.acceptance.package;
  assert.deepEqual(
    packageContent.scopeAnalysis.pathOwnership,
    stored.scopeAnalysis.pathOwnership,
    "the Accepted Package seals the same concrete decisions held by the Store"
  );
  for (const material of [ownershipMaterial(stored), ownershipMaterial(packageContent)]) {
    assertNoOpaqueProductState(material);
    assert.deepEqual(Object.keys(material.baseline).sort(), SOURCE_BINDING_KEYS);
    assert.deepEqual(Object.keys(material.analysis.frozenSourceBinding).sort(), SOURCE_BINDING_KEYS);
    assert.deepEqual(Object.keys(material.analysis.currentSourceBinding).sort(), SOURCE_BINDING_KEYS);
    assert.ok(material.analysis.decisions.length >= 2);
  }
});

test("Kernel keeps ownership denial dimensions distinct and rejects policy drift before Gate execution", async (t) => {
  const repoPath = await createGovernedFixture();
  t.after(() => rm(repoPath, { recursive: true, force: true }));
  const commands = countingCommandRunner();
  const kernel = createKernel({ repoPath, commandRunner: commands.run });
  const candidate = await kernel.createChange({
    id: "ownership-attack-matrix",
    title: "Exercise closed ownership decisions",
    primaryModule: "core",
    claims: [CLAIM],
    contextCapsule: { scope: { write: NARROWED_WRITE_SCOPE } },
    knowledgeClosure: completeKnowledgeClosure()
  });

  await writeFile(path.join(repoPath, "src/core/outside.mjs"), "export const outside = 'changed';\n");
  await writeFile(path.join(repoPath, "src/foreign/index.mjs"), "export const foreign = 'changed';\n");
  await writeFile(path.join(repoPath, "docs/ungoverned/legacy.md"), "changed legacy text\n");
  const compiled = await kernel.compileChange(candidate.id);
  const decisions = decisionIndex(compiled);
  assert.deepEqual(projectDenial(decisions.get("src/core/outside.mjs")), {
    classification: "owned-by-requested-module",
    ownerModuleRef: "core",
    dispositionRef: null,
    ownershipAllowsWrite: true,
    scopeAllowsWrite: false,
    writeAllowed: false
  }, "caller narrowing denies an otherwise owned path");
  assert.deepEqual(projectDenial(decisions.get("src/foreign/index.mjs")), {
    classification: "owned-by-other-module",
    ownerModuleRef: "foreign",
    dispositionRef: null,
    ownershipAllowsWrite: false,
    scopeAllowsWrite: false,
    writeAllowed: false
  }, "a foreign owner cannot be converted into Core authority");
  assert.deepEqual(projectDenial(decisions.get("docs/ungoverned/legacy.md")), {
    classification: "ungoverned-disposition",
    ownerModuleRef: null,
    dispositionRef: "project-ungoverned",
    ownershipAllowsWrite: false,
    scopeAllowsWrite: false,
    writeAllowed: false
  }, "an ungoverned disposition records classification but grants no write authority");

  const projectPath = path.join(repoPath, ".legatura/project.json");
  const projectDocument = JSON.parse(await readFile(projectPath, "utf8"));
  projectDocument.pathGovernance.dispositions[0].paths.include.push("archive/**");
  await writeJson(projectPath, projectDocument);

  const externalExecutions = commands.gateExecutions();
  for (const [name, operation] of [
    ["runGate", () => kernel.runGate(candidate.id, "minimum")],
    ["acceptChange", () => kernel.acceptChange(candidate.id, {
      authority: "module-maintainer",
      decidedBy: "path-ownership-test",
      decisionType: "case-decision",
      status: "approved",
      rationale: "A migrated ownership policy must invalidate this attempted decision."
    })]
  ]) {
    await assert.rejects(
      operation(),
      (error) => error?.code === "CHANGE_PATH_OWNERSHIP_DRIFT"
        && error?.details?.changedFields?.includes("ownershipPolicyDigest"),
      name
    );
    assert.equal(
      commands.gateExecutions(),
      externalExecutions,
      "ownership drift fails before an external Gate command can run"
    );
  }
});

async function createGovernedFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-path-ownership-"));
  await Promise.all([
    mkdir(path.join(repoPath, ".legatura/modules"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura/contracts"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura/gates"), { recursive: true }),
    mkdir(path.join(repoPath, "src/core/feature"), { recursive: true }),
    mkdir(path.join(repoPath, "src/foreign"), { recursive: true }),
    mkdir(path.join(repoPath, "docs/ungoverned"), { recursive: true })
  ]);
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "path-ownership-fixture", name: "Path Ownership Fixture" },
    authorities: {
      decision: [
        { id: "project-maintainer", may: ["case-decision", "normative-amendment"] },
        { id: "module-maintainer", may: ["case-decision"] }
      ],
      fact: [
        { id: "core-facts", module: "core", owns: "Core behavior" },
        { id: "foreign-facts", module: "foreign", owns: "Foreign behavior" }
      ]
    },
    assuranceBoundary: {
      governed: [
        { module: "core", reason: "The Core fixture is governed." },
        { module: "foreign", reason: "The foreign fixture is separately governed." }
      ],
      provisional: [],
      opaque: []
    },
    changePolicy: { defaultGate: "minimum" },
    pathGovernance: {
      schemaVersion: 1,
      selectorGrammar: "exact-or-recursive-prefix",
      effectiveMatch: "include-minus-exclude",
      overlapPolicy: "reject-latent-and-concrete",
      conflictResolution: "none",
      dispositionPolicy: {
        allowedKinds: ["ungoverned"],
        requiredFields: ["id", "kind", "paths.include", "paths.exclude", "rationale"],
        minimumRationaleCharacters: 12,
        grantsWriteAuthority: false
      },
      dispositions: [{
        id: "project-ungoverned",
        kind: "ungoverned",
        paths: {
          include: [".legatura/**", "README.md", "docs/ungoverned/**"],
          exclude: []
        },
        rationale: "Governance documents and legacy prose remain outside automatic Module write authority."
      }]
    }
  });
  await writeJson(path.join(repoPath, ".legatura/modules/core.json"), {
    schemaVersion: 1,
    id: "core",
    name: "Core",
    status: "governed",
    summary: "The governed Core fixture.",
    factAuthority: "core-facts",
    decisionAuthority: "module-maintainer",
    interface: { accepts: ["request"], returns: ["result"] },
    paths: { include: ["src/core/**"], exclude: [] },
    focusedTests: [],
    publicContracts: ["core-behavior"],
    dependencies: []
  });
  await writeJson(path.join(repoPath, ".legatura/modules/foreign.json"), {
    schemaVersion: 1,
    id: "foreign",
    name: "Foreign",
    status: "governed",
    summary: "A separately owned fixture Module.",
    factAuthority: "foreign-facts",
    decisionAuthority: "module-maintainer",
    interface: { returns: ["foreign result"] },
    paths: { include: ["src/foreign/**"], exclude: [] },
    focusedTests: [],
    publicContracts: [],
    dependencies: []
  });
  await writeJson(path.join(repoPath, ".legatura/contracts/core-behavior.json"), {
    schemaVersion: 1,
    id: "core-behavior",
    name: "Core Behavior",
    owner: "core",
    maturity: "governed",
    normativeSources: [],
    claims: [CLAIM],
    consumers: []
  });
  await writeJson(path.join(repoPath, ".legatura/gates/minimum.json"), {
    schemaVersion: 1,
    id: "minimum",
    name: "Minimum Gate",
    purpose: "Prove the exact fixture Claim.",
    appliesTo: ["core"],
    commands: [{
      id: "feature-proof",
      command: [process.execPath, "-e", "process.exit(0)"],
      timeoutMs: 30_000,
      claimRefs: [CLAIM.id],
      oracle: { kind: "process-exit", description: "The bounded fixture proof exits zero." },
      applicability: "Only the governed Core fixture.",
      discriminatoryPower: "A non-zero process exit rejects the exact fixture Claim.",
      residualUncertainty: "The proof is intentionally bounded to this synthetic fixture."
    }]
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), {
    schemaVersion: 1,
    gaps: []
  });
  await writeFile(
    path.join(repoPath, "src/core/feature/tracked.mjs"),
    "export const tracked = true;\n"
  );
  await writeFile(path.join(repoPath, "src/core/outside.mjs"), "export const outside = true;\n");
  await writeFile(path.join(repoPath, "src/foreign/index.mjs"), "export const foreign = true;\n");
  await writeFile(path.join(repoPath, "docs/ungoverned/legacy.md"), "legacy text\n");
  await writeFile(path.join(repoPath, "README.md"), "fixture\n");

  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return repoPath;
}

function completeKnowledgeClosure() {
  return {
    status: "complete",
    noNewKnowledge: true,
    rationale: "This fixture Change introduces no future-relevant project knowledge."
  };
}

function decisionIndex(change) {
  return new Map(change.scopeAnalysis.pathOwnership.decisions.map((decision) => [
    decision.path,
    decision
  ]));
}

function projectDenial(decision) {
  return {
    classification: decision.classification,
    ownerModuleRef: decision.ownerModuleRef,
    dispositionRef: decision.dispositionRef,
    ownershipAllowsWrite: decision.ownershipAllowsWrite,
    scopeAllowsWrite: decision.scopeAllowsWrite,
    writeAllowed: decision.writeAllowed
  };
}

function ownershipMaterial(change) {
  return {
    baseline: change.baseline.pathOwnership,
    context: change.contextCapsule.compiledFrom.pathOwnership,
    analysis: change.scopeAnalysis.pathOwnership
  };
}

function assertNoOpaqueProductState(value) {
  const forbiddenKeys = new Set([
    "assignments",
    "handle",
    "modulePathOwnershipProduct",
    "observation",
    "product",
    "subjects",
    "token",
    "trackedPathFacts"
  ]);
  const visit = (current) => {
    if (!current || typeof current !== "object") return;
    for (const [key, child] of Object.entries(current)) {
      assert.equal(forbiddenKeys.has(key), false, `serialized opaque ownership field: ${key}`);
      visit(child);
    }
  };
  visit(value);
}

function countingCommandRunner() {
  let bindingRoundCount = 0;
  let gateExecutionCount = 0;
  return {
    bindingRounds: () => bindingRoundCount,
    gateExecutions: () => gateExecutionCount,
    run: async (specification) => {
      if (specification.purpose === "git-binding"
        && specification.command === "git"
        && specification.args?.[0] === "rev-parse") {
        bindingRoundCount += 1;
      }
      if (specification.purpose === "gate") gateExecutionCount += 1;
      try {
        const result = await execFileAsync(specification.command, specification.args ?? [], {
          cwd: specification.cwd,
          env: specification.env ? { ...process.env, ...specification.env } : process.env,
          signal: specification.signal,
          maxBuffer: 4 * 1024 * 1024
        });
        return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
      } catch (error) {
        return {
          exitCode: Number.isInteger(error?.code) ? error.code : 1,
          stdout: typeof error?.stdout === "string" ? error.stdout : "",
          stderr: typeof error?.stderr === "string" ? error.stderr : String(error?.message ?? error)
        };
      }
    }
  };
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
