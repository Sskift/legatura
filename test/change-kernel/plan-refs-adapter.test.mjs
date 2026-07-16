import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);

test("create adapts canonical planRefs before the Change Store boundary", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const validCases = [
    {
      id: "canonical-scalar",
      planInput: { planRefs: "  LGT-900  " },
      expected: ["LGT-900"]
    },
    {
      id: "canonical-list",
      planInput: {
        planRefs: [" LGT-901 ", "LGT-900", " LGT-901 ", "LGT-900"]
      },
      expected: ["LGT-901", "LGT-900"]
    },
    {
      id: "legacy-alias",
      planInput: { planRef: [" LGT-900 ", "LGT-900"] },
      expected: ["LGT-900"]
    }
  ];

  for (const { id, planInput, expected } of validCases) {
    const created = await kernel.createChange(changeInput(id, planInput));
    const stored = await readStoredChange(fixture.repoPath, id);

    assert.deepEqual(created.planRefs, expected);
    assert.deepEqual(stored.planRefs, expected);
    assert.equal(Object.hasOwn(stored, "planRef"), false);
  }

  const sparse = [];
  sparse[1] = "LGT-900";
  for (const { id, planInput } of [
    { id: "sparse-create", planInput: { planRefs: sparse } },
    { id: "malformed-create", planInput: { planRefs: null } },
    { id: "string-wrapper-create", planInput: { planRefs: new String("LGT-900") } }
  ]) {
    await assert.rejects(
      kernel.createChange(changeInput(id, planInput)),
      hasErrorCode("CHANGE_PLAN_REF_INVALID")
    );
    assert.equal(await hasStoredChange(fixture.repoPath, id), false);
  }

  for (const { id, values } of [
    { id: "same-aliases", values: ["LGT-900", "LGT-900"] },
    { id: "null-aliases", values: [null, null] },
    { id: "undefined-aliases", values: [undefined, undefined] }
  ]) {
    await assert.rejects(
      kernel.createChange(changeInput(id, {
        planRefs: values[0],
        planRef: values[1]
      })),
      hasAliasConflict
    );
    assert.equal(await hasStoredChange(fixture.repoPath, id), false);
  }

  assert.deepEqual(await storedChangeIds(fixture.repoPath), validCases.map(({ id }) => id).sort());
});

test("compile patch adapts legal aliases and leaves the stored record exact on rejection", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const created = await kernel.createChange(changeInput("patch-subject", {
    planRefs: " LGT-900 "
  }));

  const compiled = await kernel.compileChange(created.id, {
    planRef: [" LGT-901 ", "LGT-901"]
  });
  assert.deepEqual(compiled.planRefs, ["LGT-901"]);
  const storedAfterCompile = await readStoredChange(fixture.repoPath, created.id);
  assert.deepEqual(storedAfterCompile.planRefs, ["LGT-901"]);
  assert.equal(Object.hasOwn(storedAfterCompile, "planRef"), false);

  await kernel.runGate(created.id);
  const lifecycleSnapshot = await readStoredChange(fixture.repoPath, created.id);
  assert.ok(lifecycleSnapshot.gateRuns.length > 0);
  const storedBytes = await readStoredChangeText(fixture.repoPath, created.id);

  const sparse = [];
  sparse[1] = "LGT-900";
  for (const planRefs of [sparse, new String("LGT-900")]) {
    await assert.rejects(
      kernel.compileChange(created.id, { planRefs }),
      hasErrorCode("CHANGE_PLAN_REF_INVALID")
    );
    assert.equal(await readStoredChangeText(fixture.repoPath, created.id), storedBytes);
  }

  for (const values of [
    ["LGT-900", "LGT-900"],
    [null, null],
    [undefined, undefined]
  ]) {
    await assert.rejects(
      kernel.compileChange(created.id, {
        planRefs: values[0],
        planRef: values[1]
      }),
      hasAliasConflict
    );
    assert.equal(await readStoredChangeText(fixture.repoPath, created.id), storedBytes);
  }

  await assert.rejects(
    kernel.compileChange(created.id, { planRefs: undefined }),
    hasErrorCode("CHANGE_PLAN_REF_REQUIRED")
  );
  assert.equal(await readStoredChangeText(fixture.repoPath, created.id), storedBytes);
});

function changeInput(id, planInput) {
  return {
    id,
    title: `Exercise planRefs adapter for ${id}`,
    primaryModule: "core",
    claims: [{
      id: "behavior-correct",
      statement: "The governed behavior remains correct."
    }],
    ...planInput
  };
}

function hasErrorCode(code) {
  return (error) => error?.code === code && error?.statusCode === 422;
}

function hasAliasConflict(error) {
  return error?.code === "CHANGE_PLAN_REF_INPUT_CONFLICT"
    && error?.statusCode === 422
    && Array.isArray(error?.details?.presentFields)
    && error.details.presentFields.join(",") === "planRefs,planRef";
}

async function readStoredChange(repoPath, id) {
  return JSON.parse(await readStoredChangeText(repoPath, id));
}

async function readStoredChangeText(repoPath, id) {
  return readFile(path.join(repoPath, ".legatura/runtime/changes", `${id}.json`), "utf8");
}

async function hasStoredChange(repoPath, id) {
  try {
    await readStoredChange(repoPath, id);
    return true;
  } catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function storedChangeIds(repoPath) {
  const directory = path.join(repoPath, ".legatura/runtime/changes");
  try {
    return (await readdir(directory))
      .filter((name) => name.endsWith(".json"))
      .map((name) => name.slice(0, -".json".length))
      .sort();
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
}

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-plan-refs-adapter-"));
  await mkdir(path.join(repoPath, ".legatura/modules"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/contracts"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/gates"), { recursive: true });
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "plan-refs-adapter-fixture", name: "planRefs Adapter Fixture" },
    authorities: {
      decision: [
        { id: "project-maintainer", may: ["case-decision", "normative-amendment"] },
        { id: "module-maintainer", may: ["case-decision", "normative-amendment"] }
      ],
      fact: [{ id: "core-facts", module: "core", owns: "Fixture behavior" }]
    },
    assuranceBoundary: {
      governed: [{ module: "core", reason: "Fixture" }],
      provisional: [],
      opaque: []
    },
    changePolicy: {
      defaultGate: "minimum",
      requirePlanRefs: true,
      outcomeAlignmentMode: "declared",
      outcomeTransitionMode: "declared",
      outcomeCriterionSelection: "unique-claim-match-or-explicit-hint"
    }
  });
  await writeJson(path.join(repoPath, ".legatura/modules/core.json"), {
    schemaVersion: 1,
    id: "core",
    name: "Core",
    status: "governed",
    summary: "Fixture Module.",
    factAuthority: "core-facts",
    decisionAuthority: "module-maintainer",
    interface: { accepts: ["request"], returns: ["result"] },
    paths: { include: ["src/**"], exclude: [] },
    publicContracts: ["core-behavior"],
    dependencies: []
  });
  await writeJson(path.join(repoPath, ".legatura/contracts/core-behavior.json"), {
    schemaVersion: 1,
    id: "core-behavior",
    name: "Core Behavior",
    owner: "core",
    maturity: "governed",
    normativeSources: [],
    claims: [{
      id: "behavior-correct",
      statement: "The governed behavior remains correct."
    }],
    consumers: []
  });
  await writeJson(path.join(repoPath, ".legatura/gates/minimum.json"), {
    schemaVersion: 1,
    id: "minimum",
    name: "Minimum Gate",
    purpose: "Fixture verification.",
    appliesTo: ["core"],
    commands: [{
      id: "behavior",
      command: [process.execPath, "-e", "process.exit(0)"],
      timeoutMs: 30_000,
      claimRefs: ["behavior-correct"],
      oracle: { kind: "fixture", description: "The fixture command exits zero." },
      applicability: "Fixture repository.",
      discriminatoryPower: "A non-zero exit rejects the fixture.",
      residualUncertainty: "Only fixture behavior is covered."
    }]
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), {
    schemaVersion: 1,
    gaps: []
  });
  await writeJson(path.join(repoPath, ".legatura/plan.json"), {
    schemaVersion: 1,
    id: "plan-refs-adapter-plan",
    authority: "project-maintainer",
    northStar: "Each Change is aligned to an explicit active Outcome.",
    stages: [{
      id: "S1",
      name: "Adapter Stage",
      status: "active",
      outcomeRefs: ["LGT-900", "LGT-901"]
    }],
    outcomes: [
      activeOutcome("LGT-900", "The scalar planRefs adapter remains exact."),
      activeOutcome("LGT-901", "The legacy planRef adapter remains exact.")
    ]
  });
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const value = true;\n");
  await writeFile(path.join(repoPath, "README.md"), "planRefs adapter fixture\n");
  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return { repoPath };
}

function activeOutcome(id, outcome) {
  return {
    id,
    stage: "S1",
    status: "active",
    outcome,
    dependsOn: [],
    acceptance: {
      claimRefs: ["behavior-correct"],
      gapRefs: [],
      exitCriteria: [`${outcome} is proven.`],
      criteria: [{
        id: `${id}-C1`,
        statement: `${outcome} is proven.`,
        claimRefs: ["behavior-correct"],
        gapRefs: []
      }]
    }
  };
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
