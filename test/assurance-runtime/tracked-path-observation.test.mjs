import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFileSync, renameSync, utimesSync } from "node:fs";
import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalDigest } from "../../src/core/canonical.mjs";
import { readGitBinding } from "../../src/core/git-binding.mjs";
import {
  REPOSITORY_SOURCE_PRODUCT_LIMITS,
  REPOSITORY_SOURCE_PRODUCT_PROOF_VERSION,
  observeStableRepositorySource,
  projectRepositorySourceProduct,
  readRepositorySourceBytes
} from "../../src/core/repository-source.mjs";

const execFileAsync = promisify(execFile);

test("tracked source observation binds stable exact bytes and rejects source attacks", async (t) => {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-tracked-path-proof-"));
  t.after(() => rm(repoPath, { recursive: true, force: true }));
  await git(repoPath, "init", "--quiet");
  await git(repoPath, "config", "user.name", "Legatura Path Proof");
  await git(repoPath, "config", "user.email", "path-proof@example.invalid");
  await mkdir(path.join(repoPath, ".legatura/runtime"), { recursive: true });
  const realPaths = [
    ".legatura/runtime/accident.json",
    "link.txt",
    "line\nbreak.txt",
    "space name.txt",
    "z.txt"
  ].sort(compareUtf8);
  for (const trackedPath of realPaths) {
    if (trackedPath === "link.txt") continue;
    await writeFile(path.join(repoPath, trackedPath), `${JSON.stringify(trackedPath)}\n`);
  }
  await symlink("z.txt", path.join(repoPath, "link.txt"));
  await git(repoPath, "add", "--", ".");
  await git(repoPath, "commit", "--quiet", "-m", "tracked path proof");

  const production = await readGitBinding(repoPath);
  assert.equal(production.available, true);
  assert.deepEqual(production.trackedPathFacts, {
    schemaVersion: 1,
    paths: realPaths,
    digest: canonicalDigest({ schemaVersion: 1, paths: realPaths })
  });
  assert.ok(
    production.trackedPathFacts.paths.includes(".legatura/runtime/accident.json"),
    "Assurance Runtime reports facts and does not make governance filtering decisions"
  );

  const paths = ["a.txt", "dir\\file.txt", "line\nbreak.txt", "z/file.mjs"];
  const exact = await readGitBinding(
    "/tmp/legatura-tracked-paths",
    runnerFor("z/file.mjs\0line\nbreak.txt\0dir\\file.txt\0a.txt\0")
  );
  assert.equal(exact.available, true);
  assert.deepEqual(exact.trackedPathFacts, {
    schemaVersion: 1,
    paths,
    digest: canonicalDigest({ schemaVersion: 1, paths })
  });
  const { contentDigest, ...boundContent } = exact;
  assert.equal(contentDigest, canonicalDigest(boundContent));

  const attacks = [
    ["failed command", "a.txt\0", { exitCode: 7, stderr: "inventory failed" }],
    ["runner rejection", "a.txt\0", { throws: true }],
    ["truncated command", "a.txt\0", { truncated: true }],
    ["missing terminator", "a.txt", {}],
    ["empty segment", "a.txt\0\0", {}],
    ["duplicate path", "a.txt\0a.txt\0", {}],
    ["parent traversal", "../escape.txt\0", {}],
    ["dot relative", "./escape.txt\0", {}],
    ["absolute path", "/escape.txt\0", {}],
    ["windows absolute path", "C:/escape.txt\0", {}],
    ["windows UNC path", "\\\\server\\share\0", {}],
    ["invalid UTF-8 replacement", "bad\uFFFDname.txt\0", {}],
    ["unpaired surrogate", `bad\uD800name.txt\0`, {}],
    ["single path limit", `${"x".repeat(4097)}\0`, {}],
    ["path count limit", "x\0".repeat(65_537), {}],
    ["raw byte limit", `${"x".repeat(1024 * 1024)}\0`, {}]
  ];

  for (const [label, stdout, override] of attacks) {
    const observed = await readGitBinding(
      `/tmp/legatura-tracked-paths-${label.replaceAll(" ", "-")}`,
      runnerFor(stdout, override)
    );
    assert.equal(observed.available, false, label);
    assert.equal(observed.trackedPathFacts, null, label);
    assert.match(observed.error, /tracked|incomplete/i, label);
  }

  assert.equal(REPOSITORY_SOURCE_PRODUCT_PROOF_VERSION, 1);
  assert.equal(Object.isFrozen(REPOSITORY_SOURCE_PRODUCT_LIMITS), true);
  const pathRefs = ["space name.txt", "z.txt"];
  const sourceRequest = {
    schemaVersion: 1,
    gitContentDigest: production.contentDigest,
    trackedPathFactsDigest: production.trackedPathFacts.digest,
    pathRefs
  };
  const sourceProduct = await observeStableRepositorySource(repoPath, sourceRequest);
  assert.equal(Object.getPrototypeOf(sourceProduct), null);
  assert.deepEqual(Object.keys(sourceProduct), []);
  assert.equal(JSON.stringify(sourceProduct), "{}");

  const expectations = { ...sourceRequest, repoPath };
  const projection = await projectRepositorySourceProduct(sourceProduct, expectations);
  const expectedEntries = pathRefs.map((pathRef) => {
    const bytes = Buffer.from(`${JSON.stringify(pathRef)}\n`);
    return {
      pathRef,
      byteLength: bytes.byteLength,
      contentDigest: canonicalDigest(bytes.toString("base64"))
    };
  });
  const pathSetDigest = canonicalDigest({ schemaVersion: 1, paths: pathRefs });
  const manifestDigest = canonicalDigest({ schemaVersion: 1, entries: expectedEntries });
  assert.deepEqual(projection, {
    schemaVersion: 1,
    repositoryIdentityDigest: projection.repositoryIdentityDigest,
    gitContentDigest: production.contentDigest,
    trackedPathFactsDigest: production.trackedPathFacts.digest,
    pathSetDigest,
    manifestDigest,
    productDigest: canonicalDigest({
      schemaVersion: 1,
      repositoryIdentityDigest: projection.repositoryIdentityDigest,
      gitContentDigest: production.contentDigest,
      trackedPathFactsDigest: production.trackedPathFacts.digest,
      pathSetDigest,
      manifestDigest
    }),
    manifest: expectedEntries
  });
  assert.equal(Object.isFrozen(projection), true);
  assert.equal(Object.isFrozen(projection.manifest), true);
  assert.equal(JSON.stringify(projection).includes(repoPath), false);
  assert.equal(
    JSON.stringify(projection).includes(`${JSON.stringify("z.txt")}\\n`),
    false,
    "the projection contains byte facts, never source bodies"
  );

  const firstRead = readRepositorySourceBytes(sourceProduct, "z.txt");
  firstRead.fill(0);
  assert.equal(
    readRepositorySourceBytes(sourceProduct, "z.txt").toString("utf8"),
    `${JSON.stringify("z.txt")}\n`,
    "byte reads are defensive copies"
  );
  assert.throws(
    () => readRepositorySourceBytes(sourceProduct, "unknown.txt"),
    hasSourceError("EXPECTATION_MISMATCH")
  );

  for (const forged of [
    {},
    Object.assign({}, sourceProduct),
    JSON.parse(JSON.stringify(sourceProduct)),
    structuredClone(sourceProduct),
    new Proxy(sourceProduct, {})
  ]) {
    await assert.rejects(
      projectRepositorySourceProduct(forged, expectations),
      hasSourceError("PRODUCT_INVALID")
    );
    assert.throws(
      () => readRepositorySourceBytes(forged, "z.txt"),
      hasSourceError("PRODUCT_INVALID")
    );
  }

  const { trackedPathFactsDigest: omitted, ...incompleteExpectations } = expectations;
  assert.ok(omitted);
  await assert.rejects(
    projectRepositorySourceProduct(sourceProduct, incompleteExpectations),
    hasSourceError("REPOSITORY_SOURCE_INPUT_INVALID")
  );
  for (const mismatch of [
    { ...expectations, gitContentDigest: `sha256:${"0".repeat(64)}` },
    { ...expectations, trackedPathFactsDigest: `sha256:${"1".repeat(64)}` },
    { ...expectations, pathRefs: ["space name.txt"] }
  ]) {
    await assert.rejects(
      projectRepositorySourceProduct(sourceProduct, mismatch),
      hasSourceError("EXPECTATION_MISMATCH")
    );
  }

  const otherRepoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-other-source-"));
  t.after(() => rm(otherRepoPath, { recursive: true, force: true }));
  await git(otherRepoPath, "init", "--quiet");
  await git(otherRepoPath, "config", "user.name", "Legatura Other Source");
  await git(otherRepoPath, "config", "user.email", "other-source@example.invalid");
  await writeFile(path.join(otherRepoPath, "z.txt"), "other\n");
  await git(otherRepoPath, "add", "z.txt");
  await git(otherRepoPath, "commit", "--quiet", "-m", "other source");
  await assert.rejects(
    projectRepositorySourceProduct(sourceProduct, { ...expectations, repoPath: otherRepoPath }),
    hasSourceError("EXPECTATION_MISMATCH")
  );

  await assert.rejects(
    observeStableRepositorySource(repoPath, {
      ...sourceRequest,
      pathRefs: ["link.txt"]
    }),
    hasSourceError("OBSERVATION_UNAVAILABLE")
  );
  for (const [invalidPathRefs, code] of [
    [["z.txt", "z.txt"], "REPOSITORY_SOURCE_INPUT_INVALID"],
    [["../z.txt"], "REPOSITORY_SOURCE_INPUT_INVALID"],
    [["untracked.txt"], "OBSERVATION_UNAVAILABLE"],
    [Array.from(
      { length: REPOSITORY_SOURCE_PRODUCT_LIMITS.pathRefs + 1 },
      (_, index) => `path-${String(index).padStart(5, "0")}.txt`
    ), "LIMIT_EXCEEDED"]
  ]) {
    await assert.rejects(
      observeStableRepositorySource(repoPath, { ...sourceRequest, pathRefs: invalidPathRefs }),
      hasSourceError(code)
    );
    assert.equal(
      String(invalidPathRefs[0]).includes(repoPath),
      false,
      "closed errors need not echo attacker-controlled paths"
    );
  }

  let accessorRead = false;
  const accessorRequest = {
    schemaVersion: 1,
    gitContentDigest: sourceRequest.gitContentDigest,
    trackedPathFactsDigest: sourceRequest.trackedPathFactsDigest
  };
  Object.defineProperty(accessorRequest, "pathRefs", {
    enumerable: true,
    get() {
      accessorRead = true;
      return pathRefs;
    }
  });
  const sparsePathRefs = new Array(1);
  const extraFieldPathRefs = ["z.txt"];
  extraFieldPathRefs.extra = true;
  for (const invalidRequest of [
    accessorRequest,
    { ...sourceRequest, pathRefs: sparsePathRefs },
    { ...sourceRequest, pathRefs: extraFieldPathRefs },
    Object.assign(Object.create(null), sourceRequest),
    { ...sourceRequest, [Symbol("extra")]: true },
    new Proxy(sourceRequest, {})
  ]) {
    await assert.rejects(
      observeStableRepositorySource(repoPath, invalidRequest),
      hasSourceError("REPOSITORY_SOURCE_INPUT_INVALID")
    );
  }
  assert.equal(accessorRead, false, "plain-data validation never invokes an accessor");
  await assert.rejects(
    observeStableRepositorySource(repoPath, sourceRequest, {
      limits: { fileBytes: REPOSITORY_SOURCE_PRODUCT_LIMITS.fileBytes + 1 }
    }),
    hasSourceError("REPOSITORY_SOURCE_INPUT_INVALID")
  );

  const racePathRef = "race.bin";
  const racePath = path.join(repoPath, racePathRef);
  const raceSeedPath = path.join(repoPath, "race-seed.bin");
  const raceNextPath = path.join(repoPath, "race-next.bin");
  const raceBytes = Buffer.alloc(REPOSITORY_SOURCE_PRODUCT_LIMITS.fileBytes, 0x5a);
  await writeFile(racePath, raceBytes);
  await writeFile(raceSeedPath, raceBytes);
  const raceTrackedStdout = `${[...realPaths, racePathRef].sort(compareUtf8).join("\0")}\0`;
  const raceBinding = await readGitBinding(repoPath, runnerFor(raceTrackedStdout));
  const raceRequest = {
    schemaVersion: 1,
    gitContentDigest: raceBinding.contentDigest,
    trackedPathFactsDigest: raceBinding.trackedPathFacts.digest,
    pathRefs: [racePathRef]
  };
  const midReadAttacks = [
    ["same inode metadata mutation", (mutation) => {
      const timestamp = new Date(Date.now() + mutation * 1_000);
      utimesSync(racePath, timestamp, timestamp);
    }],
    ["path inode replacement", () => {
      copyFileSync(raceSeedPath, raceNextPath);
      renameSync(raceNextPath, racePath);
    }]
  ];
  for (const [label, mutate] of midReadAttacks) {
    await writeFile(racePath, raceBytes);
    let mutations = 0;
    let mutationError = null;
    const timer = setInterval(() => {
      try {
        mutations += 1;
        mutate(mutations);
      } catch (error) {
        mutationError = error;
      }
    }, 0);
    try {
      await new Promise((resolve) => setImmediate(resolve));
      await assert.rejects(
        observeStableRepositorySource(repoPath, raceRequest, {
          commandRunner: runnerFor(raceTrackedStdout)
        }),
        hasSourceError("OBSERVATION_UNAVAILABLE"),
        label
      );
    } finally {
      clearInterval(timer);
    }
    assert.equal(mutationError, null, label);
    assert.ok(mutations >= 2, `${label} overlapped multiple file validation points`);
  }

  const aggregatePathRefs = ["aggregate-a.bin", "aggregate-b.bin"];
  for (const pathRef of aggregatePathRefs) {
    await writeFile(path.join(repoPath, pathRef), "abc");
  }
  const aggregateTrackedStdout = `${[
    ...realPaths,
    ...aggregatePathRefs
  ].sort(compareUtf8).join("\0")}\0`;
  const aggregateBinding = await readGitBinding(repoPath, runnerFor(aggregateTrackedStdout));
  await assert.rejects(
    observeStableRepositorySource(repoPath, {
      schemaVersion: 1,
      gitContentDigest: aggregateBinding.contentDigest,
      trackedPathFactsDigest: aggregateBinding.trackedPathFacts.digest,
      pathRefs: aggregatePathRefs
    }, {
      commandRunner: runnerFor(aggregateTrackedStdout),
      limits: { fileBytes: 3, totalBytes: 5 }
    }),
    hasSourceError("LIMIT_EXCEEDED")
  );

  const trackedStdout = `${realPaths.join("\0")}\0`;
  const syntheticBinding = await readGitBinding(repoPath, runnerFor(trackedStdout));
  const syntheticRequest = {
    schemaVersion: 1,
    gitContentDigest: syntheticBinding.contentDigest,
    trackedPathFactsDigest: syntheticBinding.trackedPathFacts.digest,
    pathRefs: ["z.txt"]
  };

  await writeFile(path.join(repoPath, "z.txt"), "A\n");
  let stabilizingRound = 0;
  const stabilized = await observeStableRepositorySource(repoPath, syntheticRequest, {
    commandRunner: mutatingRunner(runnerFor(trackedStdout), async (round) => {
      stabilizingRound = round;
      if (round === 2) await writeFile(path.join(repoPath, "z.txt"), "B\n");
    })
  });
  assert.equal(stabilizingRound, 3, "A/B/B consumes the bounded third round");
  assert.equal(readRepositorySourceBytes(stabilized, "z.txt").toString("utf8"), "B\n");

  await writeFile(path.join(repoPath, "z.txt"), "A\n");
  await assert.rejects(
    observeStableRepositorySource(repoPath, syntheticRequest, {
      commandRunner: mutatingRunner(runnerFor(trackedStdout), async (round) => {
        if (round === 2) await writeFile(path.join(repoPath, "z.txt"), "B\n");
        if (round === 3) await writeFile(path.join(repoPath, "z.txt"), "C\n");
      })
    }),
    hasSourceError("UNSTABLE")
  );

});

function runnerFor(trackedStdout, trackedOverride = {}) {
  return async ({ args }) => {
    const operation = args[0];
    if (operation === "rev-parse") return result("a".repeat(40));
    if (operation === "branch") return result("main\n");
    if (operation === "status" || operation === "diff") return result("");
    if (operation === "ls-files" && args.includes("--others")) return result("");
    if (operation === "ls-files" && args.includes("--cached")) {
      if (trackedOverride.throws) throw new Error("tracked inventory runner rejected");
      return { ...result(trackedStdout), ...trackedOverride };
    }
    return { exitCode: 1, stdout: "", stderr: "unexpected command" };
  };
}

function result(stdout) {
  return { exitCode: 0, stdout, stderr: "", truncated: false };
}

function mutatingRunner(baseRunner, mutateRound) {
  let round = 0;
  return async (specification) => {
    if (specification.args[0] === "rev-parse") {
      round += 1;
      await mutateRound(round);
    }
    return baseRunner(specification);
  };
}

function hasSourceError(code) {
  return (error) => error?.name === "RepositorySourceError"
    && error.code === code
    && !error.message.includes(path.sep + "legatura-");
}

function git(cwd, ...args) {
  return execFileAsync("git", args, { cwd });
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}
