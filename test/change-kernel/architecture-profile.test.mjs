import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  symlink,
  truncate,
  writeFile
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createKernel } from "../../src/core/index.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import {
  CHANGE_STORE_LIMITS,
  createChangeStore
} from "../../src/core/change-store.mjs";
import { validateEvidenceCoverage } from "../../src/core/evidence.mjs";

const execFileAsync = promisify(execFile);
const SEALED_OUTPUT_SENTINEL = "sealed-private-gate-output";
const FORBIDDEN_SUMMARY_KEYS = new Set([
  "acceptance",
  "evidence",
  "gateRuns",
  "governanceBaseline",
  "package",
  "stderr",
  "stdout"
]);

test("Change queries observe sources independently of N and keep list bodies bounded and reads pure", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const writer = createKernel({ repoPath: fixture.repoPath });
  const records = [];
  for (const id of ["query-one", "query-two", "query-three"]) {
    records.push(await writer.createChange({
      id,
      title: `${id} ${"bounded ".repeat(80)}`,
      request: `${id} ${"request ".repeat(80)}`,
      primaryModule: "core",
      claims: id === "query-three"
        ? [{ id: "secondary-behavior", statement: "The secondary governed behavior remains correct." }]
        : [{ id: "behavior-correct", statement: "The governed behavior remains correct." }]
    }));
  }
  await writer.compileChange(records[1].id, {
    knowledgeClosure: {
      status: "complete",
      noNewKnowledge: true,
      rationale: "The fixture introduces no durable project knowledge beyond this declared proof."
    }
  });
  await writer.runGate(records[1].id);
  await writer.acceptChange(records[1].id, {
    authority: "module-maintainer",
    decidedBy: "architecture-profile-test",
    decisionType: "case-decision",
    status: "approved",
    rationale: "Seal the exact fixture record before testing a top-level-only tamper."
  });
  const crossAuthorityDecision = {
    status: "approved",
    authority: "module-maintainer",
    decidedBy: "architecture-profile-test",
    decisionType: "case-decision",
    rationale: "Approve the explicit fixture-only cross-Claim mapping.",
    approvedObligationIds: ["verify-secondary-behavior"]
  };
  await writer.compileChange(records[2].id, {
    verificationObligations: [{
      id: "verify-secondary-behavior",
      claimId: "secondary-behavior",
      gateClaimRefs: ["behavior-correct"],
      mappingRationale: "The fixture deliberately uses the primary deterministic behavior route for its secondary behavior Claim.",
      applicability: "Only the fixture Core Module and this exact deterministic command route.",
      discriminatoryPower: "A non-zero deterministic process exit rejects the secondary behavior Claim."
    }],
    authorityDecision: crossAuthorityDecision
  });
  let crossReady = await writer.runGate(records[2].id);
  assert.equal(crossReady.change.state, "EvidenceReady");

  const gatePath = path.join(fixture.repoPath, ".legatura/gates/minimum.json");
  const originalGate = await readFile(gatePath, "utf8");
  const semanticallyChangedGate = JSON.parse(originalGate);
  semanticallyChangedGate.commands[0].command = [
    process.execPath,
    "-e",
    "process.stdout.write('semantically-different-route')"
  ];
  semanticallyChangedGate.commands[0].oracle = {
    kind: "fixture",
    description: "A different Oracle under the same Gate and command identity."
  };
  await writeJson(gatePath, semanticallyChangedGate);
  await writer.compileChange(records[2].id, { authorityDecision: crossAuthorityDecision });
  const frozenRouteRun = await writer.runGate(records[2].id);
  const frozenRouteEvidence = frozenRouteRun.change.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  assert.equal(
    frozenRouteEvidence.observation.stdout.includes(SEALED_OUTPUT_SENTINEL),
    true,
    "Gate execution remains frozen to the Candidate Governance Baseline"
  );
  const semanticDriftStoreBeforeProfile = await snapshotChangeStore(fixture.repoPath);
  const currentSemanticDriftProfile = await createKernel({
    repoPath: fixture.repoPath
  }).inspectArchitectureProfile();
  const frozenRouteCurrentFact = findProfileEvidence(
    currentSemanticDriftProfile,
    records[2].id,
    frozenRouteEvidence.id,
    "current-record"
  );
  assert.equal(frozenRouteCurrentFact.currency, "current");
  assert.equal(currentSemanticDriftProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
    relation.evidenceRef === frozenRouteCurrentFact.id
  )), false, "current Evidence from a frozen route cannot connect to changed current route semantics");
  assert.deepEqual(await snapshotChangeStore(fixture.repoPath), semanticDriftStoreBeforeProfile);
  await writeFile(gatePath, originalGate, "utf8");
  await writer.compileChange(records[2].id, { authorityDecision: crossAuthorityDecision });
  crossReady = await writer.runGate(records[2].id);
  assert.equal(crossReady.change.state, "EvidenceReady");

  const contractPath = path.join(fixture.repoPath, ".legatura/contracts/core-behavior.json");
  const originalContract = await readFile(contractPath, "utf8");
  const semanticallyChangedContract = JSON.parse(originalContract);
  semanticallyChangedContract.claims.find((claim) => (
    claim.id === "behavior-correct"
  )).statement = "The same source Claim id now declares different governed behavior.";
  await writeJson(contractPath, semanticallyChangedContract);
  await writer.compileChange(records[2].id, { authorityDecision: crossAuthorityDecision });
  const frozenClaimRun = await writer.runGate(records[2].id);
  const frozenClaimEvidence = frozenClaimRun.change.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  const claimDriftProfile = await createKernel({
    repoPath: fixture.repoPath
  }).inspectArchitectureProfile();
  const frozenClaimCurrentFact = findProfileEvidence(
    claimDriftProfile,
    records[2].id,
    frozenClaimEvidence.id,
    "current-record"
  );
  assert.equal(frozenClaimCurrentFact.currency, "current");
  assert.equal(claimDriftProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
    relation.evidenceRef === frozenClaimCurrentFact.id
  )), false, "same Claim ids cannot connect frozen Evidence to changed current Claim semantics");
  await writeFile(contractPath, originalContract, "utf8");
  await writer.compileChange(records[2].id, { authorityDecision: crossAuthorityDecision });
  crossReady = await writer.runGate(records[2].id);
  assert.equal(crossReady.change.state, "EvidenceReady");

  const detailPath = changePath(fixture.repoPath, records[0].id);
  const stored = JSON.parse(await readFile(detailPath, "utf8"));
  stored.evidence = [{
    id: "large-evidence",
    stdout: "private-output".repeat(1000),
    provenance: {}
  }];
  stored.gateRuns = [{
    gateId: "large-gate",
    stdout: "private-stdout".repeat(1000),
    stderr: "private-stderr".repeat(1000),
    evidenceBindings: []
  }];
  stored.acceptance = {
    valid: true,
    digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    package: { body: "private-package".repeat(1000) }
  };
  await writeJson(detailPath, stored);
  const bytesBefore = await readFile(detailPath, "utf8");

  const counted = countingCommandRunner();
  const reader = createKernel({ repoPath: fixture.repoPath, commandRunner: counted.run });
  const summaries = await reader.listChanges();

  assert.equal(counted.observations(), 2, "N records still require exactly two stable source rounds");
  assert.equal(summaries.length, 3);
  assert.ok(JSON.stringify(summaries[0]).length < 3000);
  assert.equal(summaries[0].intent.title.length, 240);
  assert.equal(summaries[0].truncated.title, true);
  assertNoForbiddenSummaryKeys(summaries);
  assert.equal(await readFile(detailPath, "utf8"), bytesBefore, "list must not rewrite runtime records");

  counted.reset();
  const detail = await reader.getChange(records[0].id);
  assert.equal(counted.observations(), 2, "detail also acquires one stable composite snapshot");
  assert.equal(detail.state, stored.state);
  assert.deepEqual(detail.acceptance, stored.acceptance, "historical acceptance is returned without projection mutation");
  assert.equal(detail.evidence[0].stdout.startsWith("private-output"), true);
  assert.equal(detail.gateRuns[0].stderr.startsWith("private-stderr"), true);
  assert.equal(detail.acceptance.package.body.startsWith("private-package"), true);
  assert.deepEqual(detail.observation.seal.problems.includes("package-digest-mismatch"), true);
  assert.equal(detail.observation.evidenceCurrency.invalidIds.includes("large-evidence"), true);
  assert.equal(await readFile(detailPath, "utf8"), bytesBefore, "detail must not rewrite runtime records");

  counted.reset();
  const currentDetail = await reader.getChange(records[1].id);
  assert.equal(counted.observations(), 2);
  assert.equal(currentDetail.observation.evidenceCurrency.currentIds.length, 2);
  assert.deepEqual(currentDetail.observation.evidenceCurrency.invalidIds, []);
  assert.equal(currentDetail.observation.seal.intact, true);
  assert.equal(currentDetail.observation.currentApplicability.status, "current");
  assert.equal(currentDetail.acceptance.package.evidence.some((item) => (
    item.observation?.stdout?.includes(SEALED_OUTPUT_SENTINEL)
  )), true, "the valid sealed package really contains private command output");

  const acceptedGateEvidence = currentDetail.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  const storeBytesBeforeProfile = await snapshotChangeStore(fixture.repoPath);
  counted.reset();
  const profile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2, "Profile reuses one stable composite source snapshot");
  for (const digest of Object.values(profile.source)) {
    assert.match(digest, /^sha256:[a-f0-9]{64}$/u);
  }
  assert.deepEqual(profile.entities.changes.map((change) => change.id).sort(), [
    "query-one",
    "query-three",
    "query-two"
  ]);
  const serializedProfile = JSON.stringify(profile);
  for (const privateValue of [
    "private-output",
    "private-stdout",
    "private-stderr",
    "private-package",
    SEALED_OUTPUT_SENTINEL
  ]) {
    assert.equal(serializedProfile.includes(privateValue), false, `Profile leaked ${privateValue}`);
  }
  const currentGateFact = findProfileEvidence(
    profile,
    records[1].id,
    acceptedGateEvidence.id,
    "current-record"
  );
  const historicalGateFact = findProfileEvidence(
    profile,
    records[1].id,
    acceptedGateEvidence.id,
    "sealed-package"
  );
  assert.equal(currentGateFact.currency, "current");
  assert.equal(historicalGateFact.currency, "sealed-historical");
  const currentAssociation = profile.relations.currentEvidenceClaimAssociations.find((relation) => (
    relation.evidenceRef === currentGateFact.id && relation.targetClaimRef === "behavior-correct"
  ));
  const historicalAssociation = profile.relations.historicalEvidenceClaimAssociations.find((relation) => (
    relation.evidenceRef === historicalGateFact.id && relation.targetClaimRef === "behavior-correct"
  ));
  assert.ok(currentAssociation);
  assert.ok(historicalAssociation);
  const crossGateEvidence = crossReady.change.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  const crossGateFact = findProfileEvidence(
    profile,
    records[2].id,
    crossGateEvidence.id,
    "current-record"
  );
  assert.deepEqual(
    profile.relations.currentEvidenceClaimAssociations.find((relation) => (
      relation.evidenceRef === crossGateFact.id
        && relation.targetClaimRef === "secondary-behavior"
    )),
    {
      evidenceRef: crossGateFact.id,
      targetClaimRef: "secondary-behavior",
      sourceClaimRef: "behavior-correct",
      routeRef: currentAssociation.routeRef,
      associationKind: "cross-claim",
      obligationRef: "verify-secondary-behavior",
      obligationDigest: canonicalDigest(crossReady.change.verificationObligations[0]),
      authorityDecisionDigest: canonicalDigest(crossReady.change.authorityDecision)
    }
  );
  assert.deepEqual(
    await snapshotChangeStore(fixture.repoPath),
    storeBytesBeforeProfile,
    "Profile inspection must not rewrite any Change record"
  );

  const sourcePath = path.join(fixture.repoPath, "src/index.mjs");
  const originalSource = await readFile(sourcePath, "utf8");
  await writeFile(sourcePath, `${originalSource}// observed source drift\n`, "utf8");
  counted.reset();
  const staleProfile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2);
  assert.equal(staleProfile.source.projectModelDigest, profile.source.projectModelDigest);
  assert.notEqual(staleProfile.source.gitContentDigest, profile.source.gitContentDigest);
  assert.equal(staleProfile.source.changeStoreDigest, profile.source.changeStoreDigest);
  const staleGateFact = findProfileEvidence(
    staleProfile,
    records[1].id,
    acceptedGateEvidence.id,
    "current-record"
  );
  const staleHistoricalGateFact = findProfileEvidence(
    staleProfile,
    records[1].id,
    acceptedGateEvidence.id,
    "sealed-package"
  );
  assert.equal(staleGateFact.currency, "stale");
  assert.equal(staleProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
    relation.evidenceRef === staleGateFact.id
  )), false);
  assert.deepEqual(staleHistoricalGateFact, historicalGateFact);
  assert.deepEqual(staleProfile.relations.historicalEvidenceClaimAssociations.find((relation) => (
    relation.evidenceRef === staleHistoricalGateFact.id
      && relation.targetClaimRef === "behavior-correct"
  )), historicalAssociation);
  assert.deepEqual(await snapshotChangeStore(fixture.repoPath), storeBytesBeforeProfile);
  await writeFile(sourcePath, originalSource, "utf8");

  await writeJson(gatePath, semanticallyChangedGate);
  counted.reset();
  const changedRouteProfile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2);
  const routeHistoricalGateFact = findProfileEvidence(
    changedRouteProfile,
    records[1].id,
    acceptedGateEvidence.id,
    "sealed-package"
  );
  assert.equal(routeHistoricalGateFact.currency, "sealed-historical");
  assert.equal(changedRouteProfile.relations.historicalEvidenceClaimAssociations.some((relation) => (
    relation.evidenceRef === routeHistoricalGateFact.id
  )), false, "same route ids cannot connect frozen Evidence to different current route semantics");
  assert.deepEqual(await snapshotChangeStore(fixture.repoPath), storeBytesBeforeProfile);
  await writeFile(gatePath, originalGate, "utf8");

  const routeForgedPath = changePath(fixture.repoPath, records[1].id);
  const routeForged = JSON.parse(await readFile(routeForgedPath, "utf8"));
  const gateEvidence = routeForged.evidence.find((item) => item.provenance?.kind === "gate-command");
  gateEvidence.provenance.gateId = "forged-gate";
  const gateRun = routeForged.gateRuns.find((run) => run.evidenceIds?.includes(gateEvidence.id));
  gateRun.evidenceBindings.find((binding) => binding.id === gateEvidence.id).digest = canonicalDigest(gateEvidence);
  await writeJson(routeForgedPath, routeForged);
  const routeForgedBytes = await readFile(routeForgedPath, "utf8");
  const forgedDetail = await reader.getChange(records[1].id);
  assert.equal(forgedDetail.observation.evidenceCurrency.invalidIds.includes(gateEvidence.id), true);
  assert.equal(forgedDetail.observation.seal.packageIntact, true);
  assert.equal(forgedDetail.observation.seal.recordProjectionIntact, false);
  assert.equal(forgedDetail.observation.seal.intact, false);
  assert.equal(forgedDetail.observation.currentApplicability.status, "invalid");
  assert.equal(
    forgedDetail.acceptance.package.evidence.some((item) => item.provenance?.gateId === "forged-gate"),
    false,
    "the historical package remains distinct from mutable top-level Evidence"
  );
  assert.equal(await readFile(routeForgedPath, "utf8"), routeForgedBytes);

  routeForged.governanceBaseline.project.name = "tampered-top-level-baseline";
  await writeJson(routeForgedPath, routeForged);
  const baselineForgedBytes = await readFile(routeForgedPath, "utf8");

  counted.reset();
  const forgedProfile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2);
  assert.equal(forgedProfile.source.projectModelDigest, profile.source.projectModelDigest);
  assert.equal(forgedProfile.source.gitContentDigest, profile.source.gitContentDigest);
  assert.notEqual(forgedProfile.source.changeStoreDigest, profile.source.changeStoreDigest);
  assert.notEqual(forgedProfile.source.snapshotDigest, profile.source.snapshotDigest);
  const forgedCurrentGateFact = findProfileEvidence(
    forgedProfile,
    records[1].id,
    acceptedGateEvidence.id,
    "current-record"
  );
  const preservedHistoricalGateFact = findProfileEvidence(
    forgedProfile,
    records[1].id,
    acceptedGateEvidence.id,
    "sealed-package"
  );
  assert.equal(forgedCurrentGateFact.currency, "invalid");
  assert.equal(
    forgedProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
      relation.evidenceRef === forgedCurrentGateFact.id
    )),
    false
  );
  assert.deepEqual(preservedHistoricalGateFact, historicalGateFact);
  assert.deepEqual(
    forgedProfile.relations.historicalEvidenceClaimAssociations.find((relation) => (
      relation.evidenceRef === preservedHistoricalGateFact.id
        && relation.targetClaimRef === "behavior-correct"
    )),
    historicalAssociation
  );
  assert.equal(await readFile(routeForgedPath, "utf8"), baselineForgedBytes);

  const envelopeForgedPath = changePath(fixture.repoPath, records[2].id);
  const envelopeForged = JSON.parse(await readFile(envelopeForgedPath, "utf8"));
  const crossEvidence = envelopeForged.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  crossEvidence.claim.refs = [];
  const crossRun = envelopeForged.gateRuns.find((run) => run.evidenceIds?.includes(crossEvidence.id));
  crossRun.evidenceBindings.find((binding) => binding.id === crossEvidence.id).digest = (
    canonicalDigest(crossEvidence)
  );
  await writeJson(envelopeForgedPath, envelopeForged);
  const envelopeForgedBytes = await readFile(envelopeForgedPath, "utf8");
  const envelopeForgedDetail = await reader.getChange(records[2].id);
  assert.equal(envelopeForgedDetail.observation.evidenceCurrency.currentIds.includes(crossEvidence.id), true);
  assert.equal(envelopeForgedDetail.readiness.coverage.coveredClaimIds.includes("secondary-behavior"), false);
  counted.reset();
  const envelopeForgedProfile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2);
  const envelopeForgedFact = findProfileEvidence(
    envelopeForgedProfile,
    records[2].id,
    crossEvidence.id,
    "current-record"
  );
  assert.equal(envelopeForgedFact.currency, "current", "currency remains orthogonal to eligibility");
  assert.equal(envelopeForgedProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
    relation.evidenceRef === envelopeForgedFact.id
  )), false, "readiness and Profile share the exact Claim-envelope eligibility decision");
  assert.equal(await readFile(envelopeForgedPath, "utf8"), envelopeForgedBytes);

  envelopeForged.evidence.push({
    ...structuredClone(crossEvidence),
    observation: { ...crossEvidence.observation, stdout: "duplicate-identity-body" }
  });
  await writeJson(envelopeForgedPath, envelopeForged);
  counted.reset();
  const duplicateIdentityProfile = await reader.inspectArchitectureProfile();
  assert.equal(counted.observations(), 2);
  const duplicateOccurrences = duplicateIdentityProfile.entities.evidence.filter((item) => (
    item.changeRef === records[2].id
      && item.evidenceRef === crossEvidence.id
      && item.origin === "current-record"
  ));
  assert.equal(duplicateOccurrences.length, 2);
  assert.equal(duplicateOccurrences.every((item) => item.currency === "invalid"), true);
  assert.equal(duplicateIdentityProfile.relations.currentEvidenceClaimAssociations.some((relation) => (
    duplicateOccurrences.some((item) => item.id === relation.evidenceRef)
  )), false);
  assertEvidenceEligibilityFailsClosed();
  assertAssociationDerivationIsBounded();
});

test("bounded stabilization accepts A/B/B and fails closed on A/B/C", async (t) => {
  const fixture = await createFixture();
  t.after(() => rm(fixture.repoPath, { recursive: true, force: true }));
  const a = "a".repeat(40);
  const b = "b".repeat(40);
  const c = "c".repeat(40);

  const converging = sequencedGitRunner([a, b, b]);
  const convergingKernel = createKernel({ repoPath: fixture.repoPath, commandRunner: converging.run });
  const profile = await convergingKernel.inspectArchitectureProfile();
  assert.deepEqual(profile.entities.changes, []);
  assert.equal(converging.observations(), 3);

  const projectConverging = sequencedGitRunner([a, b, b]);
  const inspection = await createKernel({
    repoPath: fixture.repoPath,
    commandRunner: projectConverging.run
  }).inspectProject();
  assert.equal(inspection.git.head, b);
  assert.equal(profile.source.gitContentDigest, inspection.git.contentDigest);
  assert.equal(projectConverging.observations(), 3);

  const unstable = sequencedGitRunner([a, b, c]);
  const unstableKernel = createKernel({ repoPath: fixture.repoPath, commandRunner: unstable.run });
  await assert.rejects(
    unstableKernel.inspectArchitectureProfile(),
    (error) => error?.code === "CHANGE_QUERY_SNAPSHOT_UNSTABLE"
      && error?.statusCode === 409
      && error.details.observationCount === 3
      && error.details.observedDigests.length === 3
      && new Set(error.details.observedDigests).size === 3
      && Object.keys(error.details).sort().join(",") === "observationCount,observedDigests"
  );
  assert.equal(unstable.observations(), 3);
});

test("Change Store bounds and anchors sources before query parsing", async (t) => {
  const fixture = await createFixture();
  const anchorRoot = await mkdtemp(path.join(os.tmpdir(), "legatura-store-anchor-"));
  t.after(() => Promise.all([
    rm(fixture.repoPath, { recursive: true, force: true }),
    rm(anchorRoot, { recursive: true, force: true })
  ]));
  const store = createChangeStore(fixture.repoPath);
  const directory = path.join(fixture.repoPath, ".legatura/runtime/changes");

  await store.save({ id: "roundtrip", state: "Candidate", value: "bounded" });
  assert.deepEqual(await store.get("roundtrip"), {
    id: "roundtrip",
    state: "Candidate",
    value: "bounded"
  });
  const ordinary = await store.snapshot();
  assert.equal(ordinary.records.length, 1);
  assert.equal(ordinary.observed.recordCount, 1);
  assert.match(ordinary.digest, /^sha256:[a-f0-9]{64}$/u);
  await rm(path.join(directory, "roundtrip.json"));

  for (const invalid of [
    { id: "omitted-value", omitted: undefined },
    { id: "nonfinite-value", value: Number.POSITIVE_INFINITY }
  ]) {
    await assert.rejects(
      store.save(invalid),
      (error) => error?.code === "CHANGE_RECORD_INVALID" && error?.statusCode === 422
    );
  }
  await assert.rejects(
    store.get("x".repeat(CHANGE_STORE_LIMITS.changeIdBytes + 1)),
    (error) => error?.code === "CHANGE_ID_INVALID" && error?.statusCode === 400
  );
  assert.deepEqual(await readdir(directory), []);

  const oversizedPath = path.join(directory, "oversized.json");
  await writeFile(oversizedPath, "");
  await truncate(oversizedPath, CHANGE_STORE_LIMITS.fileBytes + 1);
  await assert.rejects(
    createKernel({ repoPath: fixture.repoPath }).inspectArchitectureProfile(),
    (error) => error?.code === "CHANGE_STORE_LIMIT_EXCEEDED"
      && error?.statusCode === 413
      && error.details.location === "fileBytes:oversized.json"
  );
  await rm(oversizedPath);

  const aggregatePaths = Array.from({ length: 5 }, (_, index) => (
    path.join(directory, `aggregate-${index + 1}.json`)
  ));
  for (const filePath of aggregatePaths) {
    await writeFile(filePath, "");
    await truncate(filePath, CHANGE_STORE_LIMITS.fileBytes);
  }
  await assert.rejects(
    store.snapshot(),
    (error) => error?.code === "CHANGE_STORE_LIMIT_EXCEEDED"
      && error?.statusCode === 413
      && error.details.location === "totalBytes"
  );
  await Promise.all(aggregatePaths.map((filePath) => rm(filePath)));

  let nested = "leaf";
  for (let depth = 0; depth <= CHANGE_STORE_LIMITS.depth; depth += 1) nested = { nested };
  await writeJson(path.join(directory, "depth-bomb.json"), { id: "depth-bomb", nested });
  await assert.rejects(
    store.snapshot(),
    (error) => error?.code === "CHANGE_STORE_LIMIT_EXCEEDED"
      && error?.statusCode === 413
      && error.details.location === "depth:depth-bomb.json"
  );
  await rm(path.join(directory, "depth-bomb.json"));

  await writeFile(
    path.join(directory, "negative-zero.json"),
    '{"id":"negative-zero","value":-0}\n',
    "utf8"
  );
  await assert.rejects(
    store.snapshot(),
    (error) => error?.code === "CHANGE_RECORD_INVALID"
      && error.details.file === "negative-zero.json"
  );
  await rm(path.join(directory, "negative-zero.json"));

  await writeJson(path.join(fixture.repoPath, "linked-source.json"), { id: "linked" });
  await symlink(
    path.join(fixture.repoPath, "linked-source.json"),
    path.join(directory, "linked.json")
  );
  await assert.rejects(
    store.snapshot(),
    (error) => error?.code === "CHANGE_STORE_ENTRY_INVALID" && error?.statusCode === 422
  );
  await rm(path.join(directory, "linked.json"));

  await writeJson(path.join(directory, "filename.json"), { id: "different-id" });
  await assert.rejects(
    store.snapshot(),
    (error) => error?.code === "CHANGE_RECORD_INVALID"
      && error.details.file === "filename.json"
  );

  const escapedRepo = path.join(anchorRoot, "repo");
  const outsideRuntime = path.join(anchorRoot, "outside-runtime");
  await mkdir(path.join(escapedRepo, ".legatura"), { recursive: true });
  await mkdir(path.join(outsideRuntime, "changes"), { recursive: true });
  await symlink(outsideRuntime, path.join(escapedRepo, ".legatura/runtime"));
  const escapedStore = createChangeStore(escapedRepo);
  for (const operation of [
    () => escapedStore.snapshot(),
    () => escapedStore.save({ id: "escaped" })
  ]) {
    await assert.rejects(
      operation(),
      (error) => error?.code === "CHANGE_STORE_DIRECTORY_INVALID"
        && error?.statusCode === 422
        && error.details.location === "runtime"
    );
  }
});

function findProfileEvidence(profile, changeRef, evidenceRef, origin) {
  const fact = profile.entities.evidence.find((item) => (
    item.changeRef === changeRef && item.evidenceRef === evidenceRef && item.origin === origin
  ));
  assert.ok(fact, `missing ${origin} occurrence for ${evidenceRef}`);
  return fact;
}

function assertAssociationDerivationIsBounded() {
  const sourceClaimIds = Array.from({ length: 256 }, (_, index) => `source-claim-${index + 1}`);
  const subjectDigest = canonicalDigest("bounded-association-subject");
  const supportBindings = Array.from({ length: 256 }, () => ({
    obligationId: "verify-target",
    claimId: "target-claim"
  }));
  const evidence = Array.from({ length: 256 }, (_, index) => ({
    id: `association-fanout-${index + 1}`,
    claim: { refs: sourceClaimIds },
    observation: { status: "passed" },
    provenance: {
      kind: "gate-command",
      gateId: "nonmatching-gate",
      commandId: "fanout-command",
      verificationSubjectDigest: subjectDigest
    },
    directSupportBindings: [],
    supportBindings
  }));
  assert.throws(
    () => validateEvidenceCoverage(
      [{ id: "target-claim", statement: "The bounded target remains exact." }],
      evidence,
      {
        authorityBindings: [{
          obligationId: "verify-target",
          authorityDecisionDigest: canonicalDigest("fanout-authority")
        }],
        verificationSubjectDigest: subjectDigest,
        trustedEvidenceBindings: evidence.map((item) => ({
          id: item.id,
          digest: canonicalDigest(item)
        })),
        verificationObligations: [{
          id: "verify-target",
          claimId: "target-claim",
          mapping: {
            kind: "cross-claim",
            sourceClaimIds,
            sourceRoutes: sourceClaimIds.map((sourceClaimId) => ({
              sourceClaimId,
              gateId: "fanout-gate",
              commandId: "fanout-command"
            }))
          }
        }]
      }
    ),
    (error) => error?.code === "EVIDENCE_COVERAGE_EVALUATION_LIMIT_EXCEEDED"
      && error?.statusCode === 413
  );
}

function assertEvidenceEligibilityFailsClosed() {
  const subjectDigest = canonicalDigest("fail-closed-evidence-subject");
  const targetClaim = {
    id: "target-claim",
    statement: "The target Claim has one unambiguous proof obligation."
  };
  const crossEvidence = {
    id: "ambiguous-obligation-evidence",
    claim: { refs: ["source-claim"] },
    observation: { status: "passed" },
    provenance: {
      kind: "gate-command",
      gateId: "minimum",
      commandId: "behavior",
      verificationSubjectDigest: subjectDigest
    },
    directSupportBindings: [],
    supportBindings: [{ obligationId: "verify-target-one", claimId: targetClaim.id }]
  };
  const crossMapping = {
    kind: "cross-claim",
    sourceClaimIds: ["source-claim"],
    sourceRoutes: [{
      sourceClaimId: "source-claim",
      gateId: "minimum",
      commandId: "behavior"
    }]
  };
  const ambiguous = validateEvidenceCoverage([targetClaim], [crossEvidence], {
    authorityBindings: [{
      obligationId: "verify-target-one",
      authorityDecisionDigest: canonicalDigest("ambiguous-authority")
    }],
    verificationSubjectDigest: subjectDigest,
    trustedEvidenceBindings: [{
      id: crossEvidence.id,
      digest: canonicalDigest(crossEvidence)
    }],
    verificationObligations: [
      { id: "verify-target-one", claimId: targetClaim.id, mapping: crossMapping },
      { id: "verify-target-two", claimId: targetClaim.id, mapping: crossMapping }
    ]
  });
  assert.deepEqual(ambiguous.duplicateObligationClaimIds, [targetClaim.id]);
  assert.deepEqual(ambiguous.eligibleClaimAssociations, []);

  const builtinEvidence = {
    id: "conflicting-builtin-envelope",
    claim: {
      id: targetClaim.id,
      statement: targetClaim.statement,
      refs: ["different-claim"]
    },
    observation: { status: "passed" },
    provenance: {
      kind: "builtin-oracle",
      sourceId: "project-model",
      verificationSubjectDigest: subjectDigest
    }
  };
  const conflictingEnvelope = validateEvidenceCoverage([targetClaim], [builtinEvidence], {
    verificationSubjectDigest: subjectDigest,
    trustedEvidenceBindings: [{
      id: builtinEvidence.id,
      digest: canonicalDigest(builtinEvidence)
    }],
    verificationObligations: [{
      id: "verify-target",
      claimId: targetClaim.id,
      mapping: { kind: "builtin-oracle", sourceIds: ["project-model"] }
    }]
  });
  assert.deepEqual(conflictingEnvelope.coveredClaimIds, []);
  assert.deepEqual(conflictingEnvelope.eligibleClaimAssociations, []);
}

async function snapshotChangeStore(repoPath) {
  const directory = path.join(repoPath, ".legatura/runtime/changes");
  const names = (await readdir(directory)).sort();
  return Promise.all(names.map(async (name) => {
    const filePath = path.join(directory, name);
    const [bytes, metadata] = await Promise.all([readFile(filePath, "utf8"), stat(filePath)]);
    return {
      name,
      bytes,
      inode: metadata.ino,
      modifiedAt: metadata.mtimeMs
    };
  }));
}

function assertNoForbiddenSummaryKeys(value) {
  if (Array.isArray(value)) {
    for (const item of value) assertNoForbiddenSummaryKeys(item);
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, item] of Object.entries(value)) {
    assert.equal(FORBIDDEN_SUMMARY_KEYS.has(key), false, `summary leaked ${key}`);
    assertNoForbiddenSummaryKeys(item);
  }
}

function countingCommandRunner() {
  let count = 0;
  return {
    async run(specification) {
      if (specification.purpose === "git-binding" && specification.args?.[0] === "rev-parse") {
        count += 1;
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
    observations: () => count,
    reset: () => { count = 0; }
  };
}

function sequencedGitRunner(heads) {
  let count = 0;
  let currentHead = heads[0];
  return {
    async run(specification) {
      const operation = specification.args?.[0];
      if (operation === "rev-parse") {
        currentHead = heads[Math.min(count, heads.length - 1)];
        count += 1;
        return commandResult(`${currentHead}\n`);
      }
      if (operation === "branch") return commandResult("main\n");
      if (operation === "status" || operation === "diff" || operation === "ls-files") {
        return commandResult("");
      }
      return { exitCode: 1, stdout: "", stderr: `Unexpected Git command after ${currentHead}.` };
    },
    observations: () => count
  };
}

function commandResult(stdout) {
  return { exitCode: 0, stdout, stderr: "" };
}

async function createFixture() {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-stable-query-"));
  await mkdir(path.join(repoPath, ".legatura/modules"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/contracts"), { recursive: true });
  await mkdir(path.join(repoPath, ".legatura/gates"), { recursive: true });
  await mkdir(path.join(repoPath, "src"));
  await writeFile(path.join(repoPath, ".legatura/.gitignore"), "runtime/\n");
  await writeJson(path.join(repoPath, ".legatura/project.json"), {
    schemaVersion: 1,
    project: { id: "stable-query-fixture", name: "Stable Query Fixture" },
    authorities: {
      decision: [{ id: "module-maintainer", may: ["case-decision"] }],
      fact: [{ id: "core-facts", module: "core", owns: "Fixture behavior" }]
    },
    assuranceBoundary: {
      governed: [{ module: "core", reason: "Fixture" }],
      provisional: [],
      opaque: []
    },
    changePolicy: { defaultGate: "minimum" }
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
    claims: [
      { id: "behavior-correct", statement: "The governed behavior remains correct." },
      { id: "secondary-behavior", statement: "The secondary governed behavior remains correct." }
    ],
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
      command: [
        process.execPath,
        "-e",
        `process.stdout.write(${JSON.stringify(SEALED_OUTPUT_SENTINEL)})`
      ],
      timeoutMs: 30_000,
      claimRefs: ["behavior-correct"],
      oracle: { kind: "fixture", description: "The fixture command exits zero." },
      applicability: { phase: "acceptance" },
      discriminatoryPower: { rejects: ["A non-zero exit rejects the fixture."] },
      residualUncertainty: ["Only fixture behavior is covered."]
    }]
  });
  await writeJson(path.join(repoPath, ".legatura/knowledge-gaps.json"), { schemaVersion: 1, gaps: [] });
  await writeFile(path.join(repoPath, "src/index.mjs"), "export const value = true;\n");
  await writeFile(path.join(repoPath, "README.md"), "stable query fixture\n");
  await git(repoPath, "init", "-q");
  await git(repoPath, "config", "user.email", "fixture@example.test");
  await git(repoPath, "config", "user.name", "Fixture");
  await git(repoPath, "add", ".");
  await git(repoPath, "commit", "-qm", "fixture");
  return { repoPath };
}

function changePath(repoPath, id) {
  return path.join(repoPath, ".legatura/runtime/changes", `${id}.json`);
}

async function writeJson(filePath, value) {
  await writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function git(cwd, ...args) {
  await execFileAsync("git", args, { cwd });
}
