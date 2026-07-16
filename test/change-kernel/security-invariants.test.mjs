import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { createKernel } from "../../src/core/index.mjs";

const execFileAsync = promisify(execFile);
const GATE_CLAIM_ID = "minimum-behavior";
const GAP_PROOF_CLAIM_ID = "gap-proof-behavior";
const GAP_PROOF_ID = "governed-proof-gap";
const CASE_DECISION = {
  status: "approved",
  authority: "maintainer",
  decidedBy: "security-invariants-test",
  decisionType: "case-decision",
  rationale: "Accept only this exact bounded Change."
};
const NO_NEW_KNOWLEDGE = {
  status: "complete",
  noNewKnowledge: true,
  rationale: "The Change discovered no future-relevant project knowledge."
};

test("self-reported manual Evidence cannot cover a Claim", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const claim = {
    id: "manual-only-claim",
    statement: "A self-reported manual result must not prove this Claim."
  };

  await kernel.createChange({
    id: "manual-evidence-attack",
    title: "Reject self-ratified Evidence",
    primaryModule: "core",
    claims: [claim],
    evidence: [{
      id: "self-reported-manual-pass",
      kind: "manual",
      claim,
      supportsClaimIds: [claim.id],
      oracle: {
        kind: "self-report",
        description: "The worker says that the behavior is correct."
      },
      observation: { status: "passed", detail: "Looks good to me." },
      provenance: { kind: "manual", source: "untrusted-worker" },
      applicability: { modules: ["core"] },
      discriminatoryPower: { rejects: ["nothing independently observable"] },
      residualUncertainty: ["No independent oracle observed the claimed behavior."]
    }],
    knowledgeClosure: NO_NEW_KNOWLEDGE
  });
  await kernel.compileChange("manual-evidence-attack");
  const gateResult = await kernel.runGate("manual-evidence-attack", "minimum");

  assert.equal(gateResult.status, "passed", "the unrelated configured Gate should still pass");
  assert.equal(
    gateResult.change.state,
    "Submitted",
    "manual Evidence must not make the Change EvidenceReady"
  );
  await assert.rejects(
    () => kernel.acceptChange("manual-evidence-attack", CASE_DECISION),
    (error) => error?.code === "CHANGE_NOT_EVIDENCE_READY"
  );
});

test("frozen governance and Gap proof contracts are enforced across lifecycle boundaries", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "governance-snapshot-attack";
  await kernel.createChange(changeInput(changeId));

  const originalDigest = await mutateRuntimeChange(fixture.repoPath, changeId, (record) => {
    const digest = record.governanceBaseline.digest;
    record.governanceBaseline.project.name = "Forged Security Policy";
    assert.equal(record.governanceBaseline.digest, digest, "the attacker retains the old digest");
    return digest;
  });
  const forged = await readRuntimeChange(fixture.repoPath, changeId);
  assert.equal(forged.governanceBaseline.digest, originalDigest);

  await assert.rejects(
    () => kernel.compileChange(changeId),
    (error) => error?.code === "GOVERNANCE_BASELINE_TAMPERED"
  );

  await assertGapProofLifecycleGuards(t);
  await assertStaleGovernanceCandidateGuards(t);
});

test("tampering with an Accepted Change Package invalidates reads and cannot be integrated", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });

  const readAttackId = "accepted-package-read-attack";
  await createAcceptedChange(kernel, readAttackId);
  await mutateRuntimeChange(fixture.repoPath, readAttackId, forgeAcceptedPackage);

  const invalidatedOnRead = await kernel.getChange(readAttackId);
  assert.equal(invalidatedOnRead.acceptance.valid, false);
  assert.notEqual(invalidatedOnRead.state, "Accepted");
  assert.notEqual(invalidatedOnRead.state, "Integrated");
  await assert.rejects(
    kernel.createChange({ title: "Do not build on corrupted Accepted history" }),
    (error) => error.code === "ACCEPTED_PACKAGE_CATALOG_INVALID"
  );

  const integrationFixture = await createFixture(t);
  const integrationKernel = createKernel({ repoPath: integrationFixture.repoPath });
  const integrationAttackId = "accepted-package-integration-attack";
  await createAcceptedChange(integrationKernel, integrationAttackId);
  await mutateRuntimeChange(integrationFixture.repoPath, integrationAttackId, forgeAcceptedPackage);

  let integrationError;
  try {
    await integrationKernel.acceptChange(integrationAttackId, { integrate: true });
  } catch (error) {
    integrationError = error;
  }
  if (integrationError) {
    assert.equal(integrationError.code, "ACCEPTANCE_INVALID");
  }
  const afterIntegrationAttack = await integrationKernel.getChange(integrationAttackId);
  assert.equal(
    afterIntegrationAttack.acceptance.valid,
    false,
    "an integration request must not silently re-accept a package whose persisted content was forged"
  );
  assert.notEqual(afterIntegrationAttack.state, "Integrated");
});

test("a Gate whose appliesTo excludes the primary Module is rejected", async (t) => {
  const fixture = await createFixture(t, { gateAppliesTo: ["another-module"] });
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "inapplicable-gate-attack";
  await kernel.createChange(changeInput(changeId));
  await kernel.compileChange(changeId);

  await assert.rejects(
    () => kernel.runGate(changeId, "minimum"),
    (error) => error?.code === "GATE_NOT_APPLICABLE"
      && error?.details?.primaryModule === "core"
  );
});

test("every changed Project Model path requires an exact normative Decision amendmentRef", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "partial-amendment-authorization";
  const modulePath = ".legatura/modules/core.json";
  const contractPath = ".legatura/contracts/core-api.json";

  await kernel.createChange({
    ...changeInput(changeId),
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-amendment",
        refs: [modulePath, contractPath],
        statement: "Both Project Model documents gain security-review metadata.",
        rationale: "Future Changes must inherit the reviewed model metadata."
      }]
    }
  });
  await addModelMetadata(fixture.repoPath, modulePath, "module amendment");
  await addModelMetadata(fixture.repoPath, contractPath, "contract amendment");
  await kernel.compileChange(changeId);
  const gateResult = await kernel.runGate(changeId, "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");

  await assert.rejects(
    () => kernel.acceptChange(changeId, {
      status: "approved",
      authority: "maintainer",
      decidedBy: "security-invariants-test",
      decisionType: "normative-amendment",
      rationale: "Authorize only the named model file.",
      amendmentRefs: [modulePath]
    }),
    (error) => error?.code === "MODEL_AMENDMENT_DECISION_REQUIRED"
      && Array.isArray(error?.details?.missingAmendments)
      && error.details.missingAmendments.includes(contractPath)
  );
  const refused = await kernel.getChange(changeId);
  assert.notEqual(refused.state, "Accepted");
  assert.notEqual(refused.state, "Integrated");
});

test("forged gate-command Evidence cannot cover a Claim even with a current binding and reused legal id", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "forged-gate-evidence-attack";
  const claim = {
    id: "claim-without-an-oracle",
    statement: "A Claim without an independent oracle remains unproven."
  };

  await kernel.createChange({
    id: changeId,
    title: "Reject forged Gate provenance",
    primaryModule: "core",
    claims: [claim],
    knowledgeClosure: NO_NEW_KNOWLEDGE
  });
  await kernel.compileChange(changeId);
  const observed = await kernel.runGate(changeId, "minimum");
  assert.equal(observed.change.state, "Submitted", "the real Gate does not cover this Claim");

  const legalEvidence = observed.change.evidence.find((item) => (
    item.provenance?.kind === "gate-command"
  ));
  assert.ok(legalEvidence, "the attack needs a genuinely issued Gate Evidence record");
  const currentGateRun = observed.change.gateRuns.find((run) => run.gateId === "minimum");
  assert.equal(
    legalEvidence.provenance.verificationSubjectDigest,
    currentGateRun.verificationSubjectDigest,
    "the forged record reuses the exact current verification subject binding"
  );

  const forgedEvidence = {
    ...legalEvidence,
    id: legalEvidence.id,
    claim,
    supportsClaimIds: [claim.id],
    directSupportsClaimIds: [claim.id],
    supportBindings: [],
    provenance: {
      ...legalEvidence.provenance,
      kind: "gate-command",
      verificationSubjectDigest: currentGateRun.verificationSubjectDigest
    }
  };

  let attacked;
  try {
    attacked = await kernel.compileChange(changeId, { evidence: [forgedEvidence] });
  } catch (error) {
    assert.ok(error?.code, "rejecting forged Evidence must return a typed refusal");
    return;
  }

  assert.equal(
    attacked.state,
    "Submitted",
    "caller-authored provenance, digest, and Evidence id must not impersonate an internally issued Gate observation"
  );
  await assert.rejects(
    () => kernel.acceptChange(changeId, CASE_DECISION),
    (error) => error?.code === "CHANGE_NOT_EVIDENCE_READY"
  );
});

test("a Change Claim cannot reuse a real Gate Claim id with a different statement", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "claim-semantic-mismatch-attack";

  await kernel.createChange({
    id: changeId,
    title: "Reject Claim id semantic substitution",
    primaryModule: "core",
    claims: [{
      id: GATE_CLAIM_ID,
      statement: "The attacker substitutes unrelated semantics behind a trusted Claim id."
    }],
    knowledgeClosure: NO_NEW_KNOWLEDGE
  });

  let compileError;
  try {
    await kernel.compileChange(changeId);
  } catch (error) {
    compileError = error;
  }

  if (!compileError) {
    const gateResult = await kernel.runGate(changeId, "minimum");
    assert.notEqual(
      gateResult.change.state,
      "EvidenceReady",
      "a Gate for the normative statement must never prove different semantics that reuse only its Claim id"
    );
    assert.fail("compileChange must reject a Contract Claim id whose statement was substituted");
  }

  assert.equal(compileError.code, "CLAIM_SEMANTIC_MISMATCH");
  const refused = await kernel.getChange(changeId);
  assert.notEqual(refused.state, "EvidenceReady");
  assert.notEqual(refused.state, "Accepted");
  assert.notEqual(refused.state, "Integrated");
});

test("a supplied write scope cannot broaden a generated non-recursive Module scope", async (t) => {
  const fixture = await createFixture(t, { moduleInclude: ["src/*.mjs"] });
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "context-write-scope-expansion";
  await kernel.createChange(changeInput(changeId));

  await assert.rejects(
    () => kernel.compileChange(changeId, {
      contextCapsule: {
        scope: {
          write: { include: ["src/evil/**"] }
        }
      }
    }),
    (error) => error?.code === "CONTEXT_SCOPE_EXPANSION_FORBIDDEN"
      && error?.details?.outside?.includes("src/evil/**")
      && error?.details?.allowed?.includes("src/*.mjs")
  );
  const refused = await kernel.getChange(changeId);
  assert.equal(refused.state, "Candidate");
  assert.equal(refused.contextCapsule, null);
});

test("committing an out-of-scope path after Change creation remains visible and blocks acceptance", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "committed-scope-escape";
  const escapedPath = "outside/evil.mjs";
  await kernel.createChange(changeInput(changeId));

  await mkdir(path.join(fixture.repoPath, "outside"), { recursive: true });
  await writeFile(
    path.join(fixture.repoPath, escapedPath),
    "export const escapedGovernance = true;\n"
  );
  await execFileAsync("git", ["add", escapedPath], { cwd: fixture.repoPath });
  await execFileAsync("git", ["commit", "--quiet", "-m", "commit scope escape"], {
    cwd: fixture.repoPath
  });

  const compiled = await kernel.compileChange(changeId);
  assert.equal(compiled.changeSet.observed.dirty, false, "the attack hides in a clean committed HEAD");
  assert.equal(compiled.changeSet.observed.headChanged, true);
  assert.ok(compiled.scopeAnalysis.touchedPaths.includes(escapedPath));
  assert.ok(compiled.scopeAnalysis.outOfScopePaths.includes(escapedPath));

  const gateResult = await kernel.runGate(changeId, "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");
  assert.ok(gateResult.change.scopeAnalysis.outOfScopePaths.includes(escapedPath));
  await assert.rejects(
    () => kernel.acceptChange(changeId, CASE_DECISION),
    (error) => error?.code === "CHANGE_SCOPE_EXCEEDED"
      && error?.details?.outOfScopePaths?.includes(escapedPath)
  );
  const refused = await kernel.getChange(changeId);
  assert.notEqual(refused.state, "Accepted");
  assert.notEqual(refused.state, "Integrated");
});

test("an Accepted Change is sealed against recompilation and minimum Gate replay", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "sealed-accepted-change";
  const accepted = await createAcceptedChange(kernel, changeId);
  const acceptedState = accepted.state;
  const acceptedPackage = accepted.acceptance;

  await assert.rejects(
    () => kernel.compileChange(changeId, { description: "Attempt to mutate sealed intent." }),
    (error) => error?.code === "CHANGE_SEALED"
  );
  const afterCompile = await kernel.getChange(changeId);
  assert.equal(afterCompile.state, acceptedState);
  assert.deepEqual(afterCompile.acceptance, acceptedPackage);

  await assert.rejects(
    () => kernel.runGate(changeId, "minimum"),
    (error) => error?.code === "CHANGE_SEALED"
  );
  const afterGateReplay = await kernel.getChange(changeId);
  assert.equal(afterGateReplay.state, acceptedState);
  assert.deepEqual(afterGateReplay.acceptance, acceptedPackage);
});

test("a runtime-only model-gap Closure is not durable knowledge", async (t) => {
  const fixture = await createFixture(t);
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const changeId = "runtime-only-model-gap";
  await kernel.createChange({
    ...changeInput(changeId),
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-gap",
        refs: ["gap-runtime-only"],
        statement: "An unresolved governed behavior remains unknown.",
        rationale: "Future Changes must see this uncertainty."
      }]
    }
  });
  await kernel.compileChange(changeId);
  const gateResult = await kernel.runGate(changeId, "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");
  assert.equal(gateResult.change.scopeAnalysis.modelAmendmentPaths.length, 0);

  await assert.rejects(
    () => kernel.acceptChange(changeId, CASE_DECISION),
    (error) => error?.code === "KNOWLEDGE_CLOSURE_NOT_DURABLE"
      && error?.details?.knowledgeGapFileChanged === false
      && error?.details?.unknownGapRefs?.includes("gap-runtime-only")
  );
  const refused = await kernel.getChange(changeId);
  assert.notEqual(refused.state, "Accepted");
  assert.notEqual(refused.state, "Integrated");
});

async function createAcceptedChange(kernel, changeId) {
  await kernel.createChange(changeInput(changeId));
  await kernel.compileChange(changeId);
  const gateResult = await kernel.runGate(changeId, "minimum");
  assert.equal(gateResult.change.state, "EvidenceReady");
  const accepted = await kernel.acceptChange(changeId, CASE_DECISION);
  assert.equal(accepted.state, "Accepted");
  assert.equal(accepted.acceptance.valid, true);
  return accepted;
}

async function assertGapProofLifecycleGuards(t) {
  const compileFixture = await createFixture(t, {
    proofContract: true,
    gateWritesMarker: true
  });
  const compileKernel = createKernel({ repoPath: compileFixture.repoPath });
  const compileChangeId = "proof-route-drift-before-compile";
  await compileKernel.createChange(changeInput(compileChangeId));
  await rewriteProofRoute(compileFixture.repoPath, "compile-time weakened oracle");
  await assert.rejects(
    () => compileKernel.compileChange(compileChangeId),
    isProofRouteRewrite
  );
  const compileRefusal = await readRuntimeChange(compileFixture.repoPath, compileChangeId);
  assert.equal(compileRefusal.state, "Candidate");
  assert.deepEqual(compileRefusal.gateRuns, []);
  assert.equal(compileRefusal.acceptance, null);
  await assertFileMissing(compileFixture.gateMarkerPath);

  const gateFixture = await createFixture(t, {
    proofContract: true,
    gateWritesMarker: true
  });
  const gateKernel = createKernel({ repoPath: gateFixture.repoPath });
  const gateChangeId = "proof-route-drift-before-gate";
  await gateKernel.createChange(changeInput(gateChangeId));
  await gateKernel.compileChange(gateChangeId);
  await rewriteProofRoute(gateFixture.repoPath, "gate-time weakened oracle");
  await assert.rejects(
    () => gateKernel.runGate(gateChangeId, "minimum"),
    isProofRouteRewrite
  );
  const gateRefusal = await readRuntimeChange(gateFixture.repoPath, gateChangeId);
  assert.equal(gateRefusal.state, "Submitted");
  assert.deepEqual(gateRefusal.gateRuns, []);
  assert.equal(gateRefusal.acceptance, null);
  await assertFileMissing(gateFixture.gateMarkerPath);

  const acceptFixture = await createFixture(t, {
    proofContract: true,
    gateWritesMarker: true
  });
  const acceptKernel = createKernel({ repoPath: acceptFixture.repoPath });
  const acceptChangeId = "proof-route-drift-before-accept";
  await acceptKernel.createChange(changeInput(acceptChangeId));
  await acceptKernel.compileChange(acceptChangeId);
  const evidenceReady = await acceptKernel.runGate(acceptChangeId, "minimum");
  assert.equal(
    evidenceReady.change.state,
    "EvidenceReady",
    JSON.stringify(evidenceReady.gateRuns)
  );
  await rm(acceptFixture.gateMarkerPath, { force: true });
  await rewriteProofRoute(acceptFixture.repoPath, "accept-time weakened oracle");
  await assert.rejects(
    () => acceptKernel.acceptChange(acceptChangeId, CASE_DECISION),
    isProofRouteRewrite
  );
  const acceptRefusal = await readRuntimeChange(acceptFixture.repoPath, acceptChangeId);
  assert.equal(acceptRefusal.state, "EvidenceReady");
  assert.deepEqual(acceptRefusal.gateRuns, evidenceReady.change.gateRuns);
  assert.equal(acceptRefusal.authorityDecision, null);
  assert.equal(acceptRefusal.acceptance, null);
  await assertFileMissing(acceptFixture.gateMarkerPath);

  const closureFixture = await createFixture(t, { proofContract: true });
  const closureKernel = createKernel({ repoPath: closureFixture.repoPath });
  const closureChangeId = "ordinary-change-forges-gap-closure";
  await closureKernel.createChange(changeInput(closureChangeId));
  await forgeGapClosure(closureFixture.repoPath);
  await assert.rejects(
    () => closureKernel.compileChange(closureChangeId),
    (error) => error?.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
      && error?.details?.problems?.includes("gap-closure-transition-uncompiled")
  );
  const closureRefusal = await readRuntimeChange(closureFixture.repoPath, closureChangeId);
  assert.equal(closureRefusal.state, "Candidate");
  assert.deepEqual(closureRefusal.gateRuns, []);
  assert.equal(closureRefusal.acceptance, null);
}

async function assertStaleGovernanceCandidateGuards(t) {
  const fixture = await createFixture(t, { gateWritesMarker: true });
  const kernel = createKernel({ repoPath: fixture.repoPath });
  const compileChangeId = "stale-governance-before-compile";
  const gateChangeId = "stale-governance-before-gate";
  const acceptChangeId = "stale-governance-before-accept";
  for (const changeId of [compileChangeId, gateChangeId, acceptChangeId]) {
    await kernel.createChange(changeInput(changeId));
  }

  await kernel.compileChange(gateChangeId);
  await kernel.compileChange(acceptChangeId);
  const evidenceReady = await kernel.runGate(acceptChangeId, "minimum");
  assert.equal(evidenceReady.change.state, "EvidenceReady");
  await rm(fixture.gateMarkerPath, { force: true });

  const governanceChangeId = "accepted-governance-after-candidates";
  const modulePath = ".legatura/modules/core.json";
  const moduleFile = path.join(fixture.repoPath, modulePath);
  const originalModule = await readFile(moduleFile, "utf8");
  await kernel.createChange({
    ...changeInput(governanceChangeId),
    knowledgeClosure: {
      status: "complete",
      entries: [{
        kind: "model-amendment",
        refs: [modulePath],
        statement: "The governed Module records an Accepted security review.",
        rationale: "Later Candidates must inherit the reviewed Project Model baseline."
      }]
    }
  });
  await addModelMetadata(fixture.repoPath, modulePath, "accepted governance watermark");
  await kernel.compileChange(governanceChangeId);
  const governanceGate = await kernel.runGate(governanceChangeId, "minimum");
  assert.equal(governanceGate.change.state, "EvidenceReady");
  const acceptedGovernance = await kernel.acceptChange(governanceChangeId, {
    status: "approved",
    authority: "maintainer",
    decidedBy: "security-invariants-test",
    decisionType: "normative-amendment",
    rationale: "Accept the exact Project Model amendment.",
    amendmentRefs: [modulePath]
  });
  assert.equal(acceptedGovernance.state, "Accepted");
  const acceptedReference = {
    changeId: governanceChangeId,
    acceptanceDigest: acceptedGovernance.acceptance.digest
  };
  const integratedGovernance = await kernel.acceptChange(governanceChangeId, { integrate: true });
  assert.equal(integratedGovernance.state, "Integrated", "the governance Package must not stale itself");

  await writeFile(moduleFile, originalModule, "utf8");
  await rm(fixture.gateMarkerPath, { force: true });
  const invalidatedGovernance = await kernel.getChange(governanceChangeId);
  assert.equal(invalidatedGovernance.acceptance.valid, false);
  assert.equal(invalidatedGovernance.state, "Submitted");

  const rejectsStaleCandidate = (error) => isStaleGovernanceError(
    error,
    acceptedReference,
    modulePath
  );
  await assert.rejects(() => kernel.compileChange(compileChangeId), rejectsStaleCandidate);
  const compileRefusal = await readRuntimeChange(fixture.repoPath, compileChangeId);
  assert.equal(compileRefusal.state, "Candidate");
  assert.equal(compileRefusal.compilation, undefined);
  assert.deepEqual(compileRefusal.gateRuns, []);
  assert.equal(compileRefusal.authorityDecision, null);
  assert.equal(compileRefusal.acceptance, null);

  await assert.rejects(() => kernel.runGate(gateChangeId, "minimum"), rejectsStaleCandidate);
  const gateRefusal = await readRuntimeChange(fixture.repoPath, gateChangeId);
  assert.equal(gateRefusal.state, "Submitted");
  assert.deepEqual(gateRefusal.gateRuns, []);
  assert.equal(gateRefusal.authorityDecision, null);
  assert.equal(gateRefusal.acceptance, null);
  await assertFileMissing(fixture.gateMarkerPath);

  await assert.rejects(
    () => kernel.acceptChange(acceptChangeId, CASE_DECISION),
    rejectsStaleCandidate
  );
  const acceptRefusal = await readRuntimeChange(fixture.repoPath, acceptChangeId);
  assert.equal(acceptRefusal.state, "EvidenceReady");
  assert.deepEqual(acceptRefusal.gateRuns, evidenceReady.change.gateRuns);
  assert.equal(acceptRefusal.authorityDecision, null);
  assert.equal(acceptRefusal.acceptance, null);
}

function isStaleGovernanceError(error, expectedReference, expectedPath) {
  if (error?.code !== "GOVERNANCE_BASELINE_STALE") return false;
  const superseding = error?.details?.supersedingPackages;
  return Array.isArray(superseding) && superseding.some((entry) => (
    entry?.reference?.changeId === expectedReference.changeId
      && entry.reference.acceptanceDigest === expectedReference.acceptanceDigest
      && entry.modelAmendmentPaths?.includes(expectedPath)
      && entry.decisionType === "normative-amendment"
  ));
}

function isProofRouteRewrite(error) {
  return error?.code === "KNOWLEDGE_GAP_PROOF_CONTRACT_REWRITE_FORBIDDEN"
    && error?.details?.claimRef === GAP_PROOF_CLAIM_ID
    && error?.details?.problems?.includes("gate-route-semantic-mismatch");
}

async function rewriteProofRoute(repoPath, rejectedBehavior) {
  const gatePath = path.join(repoPath, ".legatura", "gates", "minimum.json");
  const gate = JSON.parse(await readFile(gatePath, "utf8"));
  gate.commands[0].discriminatoryPower = { rejects: [rejectedBehavior] };
  await writeJson(gatePath, gate);
}

async function forgeGapClosure(repoPath) {
  const gapPath = path.join(repoPath, ".legatura", "knowledge-gaps.json");
  const document = JSON.parse(await readFile(gapPath, "utf8"));
  const gap = document.gaps.find((entry) => entry.id === GAP_PROOF_ID);
  gap.status = "closed";
  gap.resolution = "The ordinary Change falsely declares the governed uncertainty resolved.";
  gap.reopenTrigger = "Any observation that exposes the forged closure.";
  gap.closedBy = [{
    changeId: "forged-accepted-package",
    acceptanceDigest: `sha256:${"0".repeat(64)}`
  }];
  await writeJson(gapPath, document);
}

async function assertFileMissing(targetPath) {
  await assert.rejects(
    () => readFile(targetPath),
    (error) => error?.code === "ENOENT"
  );
}

function changeInput(id) {
  return {
    id,
    title: `Security invariant ${id}`,
    primaryModule: "core",
    claims: [{
      id: GATE_CLAIM_ID,
      statement: "The minimum governed behavior remains correct."
    }],
    knowledgeClosure: NO_NEW_KNOWLEDGE
  };
}

function forgeAcceptedPackage(record) {
  assert.equal(record.acceptance.valid, true);
  const digest = record.acceptance.digest;
  record.acceptance.package.intent.title = "Forged accepted intent";
  assert.equal(record.acceptance.digest, digest, "the attacker retains the accepted digest");
}

async function addModelMetadata(repoPath, relativePath, value) {
  const target = path.join(repoPath, relativePath);
  const document = JSON.parse(await readFile(target, "utf8"));
  document.securityReview = value;
  await writeJson(target, document);
}

async function mutateRuntimeChange(repoPath, changeId, mutate) {
  const record = await readRuntimeChange(repoPath, changeId);
  const result = mutate(record);
  await writeJson(runtimeChangePath(repoPath, changeId), record);
  return result;
}

async function readRuntimeChange(repoPath, changeId) {
  return JSON.parse(await readFile(runtimeChangePath(repoPath, changeId), "utf8"));
}

function runtimeChangePath(repoPath, changeId) {
  return path.join(repoPath, ".legatura", "runtime", "changes", `${changeId}.json`);
}

async function createFixture(t, {
  gateAppliesTo = ["core"],
  moduleInclude = ["src/**"],
  proofContract = false,
  gateWritesMarker = false
} = {}) {
  const repoPath = await mkdtemp(path.join(os.tmpdir(), "legatura-security-"));
  const gateMarkerPath = path.join(
    repoPath,
    ".legatura",
    "runtime",
    "external-gate-ran.marker"
  );
  const gateCommand = gateWritesMarker
    ? [
        process.execPath,
        "-e",
        "require('node:fs').writeFileSync(process.argv[1], 'external gate ran')",
        gateMarkerPath
      ]
    : [process.execPath, "-e", "process.exit(0)"];
  t.after(() => rm(repoPath, { force: true, recursive: true }));
  await Promise.all([
    mkdir(path.join(repoPath, ".legatura", "modules"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "contracts"), { recursive: true }),
    mkdir(path.join(repoPath, ".legatura", "gates"), { recursive: true }),
    mkdir(path.join(repoPath, "src"), { recursive: true })
  ]);

  await Promise.all([
    writeFile(path.join(repoPath, ".legatura", ".gitignore"), "runtime/\n"),
    writeJson(path.join(repoPath, ".legatura", "project.json"), {
      project: { id: "security-fixture", name: "Security Fixture" },
      normativeSources: [{ id: "accepted-requirement" }],
      authorities: {
        fact: [{ id: "core-facts" }],
        decision: [{
          id: "maintainer",
          may: ["case-decision", "normative-amendment"]
        }]
      },
      assuranceBoundary: { governed: ["core"], provisional: [], opaque: [] },
      changePolicy: { defaultGate: "minimum" }
    }),
    writeJson(path.join(repoPath, ".legatura", "modules", "core.json"), {
      id: "core",
      name: "Core",
      status: "governed",
      paths: { include: moduleInclude },
      interface: { description: "The governed security fixture interface." },
      factAuthority: "core-facts",
      decisionAuthority: "maintainer",
      publicContracts: ["core-api"]
    }),
    writeJson(path.join(repoPath, ".legatura", "contracts", "core-api.json"), {
      id: "core-api",
      name: "Core API",
      owner: "core",
      consumers: [],
      normativeSources: ["accepted-requirement"],
      claims: [{
        id: GATE_CLAIM_ID,
        statement: "The minimum governed behavior remains correct."
      }, ...(proofContract ? [{
        id: GAP_PROOF_CLAIM_ID,
        statement: "The governed Gap closes only through its exact independent proof route."
      }] : [])]
    }),
    writeJson(path.join(repoPath, ".legatura", "gates", "minimum.json"), {
      id: "minimum",
      name: "Minimum Verification",
      appliesTo: gateAppliesTo,
      commands: [{
        id: "minimum-command",
        command: gateCommand,
        claimRefs: [GATE_CLAIM_ID, ...(proofContract ? [GAP_PROOF_CLAIM_ID] : [])],
        oracle: {
          kind: "deterministic-process-exit",
          description: "The fixture command must exit successfully."
        },
        applicability: { phase: "acceptance" },
        discriminatoryPower: { rejects: ["a non-zero fixture exit"] },
        residualUncertainty: ["The fixture is intentionally bounded."]
      }]
    }),
    writeJson(path.join(repoPath, ".legatura", "knowledge-gaps.json"), {
      gaps: proofContract ? [{
        id: GAP_PROOF_ID,
        status: "open",
        statement: "The governed behavior remains unresolved until exact independent proof exists.",
        affects: ["core"],
        owner: "maintainer",
        expansionTrigger: "The proof route or governed behavior changes.",
        proofClaimRefs: [GAP_PROOF_CLAIM_ID]
      }] : []
    }),
    writeFile(path.join(repoPath, "src", "index.mjs"), "export const governed = true;\n")
  ]);

  await execFileAsync("git", ["init", "--quiet"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.name", "Legatura Security Test"], { cwd: repoPath });
  await execFileAsync("git", ["config", "user.email", "security@example.invalid"], { cwd: repoPath });
  await execFileAsync("git", ["add", "."], { cwd: repoPath });
  await execFileAsync("git", ["commit", "--quiet", "-m", "security baseline"], { cwd: repoPath });
  return { repoPath, gateMarkerPath };
}

function writeJson(targetPath, value) {
  return writeFile(targetPath, `${JSON.stringify(value, null, 2)}\n`);
}
