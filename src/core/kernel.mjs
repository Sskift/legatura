import path from "node:path";
import { randomUUID } from "node:crypto";
import {
  ARCHITECTURE_PROFILE_LIMITS,
  compileArchitectureProfile
} from "./architecture-profile.mjs";
import { canonicalDigest, cloneJson } from "./canonical.mjs";
import {
  assertIntegrityFailureEvidenceCurrent,
  compileChangeAgainstGovernance,
  parseChangePlanRefs,
  validateIntegrityFailureEvidence
} from "./change-compiler.mjs";
import { createChangeStore } from "./change-store.mjs";
import { executeCommand, normalizeGateCommand } from "./command-runner.mjs";
import {
  createGateEvidence,
  createProjectModelEvidence,
  normalizeAuthorityDecision,
  normalizeClaims,
  normalizeEvidenceList,
  readExpectedAuthorities,
  validateAuthorityDecision,
  validateEvidenceCoverage,
  validateKnowledgeClosure
} from "./evidence.mjs";
import { readGitBinding } from "./git-binding.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  compileClaimGateRouteIndex,
  loadProjectModel,
  projectCompiledClaimGateRouteIndex,
  publicProjectModel,
  validateProjectModel
} from "./project-model.mjs";
import {
  OUTCOME_TRANSITION_SCHEMA_VERSION,
  compileOutcomeTransitions,
  inspectAcceptedPackageRecord
} from "./outcome-transitions.mjs";

const CHANGE_SCHEMA_VERSION = 1;
const OUTCOME_ALIGNMENT_SCHEMA_VERSION = 1;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const STATES = ["Candidate", "Submitted", "EvidenceReady", "Accepted", "Integrated"];
const STABLE_OBSERVATION_LIMIT = 3;
const CHANGE_SUMMARY_TEXT_LIMIT = 240;
const CHANGE_SUMMARY_PLAN_REF_LIMIT = 8;
const EVIDENCE_ASSESSMENT_COLLECTION_LIMIT = 256;
const EVIDENCE_ASSESSMENT_WORK_LIMIT = 32768;
const ARCHITECTURE_PROFILE_QUERY_FACT_LIMIT = 32768;
const ARCHITECTURE_PROFILE_MODEL_ROUTE_WORK_LIMIT = 32768;
const WORKBENCH_ACTION_FACT_LIMIT = 65536;
const WORKBENCH_PROJECTION_BYTE_LIMIT = 4 * 1024 * 1024;

export const WORKBENCH_DISABLED_REASON_CODES = Object.freeze([
  "MODULE_NOT_GOVERNED",
  "CLAIM_ACCEPTANCE_ROUTE_MISSING",
  "CHANGE_CLAIM_REQUIRED",
  "CHANGE_NOT_COMPILED",
  "CHANGE_NOT_EVIDENCE_READY",
  "CHANGE_SEALED",
  "GATE_NOT_APPLICABLE",
  "GATE_COMMAND_NOT_APPLICABLE"
]);

const WORKBENCH_DISABLED_REASON_PRECEDENCE = new Map(
  WORKBENCH_DISABLED_REASON_CODES.map((code, index) => [code, index])
);

export function createKernel({ repoPath, clock, commandRunner } = {}) {
  if (typeof repoPath !== "string" || !repoPath.trim()) {
    throw kernelError("REPO_PATH_REQUIRED", "createKernel requires repoPath.", 400);
  }
  const resolvedRepoPath = path.resolve(repoPath);
  const store = createChangeStore(resolvedRepoPath);
  const now = () => readClock(clock);
  let operationQueue = Promise.resolve();

  function serializeOperation(operation) {
    const result = operationQueue.then(operation, operation);
    operationQueue = result.then(() => undefined, () => undefined);
    return result;
  }

  async function observeProjectOnce() {
    const [model, git] = await Promise.all([
      loadProjectModel(resolvedRepoPath),
      readGitBinding(resolvedRepoPath, commandRunner)
    ]);
    const validation = validateProjectModel(model);
    if (!git.available) {
      validation.errors.push({
        code: "git.repository.required",
        location: resolvedRepoPath,
        message: "Project must be backed by a Git repository with a HEAD commit."
      });
      validation.valid = false;
    }
    const inspection = {
      valid: validation.valid,
      repoPath: resolvedRepoPath,
      ...publicProjectModel(model),
      git: cloneJson(git),
      validation
    };
    return {
      digest: canonicalDigest({
        projectModelDigest: inspection.digest,
        gitContentDigest: inspection.git.contentDigest
      }),
      inspection
    };
  }

  async function inspectProject() {
    const stable = await readStableObservation({
      observe: observeProjectOnce,
      code: "PROJECT_SNAPSHOT_UNSTABLE",
      message: "Project Model and Git sources did not stabilize within the bounded observation window."
    });
    return cloneJson(stable.inspection);
  }

  async function observeChangeQueryOnce() {
    const [project, changeStore] = await Promise.all([
      observeProjectOnce(),
      store.snapshot()
    ]);
    return {
      digest: canonicalDigest({
        projectModelGitDigest: project.digest,
        changeStoreDigest: changeStore.digest
      }),
      changeStoreDigest: changeStore.digest,
      inspection: project.inspection,
      records: changeStore.records
    };
  }

  async function inspectChangeQuery() {
    return readStableObservation({
      observe: observeChangeQueryOnce,
      code: "CHANGE_QUERY_SNAPSHOT_UNSTABLE",
      message: "Project Model, Git, and Change Store sources did not stabilize within the bounded observation window."
    });
  }

  async function listChanges() {
    const snapshot = await inspectChangeQuery();
    return snapshot.records.map((record) => summarizeChangeForRead(record, snapshot));
  }

  async function inspectArchitectureProfile() {
    const snapshot = await inspectChangeQuery();
    return compileArchitectureProfileFromSnapshot(snapshot);
  }

  async function inspectWorkbenchProjection() {
    const snapshot = await inspectChangeQuery();
    return compileWorkbenchProjectionFromSnapshot(snapshot);
  }

  async function observeCurrentChangeScope(change, git, currentPlan) {
    const touchedPaths = await readObservedTouchedPaths(change, git, resolvedRepoPath, commandRunner);
    change.changeSet = compileObservedChangeSet(change, git, touchedPaths);
    change.scopeAnalysis = analyzeChangeScope(change, git, touchedPaths);
    assertPlanChangeSeparation(change, touchedPaths);
    assertPlanHistoryPreserved(change, currentPlan);
  }

  async function deriveCurrentOutcomeTransitions(change, currentModel) {
    const catalog = assertPriorAcceptedPackageCatalog(change.priorAcceptedPackages, {
      required: change.changeKind === "plan-amendment"
    });
    const resolvedPackages = catalog
      ? (await Promise.all(catalog.entries.map((entry) => store.get(entry.changeId)))).filter(Boolean)
      : [];
    return compileOutcomeTransitions({
      change,
      governanceBaseline: readGovernanceBaseline(change),
      currentModel,
      resolvedPackages,
      priorAcceptedPackages: catalog
    });
  }

  async function assertCurrentOutcomeTransitions(change, currentModel) {
    if (change.outcomeTransitionSchemaVersion !== OUTCOME_TRANSITION_SCHEMA_VERSION
      || !change.outcomeTransitionCompilation) {
      throw kernelError(
        "OUTCOME_TRANSITION_COMPILATION_STALE",
        "Compile the Outcome Transition projection before running Gates or accepting the Change.",
        409
      );
    }
    const expected = await deriveCurrentOutcomeTransitions(change, currentModel);
    if (canonicalDigest(expected) !== canonicalDigest(change.outcomeTransitionCompilation)) {
      throw kernelError(
        "OUTCOME_TRANSITION_COMPILATION_STALE",
        "Outcome Transition proof no longer matches the frozen catalog, current Plan, or resolved Accepted Packages.",
        409,
        {
          expectedDigest: canonicalDigest(expected),
          observedDigest: canonicalDigest(change.outcomeTransitionCompilation)
        }
      );
    }
    return expected;
  }

  async function assertCurrentGovernanceContracts(change, currentModel, { modelValid = true } = {}) {
    if (!modelValid) return null;
    if (change.changeKind === "plan-amendment") {
      return assertCurrentOutcomeTransitions(change, currentModel);
    }
    return assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: readGovernanceBaseline(change),
      currentModel
    });
  }

  async function assertGovernanceWatermarkCurrent(change) {
    const frozenCatalog = assertPriorAcceptedPackageCatalog(change.priorAcceptedPackages);
    if (!frozenCatalog) {
      throw kernelError(
        "ACCEPTED_PACKAGE_CATALOG_INVALID",
        `Change ${change.id} has no Candidate-frozen Accepted Package catalog.`,
        409,
        { changeId: change.id, problems: ["candidate-catalog-missing"] }
      );
    }

    const governanceBaseline = readGovernanceBaseline(change);
    const records = (await store.list()).filter((record) => record?.id !== change.id);
    const frozenReferences = new Set(frozenCatalog.entries.map((entry) => canonicalDigest(entry)));
    const supersedingPackages = [];

    for (const record of records) {
      if (!claimsHistoricalAcceptance(record)) continue;
      const claimedReference = {
        changeId: readString(record?.id),
        acceptanceDigest: readString(record?.acceptance?.digest)
      };
      if (claimedReference.changeId && claimedReference.acceptanceDigest
        && frozenReferences.has(canonicalDigest(claimedReference))) continue;
      const inspection = inspectAcceptedPackageRecord(record);
      if (!inspection.valid) {
        throw kernelError(
          "ACCEPTED_PACKAGE_CATALOG_INVALID",
          `Cannot evaluate Candidate governance history because Change ${record?.id ?? "unknown"} claims an invalid Accepted Package.`,
          409,
          { changeId: record?.id ?? null, problems: inspection.problems }
        );
      }
      const packageContent = inspection.package;
      if (!acceptedPackageMatchesProject(packageContent, resolvedRepoPath, governanceBaseline)) continue;
      const rawModelAmendmentPaths = packageContent?.scopeAnalysis?.modelAmendmentPaths;
      const hasModelAmendmentPathList = Array.isArray(rawModelAmendmentPaths);
      const modelAmendmentPaths = hasModelAmendmentPathList
        ? normalizeStringList(rawModelAmendmentPaths).sort()
        : [];
      const decisionType = readString(packageContent?.authorityDecision?.decisionType);
      const legacyNormativeAmendment = !hasModelAmendmentPathList
        && decisionType === "normative-amendment";
      if (modelAmendmentPaths.length === 0 && !legacyNormativeAmendment) continue;
      supersedingPackages.push({
        reference: inspection.reference,
        acceptedAt: inspection.acceptedAt,
        modelAmendmentPaths,
        decisionType: decisionType ?? null
      });
    }

    if (supersedingPackages.length > 0) {
      throw kernelError(
        "GOVERNANCE_BASELINE_STALE",
        `Change ${change.id} predates historically Accepted Project Model governance; create a successor Candidate.`,
        409,
        {
          changeId: change.id,
          governanceBaselineDigest: governanceBaseline.digest,
          frozenAcceptedPackagesDigest: frozenCatalog.digest,
          supersedingPackages
        }
      );
    }
  }

  async function createChange(input = {}) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw kernelError("CHANGE_INPUT_INVALID", "createChange input must be an object.", 400);
    }
    const planRefsInput = adaptChangePlanRefsInput(input);
    const inspection = await inspectProject();
    assertValidProject(inspection);
    const id = readString(input.id) ?? await createUniqueChangeId(store, now());
    if (await store.get(id)) {
      throw kernelError("CHANGE_EXISTS", `Change already exists: ${id}.`, 409, { changeId: id });
    }
    const title = readString(input.title)
      ?? readString(input.request)
      ?? readString(input.description);
    if (!title) {
      throw kernelError("CHANGE_TITLE_REQUIRED", "Change requires title, request, or description.", 422);
    }
    const createdAt = now();
    const primaryModule = readString(input.primaryModule) ?? readString(input.module);
    if (primaryModule && !inspection.modules.some((module) => module.id === primaryModule)) {
      throw kernelError("CHANGE_MODULE_UNKNOWN", `Unknown primary Module: ${primaryModule}.`, 422);
    }
    const claims = normalizeClaims(input.claims ?? input.claim);
    const evidence = normalizeEvidenceList(input.evidence);
    const governanceBaseline = freezeGovernanceBaseline(inspection);
    const priorAcceptedPackages = freezePriorAcceptedPackageCatalog({
      records: await store.list(),
      createdAt,
      repoPath: resolvedRepoPath,
      governanceBaseline
    });
    const change = {
      schemaVersion: CHANGE_SCHEMA_VERSION,
      id,
      repoPath: resolvedRepoPath,
      state: "Candidate",
      intent: {
        title,
        request: readString(input.request) ?? title,
        ...(readString(input.description) ? { description: input.description.trim() } : {}),
        nonGoals: normalizeStringList(input.nonGoals)
      },
      ...(primaryModule ? { primaryModule } : {}),
      changeKind: readString(input.changeKind) ?? "implementation",
      planRefs: planRefsInput.planRefs,
      integrityTarget: cloneJson(input.integrityTarget ?? null),
      outcomeAlignmentSchemaVersion: OUTCOME_ALIGNMENT_SCHEMA_VERSION,
      outcomeAlignment: null,
      outcomeTransitionSchemaVersion: OUTCOME_TRANSITION_SCHEMA_VERSION,
      priorAcceptedPackages,
      outcomeTransitionCompilation: null,
      claims,
      verificationObligations: normalizeVerificationObligations(input.verificationObligations, claims),
      verificationPlan: null,
      evidence,
      knowledgeClosure: cloneJson(input.knowledgeClosure ?? null),
      authorityDecision: input.authorityDecision
        ? normalizeAuthorityDecision(input.authorityDecision, createdAt)
        : null,
      impact: {},
      taskPlan: cloneJson(input.taskPlan ?? null),
      contextCapsule: null,
      changeSet: cloneJson(input.changeSet ?? {}),
      modelExpansion: cloneJson(input.modelExpansion ?? null),
      compilerInput: {
        verificationObligations: cloneJson(input.verificationObligations ?? []),
        impact: cloneJson(input.impact ?? null),
        contextCapsule: cloneJson(input.contextCapsule ?? null),
        outcomeContributionHints: cloneJson(input.outcomeContributionHints ?? []),
        outcomeExceptions: cloneJson(input.outcomeExceptions ?? [])
      },
      projectModelDigest: inspection.digest,
      governanceBaseline,
      baseline: {
        projectModelDigest: inspection.digest,
        git: inspection.git,
        governanceDigest: governanceBaseline.digest
      },
      currentGit: inspection.git,
      gateRuns: [],
      acceptance: null,
      createdAt,
      updatedAt: createdAt,
      history: [{ to: "Candidate", at: createdAt, reason: "Change created." }]
    };
    return store.save(change);
  }

  async function getChange(idOrInput) {
    const changeId = readChangeId(idOrInput);
    const snapshot = await inspectChangeQuery();
    const change = snapshot.records.find((record) => record?.id === changeId);
    if (!change) {
      throw kernelError("CHANGE_NOT_FOUND", `Change not found: ${changeId}.`, 404, { changeId });
    }
    return projectChangeDetailForRead(change, snapshot);
  }

  async function compileChange(idOrInput, optionalPatch = {}) {
    const { changeId, patch } = readChangePatch(idOrInput, optionalPatch);
    assertCompilePatchInput(patch);
    const planRefsInput = adaptChangePlanRefsInput(patch);
    let change = await requireChange(changeId);
    change = await refreshChangeForWrite(change);
    if (change.acceptance || change.state === "Accepted" || change.state === "Integrated") {
      throw kernelError(
        "CHANGE_SEALED",
        `Change ${change.id} has historical acceptance; an Accepted Package is immutable and follow-up work requires a new Change.`,
        409
      );
    }
    await assertGovernanceWatermarkCurrent(change);
    change = applyCompilePatch(change, patch, now(), planRefsInput);
    const inspection = await inspectProject();
    assertValidProject(inspection);
    change.projectModelDigest = inspection.digest;
    change.currentGit = inspection.git;
    if (change.claims.length === 0) {
      throw kernelError("CHANGE_CLAIM_REQUIRED", "A Change must declare at least one falsifiable Claim before submission.", 422);
    }
    if (change.changeKind !== "plan-amendment") {
      await assertCurrentGovernanceContracts(change, inspection);
    }
    change = compileChangeAgainstGovernance(change, readGovernanceBaseline(change));
    await observeCurrentChangeScope(change, inspection.git, inspection.plan);
    change.outcomeTransitionSchemaVersion = OUTCOME_TRANSITION_SCHEMA_VERSION;
    change.outcomeTransitionCompilation = await deriveCurrentOutcomeTransitions(change, inspection);
    if (patch.authorityDecision !== undefined) bindAuthorityDecision(change);
    transition(change, "Submitted", now(), "Change compiled with explicit Claims.");
    deriveEvidenceReady(change, inspection, now());
    change.updatedAt = now();
    return store.save(change);
  }

  async function runGate(idOrInput, optionalGateId) {
    const request = readGateRequest(idOrInput, optionalGateId);
    let change = await requireChange(request.changeId);
    change = await refreshChangeForWrite(change);
    if (change.claims.length === 0) {
      throw kernelError("CHANGE_CLAIM_REQUIRED", "Compile the Change with at least one Claim before running Gates.", 422);
    }
    if (!change.compilation) {
      throw kernelError("CHANGE_NOT_COMPILED", "Compile the Change before running Gates.", 409);
    }
    if (change.acceptance && change.state !== "Accepted") {
      throw kernelError(
        "CHANGE_SEALED",
        "A historically Accepted Package cannot be replaced; create a follow-up Change.",
        409
      );
    }
    await assertGovernanceWatermarkCurrent(change);
    const inspection = await inspectProject();
    const observedAt = now();
    const model = inspection;
    const validation = inspection.validation;
    const governanceBaseline = readGovernanceBaseline(change);
    await assertCurrentGovernanceContracts(change, model, { modelValid: validation.valid });
    const selectedGates = selectGates(governanceBaseline, request, change);
    if (change.state === "Integrated") {
      throw kernelError("CHANGE_SEALED", `Change ${change.id} is Integrated and cannot run more Gates.`, 409);
    }
    await observeCurrentChangeScope(change, inspection.git, model.plan);
    assertIntegrityFailureEvidenceCurrent(change);
    if (change.state === "Accepted") {
      if (!validation.valid) {
        throw kernelError("PROJECT_MODEL_INVALID", "The current Project Model is invalid.", 422, validation);
      }
      return runIntegrationGates({
        change,
        selectedGates,
        model,
        validation,
        inspection,
        observedAt
      });
    }
    change.projectModelDigest = model.digest;
    change.currentGit = inspection.git;
    const subjectDigest = verificationSubjectDigest(change);
    const builtinEvidence = createProjectModelEvidence({
      change,
      git: inspection.git,
      model,
      validation,
      observedAt,
      verificationSubjectDigest: subjectDigest
    });
    change.evidence = replaceEvidence(change.evidence, builtinEvidence);
    change.gateRuns = upsertGateRun(change.gateRuns, {
      gateId: "project-model",
      kind: "builtin-oracle",
      status: validation.valid ? "passed" : "failed",
      observedAt,
      projectModelDigest: model.digest,
      gitContentDigest: inspection.git.contentDigest,
      verificationSubjectDigest: subjectDigest,
      evidenceIds: [builtinEvidence.id],
      evidenceBindings: [createEvidenceBinding(builtinEvidence)],
      errors: validation.errors,
      warnings: validation.warnings
    });
    assertIntegrityFailureEvidenceCurrent(change);
    if (!validation.valid) {
      transition(change, "Submitted", now(), "Project Model Oracle failed; external Gates were not run.");
      change.updatedAt = now();
      await store.save(change);
      return {
        change: cloneJson(change),
        status: "failed",
        blocked: true,
        modelValidation: validation,
        gateRuns: [cloneJson(change.gateRuns.find((run) => run.gateId === "project-model"))]
      };
    }

    const executedRuns = [change.gateRuns.find((run) => run.gateId === "project-model")];
    for (const gate of selectedGates) {
      const run = await executeGate({
        change,
        gate,
        model,
        git: inspection.git,
        observedAt: now(),
        verificationSubjectDigest: subjectDigest
      });
      change.gateRuns = upsertGateRun(change.gateRuns, run);
      for (const evidence of run.evidence) {
        change.evidence = replaceEvidence(change.evidence, evidence);
      }
      executedRuns.push({ ...run, evidence: undefined });
    }
    assertIntegrityFailureEvidenceCurrent(change);

    const gitAfter = await readGitBinding(resolvedRepoPath, commandRunner);
    change.currentGit = gitAfter;
    if (gitAfter.contentDigest !== inspection.git.contentDigest) {
      for (const run of change.gateRuns.filter((entry) => selectedGates.some((gate) => gate.id === entry.gateId))) {
        run.status = "failed";
        run.reason = "Gate execution changed repository content; Evidence no longer binds the current ChangeSet.";
      }
    }
    transition(change, "Submitted", now(), "Gate observations recorded.");
    deriveEvidenceReady(change, { ...inspection, git: gitAfter, validation }, now());
    change.updatedAt = now();
    await store.save(change);
    return {
      change: cloneJson(change),
      status: executedRuns.every((run) => run?.status === "passed")
        && gitAfter.contentDigest === inspection.git.contentDigest ? "passed" : "failed",
      blocked: false,
      modelValidation: validation,
      gateRuns: cloneJson(executedRuns)
    };
  }

  async function acceptChange(idOrInput, optionalDecision) {
    const request = readAcceptanceRequest(idOrInput, optionalDecision);
    let change = await requireChange(request.changeId);
    change = await refreshChangeForWrite(change);
    await assertGovernanceWatermarkCurrent(change);
    const inspection = await inspectProject();
    assertValidProject(inspection);
    if (change.changeKind !== "plan-amendment" || change.compilation) {
      await assertCurrentGovernanceContracts(change, inspection);
    }
    if (change.compilation) {
      await observeCurrentChangeScope(change, inspection.git, inspection.plan);
      assertIntegrityFailureEvidenceCurrent(change);
    }

    if (request.integrate === true && change.acceptance && change.acceptance.valid !== true) {
      throw kernelError(
        "ACCEPTANCE_INVALID",
        "An invalidated Accepted Change Package cannot be re-accepted and integrated in the same request.",
        409,
        { invalidationReason: change.acceptance.invalidationReason ?? null }
      );
    }
    if (change.acceptance && !(change.state === "Accepted" && request.integrate === true)) {
      throw kernelError(
        "CHANGE_SEALED",
        "A historically Accepted Package cannot be replaced; create a follow-up Change.",
        409
      );
    }

    if (request.authorityDecision !== undefined) {
      change.authorityDecision = normalizeAuthorityDecision(request.authorityDecision, now());
      bindAuthorityDecision(change);
    }
    deriveEvidenceReady(change, inspection, now());

    if (change.state === "Accepted" && request.integrate === true) {
      assertValidAcceptance(change);
      assertIntegrationAllowed(change, inspection);
      transition(change, "Integrated", now(), "Accepted Change Package marked integrated.");
      change.integration = {
        integratedAt: now(),
        git: inspection.git,
        acceptanceDigest: change.acceptance.digest
      };
      change.updatedAt = now();
      return store.save(change);
    }

    if (change.state !== "EvidenceReady") {
      throw kernelError(
        "CHANGE_NOT_EVIDENCE_READY",
        `Change ${change.id} is ${change.state}; acceptance requires EvidenceReady.`,
        409,
        readReadiness(change, inspection)
      );
    }
    const closureValidation = validateKnowledgeClosure(change.knowledgeClosure);
    if (!closureValidation.valid) {
      throw kernelError(
        "KNOWLEDGE_CLOSURE_REQUIRED",
        "Acceptance requires explicit, classified Knowledge Closure.",
        409,
        { errors: closureValidation.errors }
      );
    }
    assertOutcomeExceptionBinding(change);
    assertCompiledChangeCurrent(change);
    const expectedAuthorities = readExpectedAuthorities(readGovernanceBaseline(change), change);
    const authorityValidation = validateAuthorityDecision(
      change.authorityDecision,
      expectedAuthorities,
      readGovernanceBaseline(change).projectDocument?.authorities?.decision ?? []
    );
    if (!authorityValidation.valid) {
      throw kernelError("AUTHORITY_DECISION_REQUIRED", authorityValidation.errors.join(" "), 403, {
        expectedAuthorities,
        errors: authorityValidation.errors
      });
    }
    if (!authorityDecisionBindsCurrentSubject(change)) {
      throw kernelError(
        "AUTHORITY_DECISION_STALE",
        "Authority Decision is not bound to the current Change content, Governance Baseline, and Git state.",
        409
      );
    }
    assertKnowledgeClosureDurability(change, inspection);
    assertScopeDecision(change);

    const packageContent = createAcceptedPackageContent(change);
    const digest = canonicalDigest(packageContent);
    const acceptedAt = now();
    change.acceptance = {
      valid: true,
      digest,
      acceptedAt,
      projectModelDigest: inspection.digest,
      gitContentDigest: inspection.git.contentDigest,
      package: packageContent
    };
    transition(change, "Accepted", acceptedAt, "Evidence, Knowledge Closure, and Authority Decision accepted.", digest);
    if (request.integrate === true) {
      assertIntegrationAllowed(change, inspection);
      transition(change, "Integrated", now(), "Accepted Change Package marked integrated.");
      change.integration = {
        integratedAt: now(),
        git: inspection.git,
        acceptanceDigest: digest
      };
    }
    change.updatedAt = now();
    return store.save(change);
  }

  async function refreshChangeForWrite(change) {
    const inspection = await inspectProject();
    const next = cloneJson(change);
    next.currentGit = inspection.git;
    next.projectModelDigest = inspection.digest;
    if (next.acceptance?.valid === true) {
      const currentDigest = changeContentDigest(next);
      const storedPackageDigest = next.acceptance.package
        ? canonicalDigest(next.acceptance.package)
        : null;
      if (currentDigest !== next.acceptance.digest || storedPackageDigest !== next.acceptance.digest) {
        invalidateAcceptance(next, now(), "Project Model or repository content changed after acceptance.");
        deriveEvidenceReady(next, inspection, now());
        next.updatedAt = now();
        await store.save(next);
      }
    }
    return next;
  }

  async function requireChange(id) {
    const change = await store.get(id);
    if (!change) {
      throw kernelError("CHANGE_NOT_FOUND", `Change not found: ${id}.`, 404, { changeId: id });
    }
    return change;
  }

  async function executeGate({ change, gate, model, git, observedAt, verificationSubjectDigest: subjectDigest }) {
    const commandResults = [];
    const evidence = [];
    const gateCommands = readGateCommands(gate);
    const selectedCommands = gateCommands.filter((command) => commandAppliesToChange(command, change));
    const skippedCommandIds = gateCommands
      .filter((command) => !selectedCommands.includes(command))
      .map((command) => command.id);
    if (selectedCommands.length === 0) {
      throw kernelError(
        "GATE_COMMAND_NOT_APPLICABLE",
        `Gate ${gate.id} has no command applicable to Module ${change.primaryModule}.`,
        409,
        { gateId: gate.id, primaryModule: change.primaryModule }
      );
    }
    for (const command of selectedCommands) {
      const specification = normalizeGateCommand(command.command);
      const result = await executeWithTimeout({
        ...specification,
        cwd: resolvedRepoPath,
        purpose: "gate",
        gateId: gate.id,
        commandId: command.id
      }, command.timeoutMs);
      const obligationMappings = readObligationMappings(
        change.verificationObligations,
        command.claimRefs,
        gate.id,
        command.id
      );
      const item = createGateEvidence({
        change,
        gate,
        command,
        result,
        git,
        model,
        observedAt,
        verificationSubjectDigest: subjectDigest,
        supportsClaimIds: obligationMappings.map((mapping) => mapping.claimId),
        supportBindings: obligationMappings.map((mapping) => ({
          obligationId: mapping.obligationId,
          claimId: mapping.claimId
        }))
      });
      evidence.push(item);
      commandResults.push({
        id: command.id,
        command: specification.display,
        status: result.exitCode === 0 ? "passed" : "failed",
        exitCode: result.exitCode,
        evidenceId: item.id,
        ...(result.signal ? { signal: result.signal } : {})
      });
    }
    return {
      gateId: gate.id,
      kind: "configured-gate",
      status: commandResults.every((result) => result.status === "passed") ? "passed" : "failed",
      observedAt,
      projectModelDigest: model.digest,
      gitContentDigest: git.contentDigest,
      verificationSubjectDigest: subjectDigest,
      selection: {
        primaryModule: change.primaryModule,
        selectedCommandIds: selectedCommands.map((command) => command.id),
        skippedCommandIds
      },
      commandResults,
      evidenceIds: evidence.map((item) => item.id),
      evidenceBindings: evidence.map(createEvidenceBinding),
      evidence
    };
  }

  async function runIntegrationGates({ change, selectedGates, model, validation, inspection, observedAt }) {
    assertValidAcceptance(change);
    const allowedGateIds = new Set(normalizeStringList(change.verificationPlan?.integrationGateIds));
    const disallowedGateIds = selectedGates.map((gate) => gate.id).filter((id) => !allowedGateIds.has(id));
    if (disallowedGateIds.length > 0 || selectedGates.length === 0) {
      throw kernelError(
        "CHANGE_SEALED",
        "An Accepted Change may only run Gates explicitly required for integration.",
        409,
        { allowedGateIds: [...allowedGateIds], requestedGateIds: selectedGates.map((gate) => gate.id) }
      );
    }

    const subjectDigest = verificationSubjectDigest(change);
    const gateRuns = [];
    const evidence = [];
    for (const gate of selectedGates) {
      const run = await executeGate({
        change,
        gate,
        model,
        git: inspection.git,
        observedAt: now(),
        verificationSubjectDigest: subjectDigest
      });
      const { evidence: runEvidence, ...gateRun } = run;
      gateRuns.push(gateRun);
      evidence.push(...runEvidence);
    }

    const gitAfter = await readGitBinding(resolvedRepoPath, commandRunner);
    if (!gitAfter.available || gitAfter.contentDigest !== inspection.git.contentDigest) {
      for (const run of gateRuns) {
        run.status = "failed";
        run.reason = "Integration Gate changed repository content or lost its exact Git binding.";
      }
    }
    const assuranceContent = {
      schemaVersion: 1,
      acceptanceDigest: change.acceptance.digest,
      verificationSubjectDigest: subjectDigest,
      projectModelDigest: model.digest,
      gitContentDigest: inspection.git.contentDigest,
      observedAt,
      gateRuns,
      evidence
    };
    change.integrationAssurance = {
      ...assuranceContent,
      valid: true,
      digest: canonicalDigest(assuranceContent)
    };
    change.updatedAt = now();
    await store.save(change);
    return {
      change: cloneJson(change),
      status: gateRuns.every((run) => run.status === "passed")
        && gitAfter.available
        && gitAfter.contentDigest === inspection.git.contentDigest ? "passed" : "failed",
      blocked: false,
      modelValidation: validation,
      gateRuns: cloneJson(gateRuns)
    };
  }

  async function executeWithTimeout(specification, timeoutMs) {
    const timeout = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 300_000;
    const controller = new AbortController();
    let timer;
    try {
      return await Promise.race([
        executeCommand(commandRunner, { ...specification, signal: controller.signal }),
        new Promise((resolve) => {
          timer = setTimeout(() => {
            controller.abort();
            resolve({ exitCode: 124, stdout: "", stderr: `Gate timed out after ${timeout}ms.` });
          }, timeout);
        })
      ]);
    } catch (error) {
      return {
        exitCode: controller.signal.aborted ? 124 : 1,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error)
      };
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    inspectProject,
    inspectWorkbenchProjection: (...args) => (
      serializeOperation(() => inspectWorkbenchProjection(...args))
    ),
    inspectArchitectureProfile: (...args) => (
      serializeOperation(() => inspectArchitectureProfile(...args))
    ),
    listChanges: (...args) => serializeOperation(() => listChanges(...args)),
    createChange: (...args) => serializeOperation(() => createChange(...args)),
    getChange: (...args) => serializeOperation(() => getChange(...args)),
    compileChange: (...args) => serializeOperation(() => compileChange(...args)),
    runGate: (...args) => serializeOperation(() => runGate(...args)),
    acceptChange: (...args) => serializeOperation(() => acceptChange(...args))
  };
}

async function readStableObservation({ observe, code, message }) {
  let previous = await observe();
  const digests = [previous.digest];
  for (let count = 2; count <= STABLE_OBSERVATION_LIMIT; count += 1) {
    const current = await observe();
    digests.push(current.digest);
    if (current.digest === previous.digest) return current;
    previous = current;
  }
  throw kernelError(code, message, 409, {
    observedDigests: digests,
    observationCount: digests.length
  });
}

function projectChangeDetailForRead(change, snapshot) {
  const persisted = cloneJson(change);
  const observed = projectChangeOntoInspection(change, snapshot.inspection);
  return cloneJson({
    ...persisted,
    observation: compileChangeObservationSafely(change, snapshot),
    readiness: compileReadinessForRead(observed, snapshot.inspection)
  });
}

function summarizeChangeForRead(change, snapshot) {
  const observation = compileChangeObservationSafely(change, snapshot);
  const planRefs = Array.isArray(change?.planRefs) ? change.planRefs : [];
  const title = boundedSummaryText(change?.intent?.title);
  const request = boundedSummaryText(change?.intent?.request);
  const summary = {
    schemaVersion: CHANGE_SCHEMA_VERSION,
    id: readString(change?.id) ?? "unknown",
    state: boundedSummaryText(change?.state) ?? "unknown",
    intent: {
      ...(title ? { title } : {}),
      ...(request ? { request } : {})
    },
    ...(readString(change?.primaryModule)
      ? { primaryModule: boundedSummaryText(change.primaryModule) }
      : {}),
    changeKind: boundedSummaryText(change?.changeKind) ?? "implementation",
    planRefs: planRefs
      .slice(0, CHANGE_SUMMARY_PLAN_REF_LIMIT)
      .map((value) => boundedSummaryText(value))
      .filter(Boolean),
    createdAt: boundedSummaryText(change?.createdAt),
    updatedAt: boundedSummaryText(change?.updatedAt),
    counts: {
      planRefCount: planRefs.length,
      claimCount: arrayLength(change?.claims),
      obligationCount: arrayLength(change?.verificationObligations),
      evidenceCount: arrayLength(change?.evidence),
      gateRunCount: arrayLength(change?.gateRuns)
    },
    observation: summarizeChangeObservation(observation)
  };
  if (planRefs.length > CHANGE_SUMMARY_PLAN_REF_LIMIT
    || isSummaryTextTruncated(change?.intent?.title)
    || isSummaryTextTruncated(change?.intent?.request)) {
    summary.truncated = {
      title: isSummaryTextTruncated(change?.intent?.title),
      request: isSummaryTextTruncated(change?.intent?.request),
      planRefs: planRefs.length > CHANGE_SUMMARY_PLAN_REF_LIMIT
    };
  }
  return cloneJson(summary);
}

function compileArchitectureProfileFromSnapshot(snapshot) {
  return compileArchitectureProfileBundleFromSnapshot(snapshot).profile;
}

function compileArchitectureProfileBundleFromSnapshot(snapshot) {
  assertArchitectureProfileListBound(
    snapshot.records,
    ARCHITECTURE_PROFILE_LIMITS.changes,
    "changeStore.records"
  );
  preflightArchitectureProfileSnapshotFacts(snapshot.records);
  const evidenceWorkBudget = { observed: 0 };
  const preparedFacts = snapshot.records.map((record) => (
    prepareArchitectureProfileChangeFact(record, snapshot, evidenceWorkBudget)
  ));
  const historicalRequirements = collectArchitectureProfileRouteRequirements(preparedFacts);
  const routeQuery = createArchitectureProfileRouteQueryBudget();
  const current = prepareCurrentModelRouteProduct(snapshot, routeQuery);
  const {
    model,
    modelClaimRefs,
    currentRouteProvider,
    currentClaimDescriptors
  } = current;
  const historicalProviders = compileArchitectureProfileHistoricalProviders(
    historicalRequirements,
    routeQuery
  );
  const changeFacts = [];
  let associationCount = 0;
  for (const prepared of preparedFacts) {
    const fact = normalizeArchitectureProfileChangeFact(
      prepared,
      snapshot,
      modelClaimRefs,
      currentClaimDescriptors,
      currentRouteProvider.routeDigests,
      historicalProviders
    );
    associationCount += fact.evidence.reduce((count, item) => (
      count + item.claimAssociations.length
    ), 0);
    if (associationCount > ARCHITECTURE_PROFILE_LIMITS.evidence) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_FACTS_UNBOUNDED",
        "Architecture Profile normalized associations exceeded a query-level hard bound.",
        413,
        {
          location: "changeFacts.evidence.claimAssociations",
          limit: ARCHITECTURE_PROFILE_LIMITS.evidence,
          observed: associationCount
        }
      );
    }
    changeFacts.push(fact);
  }
  const profile = compileArchitectureProfile(
    {
      model,
      source: {
        snapshotDigest: snapshot.digest,
        projectModelDigest: snapshot.inspection.digest,
        gitContentDigest: snapshot.inspection.git.contentDigest,
        changeStoreDigest: snapshot.changeStoreDigest
      },
      changeFacts
    },
    { claimGateRouteIndex: currentRouteProvider.token }
  );
  return {
    profile,
    model,
    modelClaimRefs,
    currentClaimDescriptors,
    currentRouteProvider,
    historicalProviders
  };
}

function compileWorkbenchProjectionFromSnapshot(snapshot) {
  assertArchitectureProfileListBound(
    snapshot.records,
    ARCHITECTURE_PROFILE_LIMITS.changes,
    "changeStore.records"
  );
  assertValidProject(snapshot.inspection);
  const budget = { observed: 0 };
  const routeQuery = createArchitectureProfileRouteQueryBudget();
  const current = prepareCurrentModelRouteProduct(snapshot, routeQuery);
  const currentAcceptanceGateScopeIndex = compileWorkbenchAcceptanceGateScopeIndex(
    current.model,
    budget
  );
  const historicalRequirements = new Map();
  collectWorkbenchHistoricalRouteRequirements(snapshot.records, historicalRequirements, budget);
  const historicalProviders = compileArchitectureProfileHistoricalProviders(
    historicalRequirements,
    routeQuery,
    { includeClaimDescriptors: false }
  );
  const historicalAcceptanceGateScopeIndices = new Map(
    [...historicalRequirements.values()].map((requirement) => [
      requirement.baselineDigest,
      compileWorkbenchAcceptanceGateScopeIndex(requirement.baseline, budget)
    ])
  );
  const bundle = {
    ...current,
    currentAcceptanceGateScopeIndex,
    historicalProviders,
    historicalAcceptanceGateScopeIndices
  };
  const content = {
    schemaVersion: 1,
    source: {
      snapshotDigest: snapshot.digest,
      projectModelDigest: snapshot.inspection.digest,
      gitContentDigest: snapshot.inspection.git.contentDigest,
      changeStoreDigest: snapshot.changeStoreDigest
    },
    authoring: {
      modules: compileWorkbenchAuthoringModules(bundle, budget)
    },
    changes: snapshot.records
      .map((record) => compileWorkbenchChangeActions(record, snapshot, bundle, budget))
      .sort((left, right) => left.id.localeCompare(right.id))
  };
  const result = { ...content, projectionDigest: canonicalDigest(content) };
  const observedBytes = Buffer.byteLength(JSON.stringify(result), "utf8");
  if (observedBytes > WORKBENCH_PROJECTION_BYTE_LIMIT) {
    throw kernelError(
      "WORKBENCH_PROJECTION_LIMIT_EXCEEDED",
      "Workbench semantic projection exceeded its bounded output limit.",
      413,
      { dimension: "bytes", limit: WORKBENCH_PROJECTION_BYTE_LIMIT, observed: observedBytes }
    );
  }
  return cloneJson(result);
}

function prepareCurrentModelRouteProduct(snapshot, routeQuery) {
  const model = publicProjectModel(snapshot.inspection);
  const { modelClaimRefs } = compileArchitectureProfileModelMembership(model);
  requireArchitectureProfileDigest(model.digest, "model.digest");
  const currentRouteProvider = compileArchitectureProfileRouteProvider({
    model,
    claimRefs: modelClaimRefs,
    budget: routeQuery,
    location: "model.claimGateRoutes"
  });
  const currentClaimDescriptors = compileArchitectureProfileClaimDescriptorIndex(
    model,
    routeQuery,
    "model.claimDescriptors"
  );
  return { model, modelClaimRefs, currentRouteProvider, currentClaimDescriptors };
}

function compileWorkbenchAuthoringModules(bundle, budget) {
  const {
    model,
    currentClaimDescriptors,
    currentRouteProvider,
    currentAcceptanceGateScopeIndex
  } = bundle;
  const contractIndex = new Map(
    (Array.isArray(model.contracts) ? model.contracts : [])
      .map((contract) => [readModelReference(contract), contract])
      .filter(([contractRef]) => Boolean(contractRef))
  );
  const modules = [];
  for (const module of [...(Array.isArray(model.modules) ? model.modules : [])]
    .sort((left, right) => (readString(left?.id) ?? "").localeCompare(readString(right?.id) ?? ""))) {
    consumeWorkbenchProjectionFact(budget);
    const moduleRef = requireWorkbenchReference(module?.id, "authoring.module.id");
    const visibleContracts = new Map();
    for (const contractRef of normalizeReferenceList(module?.publicContracts)) {
      addWorkbenchContractVisibility(visibleContracts, contractRef, "owned");
    }
    for (const dependency of Array.isArray(module?.dependencies) ? module.dependencies : []) {
      const contractRef = readModelReference(
        dependency?.via ?? dependency?.contract ?? dependency?.contractId
      );
      if (contractRef) addWorkbenchContractVisibility(visibleContracts, contractRef, "dependency");
    }

    const claimOptions = new Map();
    for (const [contractRef, visibilityKinds] of [...visibleContracts.entries()]
      .sort(([left], [right]) => left.localeCompare(right))) {
      const contract = contractIndex.get(contractRef);
      if (!contract) {
        throw kernelError(
          "WORKBENCH_PROJECTION_FACT_INVALID",
          `Workbench authoring Contract ${contractRef} is not present in the stabilized Project Model.`,
          422,
          { moduleRef, contractRef }
        );
      }
      for (const claim of Array.isArray(contract?.claims) ? contract.claims : []) {
        consumeWorkbenchProjectionFact(budget);
        const claimRef = requireWorkbenchReference(claim?.id, `authoring.module.${moduleRef}.claim.id`);
        const descriptor = currentClaimDescriptors.get(claimRef);
        if (!descriptor || descriptor.contractRef !== contractRef) {
          throw kernelError(
            "WORKBENCH_PROJECTION_FACT_INVALID",
            `Workbench Claim ${claimRef} does not resolve to its authoritative Contract.`,
            422,
            { moduleRef, contractRef, claimRef }
          );
        }
        const existing = claimOptions.get(claimRef);
        if (existing && existing.contractRef !== contractRef) {
          throw kernelError(
            "WORKBENCH_PROJECTION_FACT_INVALID",
            `Workbench Claim ${claimRef} resolves through multiple Contracts.`,
            422,
            { moduleRef, claimRef }
          );
        }
        const routeOptions = compileWorkbenchAcceptanceRouteOptions({
          claimRef,
          moduleRef,
          gateScopeIndex: currentAcceptanceGateScopeIndex,
          routeProvider: currentRouteProvider,
          budget
        });
        const disabledReasonCodes = compileWorkbenchDisabledReasons([
          ...(module?.status === "governed" ? [] : ["MODULE_NOT_GOVERNED"]),
          ...(routeOptions.length > 0 ? [] : ["CLAIM_ACCEPTANCE_ROUTE_MISSING"])
        ]);
        claimOptions.set(claimRef, {
          id: claimRef,
          statement: descriptor.statement,
          contractRef,
          visibilityKinds: [...new Set([
            ...(existing?.visibilityKinds ?? []),
            ...visibilityKinds
          ])].sort(),
          selectable: disabledReasonCodes.length === 0,
          disabledReasonCodes,
          acceptanceRoutes: routeOptions
        });
      }
    }
    const disabledReasonCodes = compileWorkbenchDisabledReasons(
      module?.status === "governed" ? [] : ["MODULE_NOT_GOVERNED"]
    );
    modules.push({
      id: moduleRef,
      name: readString(module?.name) ?? moduleRef,
      governanceStatus: readString(module?.status) ?? "unknown",
      selectable: disabledReasonCodes.length === 0,
      disabledReasonCodes,
      claims: [...claimOptions.values()].sort((left, right) => left.id.localeCompare(right.id))
    });
  }
  return modules;
}

function addWorkbenchContractVisibility(index, contractRef, visibilityKind) {
  if (!readString(contractRef)) return;
  if (!index.has(contractRef)) index.set(contractRef, new Set());
  index.get(contractRef).add(visibilityKind);
}

function compileWorkbenchAcceptanceGateScopeIndex(model, budget) {
  const globalGateIds = new Set();
  const gateIdsByModule = new Map();
  for (const gate of Array.isArray(model?.gates) ? model.gates : []) {
    consumeWorkbenchProjectionFact(budget);
    const gateId = requireWorkbenchReference(gate?.id, "workbench.acceptanceGate.id");
    const appliesTo = normalizeStringList(gate?.appliesTo);
    consumeWorkbenchProjectionFact(budget, appliesTo.length);
    if (appliesTo.length === 0) {
      globalGateIds.add(gateId);
      continue;
    }
    for (const rawModuleRef of appliesTo) {
      const moduleRef = readString(rawModuleRef);
      if (!moduleRef) continue;
      if (!gateIdsByModule.has(moduleRef)) gateIdsByModule.set(moduleRef, new Set());
      gateIdsByModule.get(moduleRef).add(gateId);
    }
  }
  return { globalGateIds, gateIdsByModule };
}

function workbenchAcceptanceGateSelectsModule(index, gateId, moduleRef) {
  return index?.globalGateIds.has(gateId)
    || index?.gateIdsByModule.get(moduleRef)?.has(gateId)
    || false;
}

function compileWorkbenchAcceptanceRouteOptions({
  claimRef,
  moduleRef,
  gateScopeIndex,
  routeProvider,
  budget
}) {
  return selectWorkbenchAcceptanceRoutes({
    claimRef,
    moduleRef,
    gateScopeIndex,
    routeProvider,
    budget
  }).map(({ gateId, commandId, routeDigest }) => ({
    gateId,
    commandId,
    routeRef: `route-${canonicalDigest({
      claimRef,
      gateRef: gateId,
      commandRef: commandId
    }).slice(7)}`,
    routeDigest
  }));
}

function selectWorkbenchAcceptanceRoutes({
  claimRef,
  moduleRef,
  gateScopeIndex,
  routeProvider,
  budget
}) {
  const selected = [];
  for (const route of routeProvider.routesByClaim.get(claimRef) ?? []) {
    consumeWorkbenchProjectionFact(budget);
    const gateId = readString(route?.gateId);
    const commandId = readString(route?.commandId);
    const effectiveModuleRefs = Array.isArray(route?.effectiveModuleRefs)
      ? route.effectiveModuleRefs
      : [];
    consumeWorkbenchProjectionFact(budget, effectiveModuleRefs.length);
    if (!gateId || !commandId
      || !workbenchAcceptanceGateSelectsModule(gateScopeIndex, gateId, moduleRef)
      || !effectiveModuleRefs.includes(moduleRef)) continue;
    const routeDigest = routeProvider.routeDigests.get(
      architectureProfileRouteKey(claimRef, gateId, commandId)
    );
    if (!isCanonicalDigest(routeDigest)) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench authoring route is missing its compiler-owned semantic digest.",
        422,
        { claimRef, moduleRef, gateId, commandId }
      );
    }
    selected.push({ gateId, commandId, routeDigest });
  }
  return uniqueWorkbenchRoutes(selected);
}

function compileWorkbenchChangeActions(record, snapshot, bundle, budget) {
  consumeWorkbenchProjectionFact(budget, 2);
  const id = requireWorkbenchReference(record?.id, "changes.id");
  const governanceBaseline = readGovernanceBaseline(record);
  const baselineDigest = requireArchitectureProfileDigest(
    governanceBaseline.digest,
    `workbench.change.${id}.governanceBaseline.digest`
  );
  const historicalProvider = bundle.historicalProviders.get(baselineDigest);
  const acceptanceGateScopeIndex = bundle.historicalAcceptanceGateScopeIndices.get(baselineDigest);
  const seal = inspectHistoricalSeal(record);
  assertWorkbenchVerificationPlanValid({
    record,
    governanceBaseline,
    provider: historicalProvider,
    acceptanceGateScopeIndex,
    seal,
    budget
  });
  const annotations = compileWorkbenchVerificationPlanAnnotations({
    record,
    provider: historicalProvider,
    budget
  });
  const annotationsByGate = indexWorkbenchAnnotationsByGate(annotations, budget);
  const primaryModuleKnown = (Array.isArray(governanceBaseline.modules)
    ? governanceBaseline.modules
    : []).some((module) => readString(module?.id) === readString(record?.primaryModule));
  const compileReasons = compileWorkbenchDisabledReasons([
    ...(primaryModuleKnown ? [] : ["MODULE_NOT_GOVERNED"]),
    ...(Array.isArray(record?.claims) && record.claims.length > 0
      ? []
      : ["CHANGE_CLAIM_REQUIRED"]),
    ...(record?.acceptance || ["Accepted", "Integrated"].includes(record?.state)
      ? ["CHANGE_SEALED"]
      : [])
  ]);
  const acceptReasons = compileWorkbenchDisabledReasons([
    ...(Array.isArray(record?.claims) && record.claims.length > 0
      ? []
      : ["CHANGE_CLAIM_REQUIRED"]),
    ...(record?.compilation ? [] : ["CHANGE_NOT_COMPILED"]),
    ...(workbenchChangeIsEvidenceReady(record, snapshot.inspection)
      ? []
      : ["CHANGE_NOT_EVIDENCE_READY"]),
    ...(record?.acceptance || ["Accepted", "Integrated"].includes(record?.state)
      ? ["CHANGE_SEALED"]
      : [])
  ]);
  const currentApplicability = inspectCurrentApplicability(record, snapshot.inspection, seal);
  const gates = [...(Array.isArray(governanceBaseline.gates) ? governanceBaseline.gates : [])]
    .sort((left, right) => (readString(left?.id) ?? "").localeCompare(readString(right?.id) ?? ""))
    .map((gate) => compileWorkbenchGateAction({
      record,
      governanceBaseline,
      gate,
      annotationsByGate,
      seal,
      currentApplicability,
      budget
    }));
  return {
    id,
    state: readString(record?.state) ?? "unknown",
    primaryModule: readString(record?.primaryModule) ?? null,
    governanceBaselineDigest: baselineDigest,
    actions: {
      compile: workbenchAction("compile", compileReasons),
      gates,
      accept: workbenchAction("accept", acceptReasons)
    }
  };
}

function compileWorkbenchGateAction({
  record,
  governanceBaseline,
  gate,
  annotationsByGate,
  seal,
  currentApplicability,
  budget
}) {
  consumeWorkbenchProjectionFact(budget);
  const gateId = requireWorkbenchReference(gate?.id, `change.${record?.id}.gate.id`);
  consumeWorkbenchProjectionFact(
    budget,
    Array.isArray(gate?.appliesTo) ? gate.appliesTo.length : gate?.appliesTo == null ? 0 : 1
  );
  const commands = readGateCommands(gate);
  const selectedCommandIds = [];
  const skippedCommandIds = [];
  for (const command of commands) {
    consumeWorkbenchProjectionFact(budget);
    consumeWorkbenchProjectionFact(
      budget,
      Array.isArray(command?.appliesTo)
        ? command.appliesTo.length
        : command?.appliesTo == null ? 0 : 1
    );
    const commandId = requireWorkbenchReference(
      command?.id,
      `change.${record?.id}.gate.${gateId}.command.id`
    );
    (commandAppliesToChange(command, record)
      ? selectedCommandIds
      : skippedCommandIds).push(commandId);
  }
  selectedCommandIds.sort();
  skippedCommandIds.sort();
  const gateApplicable = gateAppliesToChange(gate, governanceBaseline, record);
  const reasons = compileWorkbenchDisabledReasons([
    ...(Array.isArray(record?.claims) && record.claims.length > 0
      ? []
      : ["CHANGE_CLAIM_REQUIRED"]),
    ...(record?.compilation ? [] : ["CHANGE_NOT_COMPILED"]),
    ...(workbenchGateIsSealed(record, gateId, seal, currentApplicability)
      ? ["CHANGE_SEALED"]
      : []),
    ...(gateApplicable ? [] : ["GATE_NOT_APPLICABLE"]),
    ...(selectedCommandIds.length > 0 ? [] : ["GATE_COMMAND_NOT_APPLICABLE"])
  ]);
  return {
    kind: "gate",
    gateId,
    name: readString(gate?.name) ?? gateId,
    enabled: reasons.length === 0,
    disabledReasonCodes: reasons,
    selectedCommandIds,
    skippedCommandIds,
    claimRouteAnnotations: annotationsByGate.get(gateId) ?? []
  };
}

function indexWorkbenchAnnotationsByGate(annotations, budget) {
  const index = new Map();
  for (const annotation of annotations) {
    consumeWorkbenchProjectionFact(budget);
    if (!index.has(annotation.gateId)) index.set(annotation.gateId, []);
    index.get(annotation.gateId).push(annotation);
  }
  return index;
}

function assertWorkbenchVerificationPlanValid({
  record,
  governanceBaseline,
  provider,
  acceptanceGateScopeIndex,
  seal,
  budget
}) {
  const changeId = readString(record?.id) ?? "unknown";
  const plan = record?.verificationPlan;
  if (!record?.compilation) {
    if (plan === undefined || plan === null) return;
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "An uncompiled Change cannot carry a Verification Plan."
    );
  }
  if (!plan || typeof plan !== "object" || Array.isArray(plan)) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "A compiled Change requires an object-shaped Verification Plan."
    );
  }

  const primaryModule = readString(record?.primaryModule);
  if (!primaryModule
    || record.compilation.governanceBaselineDigest !== governanceBaseline.digest
    || readString(record.compilation.primaryModule) !== primaryModule) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "Change compilation is not bound to its frozen Governance Baseline and primary Module."
    );
  }

  const claims = readWorkbenchVerificationPlanArray(record?.claims, changeId, "claims");
  const verificationObligations = readWorkbenchVerificationPlanArray(
    record?.verificationObligations,
    changeId,
    "verificationObligations"
  );
  const planObligations = readWorkbenchVerificationPlanArray(
    plan.obligations,
    changeId,
    "verificationPlan.obligations"
  );
  consumeWorkbenchProjectionFact(
    budget,
    claims.length + verificationObligations.length + planObligations.length
  );
  const claimIds = readUniqueWorkbenchPlanIds(claims, "id", changeId, "claims");
  const verificationObligationIds = readUniqueWorkbenchPlanIds(
    verificationObligations,
    "id",
    changeId,
    "verificationObligations"
  );
  const verificationObligationClaimIds = readUniqueWorkbenchPlanIds(
    verificationObligations,
    "claimId",
    changeId,
    "verificationObligations.claimIds"
  );
  readUniqueWorkbenchPlanIds(
    planObligations,
    "id",
    changeId,
    "verificationPlan.obligations"
  );
  readUniqueWorkbenchPlanIds(
    planObligations,
    "claimId",
    changeId,
    "verificationPlan.obligations.claimIds"
  );
  if (verificationObligationIds.length !== claimIds.length
    || canonicalDigest([...verificationObligationClaimIds].sort())
      !== canonicalDigest([...claimIds].sort())) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "Verification Obligations must cover every Change Claim exactly once."
    );
  }

  const policy = governanceBaseline.projectDocument?.changePolicy ?? {};
  const defaultGateId = readString(policy.defaultGate);
  const acceptanceGateIds = uniqueStrings([
    "project-model",
    ...(defaultGateId
      ? [defaultGateId]
      : (Array.isArray(governanceBaseline.gates) ? governanceBaseline.gates : [])
          .filter((gate) => gate?.required === true)
          .map((gate) => readString(gate?.id))
          .filter(Boolean))
  ]);
  const fullGateId = readString(policy.fullGate);
  const fullGateBefore = normalizeStringList(policy.fullGateBefore)
    .map((value) => value.toLowerCase());
  const integrationGateIds = fullGateId && fullGateBefore.includes("integrated")
    ? [fullGateId]
    : [];
  const expectedObligations = verificationObligations.map((obligation) => ({
    id: obligation.id,
    claimId: obligation.claimId,
    required: obligation.required,
    mapping: cloneJson(obligation.mapping)
  }));
  const expectedPlan = {
    schemaVersion: 1,
    primaryModule,
    defaultGateId: defaultGateId ?? null,
    acceptanceGateIds,
    integrationGateIds,
    obligations: expectedObligations
  };
  if (canonicalDigest(plan) !== canonicalDigest(expectedPlan)) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "Verification Plan fields do not match their compiler-owned frozen-baseline projection."
    );
  }

  const verificationObligationsById = new Map(
    verificationObligations.map((obligation) => [obligation.id, obligation])
  );
  for (const obligation of planObligations) {
    consumeWorkbenchProjectionFact(budget);
    assertWorkbenchVerificationMappingValid({
      changeId,
      obligation,
      verificationObligation: verificationObligationsById.get(obligation.id),
      primaryModule,
      provider,
      acceptanceGateScopeIndex,
      record,
      seal,
      budget
    });
  }
}

function assertWorkbenchVerificationMappingValid({
  changeId,
  obligation,
  verificationObligation,
  primaryModule,
  provider,
  acceptanceGateScopeIndex,
  record,
  seal,
  budget
}) {
  const claimRef = readString(obligation?.claimId);
  const mapping = obligation?.mapping;
  if (!claimRef || !mapping || typeof mapping !== "object" || Array.isArray(mapping)) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      "Every Verification Plan Obligation requires an exact Claim and mapping."
    );
  }
  const builtinMappingRequired = claimRef === "project-model-self-consistent";
  if (builtinMappingRequired !== (mapping.kind === "builtin-oracle")) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification mapping ${obligation.id} does not preserve builtin Oracle ownership.`
    );
  }
  if (mapping.kind === "builtin-oracle") {
    assertWorkbenchVerificationMappingKeys(
      mapping,
      ["status", "kind", "sourceIds"],
      changeId,
      obligation.id
    );
    if (mapping.status !== "mapped"
      || canonicalDigest(mapping.sourceIds) !== canonicalDigest(["project-model"])) {
      throwWorkbenchVerificationPlanInvalid(changeId, "Builtin Oracle mapping is not canonical.");
    }
    return;
  }
  if (mapping.kind === "exact-contract-claim" && !Array.isArray(mapping.routes)) {
    assertWorkbenchVerificationMappingKeys(
      mapping,
      ["status", "kind", "gateIds"],
      changeId,
      obligation.id
    );
    if (mapping.status === "mapped" && workbenchLegacyPlanIsPackageBound(record, seal)) {
      const legacyGateIds = readExactWorkbenchPlanStringList(
        mapping.gateIds,
        changeId,
        `verificationPlan.obligation.${obligation.id}.mapping.gateIds`,
        { nonempty: true }
      );
      consumeWorkbenchProjectionFact(budget, legacyGateIds.length);
      return;
    }
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Exact Claim mapping ${obligation.id} is missing its canonical routes.`
    );
  }
  if (!provider || !acceptanceGateScopeIndex) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification mapping ${obligation.id} has no complete frozen route context.`
    );
  }
  const targetAcceptanceRoutes = selectWorkbenchAcceptanceRoutes({
    claimRef,
    moduleRef: primaryModule,
    gateScopeIndex: acceptanceGateScopeIndex,
    routeProvider: provider,
    budget
  });
  const declaredSourceClaimIds = normalizeStringList(
    verificationObligation?.gateClaimRefs
      ?? verificationObligation?.evidenceSourceRefs
      ?? verificationObligation?.supportedBy
  ).filter((sourceClaimRef) => sourceClaimRef !== claimRef);
  const expectedMappingKind = targetAcceptanceRoutes.length > 0
    ? "exact-contract-claim"
    : declaredSourceClaimIds.length > 0 && hasCrossMappingSemantics(verificationObligation)
      ? "cross-claim"
      : "unmapped";
  if (mapping.kind !== expectedMappingKind) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification mapping ${obligation.id} is ${mapping.kind}, expected ${expectedMappingKind}.`
    );
  }
  if (mapping.kind === "exact-contract-claim") {
    assertWorkbenchVerificationMappingKeys(
      mapping,
      ["status", "kind", "gateIds", "routes"],
      changeId,
      obligation.id
    );
    if (mapping.status !== "mapped" || !provider) {
      throwWorkbenchVerificationPlanInvalid(changeId, "Exact Claim mapping has no frozen route Provider.");
    }
    const expectedRoutes = targetAcceptanceRoutes
      .map(({ gateId, commandId }) => ({ gateId, commandId }));
    const observedRoutes = readWorkbenchVerificationPlanArray(
      mapping.routes,
      changeId,
      `verificationPlan.obligation.${obligation.id}.mapping.routes`
    );
    consumeWorkbenchProjectionFact(budget, observedRoutes.length);
    const expectedGateIds = uniqueStrings(expectedRoutes.map((route) => route.gateId));
    if (expectedRoutes.length === 0
      || canonicalDigest(observedRoutes) !== canonicalDigest(expectedRoutes)
      || canonicalDigest(mapping.gateIds) !== canonicalDigest(expectedGateIds)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Exact Claim mapping ${obligation.id} does not contain its complete canonical acceptance routes.`
      );
    }
    return;
  }
  if (mapping.kind === "cross-claim") {
    assertWorkbenchVerificationMappingKeys(
      mapping,
      ["status", "kind", "sourceClaimIds", "sourceRoutes", "requiredApproval"],
      changeId,
      obligation.id
    );
    if (mapping.status !== "pending-authority") {
      throwWorkbenchVerificationPlanInvalid(changeId, "Cross-Claim mapping status is not canonical.");
    }
    const sourceClaimIds = readExactWorkbenchPlanStringList(
      mapping.sourceClaimIds,
      changeId,
      `verificationPlan.obligation.${obligation.id}.mapping.sourceClaimIds`,
      { nonempty: true }
    );
    consumeWorkbenchProjectionFact(budget, sourceClaimIds.length);
    if (canonicalDigest(sourceClaimIds) !== canonicalDigest(declaredSourceClaimIds)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Cross-Claim mapping ${obligation.id} source Claims are not compiler-derived.`
      );
    }
    if (sourceClaimIds.includes(claimRef)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Cross-Claim mapping ${obligation.id} cannot name its target as a source.`
      );
    }
    const expectedSourceRoutes = sourceClaimIds.flatMap((sourceClaimId) => (
      selectWorkbenchAcceptanceRoutes({
        claimRef: sourceClaimId,
        moduleRef: primaryModule,
        gateScopeIndex: acceptanceGateScopeIndex,
        routeProvider: provider,
        budget
      }).map(({ gateId, commandId }) => ({ sourceClaimId, gateId, commandId }))
    )).sort((left, right) => (
      left.sourceClaimId.localeCompare(right.sourceClaimId)
        || left.gateId.localeCompare(right.gateId)
        || left.commandId.localeCompare(right.commandId)
    ));
    const observedSourceRoutes = readWorkbenchVerificationPlanArray(
      mapping.sourceRoutes,
      changeId,
      `verificationPlan.obligation.${obligation.id}.mapping.sourceRoutes`
    );
    consumeWorkbenchProjectionFact(budget, observedSourceRoutes.length);
    if (canonicalDigest(observedSourceRoutes) !== canonicalDigest(expectedSourceRoutes)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Cross-Claim mapping ${obligation.id} does not contain its complete canonical source routes.`
      );
    }
    if (readString(mapping.requiredApproval)
      !== `approvedObligationIds must include ${obligation.id}`) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Cross-Claim mapping ${obligation.id} has a non-canonical approval requirement.`
      );
    }
    return;
  }
  if (mapping.kind === "unmapped") {
    assertWorkbenchVerificationMappingKeys(
      mapping,
      ["status", "kind", "reason"],
      changeId,
      obligation.id
    );
    if (mapping.status !== "unmapped"
      || Object.hasOwn(mapping, "routes")
      || Object.hasOwn(mapping, "sourceRoutes")) {
      throwWorkbenchVerificationPlanInvalid(changeId, "Unmapped Claim mapping contains route facts.");
    }
    const expectedReason = declaredSourceClaimIds.length > 0
      ? "Cross-Claim mappings require mappingRationale, applicability, and discriminatoryPower."
      : "No exact Contract Claim Gate mapping is declared; independent Evidence is required.";
    if (mapping.reason !== expectedReason) {
      throwWorkbenchVerificationPlanInvalid(changeId, `Unmapped Claim ${claimRef} reason is not canonical.`);
    }
    return;
  }
  throwWorkbenchVerificationPlanInvalid(
    changeId,
    `Unsupported Verification Plan mapping kind: ${readString(mapping.kind) ?? "missing"}.`
  );
}

function assertWorkbenchVerificationMappingKeys(mapping, expectedKeys, changeId, obligationId) {
  if (canonicalDigest(Object.keys(mapping).sort()) !== canonicalDigest([...expectedKeys].sort())) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification Plan mapping ${obligationId} does not have its exact compiler-owned shape.`
    );
  }
}

function workbenchLegacyPlanIsPackageBound(record, seal) {
  const sealedPackage = record?.acceptance?.package;
  return seal?.packageIntact === true
    && Boolean(sealedPackage)
    && canonicalDigest(record?.verificationPlan) === canonicalDigest(sealedPackage.verificationPlan)
    && canonicalDigest(record?.verificationObligations)
      === canonicalDigest(sealedPackage.verificationObligations);
}

function readWorkbenchVerificationPlanArray(value, changeId, location) {
  if (!Array.isArray(value) || value.length > ARCHITECTURE_PROFILE_LIMITS.refsPerFact) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification Plan ${location} must be a bounded array.`,
      {
        location,
        limit: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
        observed: Array.isArray(value) ? value.length : null
      }
    );
  }
  return value;
}

function readUniqueWorkbenchPlanIds(values, field, changeId, location) {
  const ids = [];
  const seen = new Set();
  for (const value of values) {
    const rawId = value?.[field];
    const id = readString(rawId);
    if (typeof rawId !== "string" || id !== rawId || seen.has(id)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Verification Plan ${location} requires unique exact ${field} values.`
      );
    }
    seen.add(id);
    ids.push(id);
  }
  return ids;
}

function readExactWorkbenchPlanStringList(value, changeId, location, { nonempty = false } = {}) {
  const values = readWorkbenchVerificationPlanArray(value, changeId, location);
  const seen = new Set();
  for (const raw of values) {
    const exact = readString(raw);
    if (typeof raw !== "string" || exact !== raw || seen.has(exact)) {
      throwWorkbenchVerificationPlanInvalid(
        changeId,
        `Verification Plan ${location} requires unique exact string references.`
      );
    }
    seen.add(exact);
  }
  if (nonempty && seen.size === 0) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification Plan ${location} cannot be empty.`
    );
  }
  return [...seen];
}

function throwWorkbenchVerificationPlanInvalid(changeId, message, details = {}) {
  throw kernelError(
    "WORKBENCH_VERIFICATION_PLAN_INVALID",
    message,
    422,
    { changeId, ...details }
  );
}

function compileWorkbenchVerificationPlanAnnotations({ record, provider, budget }) {
  const annotations = [];
  const obligations = Array.isArray(record?.verificationPlan?.obligations)
    ? record.verificationPlan.obligations
    : [];
  for (const obligation of obligations) {
    const obligationRef = readString(obligation?.id);
    const targetClaimRef = readString(obligation?.claimId);
    if (!obligationRef || !targetClaimRef) continue;
    const mapping = obligation?.mapping;
    if (mapping?.kind === "exact-contract-claim") {
      for (const route of Array.isArray(mapping?.routes) ? mapping.routes : []) {
        annotations.push(compileWorkbenchPlanRouteAnnotation({
          obligationRef,
          targetClaimRef,
          sourceClaimRef: targetClaimRef,
          mappingKind: mapping.kind,
          route,
          provider,
          budget
        }));
      }
    }
    if (mapping?.kind === "cross-claim") {
      for (const route of Array.isArray(mapping?.sourceRoutes) ? mapping.sourceRoutes : []) {
        annotations.push(compileWorkbenchPlanRouteAnnotation({
          obligationRef,
          targetClaimRef,
          sourceClaimRef: readString(route?.sourceClaimId),
          mappingKind: mapping.kind,
          route,
          provider,
          budget
        }));
      }
    }
  }
  const indexed = new Map();
  for (const annotation of annotations) {
    const key = [
      annotation.obligationRef,
      annotation.targetClaimRef,
      annotation.sourceClaimRef,
      annotation.gateId,
      annotation.commandId
    ].join("\u0000");
    indexed.set(key, annotation);
  }
  return [...indexed.values()].sort((left, right) => (
    left.gateId.localeCompare(right.gateId)
      || left.commandId.localeCompare(right.commandId)
      || left.targetClaimRef.localeCompare(right.targetClaimRef)
      || left.sourceClaimRef.localeCompare(right.sourceClaimRef)
      || left.obligationRef.localeCompare(right.obligationRef)
  ));
}

function compileWorkbenchPlanRouteAnnotation({
  obligationRef,
  targetClaimRef,
  sourceClaimRef,
  mappingKind,
  route,
  provider,
  budget
}) {
  consumeWorkbenchProjectionFact(budget);
  const gateId = readString(route?.gateId);
  const commandId = readString(route?.commandId);
  if (!sourceClaimRef || !gateId || !commandId || !provider) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench verification route annotation is incomplete or has no verified frozen Provider.",
      422,
      { obligationRef, targetClaimRef, sourceClaimRef: sourceClaimRef ?? null, gateId, commandId }
    );
  }
  const routeDigest = provider.routeDigests.get(
    architectureProfileRouteKey(sourceClaimRef, gateId, commandId)
  );
  if (!isCanonicalDigest(routeDigest)) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench verification route annotation is not present in its verified frozen Governance Baseline.",
      422,
      { obligationRef, targetClaimRef, sourceClaimRef, gateId, commandId }
    );
  }
  return {
    obligationRef,
    targetClaimRef,
    sourceClaimRef,
    mappingKind,
    gateId,
    commandId,
    routeDigest
  };
}

function workbenchChangeIsEvidenceReady(record, inspection) {
  if (!record?.compilation) return false;
  try {
    return readReadiness(projectChangeOntoInspection(record, inspection), inspection).evidenceReady === true;
  } catch {
    return false;
  }
}

function workbenchGateIsSealed(record, gateId, seal, currentApplicability) {
  if (record?.state === "Integrated") return true;
  if (!record?.acceptance && record?.state !== "Accepted") return false;
  if (record?.state !== "Accepted"
    || !seal?.intact
    || currentApplicability?.status !== "current") return true;
  return !normalizeStringList(record?.verificationPlan?.integrationGateIds).includes(gateId);
}

function workbenchAction(kind, disabledReasonCodes) {
  return {
    kind,
    enabled: disabledReasonCodes.length === 0,
    disabledReasonCodes
  };
}

function compileWorkbenchDisabledReasons(values) {
  const reasons = [...new Set(values)];
  for (const reason of reasons) {
    if (!WORKBENCH_DISABLED_REASON_PRECEDENCE.has(reason)) {
      throw kernelError(
        "WORKBENCH_DISABLED_REASON_INVALID",
        `Unknown Workbench disabled-reason code: ${reason}.`,
        500
      );
    }
  }
  return reasons.sort((left, right) => (
    WORKBENCH_DISABLED_REASON_PRECEDENCE.get(left)
      - WORKBENCH_DISABLED_REASON_PRECEDENCE.get(right)
  ));
}

function uniqueWorkbenchRoutes(routes) {
  const indexed = new Map();
  for (const route of routes) {
    indexed.set(`${route.gateId}\u0000${route.commandId}`, route);
  }
  return [...indexed.values()].sort((left, right) => (
    left.gateId.localeCompare(right.gateId)
      || left.commandId.localeCompare(right.commandId)
  ));
}

function consumeWorkbenchProjectionFact(budget, units = 1) {
  budget.observed += units;
  if (budget.observed > WORKBENCH_ACTION_FACT_LIMIT) {
    throw kernelError(
      "WORKBENCH_PROJECTION_LIMIT_EXCEEDED",
      "Workbench semantic projection exceeded its bounded fact limit.",
      413,
      { dimension: "facts", limit: WORKBENCH_ACTION_FACT_LIMIT, observed: budget.observed }
    );
  }
}

function requireWorkbenchReference(value, location) {
  const reference = readString(value);
  if (reference) return reference;
  throw kernelError(
    "WORKBENCH_PROJECTION_FACT_INVALID",
    "Workbench semantic projection requires exact non-empty references.",
    422,
    { location }
  );
}

function preflightArchitectureProfileSnapshotFacts(records) {
  let contributionCount = 0;
  let evidenceCount = 0;
  let residualCount = 0;
  const queryFactBudget = { observed: 0 };
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_FACT_INVALID",
        "Architecture Profile compilation requires object-shaped Change records.",
        422
      );
    }
    assertArchitectureProfileRecordBounds(record, "current-record", queryFactBudget);
    const packageContent = record.acceptance?.package;
    if (packageContent && typeof packageContent === "object" && !Array.isArray(packageContent)) {
      assertArchitectureProfileRecordBounds(
        { ...packageContent, id: packageContent.changeId ?? record.id },
        "sealed-package",
        queryFactBudget
      );
    }
    const currentContributions = Array.isArray(record.outcomeAlignment?.contributions)
      ? record.outcomeAlignment.contributions.length
      : 0;
    const packageContributions = Array.isArray(packageContent?.outcomeAlignment?.contributions)
      ? packageContent.outcomeAlignment.contributions.length
      : 0;
    const currentEvidence = Array.isArray(record.evidence) ? record.evidence : [];
    const packageEvidence = Array.isArray(packageContent?.evidence) ? packageContent.evidence : [];
    assertArchitectureProfileCountBound(
      currentContributions + packageContributions,
      ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
      `change.${readString(record.id) ?? "unknown"}.contributions`
    );
    assertArchitectureProfileCountBound(
      currentEvidence.length + packageEvidence.length,
      ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
      `change.${readString(record.id) ?? "unknown"}.evidence`
    );
    contributionCount += currentContributions + packageContributions;
    evidenceCount += currentEvidence.length + packageEvidence.length;
    residualCount += [...currentEvidence, ...packageEvidence].reduce((count, item) => (
      count + (Array.isArray(item?.residualUncertainty)
        ? item.residualUncertainty.length
        : item?.residualUncertainty === undefined || item?.residualUncertainty === null ? 0 : 1)
    ), 0);
    assertArchitectureProfileCountBound(
      contributionCount,
      ARCHITECTURE_PROFILE_LIMITS.contributions,
      "changeFacts.contributions"
    );
    assertArchitectureProfileCountBound(
      evidenceCount,
      ARCHITECTURE_PROFILE_LIMITS.evidence,
      "changeFacts.evidence"
    );
    assertArchitectureProfileCountBound(
      residualCount,
      ARCHITECTURE_PROFILE_LIMITS.residuals,
      "changeFacts.evidence.residualUncertainty"
    );
  }
}

function compileArchitectureProfileModelMembership(model) {
  // This is only a bounded Contract Claim membership index. Route policy is owned by
  // the Project Model Provider and is compiled below as one reusable product.
  const contracts = Array.isArray(model.contracts) ? model.contracts : [];
  const gates = Array.isArray(model.gates) ? model.gates : [];
  const modules = Array.isArray(model.modules) ? model.modules : [];
  assertArchitectureProfileCountBound(
    contracts.length,
    ARCHITECTURE_PROFILE_LIMITS.contracts,
    "model.contracts"
  );
  assertArchitectureProfileCountBound(
    gates.length,
    ARCHITECTURE_PROFILE_LIMITS.gates,
    "model.gates"
  );
  assertArchitectureProfileCountBound(
    modules.length,
    ARCHITECTURE_PROFILE_LIMITS.modules,
    "model.modules"
  );
  const modelClaimRefs = new Set();
  for (const [contractIndex, contract] of contracts.entries()) {
    const claims = Array.isArray(contract?.claims) ? contract.claims : [];
    assertArchitectureProfileCountBound(
      claims.length,
      ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
      `model.contracts.${contractIndex}.claims`
    );
    for (const claim of claims) {
      const claimRef = readString(claim?.id);
      if (claimRef) modelClaimRefs.add(claimRef);
    }
    assertArchitectureProfileCountBound(
      modelClaimRefs.size,
      ARCHITECTURE_PROFILE_LIMITS.claims,
      "model.claims"
    );
  }
  return { modelClaimRefs };
}

function compileArchitectureProfileClaimDescriptorIndex(model, budget, location) {
  const modelBindingDigest = requireArchitectureProfileDigest(model?.digest, `${location}.modelDigest`);
  const cacheKey = `claims\u0000${modelBindingDigest}`;
  const cached = budget.claimDescriptorCache.get(cacheKey);
  if (cached) return cached;
  const contracts = Array.isArray(model?.contracts) ? model.contracts : [];
  assertArchitectureProfileCountBound(
    contracts.length,
    ARCHITECTURE_PROFILE_LIMITS.contracts,
    `${location}.contracts`
  );
  consumeArchitectureProfileRouteQueryWork(
    budget,
    contracts.length,
    `${location}.contracts`
  );
  const descriptors = new Map();
  let claimCount = 0;
  for (const [contractIndex, contract] of contracts.entries()) {
    const claims = Array.isArray(contract?.claims) ? contract.claims : [];
    assertArchitectureProfileCountBound(
      claims.length,
      ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
      `${location}.contracts.${contractIndex}.claims`
    );
    claimCount += claims.length;
    assertArchitectureProfileCountBound(
      claimCount,
      ARCHITECTURE_PROFILE_LIMITS.claims,
      `${location}.claims`
    );
    consumeArchitectureProfileRouteQueryWork(
      budget,
      claims.length,
      `${location}.contracts.${contractIndex}.claims`
    );
    const contractRef = requireArchitectureProfileString(
      readModelReference(contract),
      `${location}.contracts.${contractIndex}.id`
    );
    const ownerModuleRef = requireArchitectureProfileString(
      readModelReference(contract?.owner),
      `${location}.contracts.${contractIndex}.owner`
    );
    for (const [claimIndex, claim] of claims.entries()) {
      const descriptor = {
        id: requireArchitectureProfileString(
          readModelReference(claim),
          `${location}.contracts.${contractIndex}.claims.${claimIndex}.id`
        ),
        statement: requireArchitectureProfileString(
          claim?.statement,
          `${location}.contracts.${contractIndex}.claims.${claimIndex}.statement`
        ),
        contractRef,
        ownerModuleRef
      };
      if (descriptors.has(descriptor.id)) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_FACT_INVALID",
          "Architecture Profile Claim identity must resolve to one authoritative descriptor.",
          422,
          { location, claimRef: descriptor.id }
        );
      }
      descriptors.set(descriptor.id, {
        ...descriptor,
        digest: canonicalDigest(descriptor)
      });
    }
  }
  budget.claimDescriptorCache.set(cacheKey, descriptors);
  return descriptors;
}

function createArchitectureProfileRouteQueryBudget() {
  return {
    limits: {
      workUnits: ARCHITECTURE_PROFILE_MODEL_ROUTE_WORK_LIMIT,
      routes: ARCHITECTURE_PROFILE_LIMITS.routes,
      totalRouteBytes: ARCHITECTURE_PROFILE_LIMITS.profileBytes
    },
    observed: { workUnits: 0, routes: 0, totalRouteBytes: 0 },
    claimDescriptorCache: new Map()
  };
}

function collectArchitectureProfileRouteRequirements(preparedFacts) {
  const requirements = new Map();
  for (const prepared of preparedFacts) {
    for (const sourceContext of prepared.evidenceSources) {
      const associations = sourceContext.forceInvalid
        ? []
        : sourceContext.assessment.coverage?.eligibleClaimAssociations ?? [];
      if (associations.length === 0) continue;
      const baseline = sourceContext.assessment.governanceBaseline;
      if (!baseline) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_FACT_INVALID",
          "Architecture Profile Evidence associations require a verified Governance Baseline.",
          422,
          { location: sourceContext.location }
        );
      }
      const baselineDigest = requireArchitectureProfileDigest(
        baseline.digest,
        `${sourceContext.location}.governanceBaseline.digest`
      );
      sourceContext.providerKey = baselineDigest;
      if (!requirements.has(baselineDigest)) {
        requirements.set(baselineDigest, {
          baseline,
          baselineDigest,
          routeClaimRefs: new Set()
        });
      }
      const requirement = requirements.get(baselineDigest);
      for (const association of associations) {
        if (association?.kind === "builtin") continue;
        const sourceClaimRef = readString(association?.sourceClaimRef);
        if (sourceClaimRef) requirement.routeClaimRefs.add(sourceClaimRef);
      }
      assertArchitectureProfileCountBound(
        requirement.routeClaimRefs.size,
        ARCHITECTURE_PROFILE_LIMITS.claims,
        `${sourceContext.location}.sourceClaimRefs`
      );
    }
  }
  return requirements;
}

function collectWorkbenchHistoricalRouteRequirements(records, requirements, budget) {
  for (const record of records) {
    const claimRefs = collectWorkbenchVerificationPlanClaimRefs(record?.verificationPlan, budget);
    if (claimRefs.size === 0) continue;
    const baseline = readGovernanceBaseline(record);
    const baselineDigest = requireArchitectureProfileDigest(
      baseline.digest,
      `workbench.change.${readString(record?.id) ?? "unknown"}.governanceBaseline.digest`
    );
    if (!requirements.has(baselineDigest)) {
      requirements.set(baselineDigest, {
        baseline,
        baselineDigest,
        routeClaimRefs: new Set()
      });
    }
    const requirement = requirements.get(baselineDigest);
    for (const claimRef of claimRefs) requirement.routeClaimRefs.add(claimRef);
    assertArchitectureProfileCountBound(
      requirement.routeClaimRefs.size,
      ARCHITECTURE_PROFILE_LIMITS.claims,
      `workbench.change.${readString(record?.id) ?? "unknown"}.verificationPlan.claimRefs`
    );
  }
}

function collectWorkbenchVerificationPlanClaimRefs(verificationPlan, budget) {
  const claimRefs = new Set();
  for (const obligation of Array.isArray(verificationPlan?.obligations)
    ? verificationPlan.obligations
    : []) {
    consumeWorkbenchProjectionFact(budget);
    if (obligation?.mapping?.kind === "exact-contract-claim"
      && Array.isArray(obligation.mapping.routes)
      && obligation.mapping.routes.length > 0) {
      const claimRef = readString(obligation?.claimId);
      if (claimRef) claimRefs.add(claimRef);
      consumeWorkbenchProjectionFact(budget, obligation.mapping.routes.length);
    }
    if (obligation?.mapping?.kind === "cross-claim") {
      const targetClaimRef = readString(obligation?.claimId);
      if (targetClaimRef) claimRefs.add(targetClaimRef);
      for (const sourceClaimRef of Array.isArray(obligation.mapping.sourceClaimIds)
        ? obligation.mapping.sourceClaimIds
        : []) {
        consumeWorkbenchProjectionFact(budget);
        const exactSourceClaimRef = readString(sourceClaimRef);
        if (exactSourceClaimRef) claimRefs.add(exactSourceClaimRef);
      }
      for (const route of Array.isArray(obligation.mapping.sourceRoutes)
        ? obligation.mapping.sourceRoutes
        : []) {
        consumeWorkbenchProjectionFact(budget);
        const sourceClaimRef = readString(route?.sourceClaimId);
        if (sourceClaimRef) claimRefs.add(sourceClaimRef);
      }
    }
    if (obligation?.mapping?.kind === "unmapped") {
      const targetClaimRef = readString(obligation?.claimId);
      if (targetClaimRef) claimRefs.add(targetClaimRef);
    }
  }
  return claimRefs;
}

function compileArchitectureProfileHistoricalProviders(requirements, budget, options = {}) {
  const providers = new Map();
  const ordered = [...requirements.values()].sort((left, right) => (
    left.baselineDigest.localeCompare(right.baselineDigest)
  ));
  for (const requirement of ordered) {
    const location = `historicalBaseline.${requirement.baselineDigest}`;
    const claimDescriptors = options.includeClaimDescriptors === false
      ? null
      : compileArchitectureProfileClaimDescriptorIndex(
          requirement.baseline,
          budget,
          `${location}.claimDescriptors`
        );
    const routeProvider = requirement.routeClaimRefs.size > 0
      ? compileArchitectureProfileRouteProvider({
          model: requirement.baseline,
          claimRefs: requirement.routeClaimRefs,
          budget,
          location: `${location}.claimGateRoutes`,
          baselineDigest: requirement.baselineDigest
        })
      : { routeDigests: new Map(), token: null };
    providers.set(requirement.baselineDigest, {
      ...(claimDescriptors ? { claimDescriptors } : {}),
      routesByClaim: routeProvider.routesByClaim ?? new Map(),
      routeDigests: routeProvider.routeDigests
    });
  }
  return providers;
}

function compileArchitectureProfileRouteProvider({
  model,
  claimRefs,
  budget,
  location,
  baselineDigest
}) {
  const exactClaimRefs = [...new Set([...claimRefs].map(readString).filter(Boolean))].sort();
  assertArchitectureProfileCountBound(
    exactClaimRefs.length,
    ARCHITECTURE_PROFILE_LIMITS.claims,
    `${location}.claims`
  );
  let token;
  try {
    token = compileClaimGateRouteIndex(model, {
      claimRefs: exactClaimRefs,
      limits: architectureProfileRouteProviderLimits(budget)
    });
  } catch (error) {
    throwArchitectureProfileRouteProviderError(error, budget, location, baselineDigest);
  }
  let projection;
  try {
    projection = projectCompiledClaimGateRouteIndex(token, {
      model,
      claimRefs: exactClaimRefs
    });
  } catch (error) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_ROUTE_PROVIDER_INVALID",
      "Architecture Profile could not reuse its freshly compiled route Provider.",
      500,
      {
        location,
        ...(baselineDigest ? { baselineDigest } : {}),
        ...(readString(error?.code) ? { providerCode: error.code } : {})
      }
    );
  }
  consumeArchitectureProfileRouteProviderObservation(
    budget,
    projection.observation,
    location,
    baselineDigest
  );
  const provider = {
    token,
    routesByClaim: projection.routesByClaim,
    routeDigests: compileArchitectureProfileRouteDigestIndex(
      projection.routesByClaim,
      budget,
      location,
      baselineDigest
    )
  };
  return provider;
}

function architectureProfileRouteProviderLimits(budget) {
  return {
    claimRefs: ARCHITECTURE_PROFILE_LIMITS.claims,
    modules: ARCHITECTURE_PROFILE_LIMITS.modules,
    gates: ARCHITECTURE_PROFILE_LIMITS.gates,
    commands: ARCHITECTURE_PROFILE_LIMITS.routes,
    refsPerCommand: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    totalCommandClaimRefs: ARCHITECTURE_PROFILE_LIMITS.relations,
    routes: budget.limits.routes - budget.observed.routes,
    totalRouteBytes: budget.limits.totalRouteBytes - budget.observed.totalRouteBytes,
    depth: ARCHITECTURE_PROFILE_LIMITS.depth,
    textBytes: ARCHITECTURE_PROFILE_LIMITS.textBytes,
    workUnits: budget.limits.workUnits - budget.observed.workUnits
  };
}

function compileArchitectureProfileRouteDigestIndex(
  routesByClaim,
  budget,
  location,
  baselineDigest
) {
  const index = new Map();
  for (const [claimRef, routes] of routesByClaim) {
    for (const route of routes) {
      // Route bytes are already bounded by the Provider observation; one additional
      // unit per digest keeps projection work bounded without reinterpreting policy.
      consumeArchitectureProfileRouteQueryWork(
        budget,
        1,
        `${location}.routeDigests`,
        baselineDigest
      );
      const key = architectureProfileRouteKey(claimRef, route?.gateId, route?.commandId);
      const digest = canonicalDigest(route);
      if (index.has(key) && index.get(key) !== digest) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_FACT_INVALID",
          "Architecture Profile route identity resolves to conflicting semantics.",
          422,
          { location, claimRef, gateId: route?.gateId ?? null, commandId: route?.commandId ?? null }
        );
      }
      index.set(key, digest);
    }
  }
  return index;
}

function consumeArchitectureProfileRouteProviderObservation(
  budget,
  observation,
  location,
  baselineDigest
) {
  const next = {};
  for (const dimension of ["workUnits", "routes", "totalRouteBytes"]) {
    const units = observation?.[dimension];
    if (!Number.isSafeInteger(units) || units < 0) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_ROUTE_PROVIDER_INVALID",
        "Architecture Profile route Provider returned an invalid resource observation.",
        500,
        { dimension, location, ...(baselineDigest ? { baselineDigest } : {}) }
      );
    }
    next[dimension] = budget.observed[dimension] + units;
    assertArchitectureProfileRouteQueryLimit(
      budget,
      dimension,
      next[dimension],
      location,
      baselineDigest
    );
  }
  Object.assign(budget.observed, next);
}

function consumeArchitectureProfileRouteQueryWork(budget, units, location, baselineDigest) {
  const observed = budget.observed.workUnits + units;
  assertArchitectureProfileRouteQueryLimit(
    budget,
    "workUnits",
    observed,
    location,
    baselineDigest
  );
  budget.observed.workUnits = observed;
}

function assertArchitectureProfileRouteQueryLimit(
  budget,
  dimension,
  observed,
  location,
  baselineDigest
) {
  const limit = budget.limits[dimension];
  if (observed <= limit) return;
  throw kernelError(
    "ARCHITECTURE_PROFILE_ROUTE_QUERY_LIMIT_EXCEEDED",
    "Architecture Profile route query exceeded its aggregate resource budget.",
    413,
    { dimension, limit, observed, location, ...(baselineDigest ? { baselineDigest } : {}) }
  );
}

function throwArchitectureProfileRouteProviderError(error, budget, location, baselineDigest) {
  if (error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED") {
    const dimension = readString(error?.details?.dimension) ?? "workUnits";
    const aggregateDimension = Object.hasOwn(budget.limits, dimension);
    const localObserved = Number.isSafeInteger(error?.details?.observed)
      ? error.details.observed
      : 1;
    if (!aggregateDimension) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_FACTS_UNBOUNDED",
        "Architecture Profile route policy exceeded a fixed Provider bound.",
        413,
        {
          dimension,
          limit: Number.isSafeInteger(error?.details?.limit) ? error.details.limit : 0,
          observed: localObserved,
          location,
          ...(baselineDigest ? { baselineDigest } : {})
        }
      );
    }
    throw kernelError(
      "ARCHITECTURE_PROFILE_ROUTE_QUERY_LIMIT_EXCEEDED",
      "Architecture Profile route query exceeded its aggregate resource budget.",
      413,
      {
        dimension,
        limit: budget.limits[dimension],
        observed: budget.observed[dimension] + localObserved,
        location,
        ...(baselineDigest ? { baselineDigest } : {})
      }
    );
  }
  if (error?.code === "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID") {
    throw kernelError(
      "ARCHITECTURE_PROFILE_FACT_INVALID",
      "Architecture Profile route policy input is not a valid Project Model fact.",
      422,
      { location, providerCode: error.code, ...(baselineDigest ? { baselineDigest } : {}) }
    );
  }
  if (readString(error?.code)?.startsWith("CLAIM_GATE_ROUTE_INDEX_")) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_ROUTE_PROVIDER_INVALID",
      "Architecture Profile route Provider failed at its internal compilation boundary.",
      500,
      { location, providerCode: error.code, ...(baselineDigest ? { baselineDigest } : {}) }
    );
  }
  throw error;
}

function prepareArchitectureProfileChangeFact(record, snapshot, evidenceWorkBudget) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_FACT_INVALID",
      "Architecture Profile compilation requires object-shaped Change records.",
      422
    );
  }
  const packageProjection = record.acceptance?.package
    && typeof record.acceptance.package === "object"
    && !Array.isArray(record.acceptance.package)
    ? { ...record.acceptance.package, id: record.acceptance.package.changeId ?? record.id }
    : null;
  const seal = inspectHistoricalSeal(record);
  const sealedPackage = seal.packageIntact ? packageProjection : null;

  const currentContributions = normalizeArchitectureProfileContributions(
    record.outcomeAlignment?.contributions,
    { origin: "current-record" }
  );
  const sealedContributions = sealedPackage
    ? normalizeArchitectureProfileContributions(
        sealedPackage.outcomeAlignment?.contributions,
        { origin: "sealed-package", acceptanceDigest: seal.acceptanceDigest }
      )
    : [];
  assertArchitectureProfileListBound(
    [...currentContributions, ...sealedContributions],
    ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    `change.${readString(record.id) ?? "unknown"}.contributions`
  );

  const currentAssessment = compileCurrentEvidenceAssessmentForProfile(
    record,
    snapshot.inspection,
    {
      allowInvalidProjection: seal.packageIntact && !seal.recordProjectionIntact,
      workBudget: evidenceWorkBudget
    }
  );
  return {
    record,
    contributions: [...currentContributions, ...sealedContributions],
    evidenceSources: [
      {
        source: record,
        assessment: currentAssessment,
        origin: "current-record",
        forceInvalid: seal.present && !seal.intact,
        historical: false,
        location: `change.${readString(record.id) ?? "unknown"}.current`
      },
      ...(sealedPackage ? [{
        source: sealedPackage,
        assessment: compileEvidenceAssessment(sealedPackage, {
          digest: sealedPackage.projectModelDigest,
          git: sealedPackage.currentGit,
          validation: { valid: true }
        }, { workBudget: evidenceWorkBudget }),
        origin: "sealed-package",
        acceptanceDigest: seal.acceptanceDigest,
        historical: true,
        forceInvalid: false,
        location: `change.${readString(record.id) ?? "unknown"}.sealed`
      }] : [])
    ]
  };
}

function normalizeArchitectureProfileChangeFact(
  prepared,
  snapshot,
  modelClaimRefs,
  currentClaimDescriptors,
  currentClaimRouteDigests,
  historicalProviders
) {
  const { record } = prepared;
  const evidence = prepared.evidenceSources.flatMap((sourceContext) => {
    const provider = sourceContext.providerKey
      ? historicalProviders.get(sourceContext.providerKey)
      : null;
    if (sourceContext.providerKey && !provider) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_ROUTE_PROVIDER_INVALID",
        "Architecture Profile Evidence could not resolve its prepared historical Provider.",
        500,
        { location: sourceContext.location, baselineDigest: sourceContext.providerKey }
      );
    }
    return normalizeArchitectureProfileEvidence({
      source: sourceContext.source,
      assessment: sourceContext.assessment,
      modelClaimRefs,
      currentClaimDescriptors,
      sourceClaimDescriptors: provider?.claimDescriptors ?? new Map(),
      currentClaimRouteDigests,
      sourceClaimRouteDigests: provider?.routeDigests ?? new Map(),
      origin: sourceContext.origin,
      ...(sourceContext.acceptanceDigest
        ? { acceptanceDigest: sourceContext.acceptanceDigest }
        : {}),
      forceInvalid: sourceContext.forceInvalid,
      historical: sourceContext.historical
    });
  });
  assertArchitectureProfileListBound(
    evidence,
    ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    `change.${readString(record.id) ?? "unknown"}.evidence`
  );
  return {
    schemaVersion: 1,
    sourceSnapshotDigest: snapshot.digest,
    id: requireArchitectureProfileString(record.id, "change.id"),
    state: requireArchitectureProfileString(record.state, `change.${record.id}.state`),
    primaryModuleRef: requireArchitectureProfileString(
      record.primaryModule,
      `change.${record.id}.primaryModule`
    ),
    contributions: prepared.contributions,
    evidence
  };
}

function normalizeArchitectureProfileContributions(value, { origin, acceptanceDigest } = {}) {
  const contributions = Array.isArray(value) ? value : [];
  return contributions.map((contribution) => ({
    contributionRef: requireArchitectureProfileString(
      contribution?.contributionId,
      "contribution.contributionId"
    ),
    origin,
    ...(acceptanceDigest ? { acceptanceDigest } : {}),
    outcomeRef: requireArchitectureProfileString(contribution?.outcomeRef, "contribution.outcomeRef"),
    criterionRef: requireArchitectureProfileString(
      contribution?.criterionRef,
      "contribution.criterionRef"
    ),
    moduleRef: requireArchitectureProfileString(contribution?.moduleRef, "contribution.moduleRef"),
    claimRefs: normalizeStringList(contribution?.claimRefs),
    bindingDigest: requireArchitectureProfileDigest(
      contribution?.bindingDigest,
      "contribution.bindingDigest"
    )
  }));
}

function normalizeArchitectureProfileEvidence({
  source,
  assessment,
  modelClaimRefs,
  currentClaimDescriptors,
  sourceClaimDescriptors,
  currentClaimRouteDigests,
  sourceClaimRouteDigests,
  origin,
  acceptanceDigest,
  forceInvalid = false,
  historical = false
}) {
  const currentIds = new Set(assessment.evidenceCurrency.currentIds);
  const staleIds = new Set(assessment.evidenceCurrency.staleIds);
  const associationIndex = indexArchitectureProfileClaimAssociations(
    assessment.coverage.eligibleClaimAssociations
  );
  const changeClaimStatements = new Map((Array.isArray(source?.claims) ? source.claims : [])
    .map((claim) => [readString(claim?.id), readString(claim?.statement)])
    .filter(([claimRef, statement]) => claimRef && statement));
  return (Array.isArray(source.evidence) ? source.evidence : []).map((item, index) => {
    const evidenceRef = readString(item?.id) ?? `invalid-evidence-${index + 1}`;
    const evidenceDigest = canonicalDigest(item);
    let currency = currentIds.has(evidenceRef)
      ? historical ? "sealed-historical" : "current"
      : staleIds.has(evidenceRef) ? "stale" : "invalid";
    if (forceInvalid) currency = "invalid";
    const claimEnvelopeRefs = readArchitectureProfileClaimEnvelopeRefs(item)
      .filter((claimRef) => modelClaimRefs.has(claimRef));
    const claimAssociations = ["current", "sealed-historical"].includes(currency)
      ? (associationIndex.get(`${evidenceRef}\u0000${evidenceDigest}`) ?? [])
          .filter((association) => (
            modelClaimRefs.has(association.targetClaimRef)
            && modelClaimRefs.has(association.sourceClaimRef)
            && claimEnvelopeRefs.includes(association.sourceClaimRef)
            && architectureProfileAssociationClaimsAreCurrent(
              association,
              changeClaimStatements,
              currentClaimDescriptors,
              sourceClaimDescriptors
            )
            && architectureProfileAssociationHasCurrentRoute(
              association,
              currentClaimRouteDigests,
              sourceClaimRouteDigests
            )))
          .map(projectArchitectureProfileClaimAssociation)
      : [];
    return {
      evidenceRef,
      evidenceDigest,
      origin,
      ...(acceptanceDigest ? { acceptanceDigest } : {}),
      currency,
      ...(readString(item?.observation?.status)
        ? { observationStatus: readString(item.observation.status) }
        : {}),
      provenance: projectArchitectureProfileProvenance(item?.provenance),
      claimEnvelopeRefs,
      claimAssociations,
      residualUncertainty: item?.residualUncertainty ?? []
    };
  });
}

function architectureProfileAssociationClaimsAreCurrent(
  association,
  changeClaimStatements,
  currentClaimDescriptors,
  sourceClaimDescriptors
) {
  const currentTarget = currentClaimDescriptors.get(association.targetClaimRef);
  const sourceTarget = sourceClaimDescriptors.get(association.targetClaimRef);
  const currentSource = currentClaimDescriptors.get(association.sourceClaimRef);
  const sourceSource = sourceClaimDescriptors.get(association.sourceClaimRef);
  return Boolean(
    currentTarget
      && sourceTarget
      && currentSource
      && sourceSource
      && currentTarget.digest === sourceTarget.digest
      && currentSource.digest === sourceSource.digest
      && changeClaimStatements.get(association.targetClaimRef) === sourceTarget.statement
  );
}

function compileCurrentEvidenceAssessmentForProfile(
  change,
  inspection,
  { allowInvalidProjection = false, workBudget } = {}
) {
  try {
    return compileEvidenceAssessment(change, inspection, { workBudget });
  } catch (error) {
    // A mutable projection cannot suppress an independently intact sealed package.
    // Resource/internal failures still abort instead of masquerading as invalid Evidence.
    const expectedInvalidRecord = [
      "GOVERNANCE_BASELINE_MISSING",
      "GOVERNANCE_BASELINE_TAMPERED"
    ].includes(error?.code) || (allowInvalidProjection
      && error?.statusCode !== 413
      && !(Number.isInteger(error?.statusCode) && error.statusCode >= 500)
      && !(error instanceof RangeError));
    if (!expectedInvalidRecord) {
      throw error;
    }
    return {
      evidenceCurrency: {
        currentIds: [],
        staleIds: [],
        invalidIds: normalizeStringList((Array.isArray(change?.evidence) ? change.evidence : [])
          .map((item, index) => readString(item?.id) ?? `invalid-evidence-${index + 1}`)),
        coverageBindings: []
      },
      coverage: { eligibleClaimAssociations: [] }
    };
  }
}

function indexArchitectureProfileClaimAssociations(value) {
  const index = new Map();
  for (const association of Array.isArray(value) ? value : []) {
    const key = `${association.evidenceRef}\u0000${association.evidenceDigest}`;
    if (!index.has(key)) index.set(key, []);
    index.get(key).push(association);
  }
  return index;
}

function architectureProfileAssociationHasCurrentRoute(
  association,
  currentClaimRouteDigests,
  sourceClaimRouteDigests
) {
  if (association.kind === "builtin") return true;
  const key = architectureProfileRouteKey(
    association.sourceClaimRef,
    association.gateId,
    association.commandId
  );
  const currentDigest = currentClaimRouteDigests.get(key);
  return Boolean(currentDigest && sourceClaimRouteDigests.get(key) === currentDigest);
}

function architectureProfileRouteKey(claimRef, gateId, commandId) {
  return `${readString(claimRef) ?? ""}\u0000${readString(gateId) ?? ""}\u0000${readString(commandId) ?? ""}`;
}

function projectArchitectureProfileClaimAssociation(association) {
  return {
    kind: association.kind,
    targetClaimRef: association.targetClaimRef,
    sourceClaimRef: association.sourceClaimRef,
    obligationRef: association.obligationRef,
    obligationDigest: association.obligationDigest,
    ...(association.sourceId ? { sourceId: association.sourceId } : {}),
    ...(association.gateId ? { gateId: association.gateId } : {}),
    ...(association.commandId ? { commandId: association.commandId } : {}),
    ...(association.authorityDecisionDigest
      ? { authorityDecisionDigest: association.authorityDecisionDigest }
      : {})
  };
}

function projectArchitectureProfileProvenance(value) {
  const provenance = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    kind: readString(provenance.kind) ?? "invalid-evidence",
    ...(readString(provenance.sourceId) ? { sourceId: readString(provenance.sourceId) } : {}),
    ...(readString(provenance.gateId) ? { gateId: readString(provenance.gateId) } : {}),
    ...(readString(provenance.commandId) ? { commandId: readString(provenance.commandId) } : {}),
    ...(isCanonicalDigest(provenance.projectModelDigest)
      ? { projectModelDigest: provenance.projectModelDigest }
      : {}),
    ...(isCanonicalDigest(provenance.git?.contentDigest)
      ? { gitContentDigest: provenance.git.contentDigest }
      : {}),
    ...(isCanonicalDigest(provenance.verificationSubjectDigest)
      ? { verificationSubjectDigest: provenance.verificationSubjectDigest }
      : {})
  };
}

function readArchitectureProfileClaimEnvelopeRefs(evidence) {
  const explicit = normalizeStringList(evidence?.claim?.refs);
  if (explicit.length > 0) return explicit;
  return evidence?.provenance?.kind === "builtin-oracle"
    ? normalizeStringList(evidence?.claim?.id)
    : [];
}

function assertArchitectureProfileRecordBounds(record, origin, queryFactBudget) {
  const changeRef = readString(record?.id) ?? readString(record?.changeId) ?? "unknown";
  const root = `${origin}.${changeRef}`;
  consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
  for (const [field, value] of [
    ["claims", record?.claims],
    ["verificationObligations", record?.verificationObligations],
    ["outcomeAlignment.contributions", record?.outcomeAlignment?.contributions],
    ["evidence", record?.evidence],
    ["gateRuns", record?.gateRuns],
    ["history", record?.history],
    ["authorityDecision.approvedObligationIds", record?.authorityDecision?.approvedObligationIds]
  ]) {
    assertArchitectureProfileOptionalListBound(value, `${root}.${field}`);
    consumeArchitectureProfileQueryFacts(queryFactBudget, Array.isArray(value) ? value.length : 0);
  }
  for (const [index, contribution] of (record?.outcomeAlignment?.contributions ?? []).entries()) {
    consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
    assertArchitectureProfileOptionalListBound(
      contribution?.claimRefs,
      `${root}.outcomeAlignment.contributions.${index}.claimRefs`
    );
    consumeArchitectureProfileQueryFacts(
      queryFactBudget,
      Array.isArray(contribution?.claimRefs) ? contribution.claimRefs.length : 0
    );
  }
  for (const [index, obligation] of (record?.verificationObligations ?? []).entries()) {
    consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
    for (const [field, value] of [
      ["mapping.routes", obligation?.mapping?.routes],
      ["mapping.sourceRoutes", obligation?.mapping?.sourceRoutes],
      ["mapping.sourceClaimIds", obligation?.mapping?.sourceClaimIds],
      ["mapping.sourceIds", obligation?.mapping?.sourceIds],
      ["evidenceSourceRefs", obligation?.evidenceSourceRefs],
      ["gateClaimRefs", obligation?.gateClaimRefs],
      ["supportedBy", obligation?.supportedBy]
    ]) {
      assertArchitectureProfileOptionalListBound(
        value,
        `${root}.verificationObligations.${index}.${field}`
      );
      consumeArchitectureProfileQueryFacts(queryFactBudget, Array.isArray(value) ? value.length : 0);
    }
  }
  for (const [index, evidence] of (record?.evidence ?? []).entries()) {
    consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
    for (const [field, value] of [
      ["claim.refs", evidence?.claim?.refs],
      ["directSupportBindings", evidence?.directSupportBindings],
      ["supportBindings", evidence?.supportBindings]
    ]) {
      assertArchitectureProfileOptionalListBound(value, `${root}.evidence.${index}.${field}`);
      consumeArchitectureProfileQueryFacts(queryFactBudget, Array.isArray(value) ? value.length : 0);
    }
    if (Array.isArray(evidence?.residualUncertainty)) {
      assertArchitectureProfileListBound(
        evidence.residualUncertainty,
        ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
        `${root}.evidence.${index}.residualUncertainty`
      );
      consumeArchitectureProfileQueryFacts(queryFactBudget, evidence.residualUncertainty.length);
    } else if (evidence?.residualUncertainty !== undefined
      && evidence?.residualUncertainty !== null) {
      consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
    }
  }
  let gateRunFactCount = 0;
  for (const [index, run] of (record?.gateRuns ?? []).entries()) {
    consumeArchitectureProfileQueryFacts(queryFactBudget, 1);
    for (const [field, value] of [
      ["evidenceBindings", run?.evidenceBindings],
      ["commandResults", run?.commandResults],
      ["evidenceIds", run?.evidenceIds]
    ]) {
      assertArchitectureProfileOptionalListBound(value, `${root}.gateRuns.${index}.${field}`);
      gateRunFactCount += Array.isArray(value) ? value.length : 0;
      consumeArchitectureProfileQueryFacts(queryFactBudget, Array.isArray(value) ? value.length : 0);
      assertArchitectureProfileCountBound(
        gateRunFactCount,
        EVIDENCE_ASSESSMENT_WORK_LIMIT,
        `${root}.gateRuns.derivedFacts`
      );
    }
  }
}

function consumeArchitectureProfileQueryFacts(budget, units) {
  budget.observed += units;
  assertArchitectureProfileCountBound(
    budget.observed,
    ARCHITECTURE_PROFILE_QUERY_FACT_LIMIT,
    "changeStore.queryDerivedFacts"
  );
}

function assertArchitectureProfileOptionalListBound(value, location) {
  if (value === undefined || value === null) return;
  if (!Array.isArray(value)) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_FACT_INVALID",
      "Architecture Profile source facts require array-shaped reference collections.",
      422,
      { location }
    );
  }
  assertArchitectureProfileListBound(value, ARCHITECTURE_PROFILE_LIMITS.refsPerFact, location);
}

function assertArchitectureProfileListBound(value, limit, location) {
  if (!Array.isArray(value)) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_FACT_INVALID",
      "Architecture Profile source facts require bounded arrays.",
      422,
      { location }
    );
  }
  if (value.length > limit) {
    throwArchitectureProfileFactsUnbounded(location, limit, value.length);
  }
}

function assertArchitectureProfileCountBound(observed, limit, location) {
  if (observed > limit) throwArchitectureProfileFactsUnbounded(location, limit, observed);
}

function throwArchitectureProfileFactsUnbounded(location, limit, observed) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_FACTS_UNBOUNDED",
      "Architecture Profile source facts exceeded a declared hard bound.",
      413,
      { location, limit, observed }
    );
}

function isCanonicalDigest(value) {
  return DIGEST_PATTERN.test(readString(value) ?? "");
}

function requireArchitectureProfileString(value, location) {
  const exact = readString(value);
  if (exact) return exact;
  throw kernelError(
    "ARCHITECTURE_PROFILE_FACT_INVALID",
    "Architecture Profile source facts require non-empty exact references.",
    422,
    { location }
  );
}

function requireArchitectureProfileDigest(value, location) {
  if (isCanonicalDigest(value)) return value;
  throw kernelError(
    "ARCHITECTURE_PROFILE_FACT_INVALID",
    "Architecture Profile source facts require canonical sha256 bindings.",
    422,
    { location }
  );
}

function compileChangeObservationSafely(change, snapshot) {
  try {
    return compileChangeObservation(change, snapshot);
  } catch (error) {
    return {
      schemaVersion: 1,
      sourceSnapshotDigest: snapshot.digest,
      classification: {
        available: false,
        errorCode: boundedSummaryText(error?.code) ?? "CHANGE_OBSERVATION_INVALID"
      }
    };
  }
}

function compileReadinessForRead(change, inspection) {
  try {
    return readReadiness(change, inspection);
  } catch (error) {
    return {
      available: false,
      errorCode: boundedSummaryText(error?.code) ?? "CHANGE_READINESS_INVALID"
    };
  }
}

function summarizeChangeObservation(observation) {
  if (observation.classification?.available === false) {
    return { classification: cloneJson(observation.classification) };
  }
  return {
    bindingMatches: cloneJson(observation.bindings.matches),
    seal: {
      present: observation.seal.present,
      ...(observation.seal.present
        ? {
            intact: observation.seal.intact,
            packageIntact: observation.seal.packageIntact,
            recordProjectionIntact: observation.seal.recordProjectionIntact,
            problemCount: arrayLength(observation.seal.problems)
          }
        : {})
    },
    currentApplicability: cloneJson(observation.currentApplicability),
    evidenceCurrency: {
      currentCount: observation.evidenceCurrency.currentIds.length,
      staleCount: observation.evidenceCurrency.staleIds.length,
      invalidCount: observation.evidenceCurrency.invalidIds.length
    }
  };
}

function compileChangeObservation(change, snapshot) {
  const assessment = compileEvidenceAssessment(change, snapshot.inspection);
  const expectedSubjectDigest = assessment.verificationSubjectDigest;
  const persistedSubjectDigest = verificationSubjectDigest(change);
  const seal = inspectHistoricalSeal(change);
  return {
    schemaVersion: 1,
    sourceSnapshotDigest: snapshot.digest,
    bindings: {
      current: {
        projectModelDigest: snapshot.inspection.digest,
        gitContentDigest: snapshot.inspection.git.contentDigest,
        verificationSubjectDigest: expectedSubjectDigest
      },
      persisted: {
        projectModelDigest: readString(change?.projectModelDigest) ?? null,
        gitContentDigest: readString(change?.currentGit?.contentDigest) ?? null,
        verificationSubjectDigest: persistedSubjectDigest
      },
      matches: {
        projectModel: change?.projectModelDigest === snapshot.inspection.digest,
        gitContent: change?.currentGit?.contentDigest === snapshot.inspection.git.contentDigest,
        verificationSubject: persistedSubjectDigest === expectedSubjectDigest
      }
    },
    seal,
    currentApplicability: inspectCurrentApplicability(change, snapshot.inspection, seal),
    evidenceCurrency: projectEvidenceCurrency(assessment.evidenceCurrency)
  };
}

function projectChangeOntoInspection(change, inspection) {
  return {
    ...change,
    projectModelDigest: inspection.digest,
    currentGit: inspection.git
  };
}

function inspectHistoricalSeal(change) {
  const acceptance = change?.acceptance;
  if (!acceptance || typeof acceptance !== "object" || Array.isArray(acceptance)) {
    return { present: false };
  }
  const inspection = inspectAcceptedPackageRecord(change);
  const problems = [...inspection.problems];
  let recordProjectionIntact = false;
  try {
    recordProjectionIntact = changeContentDigest(change) === acceptance.digest;
  } catch {
    recordProjectionIntact = false;
  }
  if (!recordProjectionIntact) problems.push("record-projection-digest-mismatch");
  return {
    present: true,
    acceptanceDigest: readString(acceptance.digest) ?? null,
    packageIntact: inspection.valid,
    recordProjectionIntact,
    intact: inspection.valid && recordProjectionIntact,
    problems: [...new Set(problems)]
  };
}

function inspectCurrentApplicability(change, inspection, seal) {
  const reasons = [];
  if (inspection.validation?.valid !== true) reasons.push("project-model-invalid");
  if (inspection.git?.available !== true) reasons.push("git-unavailable");
  if (seal.present && !seal.intact) reasons.push("historical-seal-invalid");
  if (reasons.length > 0) return { status: "invalid", reasons };

  const source = seal.present ? change.acceptance.package : change;
  const sourceProjectModelDigest = readString(source?.projectModelDigest);
  const sourceGitContentDigest = readString(source?.currentGit?.contentDigest);
  if (!sourceProjectModelDigest) reasons.push("source-project-model-binding-missing");
  if (!sourceGitContentDigest) reasons.push("source-git-binding-missing");
  if (reasons.length > 0) return { status: "invalid", reasons };
  const matches = {
    projectModel: sourceProjectModelDigest === inspection.digest,
    gitContent: sourceGitContentDigest === inspection.git.contentDigest
  };
  return {
    status: Object.values(matches).every(Boolean) ? "current" : "stale",
    bindingMatches: matches
  };
}

function classifyEvidenceCurrency(change, inspection, expectedSubjectDigest, workBudget) {
  const evidence = Array.isArray(change?.evidence) ? change.evidence : [];
  const gateRuns = Array.isArray(change?.gateRuns) ? change.gateRuns : [];
  assertEvidenceAssessmentCollectionBound(evidence, "evidence");
  assertEvidenceAssessmentCollectionBound(gateRuns, "gateRuns");
  const evaluationBudget = readEvidenceAssessmentWorkBudget(workBudget);
  const runIndex = compileGateRunEvidenceIndex(gateRuns, evaluationBudget);
  const currentIds = [];
  const staleIds = [];
  const invalidIds = [];
  const coverageBindings = [];
  const coverageBindingKeys = new Set();
  const evidenceIdentityCounts = new Map();
  for (const [index, item] of evidence.entries()) {
    consumeEvidenceAssessmentWork(evaluationBudget);
    const id = readString(item?.id) ?? `missing-id-${index + 1}`;
    evidenceIdentityCounts.set(id, (evidenceIdentityCounts.get(id) ?? 0) + 1);
  }

  for (const [index, item] of evidence.entries()) {
    consumeEvidenceAssessmentWork(evaluationBudget);
    const id = readString(item?.id) ?? `missing-id-${index + 1}`;
    if (evidenceIdentityCounts.get(id) > 1) {
      if (!invalidIds.includes(id)) invalidIds.push(id);
      continue;
    }
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      invalidIds.push(id);
      continue;
    }
    const evidenceDigest = canonicalDigest(item);
    const candidateBindingRuns = runIndex.bindingRuns.get(`${item.id}\u0000${evidenceDigest}`) ?? [];
    consumeEvidenceAssessmentWork(evaluationBudget, candidateBindingRuns.length);
    const bindingRuns = candidateBindingRuns
      .filter((run) => evidenceProvenanceMatchesRun(change, item, run, runIndex));
    const provenance = item.provenance;
    const provenanceComplete = readString(provenance?.projectModelDigest)
      && readString(provenance?.git?.contentDigest)
      && readString(provenance?.verificationSubjectDigest);
    if (bindingRuns.length === 0 || !provenanceComplete) {
      invalidIds.push(id);
      continue;
    }
    const provenanceCurrent = provenance.projectModelDigest === inspection.digest
      && provenance.git.contentDigest === inspection.git.contentDigest
      && provenance.verificationSubjectDigest === expectedSubjectDigest;
    consumeEvidenceAssessmentWork(evaluationBudget, bindingRuns.length);
    const trustedCurrentRuns = bindingRuns.filter((run) => (
      run.projectModelDigest === inspection.digest
      && run.gitContentDigest === inspection.git.contentDigest
      && run.verificationSubjectDigest === expectedSubjectDigest
    ));
    if (provenanceCurrent && trustedCurrentRuns.length > 0) {
      currentIds.push(id);
      for (const run of trustedCurrentRuns.filter((entry) => entry.status === "passed")) {
        const bindingKey = `${item.id}\u0000${evidenceDigest}`;
        if (coverageBindingKeys.has(bindingKey)) continue;
        coverageBindingKeys.add(bindingKey);
        coverageBindings.push({ id: item.id, digest: evidenceDigest });
      }
    } else {
      staleIds.push(id);
    }
  }

  return { currentIds, staleIds, invalidIds, coverageBindings };
}

function compileGateRunEvidenceIndex(gateRuns, budget) {
  const bindingRuns = new Map();
  const runFacts = new WeakMap();
  for (const [runIndex, run] of gateRuns.entries()) {
    consumeEvidenceAssessmentWork(budget);
    if (!run || typeof run !== "object" || Array.isArray(run)) continue;
    const evidenceBindings = readEvidenceAssessmentCollection(
      run.evidenceBindings,
      `gateRuns.${runIndex}.evidenceBindings`
    );
    const commandResults = readEvidenceAssessmentCollection(
      run.commandResults,
      `gateRuns.${runIndex}.commandResults`
    );
    const evidenceIds = readEvidenceAssessmentCollection(
      run.evidenceIds,
      `gateRuns.${runIndex}.evidenceIds`
    );
    const facts = {
      commandResults: new Set(),
      evidenceIds: new Set()
    };
    for (const evidenceId of evidenceIds) {
      consumeEvidenceAssessmentWork(budget);
      const exact = readString(evidenceId);
      if (exact) facts.evidenceIds.add(exact);
    }
    for (const result of commandResults) {
      consumeEvidenceAssessmentWork(budget);
      const commandId = readString(result?.id);
      const evidenceId = readString(result?.evidenceId);
      if (commandId && evidenceId) facts.commandResults.add(`${commandId}\u0000${evidenceId}`);
    }
    for (const binding of evidenceBindings) {
      consumeEvidenceAssessmentWork(budget);
      const evidenceId = readString(binding?.id);
      const evidenceDigest = readString(binding?.digest);
      if (!evidenceId || !evidenceDigest) continue;
      const key = `${evidenceId}\u0000${evidenceDigest}`;
      if (!bindingRuns.has(key)) bindingRuns.set(key, []);
      bindingRuns.get(key).push(run);
    }
    runFacts.set(run, facts);
  }
  return { bindingRuns, runFacts };
}

function readEvidenceAssessmentCollection(value, location) {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) {
    throw kernelError(
      "EVIDENCE_ASSESSMENT_INPUT_INVALID",
      "Evidence assessment requires array-shaped Gate run collections.",
      422,
      { location }
    );
  }
  assertEvidenceAssessmentCollectionBound(value, location);
  return value;
}

function assertEvidenceAssessmentCollectionBound(value, location) {
  if (value.length > EVIDENCE_ASSESSMENT_COLLECTION_LIMIT) {
    throw kernelError(
      "EVIDENCE_ASSESSMENT_LIMIT_EXCEEDED",
      "Evidence assessment exceeded a declared hard collection bound.",
      413,
      {
        location,
        limit: EVIDENCE_ASSESSMENT_COLLECTION_LIMIT,
        observed: value.length
      }
    );
  }
}

function consumeEvidenceAssessmentWork(budget, units = 1) {
  budget.observed += units;
  if (budget.observed > EVIDENCE_ASSESSMENT_WORK_LIMIT) {
    throw kernelError(
      "EVIDENCE_ASSESSMENT_EVALUATION_LIMIT_EXCEEDED",
      "Evidence assessment exceeded a declared hard work bound.",
      413,
      { limit: EVIDENCE_ASSESSMENT_WORK_LIMIT, observed: budget.observed }
    );
  }
}

function readEvidenceAssessmentWorkBudget(value) {
  if (value === undefined) return { observed: 0 };
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !Number.isSafeInteger(value.observed) || value.observed < 0) {
    throw kernelError(
      "EVIDENCE_ASSESSMENT_INPUT_INVALID",
      "Evidence assessment workBudget must expose a non-negative safe-integer observation count.",
      422,
      { location: "workBudget" }
    );
  }
  return value;
}

function compileEvidenceAssessment(change, inspection, { workBudget } = {}) {
  const evaluationBudget = readEvidenceAssessmentWorkBudget(workBudget);
  const observed = projectChangeOntoInspection(change, inspection);
  consumeEvidenceAssessmentWork(
    evaluationBudget,
    arrayLength(observed?.claims)
      + arrayLength(observed?.verificationObligations)
      + arrayLength(observed?.authorityDecision?.approvedObligationIds)
  );
  const governanceBaseline = readGovernanceBaseline(observed);
  const mappingAuthorization = readMappingAuthorization(observed, governanceBaseline);
  const subjectDigest = verificationSubjectDigest(observed);
  const evidenceCurrency = classifyEvidenceCurrency(
    observed,
    inspection,
    subjectDigest,
    evaluationBudget
  );
  const coverage = validateEvidenceCoverage(observed.claims, observed.evidence, {
    authorityBindings: mappingAuthorization.authorityBindings,
    verificationSubjectDigest: subjectDigest,
    trustedEvidenceBindings: evidenceCurrency.coverageBindings,
    verificationObligations: observed.verificationObligations,
    workBudget: evaluationBudget
  });
  return {
    observed,
    coverage,
    evidenceCurrency,
    governanceBaseline,
    mappingAuthorization,
    verificationSubjectDigest: subjectDigest
  };
}

function projectEvidenceCurrency(value) {
  return {
    currentIds: value.currentIds,
    staleIds: value.staleIds,
    invalidIds: value.invalidIds
  };
}

function evidenceProvenanceMatchesRun(change, evidence, run, runIndex) {
  const provenance = evidence?.provenance;
  const indexed = runIndex.runFacts.get(run);
  if (provenance?.changeId !== change?.id
    || provenance?.projectModelDigest !== run?.projectModelDigest
    || provenance?.git?.contentDigest !== run?.gitContentDigest
    || provenance?.verificationSubjectDigest !== run?.verificationSubjectDigest
    || !indexed?.evidenceIds.has(evidence.id)) return false;
  if (provenance.kind === "builtin-oracle") {
    return run.kind === "builtin-oracle"
      && run.gateId === "project-model"
      && provenance.sourceId === "project-model";
  }
  if (provenance.kind !== "gate-command" || run.kind !== "configured-gate"
    || provenance.gateId !== run.gateId) return false;
  return indexed.commandResults.has(`${provenance.commandId}\u0000${evidence.id}`);
}

function boundedSummaryText(value) {
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  return trimmed.slice(0, CHANGE_SUMMARY_TEXT_LIMIT);
}

function isSummaryTextTruncated(value) {
  return typeof value === "string" && value.trim().length > CHANGE_SUMMARY_TEXT_LIMIT;
}

function arrayLength(value) {
  return Array.isArray(value) ? value.length : 0;
}

function applyCompilePatch(change, patch, observedAt, planRefsInput) {
  assertCompilePatchInput(patch);
  const next = cloneJson(change);
  next.compilerInput ??= {
    verificationObligations: cloneJson(next.verificationObligations ?? []),
    impact: null,
    contextCapsule: null,
    outcomeContributionHints: [],
    outcomeExceptions: []
  };
  next.compilerInput.outcomeContributionHints ??= [];
  next.compilerInput.outcomeExceptions ??= [];
  if (patch.intent && typeof patch.intent === "object") {
    next.intent = { ...next.intent, ...cloneJson(patch.intent) };
  }
  for (const field of ["title", "request", "description"]) {
    if (readString(patch[field])) next.intent[field] = patch[field].trim();
  }
  if (patch.nonGoals !== undefined) next.intent.nonGoals = normalizeStringList(patch.nonGoals);
  if (patch.primaryModule !== undefined) next.primaryModule = readString(patch.primaryModule);
  if (patch.changeKind !== undefined) next.changeKind = readString(patch.changeKind);
  if (planRefsInput.present) next.planRefs = planRefsInput.planRefs;
  if (patch.integrityTarget !== undefined) next.integrityTarget = cloneJson(patch.integrityTarget);
  if (patch.claims !== undefined || patch.claim !== undefined) {
    next.claims = normalizeClaims(patch.claims ?? patch.claim);
  }
  if (patch.verificationObligations !== undefined) {
    next.compilerInput.verificationObligations = cloneJson(patch.verificationObligations);
  }
  if (patch.evidence !== undefined) next.evidence = normalizeEvidenceList(patch.evidence);
  if (patch.appendEvidence !== undefined) {
    for (const evidence of normalizeEvidenceList(patch.appendEvidence)) {
      next.evidence = replaceEvidence(next.evidence, evidence);
    }
  }
  for (const field of ["taskPlan", "changeSet", "knowledgeClosure", "modelExpansion"]) {
    if (patch[field] !== undefined) next[field] = cloneJson(patch[field]);
  }
  if (patch.impact !== undefined) next.compilerInput.impact = cloneJson(patch.impact);
  if (patch.contextCapsule !== undefined) next.compilerInput.contextCapsule = cloneJson(patch.contextCapsule);
  if (patch.outcomeContributionHints !== undefined) {
    next.compilerInput.outcomeContributionHints = cloneJson(patch.outcomeContributionHints);
  }
  if (patch.outcomeExceptions !== undefined) {
    next.compilerInput.outcomeExceptions = cloneJson(patch.outcomeExceptions);
  }
  if (patch.outcomeContributionHints !== undefined || patch.outcomeExceptions !== undefined) {
    next.outcomeAlignmentSchemaVersion = OUTCOME_ALIGNMENT_SCHEMA_VERSION;
    next.outcomeAlignment ??= null;
  }
  if (patch.authorityDecision !== undefined) {
    next.authorityDecision = normalizeAuthorityDecision(patch.authorityDecision, observedAt);
  }
  return next;
}

function deriveEvidenceReady(change, inspection, observedAt) {
  if (change.state === "Candidate" && change.claims.length > 0) {
    transition(change, "Submitted", observedAt, "Change contains explicit Claims.");
  }
  if (change.state === "Accepted" || change.state === "Integrated") return;
  const readiness = readReadiness(change, inspection);
  if (readiness.evidenceReady) {
    transition(change, "EvidenceReady", observedAt, "Verification Obligations and required Gates are satisfied.");
  } else if (change.state === "EvidenceReady") {
    transition(change, "Submitted", observedAt, "Evidence or Gate binding is no longer sufficient.");
  }
}

function readReadiness(change, inspection) {
  const assessment = compileEvidenceAssessment(change, inspection);
  const {
    observed,
    coverage,
    governanceBaseline,
    mappingAuthorization,
    verificationSubjectDigest: subjectDigest
  } = assessment;
  const integrityFailureEvidence = validateIntegrityFailureEvidence(observed, { requireDigest: true });
  const builtin = observed.gateRuns.find((run) => run.gateId === "project-model");
  const defaultGateId = governanceBaseline.projectDocument?.changePolicy?.defaultGate;
  const requiredGateIds = defaultGateId
    ? [defaultGateId]
    : governanceBaseline.gates.filter((gate) => gate.required === true).map((gate) => gate.id);
  const missingOrStaleGateIds = ["project-model", ...requiredGateIds].filter((gateId) => {
    const run = observed.gateRuns.find((entry) => entry.gateId === gateId);
    return !run
      || run.status !== "passed"
      || run.projectModelDigest !== inspection.digest
      || run.gitContentDigest !== inspection.git.contentDigest
      || run.verificationSubjectDigest !== subjectDigest;
  });
  return {
    evidenceReady: inspection.validation.valid
      && Boolean(builtin)
      && integrityFailureEvidence.valid
      && coverage.satisfied
      && mappingAuthorization.valid
      && missingOrStaleGateIds.length === 0,
    coverage,
    integrityFailureEvidence,
    mappingAuthorization,
    verificationSubjectDigest: subjectDigest,
    requiredGateIds: ["project-model", ...requiredGateIds],
    missingOrStaleGateIds
  };
}

function assertIntegrationAllowed(change, inspection) {
  const governanceBaseline = readGovernanceBaseline(change);
  const policy = governanceBaseline.projectDocument?.changePolicy ?? {};
  const fullGateBefore = normalizeStringList(policy.fullGateBefore).map((value) => value.toLowerCase());
  if (!fullGateBefore.includes("integrated")) return;

  const fullGateId = readString(policy.fullGate);
  if (!fullGateId) {
    throw kernelError(
      "FULL_GATE_POLICY_INVALID",
      "Governance Baseline requires a full Gate before integration but does not name fullGate.",
      409
    );
  }
  const subjectDigest = verificationSubjectDigest(change);
  let run = change.gateRuns.find((entry) => entry.gateId === fullGateId);
  let assuranceValid = true;
  if (change.integrationAssurance) {
    const { digest, valid, ...content } = change.integrationAssurance;
    assuranceValid = valid === true
      && digest === canonicalDigest(content)
      && content.acceptanceDigest === change.acceptance?.digest;
    const integrationRun = assuranceValid
      ? content.gateRuns?.find((entry) => entry.gateId === fullGateId)
      : null;
    if (integrationRun) {
      run = integrationRun;
    }
  }
  const current = assuranceValid && Boolean(run)
    && run.status === "passed"
    && run.projectModelDigest === inspection.digest
    && run.gitContentDigest === inspection.git.contentDigest
    && run.verificationSubjectDigest === subjectDigest;
  if (!current) {
    throw kernelError(
      "FULL_GATE_REQUIRED",
      `Gate ${fullGateId} must pass for the current verification subject before integration.`,
      409,
      {
        fullGateId,
        verificationSubjectDigest: subjectDigest,
        observedRun: run ?? null
      }
    );
  }
}

function compileObservedChangeSet(change, git, touchedPaths = readTouchedPaths(git)) {
  const previous = change.changeSet && typeof change.changeSet === "object"
    ? change.changeSet
    : {};
  const declared = previous.observed
    ? previous.declared ?? null
    : Object.keys(previous).length > 0 ? cloneJson(previous) : null;
  return {
    schemaVersion: 1,
    baseHead: change.baseline?.git?.head ?? null,
    baselineWorkingTreeDigest: change.baseline?.git?.contentDigest ?? null,
    preExistingAtCreation: change.baseline?.git?.dirty === true,
    observed: {
      head: git.head,
      branch: git.branch,
      dirty: git.dirty,
      status: cloneJson(git.status ?? []),
      trackedDiffDigest: git.trackedDiffDigest ?? null,
      untracked: cloneJson(git.untracked ?? []),
      contentDigest: git.contentDigest,
      touchedPaths: cloneJson(touchedPaths),
      headChanged: Boolean(change.baseline?.git?.head && git.head !== change.baseline.git.head)
    },
    declared
  };
}

function analyzeChangeScope(change, git, touchedPaths = readTouchedPaths(git)) {
  const governance = readGovernanceBaseline(change);
  const writeScope = change.contextCapsule?.scope?.write ?? { include: [], exclude: [] };
  const modelAmendmentPaths = touchedPaths.filter((filePath) => (
    filePath.startsWith(".legatura/") && !filePath.startsWith(".legatura/runtime/")
  ));
  const inModuleWriteScope = touchedPaths.filter((filePath) => (
    !modelAmendmentPaths.includes(filePath) && pathAllowed(filePath, writeScope)
  ));
  const outOfScopePaths = touchedPaths.filter((filePath) => (
    !modelAmendmentPaths.includes(filePath) && !inModuleWriteScope.includes(filePath)
  ));
  const touchedModules = governance.modules
    .filter((module) => touchedPaths.some((filePath) => pathAllowed(filePath, module.paths)))
    .map((module) => ({ id: module.id, name: module.name, status: module.status }));
  const opaquePaths = outOfScopePaths.filter((filePath) => touchedModules.some((module) => (
    module.status === "opaque"
      && pathAllowed(filePath, governance.modules.find((candidate) => candidate.id === module.id)?.paths)
  )));
  const preExistingPaths = change.baseline?.git?.dirty
    ? readTouchedPaths(change.baseline.git)
    : [];
  return {
    schemaVersion: 1,
    touchedPaths,
    inModuleWriteScope,
    modelAmendmentPaths,
    outOfScopePaths,
    opaquePaths,
    preExistingPaths,
    touchedModules,
    requires: uniqueStrings([
      ...(modelAmendmentPaths.length > 0 ? ["normative-amendment"] : []),
      ...(outOfScopePaths.length > 0 ? ["scoped-waiver-or-change-split"] : []),
      ...(preExistingPaths.length > 0 ? ["explicit-adoption"] : [])
    ])
  };
}

function assertPlanChangeSeparation(change, touchedPaths) {
  const changeKind = readString(change.changeKind) ?? "implementation";
  const planChanged = touchedPaths.includes(".legatura/plan.json");
  if (changeKind === "plan-amendment") {
    if (!planChanged) {
      throw kernelError(
        "PLAN_AMENDMENT_CHANGESET_REQUIRED",
        "A plan-amendment Change must actually modify .legatura/plan.json.",
        422
      );
    }
    const implementationPaths = touchedPaths.filter((filePath) => !filePath.startsWith(".legatura/"));
    if (implementationPaths.length > 0) {
      throw kernelError(
        "PLAN_AMENDMENT_IMPLEMENTATION_MIXED",
        "A Development Plan amendment and implementation must be separate Changes.",
        422,
        { implementationPaths }
      );
    }
    const preExistingPlanChange = readTouchedPaths(change.baseline?.git).includes(".legatura/plan.json");
    if (preExistingPlanChange) {
      throw kernelError(
        "PLAN_AMENDMENT_BASELINE_DIRTY",
        "Create a plan-amendment Change before editing .legatura/plan.json so its frozen baseline can prove history preservation.",
        422
      );
    }
    return;
  }
  if (planChanged) {
    throw kernelError(
      "PLAN_AMENDMENT_KIND_REQUIRED",
      "A Change that modifies .legatura/plan.json must use changeKind plan-amendment and cannot carry implementation.",
      422
    );
  }
}

function assertPlanHistoryPreserved(change, currentPlan) {
  if ((readString(change.changeKind) ?? "implementation") !== "plan-amendment") return;
  const baselinePlan = readGovernanceBaseline(change).plan;
  if (!baselinePlan) return;
  if (readString(currentPlan?.id) !== readString(baselinePlan.id)) {
    throw kernelError(
      "PLAN_HISTORY_REWRITE_FORBIDDEN",
      "A Development Plan amendment cannot replace the identity of the existing plan.",
      422,
      { baselinePlanId: baselinePlan.id ?? null, currentPlanId: currentPlan?.id ?? null }
    );
  }
  const currentById = new Map((Array.isArray(currentPlan?.outcomes) ? currentPlan.outcomes : [])
    .map((outcome) => [readString(outcome?.id), outcome])
    .filter(([id]) => Boolean(id)));
  const removedOutcomeIds = [];
  const rewrittenOutcomeIds = [];
  const reopenedOutcomeIds = [];
  const removedCriteria = [];
  const rewrittenCriteria = [];
  const terminalAdditions = [];
  const statusChangeAdditions = [];
  for (const baselineOutcome of Array.isArray(baselinePlan.outcomes) ? baselinePlan.outcomes : []) {
    const outcomeId = readString(baselineOutcome?.id);
    if (!outcomeId) continue;
    const currentOutcome = currentById.get(outcomeId);
    if (!currentOutcome) {
      removedOutcomeIds.push(outcomeId);
      continue;
    }
    if (readString(currentOutcome.outcome) !== readString(baselineOutcome.outcome)) {
      rewrittenOutcomeIds.push(outcomeId);
    }
    if (["achieved", "retired"].includes(baselineOutcome.status)
      && currentOutcome.status !== baselineOutcome.status) {
      reopenedOutcomeIds.push(outcomeId);
    }
    const criteriaGoverned = Array.isArray(baselineOutcome.acceptance?.criteria)
      || Array.isArray(currentOutcome.acceptance?.criteria);
    if (baselineOutcome.status === "achieved"
      && canonicalDigest(achievedAcceptanceHistoryValue(currentOutcome.acceptance, criteriaGoverned))
        !== canonicalDigest(achievedAcceptanceHistoryValue(baselineOutcome.acceptance, criteriaGoverned))) {
      rewrittenOutcomeIds.push(outcomeId);
    }
    const criterionChanges = compareStableCriteria(baselineOutcome, currentOutcome);
    removedCriteria.push(...criterionChanges.removed.map((criterionRef) => ({ outcomeRef: outcomeId, criterionRef })));
    rewrittenCriteria.push(...criterionChanges.rewritten.map((entry) => ({
      outcomeRef: outcomeId,
      ...entry
    })));
    if (["achieved", "retired"].includes(baselineOutcome.status)) {
      terminalAdditions.push(...criterionChanges.added.map((criterionRef) => ({ outcomeRef: outcomeId, criterionRef })));
    }
    if (currentOutcome.status !== baselineOutcome.status) {
      statusChangeAdditions.push(...criterionChanges.added.map((criterionRef) => ({ outcomeRef: outcomeId, criterionRef })));
    }
  }
  if (removedOutcomeIds.length > 0 || rewrittenOutcomeIds.length > 0 || reopenedOutcomeIds.length > 0) {
    throw kernelError(
      "PLAN_HISTORY_REWRITE_FORBIDDEN",
      "Existing Outcome identities and achieved records are durable history; retire or supersede them instead of deleting, renaming, reopening, or rewriting them.",
      422,
      {
        removedOutcomeIds,
        rewrittenOutcomeIds: uniqueStrings(rewrittenOutcomeIds),
        reopenedOutcomeIds
      }
    );
  }
  if (removedCriteria.length > 0
    || rewrittenCriteria.length > 0
    || terminalAdditions.length > 0
    || statusChangeAdditions.length > 0) {
    throw kernelError(
      "PLAN_CRITERIA_HISTORY_REWRITE_FORBIDDEN",
      "Stable Outcome Criteria cannot be removed or reinterpreted; new Criteria must be declared before a status transition and before an Outcome becomes terminal.",
      422,
      { removedCriteria, rewrittenCriteria, terminalAdditions, statusChangeAdditions }
    );
  }
}

function compareStableCriteria(baselineOutcome, currentOutcome) {
  const baselineById = new Map((Array.isArray(baselineOutcome?.acceptance?.criteria)
    ? baselineOutcome.acceptance.criteria
    : []).map((criterion) => [readString(criterion?.id), criterion]).filter(([id]) => Boolean(id)));
  const currentById = new Map((Array.isArray(currentOutcome?.acceptance?.criteria)
    ? currentOutcome.acceptance.criteria
    : []).map((criterion) => [readString(criterion?.id), criterion]).filter(([id]) => Boolean(id)));
  const removed = [];
  const rewritten = [];
  for (const [criterionRef, baselineCriterion] of baselineById) {
    const currentCriterion = currentById.get(criterionRef);
    if (!currentCriterion) {
      removed.push(criterionRef);
      continue;
    }
    const baselineValue = criterionSemanticValue(baselineCriterion);
    const currentValue = criterionSemanticValue(currentCriterion);
    if (canonicalDigest(baselineValue) !== canonicalDigest(currentValue)) {
      rewritten.push({
        criterionRef,
        changedFields: ["statement", "claimRefs", "gapRefs"].filter((field) => (
          canonicalDigest(baselineValue[field]) !== canonicalDigest(currentValue[field])
        )),
        baselineDigest: canonicalDigest(baselineValue),
        currentDigest: canonicalDigest(currentValue)
      });
    }
  }
  const added = [...currentById.keys()].filter((criterionRef) => !baselineById.has(criterionRef));
  return { removed, rewritten, added };
}

function criterionSemanticValue(criterion) {
  return {
    id: readString(criterion?.id) ?? null,
    statement: readString(criterion?.statement) ?? null,
    claimRefs: normalizeStringList(criterion?.claimRefs).sort(),
    gapRefs: normalizeStringList(criterion?.gapRefs).sort()
  };
}

function achievedAcceptanceHistoryValue(acceptance, criteriaGoverned) {
  const value = acceptance && typeof acceptance === "object" && !Array.isArray(acceptance)
    ? cloneJson(acceptance)
    : {};
  if (criteriaGoverned) {
    delete value.criteria;
    delete value.exitCriteria;
    delete value.claimRefs;
    delete value.gapRefs;
    return value;
  }
  if (Array.isArray(value.exitCriteria)) value.exitCriteria = normalizeStringList(value.exitCriteria).sort();
  for (const field of ["claimRefs", "gapRefs"]) {
    if (Array.isArray(value[field])) value[field] = normalizeReferenceList(value[field]).sort();
  }
  return value;
}

function assertOutcomeExceptionBinding(change) {
  const requestedValue = change.compilerInput?.outcomeExceptions;
  const compiledValue = change.outcomeAlignment?.exceptions;
  const requests = Array.isArray(requestedValue) ? requestedValue : [];
  const exceptions = Array.isArray(compiledValue) ? compiledValue : [];
  const requestListMalformed = requestedValue !== undefined && requestedValue !== null
    && !Array.isArray(requestedValue);
  const compiledListMalformed = compiledValue !== undefined && compiledValue !== null
    && !Array.isArray(compiledValue);
  if (requests.length === 0 && exceptions.length === 0
    && !requestListMalformed && !compiledListMalformed) return;

  const problems = [];
  if (requestListMalformed) problems.push("request-list-invalid");
  if (compiledListMalformed) problems.push("compiled-list-invalid");
  const normalizedRequests = requests.map(outcomeExceptionSemanticValue).sort(compareOutcomeExceptionValues);
  const normalizedExceptions = exceptions.map(outcomeExceptionSemanticValue).sort(compareOutcomeExceptionValues);
  if (canonicalDigest(normalizedRequests) !== canonicalDigest(normalizedExceptions)) {
    problems.push("request-output-mismatch");
  }
  const planAuthority = readString(readGovernanceBaseline(change).plan?.authority);
  if (change.outcomeAlignmentSchemaVersion !== OUTCOME_ALIGNMENT_SCHEMA_VERSION) {
    problems.push("schema-version-missing");
  }
  if (!planAuthority) problems.push("plan-authority-missing");
  for (const [index, exception] of exceptions.entries()) {
    if (readString(exception?.requiredAuthorityRef) !== planAuthority) {
      problems.push(`exception-${index + 1}-authority-mismatch`);
    }
    if (exception?.progress !== "none") {
      problems.push(`exception-${index + 1}-progress-invalid`);
    }
    if (exception?.transitionUse !== "forbidden") {
      problems.push(`exception-${index + 1}-transition-use-invalid`);
    }
  }
  if (problems.length > 0) {
    throw kernelError(
      "OUTCOME_EXCEPTION_BINDING_INVALID",
      "Compiled Outcome exceptions must remain bound to the frozen Development Plan authority and cannot grant progress or transition proof.",
      409,
      { planAuthority: planAuthority ?? null, problems }
    );
  }
}

function outcomeExceptionSemanticValue(exception) {
  return {
    outcomeRef: readString(exception?.outcomeRef) ?? null,
    reason: readString(exception?.reason) ?? null,
    residualUncertainty: exception?.residualUncertainty ?? null
  };
}

function compareOutcomeExceptionValues(left, right) {
  return (left.outcomeRef ?? "").localeCompare(right.outcomeRef ?? "")
    || canonicalDigest(left).localeCompare(canonicalDigest(right));
}

function assertCompiledChangeCurrent(change) {
  const governanceBaseline = readGovernanceBaseline(change);
  const recompiled = compileChangeAgainstGovernance(change, governanceBaseline);
  const expected = compiledChangeProjection(recompiled);
  const observed = compiledChangeProjection(change);
  const expectedDigest = canonicalDigest(expected);
  const observedDigest = canonicalDigest(observed);
  if (expectedDigest !== observedDigest) {
    throw kernelError(
      "CHANGE_COMPILATION_STALE",
      "Compiler-owned Change projections must match a fresh compilation from the frozen Governance Baseline before acceptance.",
      409,
      {
        expectedDigest,
        observedDigest,
        changedFields: Object.keys(expected).filter((field) => (
          canonicalDigest(expected[field]) !== canonicalDigest(observed[field])
        ))
      }
    );
  }
}

function compiledChangeProjection(change) {
  return {
    integrityTarget: change.integrityTarget ?? null,
    outcomeAlignmentSchemaVersion: change.outcomeAlignmentSchemaVersion ?? null,
    outcomeAlignment: change.outcomeAlignment ?? null,
    contextCapsule: change.contextCapsule ?? null,
    impact: change.impact ?? null,
    verificationObligations: change.verificationObligations ?? [],
    verificationPlan: change.verificationPlan ?? null,
    compilation: change.compilation ?? null
  };
}

async function readObservedTouchedPaths(change, git, repoPath, commandRunner) {
  const worktreePaths = readTouchedPaths(git);
  const baselineHead = readString(change.baseline?.git?.head);
  const currentHead = readString(git?.head);
  if (!baselineHead || !currentHead || baselineHead === currentHead) return worktreePaths;

  const result = await executeCommand(commandRunner, {
    cwd: repoPath,
    purpose: "change-scope",
    command: "git",
    args: [
      "diff",
      "--name-status",
      "--find-renames",
      baselineHead,
      currentHead,
      "--",
      ".",
      ":(exclude).legatura/runtime/**"
    ]
  });
  if (result.truncated) {
    throw kernelError(
      "GIT_CHANGESET_TRUNCATED",
      "Committed ChangeSet path output was truncated; scope cannot be proven safely.",
      409
    );
  }
  if (result.exitCode !== 0) {
    throw kernelError(
      "GIT_CHANGESET_UNREADABLE",
      "Could not compare the current Git HEAD with the Change baseline.",
      409,
      { baselineHead, currentHead, stderr: result.stderr }
    );
  }
  const committedPaths = result.stdout.split(/\r?\n/u).flatMap((line) => {
    if (!line) return [];
    const fields = line.split("\t");
    return fields.slice(1).map(decodeGitPath).filter(Boolean);
  });
  return uniqueStrings([...worktreePaths, ...committedPaths]);
}

function assertScopeDecision(change) {
  const analysis = change.scopeAnalysis;
  if (!analysis) {
    throw kernelError("CHANGE_SCOPE_MISSING", "Compile the observed ChangeSet before acceptance.", 409);
  }
  const decision = change.authorityDecision ?? {};
  const amendmentRefs = new Set(normalizeStringList(decision.amendmentRefs));
  const missingAmendments = analysis.modelAmendmentPaths.filter((filePath) => !amendmentRefs.has(filePath));
  if (analysis.modelAmendmentPaths.length > 0
    && (decision.decisionType !== "normative-amendment" || missingAmendments.length > 0)) {
    throw kernelError(
      "MODEL_AMENDMENT_DECISION_REQUIRED",
      "Project Model changes require a normative-amendment Decision that names every amended file.",
      409,
      { modelAmendmentPaths: analysis.modelAmendmentPaths, missingAmendments }
    );
  }
  if (analysis.outOfScopePaths.length > 0) {
    throw kernelError(
      "CHANGE_SCOPE_EXCEEDED",
      "The observed ChangeSet contains paths outside the compiled Module write scope. Split the Change or provide a fully scoped waiver in a later implementation.",
      409,
      { outOfScopePaths: analysis.outOfScopePaths, opaquePaths: analysis.opaquePaths }
    );
  }
  if (analysis.preExistingPaths.length > 0) {
    const adopted = new Set([
      ...normalizeStringList(decision.adoptedChangePaths),
      ...normalizeStringList(decision.amendmentRefs)
    ]);
    const missingAdoption = analysis.preExistingPaths.filter((filePath) => !adopted.has(filePath));
    if (missingAdoption.length > 0) {
      throw kernelError(
        "PREEXISTING_CHANGE_ADOPTION_REQUIRED",
        "This Change began from a dirty worktree; the Authority Decision must explicitly adopt every pre-existing path.",
        409,
        { missingAdoption }
      );
    }
  }
}

function assertKnowledgeClosureDurability(change, inspection) {
  const closure = validateKnowledgeClosure(change.knowledgeClosure);
  const modelPaths = new Set(change.scopeAnalysis?.modelAmendmentPaths ?? []);
  if (closure.mode === "no-new-knowledge") {
    if (modelPaths.size > 0) {
      throw kernelError(
        "KNOWLEDGE_CLOSURE_NOT_DURABLE",
        "Project Model files changed, so Knowledge Closure cannot declare no new knowledge.",
        409,
        { modelAmendmentPaths: [...modelPaths] }
      );
    }
    return;
  }

  const entries = closure.entries ?? [];
  const amendmentRefs = new Set(entries
    .filter((entry) => (entry.kind ?? entry.classification) === "model-amendment")
    .flatMap((entry) => normalizeStringList(entry.refs)));
  const missingDispositions = [...modelPaths].filter((filePath) => !amendmentRefs.has(filePath));
  const unobservedAmendments = [...amendmentRefs].filter((filePath) => !modelPaths.has(filePath));
  if (missingDispositions.length > 0 || unobservedAmendments.length > 0) {
    throw kernelError(
      "KNOWLEDGE_CLOSURE_NOT_DURABLE",
      "Every Project Model amendment must be both observed in Git and named by Knowledge Closure.",
      409,
      { missingDispositions, unobservedAmendments }
    );
  }

  const gapEntries = entries.filter((entry) => (entry.kind ?? entry.classification) === "model-gap");
  if (gapEntries.length === 0) return;
  const gapRefs = new Set(gapEntries.flatMap((entry) => normalizeStringList(entry.refs)));
  const knownGapIds = new Set((inspection.knowledgeGaps ?? []).map((gap) => readString(gap?.id)).filter(Boolean));
  const unknownGapRefs = [...gapRefs].filter((id) => !knownGapIds.has(id));
  if (gapRefs.size === 0
    || unknownGapRefs.length > 0
    || !modelPaths.has(".legatura/knowledge-gaps.json")) {
    throw kernelError(
      "KNOWLEDGE_CLOSURE_NOT_DURABLE",
      "Model Gaps must already exist in a changed .legatura/knowledge-gaps.json before acceptance.",
      409,
      {
        unknownGapRefs,
        knowledgeGapFileChanged: modelPaths.has(".legatura/knowledge-gaps.json")
      }
    );
  }
}

function bindAuthorityDecision(change) {
  if (!change.authorityDecision || typeof change.authorityDecision !== "object") return;
  change.authorityDecision.binding = {
    changeId: change.id,
    verificationSubjectDigest: verificationSubjectDigest(change),
    governanceBaselineDigest: readGovernanceBaseline(change).digest,
    gitContentDigest: change.currentGit?.contentDigest ?? null
  };
}

function authorityDecisionBindsCurrentSubject(change) {
  const binding = change.authorityDecision?.binding;
  return Boolean(binding)
    && binding.changeId === change.id
    && binding.verificationSubjectDigest === verificationSubjectDigest(change)
    && binding.governanceBaselineDigest === readGovernanceBaseline(change).digest
    && binding.gitContentDigest === change.currentGit?.contentDigest;
}

function readTouchedPaths(git) {
  const statusLines = Array.isArray(git?.status) ? git.status : [];
  const fromStatus = statusLines.filter((line) => typeof line === "string" && line.length > 0).flatMap((line) => {
    // Git porcelain v1 reserves the first two columns for XY status and the
    // third for a separator. Preserve the leading status column: trimming it
    // before slicing would silently remove the first characters of a path.
    const value = line.length >= 3 && line[2] === " " ? line.slice(3).trim() : line.trim();
    // A rename/copy touches both authority domains. Keeping only the target
    // could turn an out-of-scope source deletion into an apparently safe move.
    return value.split(" -> ").map(decodeGitPath).filter(Boolean);
  });
  const untracked = Array.isArray(git?.untracked)
    ? git.untracked.map((entry) => decodeGitPath(entry?.path)).filter(Boolean)
    : [];
  return uniqueStrings([...fromStatus, ...untracked].filter(Boolean));
}

function decodeGitPath(value) {
  if (!readString(value)) return undefined;
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function pathAllowed(filePath, scope = {}) {
  const includes = normalizeStringList(scope?.include ?? scope);
  const excludes = normalizeStringList(scope?.exclude);
  return includes.some((pattern) => globMatches(filePath, pattern))
    && !excludes.some((pattern) => globMatches(filePath, pattern));
}

function globMatches(filePath, pattern) {
  if (!readString(pattern)) return false;
  let expression = "";
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index];
    if (character === "*" && pattern[index + 1] === "*") {
      expression += ".*";
      index += 1;
    } else if (character === "*") {
      expression += "[^/]*";
    } else if (character === "?") {
      expression += "[^/]";
    } else {
      expression += character.replace(/[|\\{}()[\]^$+?.]/gu, "\\$&");
    }
  }
  return new RegExp(`^${expression}$`, "u").test(filePath);
}

function uniqueStrings(values) {
  return [...new Set(values.filter(readString))];
}

function createAcceptedPackageContent(change) {
  return {
    schemaVersion: 1,
    changeId: change.id,
    repoPath: change.repoPath,
    intent: change.intent,
    primaryModule: change.primaryModule ?? null,
    changeKind: change.changeKind ?? "implementation",
    planRefs: change.planRefs ?? [],
    integrityTarget: change.integrityTarget ?? null,
    ...readOutcomeAlignmentFields(change),
    ...readOutcomeTransitionFields(change),
    claims: change.claims,
    verificationObligations: change.verificationObligations,
    verificationPlan: change.verificationPlan,
    impact: change.impact,
    scopeAnalysis: change.scopeAnalysis ?? null,
    taskPlan: change.taskPlan,
    contextCapsule: change.contextCapsule,
    changeSet: change.changeSet,
    modelExpansion: change.modelExpansion,
    compilation: change.compilation,
    evidence: change.evidence,
    gateRuns: change.gateRuns,
    knowledgeClosure: change.knowledgeClosure,
    authorityDecision: change.authorityDecision,
    projectModelDigest: change.projectModelDigest,
    governanceBaseline: change.governanceBaseline,
    baseline: change.baseline,
    currentGit: change.currentGit
  };
}

function createVerificationSubject(change) {
  return {
    schemaVersion: 1,
    intent: change.intent,
    primaryModule: change.primaryModule ?? null,
    changeKind: change.changeKind ?? "implementation",
    planRefs: change.planRefs ?? [],
    integrityTarget: change.integrityTarget ?? null,
    ...readOutcomeAlignmentFields(change),
    ...readOutcomeTransitionFields(change),
    claims: change.claims,
    verificationObligations: change.verificationObligations,
    verificationPlan: change.verificationPlan,
    impact: change.impact,
    scopeAnalysis: change.scopeAnalysis ?? null,
    taskPlan: change.taskPlan,
    contextCapsule: change.contextCapsule,
    changeSet: change.changeSet,
    baseline: change.baseline,
    current: {
      projectModelDigest: change.projectModelDigest,
      git: change.currentGit
    }
  };
}

function readOutcomeAlignmentFields(change) {
  if (change.outcomeAlignmentSchemaVersion !== OUTCOME_ALIGNMENT_SCHEMA_VERSION) return {};
  return cloneJson({
    outcomeAlignmentSchemaVersion: OUTCOME_ALIGNMENT_SCHEMA_VERSION,
    outcomeContributionHints: change.compilerInput?.outcomeContributionHints ?? [],
    outcomeExceptions: change.compilerInput?.outcomeExceptions ?? [],
    outcomeAlignment: change.outcomeAlignment ?? null
  });
}

function readOutcomeTransitionFields(change) {
  if (change.outcomeTransitionSchemaVersion !== OUTCOME_TRANSITION_SCHEMA_VERSION) return {};
  return cloneJson({
    outcomeTransitionSchemaVersion: OUTCOME_TRANSITION_SCHEMA_VERSION,
    priorAcceptedPackages: change.priorAcceptedPackages ?? null,
    outcomeTransitionCompilation: change.outcomeTransitionCompilation ?? null
  });
}

function verificationSubjectDigest(change) {
  return canonicalDigest(createVerificationSubject(change));
}

function freezeGovernanceBaseline(inspection) {
  const snapshot = {
    schemaVersion: 1,
    modelDigest: inspection.digest,
    project: inspection.project,
    projectDocument: inspection.projectDocument,
    modules: inspection.modules,
    contracts: inspection.contracts,
    gates: inspection.gates,
    plan: inspection.plan,
    knowledgeGaps: inspection.knowledgeGaps,
    files: inspection.files
  };
  return cloneJson({ ...snapshot, digest: canonicalDigest(snapshot) });
}

function freezePriorAcceptedPackageCatalog({ records, createdAt, repoPath, governanceBaseline }) {
  const entries = [];
  const seenChangeIds = new Set();
  for (const record of Array.isArray(records) ? records : []) {
    if (!claimsHistoricalAcceptance(record)) continue;
    const inspection = inspectAcceptedPackageRecord(record);
    if (!inspection.valid) {
      throw kernelError(
        "ACCEPTED_PACKAGE_CATALOG_INVALID",
        `Cannot freeze Candidate history because Change ${record?.id ?? "unknown"} claims an invalid Accepted Package.`,
        409,
        { changeId: record?.id ?? null, problems: inspection.problems }
      );
    }
    if (Date.parse(inspection.acceptedAt) > Date.parse(createdAt)) {
      throw kernelError(
        "ACCEPTED_PACKAGE_CATALOG_INVALID",
        `Accepted Package ${record.id} is dated after the Candidate creation instant.`,
        409,
        { changeId: record.id, acceptedAt: inspection.acceptedAt, createdAt }
      );
    }
    if (!acceptedPackageMatchesProject(inspection.package, repoPath, governanceBaseline)) continue;
    if (seenChangeIds.has(inspection.reference.changeId)) {
      throw kernelError(
        "ACCEPTED_PACKAGE_CATALOG_INVALID",
        `Accepted Package history contains duplicate reference ${inspection.reference.changeId}.`,
        409,
        { reference: inspection.reference }
      );
    }
    seenChangeIds.add(inspection.reference.changeId);
    entries.push(inspection.reference);
  }
  entries.sort(comparePackageReferences);
  const snapshot = { schemaVersion: 1, entries };
  return cloneJson({ ...snapshot, digest: canonicalDigest(snapshot) });
}

function claimsHistoricalAcceptance(record) {
  return Boolean(record?.acceptance)
    || ["Accepted", "Integrated"].includes(record?.state)
    || (Array.isArray(record?.history) && record.history.some((event) => event?.to === "Accepted"));
}

function acceptedPackageMatchesProject(packageContent, repoPath, governanceBaseline) {
  const packageRepoPath = readString(packageContent?.repoPath);
  return Boolean(packageRepoPath)
    && path.resolve(packageRepoPath) === path.resolve(repoPath)
    && readProjectId(packageContent?.governanceBaseline) === readProjectId(governanceBaseline)
    && readString(packageContent?.governanceBaseline?.plan?.id)
      === readString(governanceBaseline?.plan?.id);
}

function assertPriorAcceptedPackageCatalog(value, { required = false } = {}) {
  if (value === undefined || value === null) {
    if (!required) return null;
    throw kernelError(
      "OUTCOME_TRANSITION_PACKAGE_NOT_PRIOR",
      "A plan-amendment requires the Accepted Package catalog frozen when its Candidate was created.",
      409
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)
    || value.schemaVersion !== 1 || !Array.isArray(value.entries)
    || Object.keys(value).some((key) => !["schemaVersion", "entries", "digest"].includes(key))) {
    throw kernelError(
      "ACCEPTED_PACKAGE_CATALOG_INVALID",
      "The Candidate's frozen Accepted Package catalog has an invalid schema.",
      409
    );
  }
  const entries = [];
  const seenChangeIds = new Set();
  for (const reference of value.entries) {
    const changeId = readString(reference?.changeId);
    const acceptanceDigest = readString(reference?.acceptanceDigest);
    if (!reference || typeof reference !== "object" || Array.isArray(reference)
      || Object.keys(reference).some((field) => !["changeId", "acceptanceDigest"].includes(field))
      || !changeId || !DIGEST_PATTERN.test(acceptanceDigest ?? "") || seenChangeIds.has(changeId)) {
      throw kernelError(
        "ACCEPTED_PACKAGE_CATALOG_INVALID",
        "The Candidate's frozen Accepted Package catalog contains an invalid or duplicate reference.",
        409,
        { reference }
      );
    }
    seenChangeIds.add(changeId);
    entries.push({ changeId, acceptanceDigest });
  }
  entries.sort(comparePackageReferences);
  const snapshot = { schemaVersion: 1, entries };
  if (canonicalDigest(snapshot) !== value.digest
    || canonicalDigest(entries) !== canonicalDigest(value.entries)) {
    throw kernelError(
      "ACCEPTED_PACKAGE_CATALOG_INVALID",
      "The Candidate's frozen Accepted Package catalog is not canonical or does not match its digest.",
      409
    );
  }
  return cloneJson(value);
}

function comparePackageReferences(left, right) {
  return left.changeId.localeCompare(right.changeId)
    || left.acceptanceDigest.localeCompare(right.acceptanceDigest);
}

function readProjectId(value) {
  return readString(value?.projectDocument?.project?.id)
    ?? readString(value?.project?.id);
}

function readGovernanceBaseline(change) {
  if (change.governanceBaseline?.digest) {
    const { digest, ...snapshot } = change.governanceBaseline;
    const observedDigest = canonicalDigest(snapshot);
    if (observedDigest !== digest) {
      throw kernelError(
        "GOVERNANCE_BASELINE_TAMPERED",
        `Change ${change.id} Governance Baseline does not match its frozen digest.`,
        409,
        { expectedDigest: digest, observedDigest }
      );
    }
    return change.governanceBaseline;
  }
  throw kernelError(
    "GOVERNANCE_BASELINE_MISSING",
    `Change ${change.id} has no frozen Governance Baseline.`,
    409
  );
}

function changeContentDigest(change) {
  return canonicalDigest(createAcceptedPackageContent(change));
}

function invalidateAcceptance(change, observedAt, reason) {
  if (!change.acceptance) return;
  change.acceptance = {
    ...change.acceptance,
    valid: false,
    invalidatedAt: observedAt,
    invalidationReason: reason
  };
  transition(change, "Submitted", observedAt, reason);
  delete change.integration;
  delete change.integrationAssurance;
}

function assertValidAcceptance(change) {
  const packageDigest = change.acceptance?.package
    ? canonicalDigest(change.acceptance.package)
    : null;
  if (!change.acceptance?.valid
    || changeContentDigest(change) !== change.acceptance.digest
    || packageDigest !== change.acceptance.digest) {
    throw kernelError("ACCEPTANCE_INVALID", "Accepted Change Package content no longer matches its canonical digest.", 409);
  }
}

function transition(change, target, observedAt, reason, digest) {
  if (!STATES.includes(target)) {
    throw kernelError("CHANGE_STATE_INVALID", `Unknown Change state: ${target}.`, 500);
  }
  if (change.state === target) return;
  const from = change.state;
  change.state = target;
  change.history.push({ from, to: target, at: observedAt, reason, ...(digest ? { digest } : {}) });
}

function selectGates(model, request, change) {
  if (request.all === true) return model.gates.filter((gate) => gateAppliesToChange(gate, model, change));
  const gateId = request.gateId
    ?? model.projectDocument?.changePolicy?.defaultGate
    ?? (model.gates.length === 1 ? model.gates[0].id : undefined);
  if (!gateId) {
    throw kernelError("GATE_ID_REQUIRED", "Specify gateId because the Project Model has no default Gate.", 422);
  }
  const gate = model.gates.find((entry) => entry.id === gateId);
  if (!gate) throw kernelError("GATE_NOT_FOUND", `Gate not found: ${gateId}.`, 404);
  if (!gateAppliesToChange(gate, model, change)) {
    throw kernelError(
      "GATE_NOT_APPLICABLE",
      `Gate ${gateId} does not apply to Module ${change.primaryModule}.`,
      409,
      { gateId, primaryModule: change.primaryModule, appliesTo: gate.appliesTo ?? [] }
    );
  }
  return [gate];
}

function gateAppliesToChange(gate, governanceBaseline, change) {
  const appliesTo = normalizeStringList(gate.appliesTo);
  if (appliesTo.length === 0 || appliesTo.includes(change.primaryModule)) return true;
  const fullGateId = readString(governanceBaseline.projectDocument?.changePolicy?.fullGate);
  return gate.id === fullGateId
    && (appliesTo.includes("integration") || appliesTo.includes("release"));
}

function readGateCommands(gate) {
  if (Array.isArray(gate?.commands)) return gate.commands;
  return gate?.command ? [gate] : [];
}

function commandAppliesToChange(command, change) {
  const appliesTo = normalizeStringList(command.appliesTo);
  return appliesTo.length === 0 || appliesTo.includes(change.primaryModule);
}

function readObligationMappings(obligations, gateClaimRefs, gateId, commandId) {
  const refs = new Set(normalizeStringList(gateClaimRefs));
  const exactGateId = readString(gateId);
  const exactCommandId = readString(commandId);
  return obligations.flatMap((obligation) => {
    const crossSourceMatched = obligation.mapping?.kind === "cross-claim"
      && exactGateId
      && exactCommandId
      && Array.isArray(obligation.mapping.sourceRoutes)
      && obligation.mapping.sourceRoutes.some((route) => {
        const sourceClaimId = readString(route?.sourceClaimId);
        return Boolean(sourceClaimId)
          && sourceClaimId !== readString(obligation.claimId)
          && refs.has(sourceClaimId)
          && readString(route?.gateId) === exactGateId
          && readString(route?.commandId) === exactCommandId;
      });
    if (!crossSourceMatched || !hasCrossMappingSemantics(obligation)) return [];
    return [{ obligationId: obligation.id, claimId: obligation.claimId }];
  });
}

function readMappingAuthorization(change, governanceBaseline) {
  const crossMappings = change.verificationObligations.filter((obligation) => {
    if (obligation.mapping?.kind === "exact-contract-claim") return false;
    const refs = [
      ...normalizeStringList(obligation.evidenceSourceRefs),
      ...normalizeStringList(obligation.gateClaimRefs),
      ...normalizeStringList(obligation.supportedBy)
    ];
    return refs.some((ref) => ref !== obligation.claimId);
  });
  const invalidObligationIds = crossMappings
    .filter((obligation) => !hasCrossMappingSemantics(obligation))
    .map((obligation) => obligation.id);
  const approvable = crossMappings.filter(hasCrossMappingSemantics);
  const expectedAuthorities = readExpectedAuthorities(governanceBaseline, change);
  const decisionValidation = validateAuthorityDecision(
    change.authorityDecision,
    expectedAuthorities,
    governanceBaseline.projectDocument?.authorities?.decision ?? []
  );
  const decisionApprovedIds = new Set(normalizeStringList(change.authorityDecision?.approvedObligationIds));
  const approvedObligationIds = decisionValidation.valid && authorityDecisionBindsCurrentSubject(change)
    ? approvable.map((obligation) => obligation.id).filter((id) => decisionApprovedIds.has(id))
    : [];
  const authorityDecisionDigest = approvedObligationIds.length > 0
    ? canonicalDigest(change.authorityDecision)
    : null;
  const authorityBindings = authorityDecisionDigest
    ? approvedObligationIds.map((obligationId) => ({
        obligationId,
        authorityDecisionDigest
      }))
    : [];
  const approved = new Set(approvedObligationIds);
  const unauthorizedObligationIds = approvable
    .map((obligation) => obligation.id)
    .filter((id) => !approved.has(id));
  return {
    valid: invalidObligationIds.length === 0 && unauthorizedObligationIds.length === 0,
    requiredObligationIds: approvable.map((obligation) => obligation.id),
    approvedObligationIds,
    authorityBindings,
    invalidObligationIds,
    unauthorizedObligationIds
  };
}

function hasCrossMappingSemantics(obligation) {
  return Boolean(readString(obligation.mappingRationale)
    && isSubstantive(obligation.applicability)
    && isSubstantive(obligation.discriminatoryPower));
}

function normalizeVerificationObligations(value, claims) {
  const supplied = Array.isArray(value) ? value : [];
  const byClaim = new Map();
  for (const item of supplied) {
    if (!item || typeof item !== "object" || !readString(item.claimId)) continue;
    byClaim.set(item.claimId, cloneJson(item));
  }
  return claims.map((claim) => ({
    id: `verify-${claim.id}`,
    claimId: claim.id,
    required: true,
    ...(byClaim.get(claim.id) ?? {})
  }));
}

function replaceEvidence(evidence, next) {
  return [...evidence.filter((item) => item.id !== next.id && !sameEvidenceSource(item, next)), next];
}

function createEvidenceBinding(evidence) {
  return { id: evidence.id, digest: canonicalDigest(evidence) };
}

function sameEvidenceSource(left, right) {
  const leftProvenance = left.provenance ?? {};
  const rightProvenance = right.provenance ?? {};
  return leftProvenance.kind === rightProvenance.kind
    && leftProvenance.gateId === rightProvenance.gateId
    && leftProvenance.commandId === rightProvenance.commandId
    && leftProvenance.implementation === rightProvenance.implementation;
}

function upsertGateRun(runs, next) {
  return [...runs.filter((run) => run.gateId !== next.gateId), cloneJson(next)];
}

function readChangePatch(idOrInput, optionalPatch) {
  if (typeof idOrInput === "string") return { changeId: idOrInput, patch: optionalPatch ?? {} };
  if (!idOrInput || typeof idOrInput !== "object") {
    throw kernelError("CHANGE_ID_REQUIRED", "Change id is required.", 400);
  }
  const changeId = readChangeId(idOrInput);
  const { changeId: _changeId, id: _id, ...inlinePatch } = idOrInput;
  return { changeId, patch: { ...inlinePatch, ...(optionalPatch ?? {}) } };
}

function readGateRequest(idOrInput, optionalGateId) {
  if (typeof idOrInput === "string") {
    return { changeId: idOrInput, gateId: readString(optionalGateId) };
  }
  return {
    changeId: readChangeId(idOrInput),
    gateId: readString(idOrInput.gateId),
    all: idOrInput.all === true
  };
}

function readAcceptanceRequest(idOrInput, optionalDecision) {
  if (typeof idOrInput === "string") {
    const optionObject = optionalDecision && typeof optionalDecision === "object" && !Array.isArray(optionalDecision)
      ? optionalDecision
      : undefined;
    const nestedDecision = optionObject?.authorityDecision ?? optionObject?.decision;
    const directDecision = optionObject && hasAuthorityDecisionShape(optionObject)
      ? optionObject
      : undefined;
    return {
      changeId: idOrInput,
      authorityDecision: nestedDecision ?? directDecision ?? (optionObject ? undefined : optionalDecision),
      integrate: optionObject?.integrate === true || optionObject?.integrated === true
    };
  }
  return {
    changeId: readChangeId(idOrInput),
    authorityDecision: idOrInput.authorityDecision ?? idOrInput.decision,
    integrate: idOrInput.integrate === true || idOrInput.integrated === true
  };
}

function hasAuthorityDecisionShape(value) {
  return ["authority", "authorityId", "decidedBy", "actor", "decisionType", "status", "role"]
    .some((key) => value[key] !== undefined);
}

function readChangeId(value) {
  const id = typeof value === "string" ? value : readString(value?.changeId) ?? readString(value?.id);
  if (!id) throw kernelError("CHANGE_ID_REQUIRED", "Change id is required.", 400);
  return id;
}

function assertValidProject(inspection) {
  if (!inspection.validation.valid) {
    throw kernelError("PROJECT_MODEL_INVALID", "Project Model validation failed.", 422, inspection.validation);
  }
}

async function createUniqueChangeId(store, observedAt) {
  const stamp = observedAt.replace(/[-:.TZ]/gu, "").slice(0, 14);
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const id = `change-${stamp}-${randomUUID().slice(0, 8)}`;
    if (!await store.get(id)) return id;
  }
  throw kernelError("CHANGE_ID_EXHAUSTED", "Could not allocate a unique Change id.", 500);
}

function readClock(clock) {
  const value = typeof clock === "function"
    ? clock()
    : typeof clock?.now === "function" ? clock.now() : new Date();
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) {
    throw kernelError("CLOCK_INVALID", "clock must return a Date-compatible value.", 500);
  }
  return date.toISOString();
}

function normalizeStringList(value) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.filter(readString).map((item) => item.trim()))];
}

function adaptChangePlanRefsInput(input) {
  const presentFields = ["planRefs", "planRef"].filter((field) => Object.hasOwn(input, field));
  if (presentFields.length > 1) {
    throw kernelError(
      "CHANGE_PLAN_REF_INPUT_CONFLICT",
      "Change input cannot contain both planRefs and legacy planRef.",
      422,
      { presentFields }
    );
  }
  const present = presentFields.length === 1;
  return {
    present,
    planRefs: parseChangePlanRefs(present ? input[presentFields[0]] : undefined)
  };
}

function assertCompilePatchInput(patch) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) {
    throw kernelError("CHANGE_PATCH_INVALID", "compileChange patch must be an object.", 400);
  }
}

function normalizeReferenceList(value) {
  if (value === undefined || value === null) return [];
  const values = Array.isArray(value) ? value : [value];
  return [...new Set(values.map(readModelReference).filter(Boolean))];
}

function readModelReference(value) {
  if (readString(value)) return value.trim();
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  for (const key of ["id", "module", "moduleId", "contract", "contractId", "target"]) {
    if (readString(value[key])) return value[key].trim();
  }
  return undefined;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function isSubstantive(value) {
  if (typeof value === "string") return Boolean(value.trim());
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object" && Object.keys(value).length > 0);
}

function kernelError(code, message, statusCode = 400, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details !== undefined) error.details = details;
  return error;
}
