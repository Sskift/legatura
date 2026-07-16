import path from "node:path";
import { randomUUID } from "node:crypto";
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
  loadProjectModel,
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

  async function inspectProject() {
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
    return {
      valid: validation.valid,
      repoPath: resolvedRepoPath,
      ...publicProjectModel(model),
      git: cloneJson(git),
      validation
    };
  }

  async function listChanges() {
    const records = await store.list();
    const refreshed = [];
    for (const record of records) {
      refreshed.push(await refreshChange(record));
    }
    return refreshed.map(cloneJson);
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
    const change = await requireChange(readChangeId(idOrInput));
    const refreshed = await refreshChange(change);
    const inspection = await inspectProject();
    return cloneJson({ ...refreshed, readiness: readReadiness(refreshed, inspection) });
  }

  async function compileChange(idOrInput, optionalPatch = {}) {
    const { changeId, patch } = readChangePatch(idOrInput, optionalPatch);
    assertCompilePatchInput(patch);
    const planRefsInput = adaptChangePlanRefsInput(patch);
    let change = await requireChange(changeId);
    change = await refreshChange(change);
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
    change = await refreshChange(change);
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
    const model = await loadProjectModel(resolvedRepoPath);
    const validation = validateProjectModel(model);
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
    change = await refreshChange(change);
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

  async function refreshChange(change) {
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
    const selectedCommands = gate.commands.filter((command) => commandAppliesToChange(command, change));
    const skippedCommandIds = gate.commands
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
    listChanges: (...args) => serializeOperation(() => listChanges(...args)),
    createChange: (...args) => serializeOperation(() => createChange(...args)),
    getChange: (...args) => serializeOperation(() => getChange(...args)),
    compileChange: (...args) => serializeOperation(() => compileChange(...args)),
    runGate: (...args) => serializeOperation(() => runGate(...args)),
    acceptChange: (...args) => serializeOperation(() => acceptChange(...args))
  };
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
  const governanceBaseline = readGovernanceBaseline(change);
  const integrityFailureEvidence = validateIntegrityFailureEvidence(change, { requireDigest: true });
  const mappingAuthorization = readMappingAuthorization(change, governanceBaseline);
  const subjectDigest = verificationSubjectDigest(change);
  const coverage = validateEvidenceCoverage(change.claims, change.evidence, {
    approvedObligationIds: mappingAuthorization.approvedObligationIds,
    verificationSubjectDigest: subjectDigest,
    trustedEvidenceBindings: readTrustedEvidenceBindings(change, inspection, subjectDigest),
    verificationObligations: change.verificationObligations
  });
  const builtin = change.gateRuns.find((run) => run.gateId === "project-model");
  const defaultGateId = governanceBaseline.projectDocument?.changePolicy?.defaultGate;
  const requiredGateIds = defaultGateId
    ? [defaultGateId]
    : governanceBaseline.gates.filter((gate) => gate.required === true).map((gate) => gate.id);
  const missingOrStaleGateIds = ["project-model", ...requiredGateIds].filter((gateId) => {
    const run = change.gateRuns.find((entry) => entry.gateId === gateId);
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

function readTrustedEvidenceBindings(change, inspection, subjectDigest) {
  return change.gateRuns
    .filter((run) => run.projectModelDigest === inspection.digest
      && run.gitContentDigest === inspection.git.contentDigest
      && run.verificationSubjectDigest === subjectDigest)
    .flatMap((run) => Array.isArray(run.evidenceBindings) ? run.evidenceBindings : []);
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
  const approved = new Set(approvedObligationIds);
  const unauthorizedObligationIds = approvable
    .map((obligation) => obligation.id)
    .filter((id) => !approved.has(id));
  return {
    valid: invalidObligationIds.length === 0 && unauthorizedObligationIds.length === 0,
    requiredObligationIds: approvable.map((obligation) => obligation.id),
    approvedObligationIds,
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
