import path from "node:path";
import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual
} from "node:crypto";
import { types as utilTypes } from "node:util";
import {
  ARCHITECTURE_PROFILE_LIMITS,
  compileArchitectureProfile
} from "./architecture-profile.mjs";
import { canonicalDigest, cloneJson } from "./canonical.mjs";
import {
  assertIntegrityFailureEvidenceCurrent,
  compileChangePlanAuthoringProjection,
  compileChangeAgainstGovernance,
  parseChangePlanRefs,
  validateIntegrityFailureEvidence
} from "./change-compiler.mjs";
import { createChangeStore } from "./change-store.mjs";
import {
  isSuccessfulCommandObservation,
  normalizeGateCommand,
  observeCommand,
  readCommandUtf8Stream
} from "./command-runner.mjs";
import {
  KNOWLEDGE_CLOSURE_ENTRY_KINDS,
  KNOWLEDGE_CLOSURE_MODES,
  compileAuthorityDecisionOptions,
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
  OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION,
  compileOutcomePlanAmendment
} from "./outcome-evolution.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  compileClaimGateRouteIndex,
  compileModulePathOwnershipIndex,
  loadProjectModel,
  projectCompiledClaimGateRouteIndex,
  projectCompiledModuleClaimGateIndex,
  projectCompiledModulePathOwnershipIndex,
  publicProjectModel,
  validateProjectModel
} from "./project-model.mjs";
import {
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
const ARCHITECTURE_PROFILE_WINDOW_DEFAULT_LIMIT = 20;
const ARCHITECTURE_PROFILE_WINDOW_MAX_LIMIT = 32;
const ARCHITECTURE_PROFILE_WINDOW_OUTPUT_BYTE_LIMIT = 2 * 1024 * 1024;
const ARCHITECTURE_PROFILE_WINDOW_CURSOR_BYTE_LIMIT = 2 * 1024;
const ARCHITECTURE_PROFILE_WINDOW_CURSOR_TTL_MS = 5 * 60 * 1000;
const ARCHITECTURE_PROFILE_WINDOW_ORDERING = "change-id-v1";
const ARCHITECTURE_PROFILE_WINDOW_PURPOSE = "architecture-profile-window";

export const ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION = 1;
export const WORKBENCH_ACCEPTANCE_CONFIRMATION_PROOF_VERSION = 1;
export const WORKBENCH_PROJECTION_INTEGRITY_PROOF_VERSION = 1;

export const WORKBENCH_DISABLED_REASON_CODES = Object.freeze([
  "PLAN_OUTCOME_UNAVAILABLE",
  "MODULE_NOT_GOVERNED",
  "CLAIM_ACCEPTANCE_ROUTE_MISSING",
  "CLAIM_NOT_PROTECTED_BY_SELECTED_OUTCOME",
  "CHANGE_CLAIM_REQUIRED",
  "CHANGE_NOT_COMPILED",
  "CHANGE_SCOPE_EXCEEDED",
  "AUTHORITY_OPTION_UNAVAILABLE",
  "CHANGE_NOT_EVIDENCE_READY",
  "CHANGE_SEALED",
  "GATE_NOT_APPLICABLE",
  "GATE_COMMAND_NOT_APPLICABLE"
]);

export const WORKBENCH_INPUT_REQUIREMENT_REASON_CODES = Object.freeze([
  "CHANGE_NOT_COMPILED",
  "CHANGE_SCOPE_EXCEEDED",
  "AUTHORITY_OPTION_UNAVAILABLE"
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
  const profileWindowCursor = createArchitectureProfileWindowCursor({
    secret: randomBytes(32),
    now: () => Date.parse(now())
  });
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
      model,
      git,
      inspection
    };
  }

  function compilePathOwnershipSource(model, trackedPathFacts) {
    const product = compileModulePathOwnershipIndex(model, trackedPathFacts);
    const projection = projectCompiledModulePathOwnershipIndex(product, {
      model,
      moduleRefs: [],
      pathRefs: []
    });
    return {
      model,
      product,
      sourceBinding: projection.sourceBinding
    };
  }

  function hasPathOwnershipGovernance(model) {
    return Object.hasOwn(model?.projectDocument ?? {}, "pathGovernance");
  }

  async function inspectStableProjectSnapshot() {
    const stable = await readStableObservation({
      observe: observeProjectOnce,
      code: "PROJECT_SNAPSHOT_UNSTABLE",
      message: "Project Model and Git sources did not stabilize within the bounded observation window."
    });
    return compilePathOwnershipSnapshot(stable);
  }

  function compilePathOwnershipSnapshot(stable) {
    const validation = cloneJson(stable.inspection.validation);
    let pathOwnership = null;
    if (validation.valid && stable.git.available && hasPathOwnershipGovernance(stable.model)) {
      try {
        pathOwnership = compilePathOwnershipSource(
          stable.model,
          stable.git.trackedPathFacts
        );
      } catch (error) {
        validation.errors.push({
          code: "module.path-ownership.invalid",
          location: ".legatura/project.json#pathGovernance",
          message: error instanceof Error ? error.message : String(error),
          sourceCode: readString(error?.code) ?? null
        });
        validation.valid = false;
      }
    }
    const inspection = {
      ...stable.inspection,
      valid: validation.valid,
      validation
    };
    return {
      ...stable,
      validation,
      inspection,
      pathOwnership
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
      model: project.model,
      git: project.git,
      inspection: project.inspection,
      records: changeStore.records
    };
  }

  async function inspectChangeQuery({ includePathOwnership = false } = {}) {
    const stable = await readStableObservation({
      observe: observeChangeQueryOnce,
      code: "CHANGE_QUERY_SNAPSHOT_UNSTABLE",
      message: "Project Model, Git, and Change Store sources did not stabilize within the bounded observation window."
    });
    return includePathOwnership ? compilePathOwnershipSnapshot(stable) : stable;
  }

  async function listChanges() {
    const snapshot = await inspectChangeQuery();
    return snapshot.records.map((record) => summarizeChangeForRead(record, snapshot));
  }

  async function inspectArchitectureProfile() {
    const snapshot = await inspectChangeQuery();
    return compileArchitectureProfileFromSnapshot(snapshot);
  }

  async function inspectArchitectureProfileWindow(request) {
    const query = readArchitectureProfileWindowRequest(request, profileWindowCursor);
    const snapshot = await inspectChangeQuery();
    const selection = selectArchitectureProfileRecordWindow(snapshot, query);
    const page = compileArchitectureProfileFromSnapshot({
      ...snapshot,
      records: selection.records
    });
    const content = {
      schemaVersion: 1,
      proofVersion: ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION,
      kind: ARCHITECTURE_PROFILE_WINDOW_PURPOSE,
      source: page.source,
      window: selection.window,
      page
    };
    const result = {
      ...content,
      windowDigest: canonicalDigest(content),
      continuation: selection.window.hasMore
        ? profileWindowCursor.issue({
            source: page.source,
            offset: selection.nextOffset,
            limit: selection.window.limit,
            precedingRecordDigest: selection.precedingRecordDigest
          })
        : null
    };
    assertArchitectureProfileWindowOutputBound(result);
    return cloneJson(result);
  }

  async function inspectWorkbenchProjection(request) {
    const query = readWorkbenchProjectionRequest(request);
    const snapshot = await inspectChangeQuery();
    const records = query.changeRef == null
      ? []
      : selectWorkbenchChangeRecord(snapshot.records, query.changeRef);
    return compileWorkbenchProjectionFromSnapshot(
      { ...snapshot, records },
      { changeRef: query.changeRef }
    );
  }

  async function observeCurrentChangeScope(change, snapshot, frozenOwnership) {
    const touchedPaths = await readObservedTouchedPaths(
      change,
      snapshot.git,
      resolvedRepoPath,
      commandRunner
    );
    change.changeSet = compileObservedChangeSet(change, snapshot.git, touchedPaths);
    change.scopeAnalysis = analyzeChangeScope(change, touchedPaths, {
      currentOwnership: snapshot.pathOwnership,
      frozenOwnership
    });
    assertPlanChangeSeparation(change, touchedPaths);
    return touchedPaths;
  }

  function compileFrozenPathOwnership(change, { allowInitialize = false } = {}) {
    const governanceBaseline = readGovernanceBaseline(change);
    const storedBinding = change.baseline?.pathOwnership;
    if (!hasPathOwnershipGovernance(governanceBaseline)) {
      if (storedBinding) {
        throw kernelError(
          "CHANGE_PATH_OWNERSHIP_BASELINE_INVALID",
          "Legacy Candidate carries a path ownership binding without frozen path governance.",
          409
        );
      }
      return null;
    }
    const baselineGit = change.baseline?.git;
    if (!baselineGit || typeof baselineGit !== "object" || Array.isArray(baselineGit)) {
      throw kernelError(
        "CHANGE_PATH_OWNERSHIP_BASELINE_INVALID",
        "Candidate path ownership requires an exact frozen Git binding.",
        409
      );
    }
    const { contentDigest, ...gitBindingContent } = baselineGit;
    if (!DIGEST_PATTERN.test(contentDigest ?? "")
      || canonicalDigest(gitBindingContent) !== contentDigest) {
      throw kernelError(
        "CHANGE_PATH_OWNERSHIP_BASELINE_INVALID",
        "Candidate frozen Git content does not match its exact digest.",
        409
      );
    }
    let frozenOwnership;
    try {
      frozenOwnership = compilePathOwnershipSource(
        governanceBaseline,
        baselineGit.trackedPathFacts
      );
    } catch (error) {
      throw kernelError(
        "CHANGE_PATH_OWNERSHIP_BASELINE_INVALID",
        "Candidate frozen ownership sources cannot produce a valid ownership product.",
        409,
        { sourceCode: readString(error?.code) ?? null }
      );
    }
    if (!storedBinding) {
      const mayInitialize = allowInitialize
        && change.state === "Candidate"
        && !change.compilation
        && !change.acceptance;
      if (!mayInitialize) {
        throw kernelError(
          "CHANGE_PATH_OWNERSHIP_BASELINE_MISSING",
          "Candidate has no frozen path ownership binding.",
          409
        );
      }
      change.baseline.pathOwnership = cloneJson(frozenOwnership.sourceBinding);
    } else if (canonicalDigest(storedBinding)
      !== canonicalDigest(frozenOwnership.sourceBinding)) {
      throw kernelError(
        "CHANGE_PATH_OWNERSHIP_BASELINE_INVALID",
        "Candidate frozen path ownership binding does not match its Model and tracked-path facts.",
        409
      );
    }
    return frozenOwnership;
  }

  async function deriveCurrentOutcomePlanAmendment(change, currentModel) {
    const catalog = assertPriorAcceptedPackageCatalog(change.priorAcceptedPackages, {
      required: change.changeKind === "plan-amendment"
    });
    const resolvedPackages = catalog
      ? (await Promise.all(catalog.entries.map((entry) => store.get(entry.changeId)))).filter(Boolean)
      : [];
    return compileOutcomePlanAmendment({
      change,
      governanceBaseline: readGovernanceBaseline(change),
      currentModel,
      resolvedPackages,
      priorAcceptedPackages: catalog
    });
  }

  async function assertCurrentOutcomePlanAmendment(change, currentModel) {
    if (change.outcomePlanAmendmentSchemaVersion !== OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION
      || !change.outcomePlanAmendmentCompilation) {
      throw kernelError(
        "OUTCOME_PLAN_AMENDMENT_COMPILATION_STALE",
        "Compile the Outcome Plan Amendment projection before running Gates or accepting the Change.",
        409
      );
    }
    const expected = await deriveCurrentOutcomePlanAmendment(change, currentModel);
    if (canonicalDigest(expected) !== canonicalDigest(change.outcomePlanAmendmentCompilation)) {
      throw kernelError(
        "OUTCOME_PLAN_AMENDMENT_COMPILATION_STALE",
        "Outcome Plan Amendment proof no longer matches the frozen catalog, current Plan, or resolved Accepted Packages.",
        409,
        {
          expectedDigest: canonicalDigest(expected),
          observedDigest: canonicalDigest(change.outcomePlanAmendmentCompilation)
        }
      );
    }
    return expected;
  }

  async function assertCurrentGovernanceContracts(change, currentModel, { modelValid = true } = {}) {
    if (!modelValid) return null;
    if (change.changeKind === "plan-amendment") {
      return assertCurrentOutcomePlanAmendment(change, currentModel);
    }
    return assertKnowledgeGapProofContractsPreserved({
      governanceBaseline: readGovernanceBaseline(change),
      currentModel
    });
  }

  async function assertGovernanceWatermarkCurrent(change, snapshotRecords) {
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
    const records = (Array.isArray(snapshotRecords) ? snapshotRecords : await store.list())
      .filter((record) => record?.id !== change.id);
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
    const snapshot = await inspectStableProjectSnapshot();
    const inspection = snapshot.inspection;
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
      outcomePlanAmendmentSchemaVersion: OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION,
      priorAcceptedPackages,
      outcomePlanAmendmentCompilation: null,
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
        governanceDigest: governanceBaseline.digest,
        ...(snapshot.pathOwnership ? {
          pathOwnership: cloneJson(snapshot.pathOwnership.sourceBinding)
        } : {})
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
    const snapshot = await inspectStableProjectSnapshot();
    const inspection = snapshot.inspection;
    change = await refreshChangeForWrite(change, inspection);
    if (change.acceptance || change.state === "Accepted" || change.state === "Integrated") {
      throw kernelError(
        "CHANGE_SEALED",
        `Change ${change.id} has historical acceptance; an Accepted Package is immutable and follow-up work requires a new Change.`,
        409
      );
    }
    await assertGovernanceWatermarkCurrent(change);
    change = applyCompilePatch(change, patch, now(), planRefsInput);
    const frozenOwnership = compileFrozenPathOwnership(change, { allowInitialize: true });
    assertValidProject(inspection);
    change.projectModelDigest = inspection.digest;
    change.currentGit = inspection.git;
    if (change.claims.length === 0) {
      throw kernelError("CHANGE_CLAIM_REQUIRED", "A Change must declare at least one falsifiable Claim before submission.", 422);
    }
    if (change.changeKind !== "plan-amendment") {
      await assertCurrentGovernanceContracts(change, inspection);
    }
    change = frozenOwnership
      ? compileChangeAgainstGovernance(change, readGovernanceBaseline(change), {
          modulePathOwnershipProduct: frozenOwnership.product
        })
      : compileChangeAgainstGovernance(change, readGovernanceBaseline(change));
    await observeCurrentChangeScope(change, snapshot, frozenOwnership);
    delete change.outcomeTransitionSchemaVersion;
    delete change.outcomeTransitionCompilation;
    change.outcomePlanAmendmentSchemaVersion = OUTCOME_PLAN_AMENDMENT_SCHEMA_VERSION;
    change.outcomePlanAmendmentCompilation = await deriveCurrentOutcomePlanAmendment(change, inspection);
    if (patch.authorityDecision !== undefined) bindAuthorityDecision(change);
    transition(change, "Submitted", now(), "Change compiled with explicit Claims.");
    deriveEvidenceReady(change, inspection, now());
    change.updatedAt = now();
    return store.save(change);
  }

  async function runGate(idOrInput, optionalGateId) {
    const request = readGateRequest(idOrInput, optionalGateId);
    let change = await requireChange(request.changeId);
    const snapshot = await inspectStableProjectSnapshot();
    const inspection = snapshot.inspection;
    change = await refreshChangeForWrite(change, inspection);
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
    const observedAt = now();
    const model = inspection;
    const validation = inspection.validation;
    const governanceBaseline = readGovernanceBaseline(change);
    await assertCurrentGovernanceContracts(change, model, { modelValid: validation.valid });
    const selectedGates = selectGates(governanceBaseline, request, change);
    if (change.state === "Integrated") {
      throw kernelError("CHANGE_SEALED", `Change ${change.id} is Integrated and cannot run more Gates.`, 409);
    }
    assertIntegrityFailureEvidenceCurrent(change);
    let frozenOwnership = null;
    if (validation.valid) {
      frozenOwnership = compileFrozenPathOwnership(change);
      await observeCurrentChangeScope(change, snapshot, frozenOwnership);
    }
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
    const snapshot = await inspectChangeQuery({ includePathOwnership: true });
    const inspection = snapshot.inspection;
    let change = requireSnapshotChange(snapshot, request.changeId);
    change = await refreshChangeForWrite(change, inspection);
    await assertGovernanceWatermarkCurrent(change, snapshot.records);
    assertValidProject(inspection);
    const frozenOwnership = compileFrozenPathOwnership(change);
    if (change.changeKind !== "plan-amendment" || change.compilation) {
      await assertCurrentGovernanceContracts(change, inspection);
    }
    if (change.compilation) {
      await observeCurrentChangeScope(change, snapshot, frozenOwnership);
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

    if (request.inputRequirementsConfirmation !== undefined) {
      assertAcceptanceInputRequirementsConfirmation(
        request.inputRequirementsConfirmation,
        compileWorkbenchAcceptanceInputRequirements(change, snapshot, { observed: 0 })
      );
    }

    if (request.knowledgeClosure !== undefined) {
      change.knowledgeClosure = cloneJson(request.knowledgeClosure);
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
    assertCompiledChangeCurrent(change, frozenOwnership?.product);
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

  async function refreshChangeForWrite(change, inspection) {
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

  function requireSnapshotChange(snapshot, id) {
    const change = snapshot.records.find((record) => readString(record?.id) === id);
    if (!change) {
      throw kernelError("CHANGE_NOT_FOUND", `Change not found: ${id}.`, 404, { changeId: id });
    }
    return cloneJson(change);
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
      const result = await observeGateCommand({
        ...specification,
        cwd: resolvedRepoPath,
        purpose: "gate",
        gateId: gate.id,
        commandId: command.id
      }, command.timeoutMs);
      const successful = isSuccessfulCommandObservation(result);
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
        status: successful ? "passed" : "failed",
        exitCode: result.termination.kind === "exited"
          ? result.termination.exitCode : null,
        supportStatus: result.support.status,
        controlKind: result.control.kind,
        terminationKind: result.termination.kind,
        observationDigest: canonicalDigest(result),
        evidenceId: item.id,
        ...(result.termination.kind === "signaled"
          ? { signal: result.termination.signal } : {})
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

  async function observeGateCommand(specification, timeoutMs) {
    const timeout = Number.isSafeInteger(timeoutMs) && timeoutMs > 0
      ? timeoutMs : 300_000;
    return observeCommand(commandRunner, { ...specification, timeoutMs: timeout });
  }

  return {
    inspectProject,
    inspectWorkbenchProjection: (...args) => (
      serializeOperation(() => inspectWorkbenchProjection(...args))
    ),
    inspectArchitectureProfile: (...args) => (
      serializeOperation(() => inspectArchitectureProfile(...args))
    ),
    inspectArchitectureProfileWindow: (...args) => (
      serializeOperation(() => inspectArchitectureProfileWindow(...args))
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

function createArchitectureProfileWindowCursor({ secret, now }) {
  return {
    issue({ source, offset, limit, precedingRecordDigest }) {
      const issuedAt = now();
      const expiresAt = issuedAt + ARCHITECTURE_PROFILE_WINDOW_CURSOR_TTL_MS;
      const payload = {
        schemaVersion: 1,
        proofVersion: ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION,
        purpose: ARCHITECTURE_PROFILE_WINDOW_PURPOSE,
        ordering: ARCHITECTURE_PROFILE_WINDOW_ORDERING,
        source: cloneJson(source),
        offset,
        limit,
        precedingRecordDigest,
        issuedAt,
        expiresAt
      };
      const payloadBytes = Buffer.from(JSON.stringify(payload), "utf8");
      const payloadSegment = payloadBytes.toString("base64url");
      const signatureSegment = signArchitectureProfileCursor(secret, payloadBytes)
        .toString("base64url");
      const cursor = `${payloadSegment}.${signatureSegment}`;
      if (Buffer.byteLength(cursor, "utf8") > ARCHITECTURE_PROFILE_WINDOW_CURSOR_BYTE_LIMIT) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_WINDOW_LIMIT_EXCEEDED",
          "Architecture Profile continuation exceeded its fixed byte limit.",
          413,
          {
            dimension: "cursorBytes",
            limit: ARCHITECTURE_PROFILE_WINDOW_CURSOR_BYTE_LIMIT,
            observed: Buffer.byteLength(cursor, "utf8")
          }
        );
      }
      return { cursor, expiresAt: new Date(expiresAt).toISOString() };
    },

    read(cursor) {
      if (typeof cursor !== "string"
        || cursor.length === 0
        || Buffer.byteLength(cursor, "utf8") > ARCHITECTURE_PROFILE_WINDOW_CURSOR_BYTE_LIMIT
        || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u.test(cursor)) {
        throwArchitectureProfileCursorInvalid("format");
      }
      const [payloadSegment, signatureSegment] = cursor.split(".");
      let payloadBytes;
      let suppliedSignature;
      try {
        payloadBytes = Buffer.from(payloadSegment, "base64url");
        suppliedSignature = Buffer.from(signatureSegment, "base64url");
      } catch {
        throwArchitectureProfileCursorInvalid("encoding");
      }
      if (payloadBytes.toString("base64url") !== payloadSegment
        || suppliedSignature.toString("base64url") !== signatureSegment
        || suppliedSignature.byteLength !== 32) {
        throwArchitectureProfileCursorInvalid("encoding");
      }
      const expectedSignature = signArchitectureProfileCursor(secret, payloadBytes);
      if (!timingSafeEqual(suppliedSignature, expectedSignature)) {
        throwArchitectureProfileCursorInvalid("signature");
      }
      let payload;
      try {
        payload = JSON.parse(payloadBytes.toString("utf8"));
      } catch {
        throwArchitectureProfileCursorInvalid("payload");
      }
      assertArchitectureProfileCursorPayload(payload);
      const observedNow = now();
      if (observedNow < payload.issuedAt) {
        throwArchitectureProfileCursorInvalid("issued-in-future");
      }
      if (observedNow >= payload.expiresAt) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_CURSOR_EXPIRED",
          "Architecture Profile continuation has expired.",
          410
        );
      }
      return payload;
    }
  };
}

function signArchitectureProfileCursor(secret, payloadBytes) {
  return createHmac("sha256", secret).update(payloadBytes).digest();
}

function readArchitectureProfileWindowRequest(request, cursorCodec) {
  if (request === undefined) {
    return { offset: 0, limit: ARCHITECTURE_PROFILE_WINDOW_DEFAULT_LIMIT, cursor: null };
  }
  const fields = readStrictQueryObject(
    request,
    ["limit", "cursor"],
    "ARCHITECTURE_PROFILE_WINDOW_INPUT_INVALID",
    "Architecture Profile window request"
  );
  if (Object.hasOwn(fields, "cursor")) {
    if (Object.keys(fields).length !== 1) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_WINDOW_INPUT_INVALID",
        "Architecture Profile continuation cannot be combined with a limit.",
        400
      );
    }
    const cursor = cursorCodec.read(fields.cursor);
    return { offset: cursor.offset, limit: cursor.limit, cursor };
  }
  const limit = Object.hasOwn(fields, "limit")
    ? fields.limit
    : ARCHITECTURE_PROFILE_WINDOW_DEFAULT_LIMIT;
  if (!Number.isSafeInteger(limit)
    || limit < 1
    || limit > ARCHITECTURE_PROFILE_WINDOW_MAX_LIMIT) {
    throw kernelError(
      "ARCHITECTURE_PROFILE_WINDOW_INPUT_INVALID",
      "Architecture Profile window limit must be a positive safe integer within the fixed maximum.",
      400,
      { limit: ARCHITECTURE_PROFILE_WINDOW_MAX_LIMIT }
    );
  }
  return { offset: 0, limit, cursor: null };
}

function readWorkbenchProjectionRequest(request) {
  if (request === undefined) return { changeRef: null };
  const fields = readStrictQueryObject(
    request,
    ["changeRef"],
    "WORKBENCH_PROJECTION_INPUT_INVALID",
    "Workbench projection request"
  );
  if (!Object.hasOwn(fields, "changeRef")) return { changeRef: null };
  const changeRef = readString(fields.changeRef);
  if (!changeRef || Buffer.byteLength(changeRef, "utf8") > 128) {
    throw kernelError(
      "WORKBENCH_PROJECTION_INPUT_INVALID",
      "Workbench projection changeRef must be a bounded non-empty Change id.",
      400
    );
  }
  return { changeRef };
}

function readStrictQueryObject(value, allowedFields, code, label) {
  if (!value
    || typeof value !== "object"
    || Array.isArray(value)
    || utilTypes.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    throw kernelError(code, `${label} must be a strict plain object.`, 400);
  }
  const allowed = new Set(allowedFields);
  const result = {};
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !allowed.has(key)) {
      throw kernelError(code, `${label} contains unsupported fields.`, 400);
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true) {
      throw kernelError(code, `${label} requires enumerable data properties.`, 400);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function assertArchitectureProfileCursorPayload(payload) {
  let fields;
  try {
    fields = readStrictQueryObject(
      payload,
      [
        "schemaVersion",
        "proofVersion",
        "purpose",
        "ordering",
        "source",
        "offset",
        "limit",
        "precedingRecordDigest",
        "issuedAt",
        "expiresAt"
      ],
      "ARCHITECTURE_PROFILE_CURSOR_INVALID",
      "Architecture Profile continuation payload"
    );
  } catch (error) {
    if (error?.code === "ARCHITECTURE_PROFILE_CURSOR_INVALID") throw error;
    throwArchitectureProfileCursorInvalid("payload");
  }
  if (Object.keys(fields).length !== 10
    || fields.schemaVersion !== 1
    || fields.proofVersion !== ARCHITECTURE_PROFILE_WINDOW_PROOF_VERSION
    || fields.purpose !== ARCHITECTURE_PROFILE_WINDOW_PURPOSE
    || fields.ordering !== ARCHITECTURE_PROFILE_WINDOW_ORDERING
    || !Number.isSafeInteger(fields.offset)
    || fields.offset < 1
    || !Number.isSafeInteger(fields.limit)
    || fields.limit < 1
    || fields.limit > ARCHITECTURE_PROFILE_WINDOW_MAX_LIMIT
    || !DIGEST_PATTERN.test(fields.precedingRecordDigest ?? "")
    || !Number.isSafeInteger(fields.issuedAt)
    || !Number.isSafeInteger(fields.expiresAt)
    || fields.expiresAt <= fields.issuedAt) {
    throwArchitectureProfileCursorInvalid("payload");
  }
  const source = fields.source;
  if (!source || typeof source !== "object" || Array.isArray(source)
    || Object.keys(source).sort().join(",") !== [
      "changeStoreDigest",
      "gitContentDigest",
      "projectModelDigest",
      "snapshotDigest"
    ].sort().join(",")
    || Object.values(source).some((digest) => !DIGEST_PATTERN.test(digest ?? ""))) {
    throwArchitectureProfileCursorInvalid("source");
  }
}

function throwArchitectureProfileCursorInvalid(reason) {
  throw kernelError(
    "ARCHITECTURE_PROFILE_CURSOR_INVALID",
    "Architecture Profile continuation is invalid.",
    400,
    { reason }
  );
}

function selectArchitectureProfileRecordWindow(snapshot, query) {
  const source = architectureProfileSnapshotSource(snapshot);
  if (query.cursor) {
    for (const field of Object.keys(source)) {
      if (query.cursor.source[field] !== source[field]) {
        throw kernelError(
          "ARCHITECTURE_PROFILE_CURSOR_SNAPSHOT_MISMATCH",
          "Architecture Profile continuation belongs to a different composite source snapshot.",
          409,
          { field }
        );
      }
    }
  }
  const records = [...snapshot.records].sort((left, right) => compareCodeUnits(
    requireArchitectureProfileString(left?.id, "change.id"),
    requireArchitectureProfileString(right?.id, "change.id")
  ));
  for (let index = 1; index < records.length; index += 1) {
    if (readString(records[index - 1]?.id) === readString(records[index]?.id)) {
      throw kernelError(
        "ARCHITECTURE_PROFILE_FACT_INVALID",
        "Architecture Profile Change identities must be unique before window selection.",
        422,
        { changeRef: readString(records[index]?.id) ?? null }
      );
    }
  }
  if (query.offset > records.length) throwArchitectureProfileCursorInvalid("offset");
  if (query.cursor) {
    const preceding = records[query.offset - 1];
    const precedingDigest = preceding
      ? canonicalDigest({ id: requireArchitectureProfileString(preceding.id, "change.id") })
      : null;
    if (precedingDigest !== query.cursor.precedingRecordDigest) {
      throwArchitectureProfileCursorInvalid("position");
    }
  }
  const selected = records.slice(query.offset, query.offset + query.limit);
  const recordRefs = selected.map((record) => ({
    id: requireArchitectureProfileString(record.id, "change.id")
  }));
  const nextOffset = query.offset + selected.length;
  const hasMore = nextOffset < records.length;
  return {
    records: selected,
    nextOffset,
    precedingRecordDigest: recordRefs.length > 0
      ? canonicalDigest(recordRefs.at(-1))
      : query.cursor?.precedingRecordDigest ?? null,
    window: {
      ordering: ARCHITECTURE_PROFILE_WINDOW_ORDERING,
      offset: query.offset,
      limit: query.limit,
      returned: selected.length,
      hasMore,
      recordRefs
    }
  };
}

function architectureProfileSnapshotSource(snapshot) {
  return {
    snapshotDigest: requireArchitectureProfileDigest(snapshot.digest, "snapshot.digest"),
    projectModelDigest: requireArchitectureProfileDigest(
      snapshot.inspection?.digest,
      "snapshot.projectModelDigest"
    ),
    gitContentDigest: requireArchitectureProfileDigest(
      snapshot.inspection?.git?.contentDigest,
      "snapshot.gitContentDigest"
    ),
    changeStoreDigest: requireArchitectureProfileDigest(
      snapshot.changeStoreDigest,
      "snapshot.changeStoreDigest"
    )
  };
}

function assertArchitectureProfileWindowOutputBound(value) {
  const observed = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (observed <= ARCHITECTURE_PROFILE_WINDOW_OUTPUT_BYTE_LIMIT) return;
  throw kernelError(
    "ARCHITECTURE_PROFILE_WINDOW_LIMIT_EXCEEDED",
    "Architecture Profile window exceeded its fixed output byte limit.",
    413,
    {
      dimension: "outputBytes",
      limit: ARCHITECTURE_PROFILE_WINDOW_OUTPUT_BYTE_LIMIT,
      observed
    }
  );
}

function selectWorkbenchChangeRecord(records, changeRef) {
  const selected = records.filter((record) => readString(record?.id) === changeRef);
  if (selected.length === 0) {
    throw kernelError("CHANGE_NOT_FOUND", `Change ${changeRef} was not found.`, 404);
  }
  if (selected.length !== 1) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench Change selection resolved to an ambiguous identity.",
      422,
      { changeRef }
    );
  }
  return selected;
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

function compileWorkbenchProjectionFromSnapshot(snapshot, { changeRef = null } = {}) {
  assertArchitectureProfileListBound(
    snapshot.records,
    ARCHITECTURE_PROFILE_LIMITS.changes,
    "changeStore.records"
  );
  assertValidProject(snapshot.inspection);
  const budget = { observed: 0 };
  const routeQuery = createArchitectureProfileRouteQueryBudget();
  const current = prepareCurrentModelRouteProduct(
    snapshot,
    routeQuery,
    { includeClaimDescriptors: false }
  );
  const currentModuleProjection = compileWorkbenchModuleClaimGateProjection({
    provider: current.currentRouteProvider,
    model: current.model,
    moduleRefs: (Array.isArray(current.model.modules) ? current.model.modules : [])
      .map((module) => readString(module?.id))
      .filter(Boolean),
    routeSelections: [],
    routeQuery,
    location: "currentModel.moduleClaimGateProjection"
  });
  const historicalRequirements = new Map();
  collectWorkbenchHistoricalRouteRequirements(snapshot.records, historicalRequirements, budget);
  const historicalProviders = compileArchitectureProfileHistoricalProviders(
    historicalRequirements,
    routeQuery,
    { includeClaimDescriptors: false }
  );
  const historicalModuleProjections = compileWorkbenchHistoricalModuleProjections(
    historicalRequirements,
    historicalProviders,
    routeQuery
  );
  const bundle = {
    ...current,
    currentModuleProjection,
    historicalProviders,
    historicalModuleProjections
  };
  const modules = compileWorkbenchAuthoringModules(bundle, budget);
  const planAuthoring = compileWorkbenchPlanAuthoring(snapshot, budget);
  const content = {
    schemaVersion: 3,
    source: {
      snapshotDigest: snapshot.digest,
      projectModelDigest: snapshot.inspection.digest,
      gitContentDigest: snapshot.inspection.git.contentDigest,
      changeStoreDigest: snapshot.changeStoreDigest
    },
    selection: { changeRef },
    authoring: {
      schemaVersion: 2,
      modules,
      planOutcomes: planAuthoring.planOutcomes,
      changeKinds: compileWorkbenchPublicChangeKinds(planAuthoring.changeKinds),
      claimSelectionRoutes: compileWorkbenchClaimSelectionRoutes({
        modules,
        changeKinds: planAuthoring.changeKinds,
        budget
      })
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

function prepareCurrentModelRouteProduct(
  snapshot,
  routeQuery,
  { includeClaimDescriptors = true } = {}
) {
  const model = publicProjectModel(snapshot.inspection);
  const { modelClaimRefs } = compileArchitectureProfileModelMembership(model);
  requireArchitectureProfileDigest(model.digest, "model.digest");
  const currentRouteProvider = compileArchitectureProfileRouteProvider({
    model,
    claimRefs: modelClaimRefs,
    budget: routeQuery,
    location: "model.claimGateRoutes"
  });
  const currentClaimDescriptors = includeClaimDescriptors
    ? compileArchitectureProfileClaimDescriptorIndex(
        model,
        routeQuery,
        "model.claimDescriptors"
      )
    : null;
  return { model, modelClaimRefs, currentRouteProvider, currentClaimDescriptors };
}

function compileWorkbenchAuthoringModules(bundle, budget) {
  const {
    model,
    currentRouteProvider,
    currentModuleProjection
  } = bundle;
  const modules = [];
  for (const module of [...(Array.isArray(model.modules) ? model.modules : [])]
    .sort((left, right) => (readString(left?.id) ?? "").localeCompare(readString(right?.id) ?? ""))) {
    consumeWorkbenchProjectionFact(budget);
    const moduleRef = requireWorkbenchReference(module?.id, "authoring.module.id");
    const projectedClaims = currentModuleProjection.claimsByModule.get(moduleRef);
    if (!Array.isArray(projectedClaims)) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench authoring Module is missing its Project Model Claim projection.",
        500,
        { moduleRef }
      );
    }
    const claimOptions = projectedClaims.map((descriptor) => {
      consumeWorkbenchProjectionFact(budget);
      const claimRef = requireWorkbenchReference(
        descriptor?.claimRef,
        `authoring.module.${moduleRef}.claim.id`
      );
      const contractRef = requireWorkbenchReference(
        descriptor?.contractRef,
        `authoring.module.${moduleRef}.claim.${claimRef}.contractRef`
      );
      const visibilityKinds = normalizeStringList(descriptor?.visibilityKinds);
      const routeOptions = compileWorkbenchAcceptanceRouteOptions({
        claimRef,
        moduleRef,
        moduleProjection: currentModuleProjection,
        routeProvider: currentRouteProvider,
        budget
      });
      const disabledReasonCodes = compileWorkbenchDisabledReasons([
        ...(module?.status === "governed" ? [] : ["MODULE_NOT_GOVERNED"]),
        ...(routeOptions.length > 0 ? [] : ["CLAIM_ACCEPTANCE_ROUTE_MISSING"])
      ]);
      return {
        id: claimRef,
        statement: requireWorkbenchReference(
          descriptor?.statement,
          `authoring.module.${moduleRef}.claim.${claimRef}.statement`
        ),
        contractRef,
        visibilityKinds,
        acceptanceRoutes: routeOptions,
        selectionBaseline: disabledReasonCodes
      };
    }).sort((left, right) => compareCodeUnits(left.id, right.id));
    const disabledReasonCodes = compileWorkbenchDisabledReasons(
      module?.status === "governed" ? [] : ["MODULE_NOT_GOVERNED"]
    );
    modules.push({
      id: moduleRef,
      name: readString(module?.name) ?? moduleRef,
      governanceStatus: readString(module?.status) ?? "unknown",
      selectable: disabledReasonCodes.length === 0,
      disabledReasonCodes,
      claims: claimOptions
    });
  }
  return modules;
}

function compileWorkbenchPublicChangeKinds(changeKinds) {
  return changeKinds.map((changeKind) => ({
    id: changeKind.id,
    selectable: changeKind.selectable,
    disabledReasonCodes: cloneJson(changeKind.disabledReasonCodes),
    planSelection: cloneJson(changeKind.planSelection),
    integrityIncident: { required: changeKind.integrityIncident.required }
  }));
}

function compileWorkbenchClaimSelectionRoutes({ modules, changeKinds, budget }) {
  const routes = [];
  for (const changeKind of changeKinds) {
    const changeKindRef = requireWorkbenchReference(
      changeKind?.id,
      "authoring.claimSelectionRoutes.changeKindRef"
    );
    const integrityRequired = changeKind?.integrityIncident?.required === true;
    const protections = integrityRequired
      ? readWorkbenchIntegrityProtectionEntries(changeKind)
      : [{ outcomeRef: null, claimRefs: null }];
    for (const protection of protections) {
      for (const module of modules) {
        consumeWorkbenchProjectionFact(budget);
        const moduleRef = requireWorkbenchReference(
          module?.id,
          "authoring.claimSelectionRoutes.moduleRef"
        );
        const protectedClaimRefs = protection.claimRefs == null
          ? null
          : new Set(protection.claimRefs);
        const claimOptions = module.claims.map((claim) => {
          consumeWorkbenchProjectionFact(budget);
          const claimRef = requireWorkbenchReference(
            claim?.id,
            `authoring.claimSelectionRoutes.${changeKindRef}.${moduleRef}.claimRef`
          );
          const disabledReasonCodes = compileWorkbenchDisabledReasons([
            ...changeKind.disabledReasonCodes,
            ...claim.selectionBaseline,
            ...(protectedClaimRefs == null || protectedClaimRefs.has(claimRef)
              ? []
              : ["CLAIM_NOT_PROTECTED_BY_SELECTED_OUTCOME"])
          ]);
          return {
            claimRef,
            selectable: disabledReasonCodes.length === 0,
            disabledReasonCodes
          };
        });
        assertWorkbenchClaimSelectionCoverage(module, claimOptions, {
          changeKindRef,
          outcomeRef: protection.outcomeRef,
          moduleRef
        });
        routes.push({
          changeKindRef,
          outcomeRef: protection.outcomeRef,
          moduleRef,
          claimOptions
        });
      }
    }
  }
  for (const module of modules) {
    for (const claim of module.claims) delete claim.selectionBaseline;
  }
  return routes.sort(compareWorkbenchClaimSelectionRoutes);
}

function readWorkbenchIntegrityProtectionEntries(changeKind) {
  const entries = changeKind?.integrityIncident?.protectedClaimRefsByOutcome;
  if (!Array.isArray(entries)) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench integrity authoring policy is missing compiler-owned protected Claim entries.",
      500,
      { changeKindRef: changeKind?.id }
    );
  }
  const protections = entries.map((entry) => ({
    outcomeRef: requireWorkbenchReference(
      entry?.outcomeRef,
      `authoring.changeKind.${changeKind.id}.integrityIncident.outcomeRef`
    ),
    claimRefs: normalizeStringList(entry?.claimRefs).sort(compareCodeUnits)
  })).sort((left, right) => compareCodeUnits(left.outcomeRef, right.outcomeRef));
  const expectedOutcomeRefs = normalizeStringList(
    changeKind?.planSelection?.selectableOutcomeRefs
  ).sort(compareCodeUnits);
  const observedOutcomeRefs = protections.map((entry) => entry.outcomeRef);
  if (expectedOutcomeRefs.length !== observedOutcomeRefs.length
    || new Set(observedOutcomeRefs).size !== observedOutcomeRefs.length
    || expectedOutcomeRefs.some((outcomeRef, index) => outcomeRef !== observedOutcomeRefs[index])) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench integrity protection entries must match compiler-owned selectable Outcomes exactly.",
      500,
      { changeKindRef: changeKind.id, expectedOutcomeRefs, observedOutcomeRefs }
    );
  }
  return protections;
}

function assertWorkbenchClaimSelectionCoverage(module, claimOptions, key) {
  const expected = module.claims.map((claim) => claim.id).sort(compareCodeUnits);
  const observed = claimOptions.map((claim) => claim.claimRef).sort(compareCodeUnits);
  if (expected.length !== observed.length
    || new Set(observed).size !== observed.length
    || expected.some((claimRef, index) => claimRef !== observed[index])) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench Claim selection route must cover each visible Module Claim exactly once.",
      500,
      { ...key, expectedClaimRefs: expected, observedClaimRefs: observed }
    );
  }
}

function compareWorkbenchClaimSelectionRoutes(left, right) {
  return compareCodeUnits(left.changeKindRef, right.changeKindRef)
    || compareCodeUnits(left.outcomeRef ?? "", right.outcomeRef ?? "")
    || compareCodeUnits(left.moduleRef, right.moduleRef);
}

function compileWorkbenchPlanAuthoring(snapshot, budget) {
  const projection = compileChangePlanAuthoringProjection(snapshot.inspection);
  consumeWorkbenchProjectionFact(
    budget,
    projection.planOutcomes.length + projection.changeKinds.reduce((count, changeKind) => (
      count
        + 1
        + changeKind.planSelection.selectableOutcomeRefs.length
        + changeKind.integrityIncident.protectedClaimRefsByOutcome.reduce((sum, entry) => (
          sum + 1 + entry.claimRefs.length
        ), 0)
    ), 0)
  );
  return cloneJson(projection);
}

function compileWorkbenchAcceptanceRouteOptions({
  claimRef,
  moduleRef,
  moduleProjection,
  routeProvider,
  budget
}) {
  return readWorkbenchProjectedAcceptanceRoutes({
    claimRef,
    moduleRef,
    moduleProjection,
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

function readWorkbenchProjectedAcceptanceRoutes({
  claimRef,
  moduleRef,
  moduleProjection,
  routeProvider,
  budget
}) {
  const routesByClaim = moduleProjection?.routesByModule?.get(moduleRef);
  if (!(routesByClaim instanceof Map) || !routesByClaim.has(claimRef)) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench Claim route pair is missing from its Project Model Module projection.",
      500,
      { claimRef, moduleRef }
    );
  }
  const routes = routesByClaim.get(claimRef);
  if (!Array.isArray(routes)) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench Project Model Module projection returned invalid routes.",
      500,
      { claimRef, moduleRef }
    );
  }
  const selected = [];
  for (const route of routes) {
    consumeWorkbenchProjectionFact(budget);
    const gateId = readString(route?.gateId);
    const commandId = readString(route?.commandId);
    const providerRouteDigest = routeProvider?.routeDigests?.get(
      architectureProfileRouteKey(claimRef, gateId, commandId)
    );
    const routeDigest = canonicalDigest(route);
    if (!gateId || !commandId
      || !isCanonicalDigest(providerRouteDigest)
      || providerRouteDigest !== routeDigest) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench Project Model route is not bound to its compiler-owned product.",
        422,
        { claimRef, moduleRef, gateId, commandId }
      );
    }
    selected.push({ gateId, commandId, routeDigest });
  }
  return selected;
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
  const historicalModuleProjection = bundle.historicalModuleProjections.get(baselineDigest);
  const seal = inspectHistoricalSeal(record);
  assertWorkbenchVerificationPlanValid({
    record,
    governanceBaseline,
    provider: historicalProvider,
    moduleProjection: historicalModuleProjection,
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
  const acceptanceInputRequirements = compileWorkbenchAcceptanceInputRequirements(
    record,
    snapshot,
    budget
  );
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
      accept: {
        ...workbenchAction("accept", acceptReasons),
        inputRequirements: acceptanceInputRequirements
      }
    }
  };
}

function compileWorkbenchAcceptanceInputRequirements(record, snapshot, budget) {
  const governanceBaseline = readGovernanceBaseline(record);
  const scope = record?.scopeAnalysis;
  const modelAmendmentRefs = normalizeStringList(scope?.modelAmendmentPaths).sort(compareCodeUnits);
  const requiredAdoptedChangePaths = normalizeStringList(scope?.preExistingPaths).sort(compareCodeUnits);
  const outOfScopePaths = normalizeStringList(scope?.outOfScopePaths).sort(compareCodeUnits);
  const knowledgeGapFileChanged = modelAmendmentRefs.includes(".legatura/knowledge-gaps.json");
  const selectableKnowledgeGapRefs = knowledgeGapFileChanged
    ? normalizeStringList(snapshot.inspection?.knowledgeGaps?.map((gap) => readString(gap?.id)))
      .sort(compareCodeUnits)
    : [];
  const expectedAuthorities = readExpectedAuthorities(governanceBaseline, record);
  const allDecisionOptions = compileAuthorityDecisionOptions(
    expectedAuthorities,
    governanceBaseline.projectDocument?.authorities?.decision ?? []
  );
  const decisionOptions = allDecisionOptions.filter((option) => (
    modelAmendmentRefs.length === 0 || option.decisionType === "normative-amendment"
  ));
  const requiredApprovedObligationIds = readRequiredCrossMappingObligationIds(record);
  const disabledReasonCodes = [
    ...(!scope ? ["CHANGE_NOT_COMPILED"] : []),
    ...(outOfScopePaths.length > 0 ? ["CHANGE_SCOPE_EXCEEDED"] : []),
    ...(decisionOptions.length === 0 ? ["AUTHORITY_OPTION_UNAVAILABLE"] : [])
  ];
  for (const reason of disabledReasonCodes) {
    if (!WORKBENCH_INPUT_REQUIREMENT_REASON_CODES.includes(reason)) {
      throw kernelError(
        "WORKBENCH_INPUT_REQUIREMENT_INVALID",
        `Unknown Workbench input-requirement reason code: ${reason}.`,
        500
      );
    }
  }
  consumeWorkbenchProjectionFact(
    budget,
    8
      + modelAmendmentRefs.length
      + requiredAdoptedChangePaths.length
      + outOfScopePaths.length
      + selectableKnowledgeGapRefs.length
      + requiredApprovedObligationIds.length
      + decisionOptions.reduce((count, option) => count + 1 + option.requiredFields.length, 0)
  );
  const content = {
    schemaVersion: 1,
    binding: {
      changeRef: requireWorkbenchReference(record?.id, "acceptanceRequirements.changeRef"),
      sourceSnapshotDigest: requireArchitectureProfileDigest(
        snapshot.digest,
        "acceptanceRequirements.sourceSnapshotDigest"
      ),
      governanceBaselineDigest: requireArchitectureProfileDigest(
        governanceBaseline.digest,
        "acceptanceRequirements.governanceBaselineDigest"
      ),
      verificationSubjectDigest: record?.compilation ? verificationSubjectDigest(record) : null
    },
    available: disabledReasonCodes.length === 0,
    disabledReasonCodes,
    knowledgeClosure: {
      required: true,
      allowedModes: modelAmendmentRefs.length > 0
        ? ["entries"]
        : [...KNOWLEDGE_CLOSURE_MODES],
      entryKinds: [...KNOWLEDGE_CLOSURE_ENTRY_KINDS],
      requiredModelAmendmentRefs: modelAmendmentRefs,
      selectableKnowledgeGapRefs,
      requiredEntryFields: ["rationale"],
      referenceOrStatementRequired: true
    },
    authorityDecision: {
      required: true,
      decisionOptions,
      requiredAmendmentRefs: modelAmendmentRefs,
      requiredAdoptedChangePaths,
      requiredApprovedObligationIds,
      outOfScopePaths
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

function assertAcceptanceInputRequirementsConfirmation(confirmation, currentRequirements) {
  const bindingFields = [
    "changeRef",
    "sourceSnapshotDigest",
    "governanceBaselineDigest",
    "verificationSubjectDigest"
  ];
  if (currentRequirements?.confirmation?.required !== true
    || canonicalDigest(currentRequirements.confirmation.bindingFields) !== canonicalDigest(bindingFields)) {
    throw kernelError(
      "WORKBENCH_INPUT_REQUIREMENT_INVALID",
      "Kernel acceptance confirmation fields do not match the declared Workbench requirements.",
      500
    );
  }

  const observed = readExactConfirmationObject(
    confirmation,
    ["requirementsDigest", "binding"]
  );
  const observedBinding = observed && readExactConfirmationObject(observed.binding, bindingFields);
  if (!observed || !observedBinding) {
    throwAcceptanceInputRequirementsStale(["inputRequirementsConfirmation"]);
  }

  const mismatchedFields = [
    ...(observed.requirementsDigest === currentRequirements.requirementsDigest
      ? []
      : ["requirementsDigest"]),
    ...bindingFields.filter((field) => observedBinding[field] !== currentRequirements.binding[field])
      .map((field) => `binding.${field}`)
  ];
  if (mismatchedFields.length > 0) {
    throwAcceptanceInputRequirementsStale(mismatchedFields);
  }
}

function readExactConfirmationObject(value, fields) {
  if (!value
    || typeof value !== "object"
    || Array.isArray(value)
    || utilTypes.isProxy(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return null;
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length
    || keys.some((key) => typeof key !== "string" || !fields.includes(key))) return null;
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor
      || !Object.hasOwn(descriptor, "value")
      || descriptor.enumerable !== true) return null;
    result[field] = descriptor.value;
  }
  return result;
}

function throwAcceptanceInputRequirementsStale(mismatchedFields) {
  throw kernelError(
    "ACCEPTANCE_INPUT_REQUIREMENTS_STALE",
    "Acceptance input requirements changed or the confirmation is malformed; refresh the Workbench before accepting.",
    409,
    { mismatchedFields }
  );
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
  moduleProjection,
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
      moduleProjection,
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
  moduleProjection,
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
  if (!provider || !moduleProjection) {
    throwWorkbenchVerificationPlanInvalid(
      changeId,
      `Verification mapping ${obligation.id} has no complete frozen route context.`
    );
  }
  const targetAcceptanceRoutes = readWorkbenchProjectedAcceptanceRoutes({
    claimRef,
    moduleRef: primaryModule,
    moduleProjection,
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
      readWorkbenchProjectedAcceptanceRoutes({
        claimRef: sourceClaimId,
        moduleRef: primaryModule,
        moduleProjection,
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
        routeClaimRefs: new Set(),
        routeSelectionsByModule: new Map()
      });
    }
    const requirement = requirements.get(baselineDigest);
    for (const claimRef of claimRefs) requirement.routeClaimRefs.add(claimRef);
    const primaryModule = readString(record?.primaryModule);
    if (primaryModule) {
      if (!requirement.routeSelectionsByModule.has(primaryModule)) {
        requirement.routeSelectionsByModule.set(primaryModule, new Set());
      }
      for (const claimRef of claimRefs) {
        requirement.routeSelectionsByModule.get(primaryModule).add(claimRef);
      }
    }
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

function compileWorkbenchHistoricalModuleProjections(requirements, providers, routeQuery) {
  const projections = new Map();
  const ordered = [...requirements.values()].sort((left, right) => (
    left.baselineDigest.localeCompare(right.baselineDigest)
  ));
  for (const requirement of ordered) {
    const provider = providers.get(requirement.baselineDigest);
    const routeSelections = [];
    for (const [moduleRef, claimRefs] of [...requirement.routeSelectionsByModule.entries()]
      .sort(([left], [right]) => left.localeCompare(right))) {
      const orderedClaimRefs = [...claimRefs].sort();
      for (let offset = 0; offset < orderedClaimRefs.length;
        offset += ARCHITECTURE_PROFILE_LIMITS.refsPerFact) {
        routeSelections.push({
          moduleRef,
          claimRefs: orderedClaimRefs.slice(
            offset,
            offset + ARCHITECTURE_PROFILE_LIMITS.refsPerFact
          )
        });
      }
    }
    projections.set(
      requirement.baselineDigest,
      compileWorkbenchModuleClaimGateProjection({
        provider,
        model: requirement.baseline,
        moduleRefs: [],
        routeSelections,
        routeQuery,
        location: `historicalBaseline.${requirement.baselineDigest}.moduleClaimGateProjection`,
        baselineDigest: requirement.baselineDigest
      })
    );
  }
  return projections;
}

function compileWorkbenchModuleClaimGateProjection({
  provider,
  model,
  moduleRefs,
  routeSelections,
  routeQuery,
  location,
  baselineDigest
}) {
  if (!provider?.token || !provider?.observation) {
    throw kernelError(
      "WORKBENCH_PROJECTION_FACT_INVALID",
      "Workbench Project Model projection requires a process-local route product.",
      500,
      { location, ...(baselineDigest ? { baselineDigest } : {}) }
    );
  }
  let projection;
  const projectionLimits = compileWorkbenchModuleProjectionLimits(
    routeQuery,
    provider.observation,
    location,
    baselineDigest
  );
  try {
    projection = projectCompiledModuleClaimGateIndex(provider.token, {
      model,
      moduleRefs,
      routeSelections,
      limits: projectionLimits
    });
  } catch (error) {
    throwWorkbenchModuleProjectionError(
      error,
      routeQuery,
      provider.observation,
      projectionLimits,
      location,
      baselineDigest
    );
  }
  consumeWorkbenchModuleProjectionDelta(
    routeQuery,
    provider.observation,
    projection.observation,
    location,
    baselineDigest
  );
  return projection;
}

function compileWorkbenchModuleProjectionLimits(
  routeQuery,
  productObservation,
  location,
  baselineDigest
) {
  const limits = {};
  for (const dimension of ["workUnits", "routes", "totalRouteBytes"]) {
    const aggregateLimit = routeQuery?.limits?.[dimension];
    const aggregateObserved = routeQuery?.observed?.[dimension];
    const productUnits = productObservation?.[dimension];
    if (!Number.isSafeInteger(aggregateLimit)
      || aggregateLimit < 0
      || !Number.isSafeInteger(aggregateObserved)
      || aggregateObserved < 0
      || aggregateObserved > aggregateLimit
      || !Number.isSafeInteger(productUnits)
      || productUnits < 0) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench Project Model projection cannot derive a current aggregate resource ceiling.",
        500,
        { dimension, location, ...(baselineDigest ? { baselineDigest } : {}) }
      );
    }
    limits[dimension] = productUnits + (aggregateLimit - aggregateObserved);
  }
  return limits;
}

function throwWorkbenchModuleProjectionError(
  error,
  routeQuery,
  productObservation,
  projectionLimits,
  location,
  baselineDigest
) {
  const dimension = readString(error?.details?.dimension);
  if (error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED"
    && dimension
    && Object.hasOwn(routeQuery.limits, dimension)) {
    const productUnits = productObservation?.[dimension];
    const localObserved = Number.isSafeInteger(error?.details?.observed)
      ? error.details.observed
      : projectionLimits[dimension] + 1;
    if (!Number.isSafeInteger(productUnits) || productUnits < 0 || localObserved < productUnits) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench Project Model projection returned an invalid local resource observation.",
        500,
        { dimension, location, ...(baselineDigest ? { baselineDigest } : {}) }
      );
    }
    throw kernelError(
      "ARCHITECTURE_PROFILE_ROUTE_QUERY_LIMIT_EXCEEDED",
      "Architecture Profile route query exceeded its aggregate resource budget.",
      413,
      {
        dimension,
        limit: routeQuery.limits[dimension],
        observed: routeQuery.observed[dimension] + (localObserved - productUnits),
        location,
        ...(baselineDigest ? { baselineDigest } : {})
      }
    );
  }
  throwArchitectureProfileRouteProviderError(error, routeQuery, location, baselineDigest);
}

function consumeWorkbenchModuleProjectionDelta(
  routeQuery,
  productObservation,
  projectionObservation,
  location,
  baselineDigest
) {
  const delta = {};
  for (const dimension of ["workUnits", "routes", "totalRouteBytes"]) {
    const productUnits = productObservation?.[dimension];
    const projectionUnits = projectionObservation?.[dimension];
    if (!Number.isSafeInteger(productUnits)
      || productUnits < 0
      || !Number.isSafeInteger(projectionUnits)
      || projectionUnits < productUnits) {
      throw kernelError(
        "WORKBENCH_PROJECTION_FACT_INVALID",
        "Workbench Project Model projection returned an invalid cumulative resource observation.",
        500,
        { dimension, location, ...(baselineDigest ? { baselineDigest } : {}) }
      );
    }
    delta[dimension] = projectionUnits - productUnits;
  }
  consumeArchitectureProfileRouteProviderObservation(
    routeQuery,
    delta,
    location,
    baselineDigest
  );
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
      token: routeProvider.token,
      observation: routeProvider.observation,
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
    observation: projection.observation,
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
    contracts: ARCHITECTURE_PROFILE_LIMITS.contracts,
    modelClaims: ARCHITECTURE_PROFILE_LIMITS.claims,
    refsPerModule: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    visibilityRefs: ARCHITECTURE_PROFILE_LIMITS.relations,
    gates: ARCHITECTURE_PROFILE_LIMITS.gates,
    commands: ARCHITECTURE_PROFILE_LIMITS.routes,
    refsPerCommand: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    totalCommandClaimRefs: ARCHITECTURE_PROFILE_LIMITS.relations,
    routeSelectionRows: ARCHITECTURE_PROFILE_LIMITS.modules,
    refsPerRouteSelection: ARCHITECTURE_PROFILE_LIMITS.refsPerFact,
    routeSelectionClaimRefs: ARCHITECTURE_PROFILE_LIMITS.relations,
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

function analyzeChangeScope(change, touchedPaths, {
  currentOwnership = null,
  frozenOwnership = null
} = {}) {
  if (!currentOwnership && !frozenOwnership) {
    return analyzeLegacyChangeScope(change, touchedPaths);
  }
  if (!currentOwnership || !frozenOwnership) {
    throw kernelError(
      "CHANGE_PATH_OWNERSHIP_DRIFT",
      "Current and Candidate-frozen path ownership governance must both be present.",
      409,
      {
        currentOwnershipPresent: Boolean(currentOwnership),
        frozenOwnershipPresent: Boolean(frozenOwnership)
      }
    );
  }
  assertOwnershipSourcesCompatible(frozenOwnership.sourceBinding, currentOwnership.sourceBinding);
  const primaryModuleRef = readString(change.primaryModule);
  const effectiveScope = change.contextCapsule?.scope?.write;
  const contextBinding = change.contextCapsule?.compiledFrom?.pathOwnership;
  if (!primaryModuleRef || !effectiveScope || !contextBinding) {
    throw kernelError(
      "CHANGE_PATH_OWNERSHIP_BINDING_INVALID",
      "Compiled Change context is missing its frozen path ownership scope binding.",
      409
    );
  }
  const effectiveScopeDigest = canonicalDigest(effectiveScope);
  const selection = [{
    id: "compiled-context-write",
    moduleRef: primaryModuleRef,
    scope: effectiveScope,
    expectedScopeDigest: effectiveScopeDigest
  }];
  const frozenProjection = projectKernelPathOwnership({
    ownership: frozenOwnership,
    primaryModuleRef,
    touchedPaths,
    selection,
    role: "frozen"
  });
  const currentProjection = projectKernelPathOwnership({
    ownership: currentOwnership,
    primaryModuleRef,
    touchedPaths,
    selection,
    role: "current"
  });
  const frozenScopeBinding = frozenProjection.scopeBindingsBySelection
    .get("compiled-context-write");
  const currentScopeBinding = currentProjection.scopeBindingsBySelection
    .get("compiled-context-write");
  assertContextOwnershipBinding({
    contextBinding,
    effectiveScope,
    effectiveScopeDigest,
    frozenOwnership,
    frozenScopeBinding
  });
  if (canonicalDigest(currentScopeBinding) !== canonicalDigest(frozenScopeBinding)) {
    throw kernelError(
      "CHANGE_PATH_OWNERSHIP_DRIFT",
      "Current and Candidate-frozen effective path ownership scopes differ.",
      409,
      {
        frozenScopeBinding: cloneJson(frozenScopeBinding),
        currentScopeBinding: cloneJson(currentScopeBinding)
      }
    );
  }

  const frozenDecisions = frozenProjection.writeDecisionsBySelection
    .get("compiled-context-write");
  const currentDecisions = currentProjection.writeDecisionsBySelection
    .get("compiled-context-write");
  const decisions = touchedPaths.map((pathRef) => {
    const frozenDecision = frozenDecisions?.get(pathRef);
    const currentDecision = currentDecisions?.get(pathRef);
    if (!frozenDecision
      || !currentDecision
      || canonicalDigest(currentDecision) !== canonicalDigest(frozenDecision)) {
      throw kernelError(
        "CHANGE_PATH_OWNERSHIP_DRIFT",
        "Current and Candidate-frozen path ownership decisions differ.",
        409,
        {
          pathRef,
          frozenDecision: frozenDecision ? cloneJson(frozenDecision) : null,
          currentDecision: currentDecision ? cloneJson(currentDecision) : null
        }
      );
    }
    return { path: pathRef, ...cloneJson(frozenDecision) };
  });
  const governance = readGovernanceBaseline(change);
  const modelAmendmentPaths = touchedPaths.filter((filePath) => (
    filePath.startsWith(".legatura/") && !filePath.startsWith(".legatura/runtime/")
  ));
  const decisionByPath = new Map(decisions.map((decision) => [decision.path, decision]));
  const inModuleWriteScope = touchedPaths.filter((filePath) => (
    !modelAmendmentPaths.includes(filePath) && decisionByPath.get(filePath)?.writeAllowed === true
  ));
  const outOfScopePaths = touchedPaths.filter((filePath) => (
    decisionByPath.get(filePath)?.writeAllowed !== true
  ));
  const touchedOwnerRefs = new Set(decisions.map((decision) => decision.ownerModuleRef).filter(Boolean));
  const touchedModules = governance.modules
    .filter((module) => touchedOwnerRefs.has(module.id))
    .map((module) => ({ id: module.id, name: module.name, status: module.status }));
  const opaqueModuleRefs = new Set(touchedModules
    .filter((module) => module.status === "opaque")
    .map((module) => module.id));
  const opaquePaths = outOfScopePaths.filter((filePath) => (
    opaqueModuleRefs.has(decisionByPath.get(filePath)?.ownerModuleRef)
  ));
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
    pathOwnership: {
      schemaVersion: 1,
      frozenSourceBinding: cloneJson(frozenOwnership.sourceBinding),
      currentSourceBinding: cloneJson(currentOwnership.sourceBinding),
      scopeBinding: projectPersistedPathOwnershipScopeBinding(frozenScopeBinding),
      decisions
    },
    requires: uniqueStrings([
      ...(modelAmendmentPaths.length > 0 ? ["normative-amendment"] : []),
      ...(outOfScopePaths.length > 0 ? ["scoped-waiver-or-change-split"] : []),
      ...(preExistingPaths.length > 0 ? ["explicit-adoption"] : [])
    ])
  };
}

function projectPersistedPathOwnershipScopeBinding(binding) {
  return {
    schemaVersion: binding.schemaVersion,
    selectionId: binding.selectionId,
    moduleRef: binding.moduleRef,
    authoritativeScopeDigest: binding.authoritativeScopeDigest,
    requestScopeDigest: binding.requestScopeDigest,
    effectiveScopeDigest: binding.effectiveScopeDigest
  };
}

function analyzeLegacyChangeScope(change, touchedPaths) {
  const governance = readGovernanceBaseline(change);
  const writeScope = change.contextCapsule?.scope?.write ?? { include: [], exclude: [] };
  const modelAmendmentPaths = touchedPaths.filter((filePath) => (
    filePath.startsWith(".legatura/") && !filePath.startsWith(".legatura/runtime/")
  ));
  const inModuleWriteScope = touchedPaths.filter((filePath) => (
    !modelAmendmentPaths.includes(filePath) && legacyPathAllowed(filePath, writeScope)
  ));
  const outOfScopePaths = touchedPaths.filter((filePath) => (
    !modelAmendmentPaths.includes(filePath) && !inModuleWriteScope.includes(filePath)
  ));
  const touchedModules = governance.modules
    .filter((module) => touchedPaths.some((filePath) => legacyPathAllowed(filePath, module.paths)))
    .map((module) => ({ id: module.id, name: module.name, status: module.status }));
  const opaquePaths = outOfScopePaths.filter((filePath) => touchedModules.some((module) => (
    module.status === "opaque"
      && legacyPathAllowed(
        filePath,
        governance.modules.find((candidate) => candidate.id === module.id)?.paths
      )
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
    legacyBootstrap: true,
    requires: uniqueStrings([
      ...(modelAmendmentPaths.length > 0 ? ["normative-amendment"] : []),
      ...(outOfScopePaths.length > 0 ? ["scoped-waiver-or-change-split"] : []),
      ...(preExistingPaths.length > 0 ? ["explicit-adoption"] : [])
    ])
  };
}

function assertOwnershipSourcesCompatible(frozenBinding, currentBinding) {
  const driftFields = [
    "schemaVersion",
    "trackedPathFactsDigest",
    "ownershipPolicyDigest",
    "assignmentDigest"
  ];
  const changedFields = driftFields.filter((field) => (
    frozenBinding?.[field] !== currentBinding?.[field]
  ));
  if (changedFields.length > 0) {
    throw kernelError(
      "CHANGE_PATH_OWNERSHIP_DRIFT",
      "Current ownership policy or tracked-path classification differs from the Candidate baseline.",
      409,
      {
        changedFields,
        frozenSourceBinding: cloneJson(frozenBinding),
        currentSourceBinding: cloneJson(currentBinding)
      }
    );
  }
}

function projectKernelPathOwnership({
  ownership,
  primaryModuleRef,
  touchedPaths,
  selection,
  role
}) {
  try {
    return projectCompiledModulePathOwnershipIndex(ownership.product, {
      model: ownership.model,
      moduleRefs: [primaryModuleRef],
      pathRefs: touchedPaths,
      scopeSelections: selection
    });
  } catch (error) {
    throw kernelError(
      role === "frozen"
        ? "CHANGE_PATH_OWNERSHIP_BINDING_INVALID"
        : "CHANGE_PATH_OWNERSHIP_DRIFT",
      `${role === "frozen" ? "Candidate-frozen" : "Current"} path ownership projection failed closed.`,
      409,
      { sourceCode: readString(error?.code) ?? null }
    );
  }
}

function assertContextOwnershipBinding({
  contextBinding,
  effectiveScope,
  effectiveScopeDigest,
  frozenOwnership,
  frozenScopeBinding
}) {
  const sourceKeys = Object.keys(frozenOwnership.sourceBinding);
  const observedSourceBinding = Object.fromEntries(sourceKeys.map((key) => [
    key,
    contextBinding?.[key] ?? null
  ]));
  const sourceCurrent = canonicalDigest(observedSourceBinding)
    === canonicalDigest(frozenOwnership.sourceBinding);
  const scopeCurrent = frozenScopeBinding
    && contextBinding?.scopeDigest === frozenScopeBinding.authoritativeScopeDigest
    && contextBinding?.effectiveScopeDigest === effectiveScopeDigest
    && frozenScopeBinding.requestScopeDigest === effectiveScopeDigest
    && frozenScopeBinding.effectiveScopeDigest === effectiveScopeDigest
    && canonicalDigest(frozenScopeBinding.effectiveScope) === canonicalDigest(effectiveScope);
  if (!sourceCurrent || !scopeCurrent) {
    throw kernelError(
      "CHANGE_PATH_OWNERSHIP_BINDING_INVALID",
      "Compiled Context path ownership binding does not match the Candidate-frozen product and scope.",
      409,
      {
        sourceCurrent,
        scopeCurrent,
        expectedSourceBinding: cloneJson(frozenOwnership.sourceBinding),
        observedSourceBinding,
        frozenScopeBinding: frozenScopeBinding ? cloneJson(frozenScopeBinding) : null
      }
    );
  }
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

function assertCompiledChangeCurrent(change, modulePathOwnershipProduct) {
  const governanceBaseline = readGovernanceBaseline(change);
  const recompiled = modulePathOwnershipProduct
    ? compileChangeAgainstGovernance(change, governanceBaseline, {
        modulePathOwnershipProduct
      })
    : compileChangeAgainstGovernance(change, governanceBaseline);
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

  const result = await observeCommand(commandRunner, {
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
    ],
    timeoutMs: 300_000
  });
  const stdout = readCommandUtf8Stream(result, "stdout");
  const stderr = readCommandUtf8Stream(result, "stderr");
  if (result.streams.stdout.truncated || result.streams.stderr.truncated) {
    throw kernelError(
      "GIT_CHANGESET_TRUNCATED",
      "Committed ChangeSet path output was truncated; scope cannot be proven safely.",
      409
    );
  }
  if (!isSuccessfulCommandObservation(result) || !stdout.available || !stderr.available) {
    throw kernelError(
      "GIT_CHANGESET_UNREADABLE",
      "Could not compare the current Git HEAD with the Change baseline.",
      409,
      {
        baselineHead,
        currentHead,
        supportStatus: result.support.status,
        controlKind: result.control.kind,
        terminationKind: result.termination.kind,
        stderr: stderr.available
          ? stderr.value : result.termination.error?.message ?? stderr.reason
      }
    );
  }
  const committedPaths = stdout.value.split(/\r?\n/u).flatMap((line) => {
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

function legacyPathAllowed(filePath, scope = {}) {
  const includes = normalizeStringList(scope?.include ?? scope);
  const excludes = normalizeStringList(scope?.exclude);
  return includes.some((pattern) => legacyGlobMatches(filePath, pattern))
    && !excludes.some((pattern) => legacyGlobMatches(filePath, pattern));
}

function legacyGlobMatches(filePath, pattern) {
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
    ...readOutcomePlanAmendmentFields(change),
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
    ...readOutcomePlanAmendmentFields(change),
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

function readOutcomePlanAmendmentFields(change) {
  const claimsCurrentSchema = Object.hasOwn(change, "outcomePlanAmendmentSchemaVersion")
    || Object.hasOwn(change, "outcomePlanAmendmentCompilation");
  if (claimsCurrentSchema) {
    return cloneJson({
      outcomePlanAmendmentSchemaVersion: change.outcomePlanAmendmentSchemaVersion ?? null,
      priorAcceptedPackages: change.priorAcceptedPackages ?? null,
      outcomePlanAmendmentCompilation: change.outcomePlanAmendmentCompilation ?? null
    });
  }
  if (change.outcomeTransitionSchemaVersion !== 1) return {};
  return cloneJson({
    outcomeTransitionSchemaVersion: 1,
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
  const crossMappings = readCrossMappingObligations(change);
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
    requiredObligationIds: readRequiredCrossMappingObligationIds(change),
    approvedObligationIds,
    authorityBindings,
    invalidObligationIds,
    unauthorizedObligationIds
  };
}

function readCrossMappingObligations(change) {
  return (Array.isArray(change?.verificationObligations) ? change.verificationObligations : [])
    .filter((obligation) => {
    if (obligation.mapping?.kind === "exact-contract-claim") return false;
    const refs = [
      ...normalizeStringList(obligation.evidenceSourceRefs),
      ...normalizeStringList(obligation.gateClaimRefs),
      ...normalizeStringList(obligation.supportedBy)
    ];
    return refs.some((ref) => ref !== obligation.claimId);
  });
}

function readRequiredCrossMappingObligationIds(change) {
  return readCrossMappingObligations(change)
    .filter(hasCrossMappingSemantics)
    .map((obligation) => readString(obligation.id))
    .filter(Boolean)
    .sort(compareCodeUnits);
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
      knowledgeClosure: optionObject?.knowledgeClosure,
      inputRequirementsConfirmation: optionObject?.inputRequirementsConfirmation,
      integrate: optionObject?.integrate === true || optionObject?.integrated === true
    };
  }
  return {
    changeId: readChangeId(idOrInput),
    authorityDecision: idOrInput.authorityDecision ?? idOrInput.decision,
    knowledgeClosure: idOrInput.knowledgeClosure,
    inputRequirementsConfirmation: idOrInput.inputRequirementsConfirmation,
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

function compareCodeUnits(left, right) {
  return left === right ? 0 : left < right ? -1 : 1;
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
