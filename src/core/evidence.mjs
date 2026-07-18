import { canonicalDigest, cloneJson } from "./canonical.mjs";

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
const EVIDENCE_COVERAGE_COLLECTION_LIMIT = 256;
const EVIDENCE_COVERAGE_EVALUATION_LIMIT = 32768;
const ELIGIBLE_ASSOCIATIONS_PER_EVIDENCE_LIMIT = 256;
const ELIGIBLE_ASSOCIATIONS_TOTAL_LIMIT = 32768;

export const KNOWLEDGE_CLOSURE_MODES = Object.freeze(["no-new-knowledge", "entries"]);
export const KNOWLEDGE_CLOSURE_ENTRY_KINDS = Object.freeze([
  "model-amendment",
  "model-gap",
  "ephemeral"
]);
export const AUTHORITY_DECISION_TYPES = Object.freeze([
  "case-decision",
  "normative-amendment",
  "waiver"
]);

export const EVIDENCE_FIELDS = [
  "claim",
  "oracle",
  "observation",
  "provenance",
  "applicability",
  "discriminatoryPower",
  "residualUncertainty"
];

export function normalizeClaims(value) {
  const claims = Array.isArray(value) ? value : value === undefined ? [] : [value];
  return claims.map((claim, index) => {
    if (typeof claim === "string" && claim.trim()) {
      const statement = claim.trim();
      return { id: `claim-${shortDigest(statement)}`, statement };
    }
    if (!claim || typeof claim !== "object" || Array.isArray(claim)) {
      throw domainError("CLAIM_INVALID", `Claim ${index + 1} must be a string or object.`);
    }
    const statement = readString(claim.statement) ?? readString(claim.description);
    if (!statement) {
      throw domainError("CLAIM_STATEMENT_REQUIRED", `Claim ${index + 1} requires a statement.`);
    }
    return {
      ...cloneJson(claim),
      id: readString(claim.id) ?? `claim-${shortDigest(statement)}`,
      statement
    };
  });
}

export function normalizeEvidenceList(value) {
  const evidence = Array.isArray(value) ? value : value === undefined ? [] : [value];
  return evidence.map(normalizeEvidence);
}

export function normalizeEvidence(value, index = 0) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw domainError("EVIDENCE_INVALID", `Evidence ${index + 1} must be an object.`);
  }
  const missing = EVIDENCE_FIELDS.filter((field) => !isSubstantive(value[field]));
  if (missing.length > 0) {
    throw domainError(
      "EVIDENCE_INCOMPLETE",
      `Evidence ${index + 1} is missing substantive fields: ${missing.join(", ")}.`,
      { missingFields: missing }
    );
  }

  const claim = normalizeEvidenceClaim(value.claim);
  return {
    ...cloneJson(value),
    id: readString(value.id) ?? `evidence-${shortDigest({ ...value, claim })}`,
    claim,
    supportsClaimIds: Array.isArray(value.supportsClaimIds)
      ? [...new Set(value.supportsClaimIds.filter(readString))]
      : []
  };
}

export function validateEvidenceCoverage(
  claims,
  evidence,
  {
    authorityBindings = [],
    verificationSubjectDigest,
    trustedEvidenceBindings = [],
    verificationObligations = [],
    workBudget
  } = {}
) {
  assertEvidenceCoverageCollection(claims, "claims");
  assertEvidenceCoverageCollection(evidence, "evidence");
  assertEvidenceCoverageCollection(authorityBindings, "authorityBindings");
  assertEvidenceCoverageCollection(trustedEvidenceBindings, "trustedEvidenceBindings");
  assertEvidenceCoverageCollection(verificationObligations, "verificationObligations");
  for (const [index, item] of evidence.entries()) {
    assertEvidenceCoverageOptionalCollection(item?.claim?.refs, `evidence.${index}.claim.refs`);
    assertEvidenceCoverageOptionalCollection(
      item?.directSupportBindings,
      `evidence.${index}.directSupportBindings`
    );
    assertEvidenceCoverageOptionalCollection(
      item?.supportBindings,
      `evidence.${index}.supportBindings`
    );
  }
  for (const [index, obligation] of verificationObligations.entries()) {
    for (const [field, value] of [
      ["mapping.routes", obligation?.mapping?.routes],
      ["mapping.sourceRoutes", obligation?.mapping?.sourceRoutes],
      ["mapping.sourceClaimIds", obligation?.mapping?.sourceClaimIds],
      ["mapping.sourceIds", obligation?.mapping?.sourceIds]
    ]) {
      assertEvidenceCoverageOptionalCollection(
        value,
        `verificationObligations.${index}.${field}`
      );
    }
  }
  const covered = new Set();
  const evaluationBudget = readEvidenceCoverageWorkBudget(workBudget);
  consumeEvidenceCoverageWork(
    evaluationBudget,
    claims.length
      + evidence.length
      + authorityBindings.length
      + trustedEvidenceBindings.length
      + (verificationObligations.length * 2)
  );
  const authorityBindingIndex = indexAuthorityBindings(authorityBindings);
  const claimIndex = indexClaims(claims);
  const claimById = claimIndex.byId;
  const obligationIndex = indexVerificationObligations(verificationObligations);
  const mappingIndex = compileEvidenceCoverageMappingIndex(
    verificationObligations,
    evaluationBudget
  );
  const evidenceIdentityIndex = indexEvidenceIdentities(evidence);
  const trustedBindingIndex = indexTrustedEvidenceBindings(trustedEvidenceBindings);
  const trustedDigests = trustedBindingIndex.byEvidenceId;
  const eligibleClaimAssociations = [];
  const eligibleAssociationDigests = new Set();
  const eligibleAssociationCounts = new Map();
  const untrustedEvidenceIds = [];
  const staleEvidenceIds = [];
  const mismatchedClaimEvidenceIds = [];
  const ineligibleRouteEvidenceIds = new Set();

  function recordEligibleAssociation(association) {
    const digest = canonicalDigest(association);
    if (eligibleAssociationDigests.has(digest)) return;
    const evidenceKey = `${association.evidenceRef}\u0000${association.evidenceDigest}`;
    const evidenceCount = (eligibleAssociationCounts.get(evidenceKey) ?? 0) + 1;
    if (evidenceCount > ELIGIBLE_ASSOCIATIONS_PER_EVIDENCE_LIMIT
      || eligibleClaimAssociations.length + 1 > ELIGIBLE_ASSOCIATIONS_TOTAL_LIMIT) {
      throw domainError(
        "EVIDENCE_ASSOCIATION_LIMIT_EXCEEDED",
        "Eligible Evidence-to-Claim associations exceeded a declared hard bound.",
        {
          evidenceRef: association.evidenceRef,
          perEvidenceLimit: ELIGIBLE_ASSOCIATIONS_PER_EVIDENCE_LIMIT,
          totalLimit: ELIGIBLE_ASSOCIATIONS_TOTAL_LIMIT
        },
        413
      );
    }
    eligibleAssociationDigests.add(digest);
    eligibleAssociationCounts.set(evidenceKey, evidenceCount);
    eligibleClaimAssociations.push({ association, digest });
  }

  for (const item of evidence) {
    consumeEvidenceCoverageWork(evaluationBudget);
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      untrustedEvidenceIds.push("invalid-evidence");
      continue;
    }
    if (evidenceIdentityIndex.duplicateIds.includes(readString(item?.id))) {
      untrustedEvidenceIds.push(item?.id);
      continue;
    }
    if (!isPositiveObservation(item.observation)) {
      continue;
    }
    const evidenceDigest = canonicalDigest(item);
    if (trustedDigests.get(item.id) !== evidenceDigest) {
      untrustedEvidenceIds.push(item.id);
      continue;
    }
    const provenanceKind = readString(item.provenance?.kind);
    if (provenanceKind !== "builtin-oracle" && provenanceKind !== "gate-command") {
      untrustedEvidenceIds.push(item.id);
      continue;
    }
    if (verificationSubjectDigest
      && item.provenance?.verificationSubjectDigest !== verificationSubjectDigest) {
      staleEvidenceIds.push(item.id);
      continue;
    }

    if (provenanceKind === "builtin-oracle") {
      const matchingClaim = claimById.get(item.claim?.id);
      const explicitEnvelopeClaimRefs = readEvidenceEnvelopeClaimRefs(item);
      const envelopeMatches = explicitEnvelopeClaimRefs.length === 0
        || explicitEnvelopeClaimRefs.includes(matchingClaim?.id);
      if (matchingClaim && item.claim?.statement === matchingClaim.statement && envelopeMatches) {
        const obligation = obligationIndex.byClaimId.get(matchingClaim.id);
        const sourceIds = mappingIndex.builtinSourceIds.get(obligation);
        if (obligation?.mapping?.kind === "builtin-oracle"
          && sourceIds?.has(readString(item.provenance?.sourceId))) {
          const obligationRef = readString(obligation?.id);
          const sourceId = readString(item.provenance?.sourceId);
          if (obligationRef && sourceId) {
            recordEligibleAssociation({
              evidenceRef: item.id,
              evidenceDigest,
              kind: "builtin",
              targetClaimRef: matchingClaim.id,
              sourceClaimRef: matchingClaim.id,
              obligationRef,
              obligationDigest: canonicalDigest(obligation),
              sourceId
            });
            covered.add(matchingClaim.id);
          } else {
            ineligibleRouteEvidenceIds.add(item.id);
          }
        } else {
          ineligibleRouteEvidenceIds.add(item.id);
        }
      } else if (matchingClaim && item.claim?.statement !== matchingClaim.statement) {
        mismatchedClaimEvidenceIds.push(item.id);
      } else if (matchingClaim) {
        ineligibleRouteEvidenceIds.add(item.id);
      }
      continue;
    }

    const envelopeClaimRefs = new Set(readEvidenceEnvelopeClaimRefs(item));

    for (const claimId of envelopeClaimRefs) {
      consumeEvidenceCoverageWork(evaluationBudget);
      if (!claimById.has(claimId)) continue;
      const obligation = obligationIndex.byClaimId.get(claimId);
      if (obligation?.mapping?.kind !== "exact-contract-claim"
        || !mappingIndex.exactRoutes.get(obligation)?.has(evidenceRouteKey(item.provenance))) {
        ineligibleRouteEvidenceIds.add(item.id);
      }
    }

    const seenDirectBindings = new Set();
    for (const binding of item.directSupportBindings ?? []) {
      consumeEvidenceCoverageWork(evaluationBudget);
      const directBindingKey = canonicalDigest({
        claimId: readString(binding?.claimId) ?? null,
        claimStatement: readString(binding?.claimStatement) ?? null
      });
      if (seenDirectBindings.has(directBindingKey)) continue;
      seenDirectBindings.add(directBindingKey);
      const directClaim = claimById.get(binding?.claimId);
      if (directClaim
        && envelopeClaimRefs.has(directClaim.id)
        && binding?.claimStatement === directClaim.statement) {
        const obligation = obligationIndex.byClaimId.get(directClaim.id);
        if (obligation?.mapping?.kind === "exact-contract-claim"
          && mappingIndex.exactRoutes.get(obligation)?.has(evidenceRouteKey(item.provenance))) {
          const obligationRef = readString(obligation?.id);
          const gateId = readString(item.provenance?.gateId);
          const commandId = readString(item.provenance?.commandId);
          if (obligationRef && gateId && commandId) {
            recordEligibleAssociation({
              evidenceRef: item.id,
              evidenceDigest,
              kind: "direct",
              targetClaimRef: directClaim.id,
              sourceClaimRef: directClaim.id,
              obligationRef,
              obligationDigest: canonicalDigest(obligation),
              gateId,
              commandId
            });
            covered.add(directClaim.id);
          } else {
            ineligibleRouteEvidenceIds.add(item.id);
          }
        } else {
          ineligibleRouteEvidenceIds.add(item.id);
        }
      } else if (directClaim && binding?.claimStatement !== directClaim.statement) {
        mismatchedClaimEvidenceIds.push(item.id);
      } else if (directClaim) {
        ineligibleRouteEvidenceIds.add(item.id);
      }
    }
    const seenSupportBindings = new Set();
    const sourceRouteMatches = new Map();
    for (const binding of item.supportBindings ?? []) {
      consumeEvidenceCoverageWork(evaluationBudget);
      const obligationId = readString(binding?.obligationId);
      const targetClaimId = readString(binding?.claimId);
      const supportBindingKey = `${obligationId ?? ""}\u0000${targetClaimId ?? ""}`;
      if (seenSupportBindings.has(supportBindingKey)) continue;
      seenSupportBindings.add(supportBindingKey);
      const targetClaim = claimById.get(targetClaimId);
      const obligation = obligationIndex.byId.get(obligationId);
      if (!targetClaim || !obligationId) continue;
      if (!obligation
        || obligation.claimId !== targetClaim.id
        || obligationIndex.byClaimId.get(targetClaim.id) !== obligation) {
        ineligibleRouteEvidenceIds.add(item.id);
        continue;
      }
      const authorityDecisionDigest = authorityBindingIndex.get(obligationId);
      if (!authorityDecisionDigest) continue;
      if (!sourceRouteMatches.has(obligationId)) {
        sourceRouteMatches.set(obligationId, matchingIndexedSourceRoutesForEvidence({
          obligation,
          evidence: item,
          envelopeClaimRefs,
          mappingIndex,
          evaluationBudget
        }));
      }
      const sourceRoutes = sourceRouteMatches.get(obligationId);
      if (obligation.mapping?.kind === "cross-claim" && sourceRoutes.length > 0) {
        covered.add(targetClaim.id);
        const obligationDigest = canonicalDigest(obligation);
        for (const route of sourceRoutes) {
          recordEligibleAssociation({
            evidenceRef: item.id,
            evidenceDigest,
            kind: "cross-claim",
            targetClaimRef: targetClaim.id,
            sourceClaimRef: route.sourceClaimId,
            obligationRef: obligationId,
            obligationDigest,
            gateId: route.gateId,
            commandId: route.commandId,
            authorityDecisionDigest
          });
        }
      } else {
        ineligibleRouteEvidenceIds.add(item.id);
      }
    }
  }
  const uncoveredClaimIds = claims
    .map((claim, index) => readString(claim?.id) ?? `invalid-claim-${index + 1}`)
    .filter((id) => !covered.has(id));
  return {
    satisfied: claims.length > 0
      && claimIndex.duplicateIds.length === 0
      && evidenceIdentityIndex.duplicateIds.length === 0
      && trustedBindingIndex.conflictingEvidenceIds.length === 0
      && obligationIndex.duplicateIds.length === 0
      && obligationIndex.duplicateClaimIds.length === 0
      && uncoveredClaimIds.length === 0,
    coveredClaimIds: [...covered],
    uncoveredClaimIds,
    duplicateClaimIds: claimIndex.duplicateIds,
    duplicateEvidenceIds: evidenceIdentityIndex.duplicateIds,
    conflictingTrustedEvidenceIds: trustedBindingIndex.conflictingEvidenceIds,
    duplicateObligationIds: obligationIndex.duplicateIds,
    duplicateObligationClaimIds: obligationIndex.duplicateClaimIds,
    untrustedEvidenceIds,
    staleEvidenceIds,
    mismatchedClaimEvidenceIds,
    ineligibleRouteEvidenceIds: [...ineligibleRouteEvidenceIds],
    eligibleClaimAssociations: eligibleClaimAssociations
      .sort((left, right) => left.digest.localeCompare(right.digest))
      .map((entry) => entry.association)
  };
}

export function createProjectModelEvidence({ change, git, model, validation, observedAt, verificationSubjectDigest }) {
  return normalizeEvidence({
    id: `evidence-project-model-${shortDigest({ model: model.digest, git: git.contentDigest })}`,
    claim: {
      id: "project-model-self-consistent",
      statement: "The versioned Project Model is internally self-consistent for this Change."
    },
    oracle: {
      kind: "deterministic-project-model-validation",
      description: "Reject duplicate ids, dangling Module/Contract/dependency references, incomplete governed Modules, and incomplete Gate definitions.",
      expected: "zero validation errors"
    },
    observation: {
      status: validation.valid ? "passed" : "failed",
      errorCount: validation.errors.length,
      warningCount: validation.warnings.length,
      errors: validation.errors,
      warnings: validation.warnings
    },
    provenance: {
      kind: "builtin-oracle",
      sourceId: "project-model",
      implementation: "legatura-core/project-model-v1",
      observedAt,
      changeId: change.id,
      verificationSubjectDigest,
      projectModelDigest: model.digest,
      git: gitProvenance(git)
    },
    applicability: {
      repoPath: change.repoPath,
      files: model.files,
      assuranceBoundary: model.projectDocument?.assuranceBoundary ?? null
    },
    discriminatoryPower: {
      rejects: [
        "duplicate model identifiers",
        "dangling Module, Contract, or dependency references",
        "governed Modules without paths, interface, or Fact Authority",
        "Gate commands without Claim or Oracle semantics"
      ]
    },
    residualUncertainty: [
      "Structural consistency does not prove that source code conforms to the Project Model.",
      "Behavioral and packaged-product Claims require independent Evidence."
    ]
  });
}

export function createGateEvidence({
  change,
  gate,
  command,
  result,
  git,
  model,
  observedAt,
  verificationSubjectDigest,
  supportsClaimIds = [],
  supportBindings = []
}) {
  const claimRefs = command.claimRefs.filter(readString);
  const contractClaims = new Map(model.contracts.flatMap((contract) => (
    Array.isArray(contract.claims) ? contract.claims : []
  )).map((claim) => [claim.id, claim]));
  const directlySupportedClaims = claimRefs.flatMap((id) => {
    const requested = change.claims.find((claim) => claim.id === id);
    const authoritative = contractClaims.get(id);
    return requested
      && authoritative?.statement === requested.statement
      && claimHasExactGateRoute(change.verificationObligations, requested.id, gate.id, command.id)
      ? [requested]
      : [];
  });
  const directlySupported = directlySupportedClaims.map((claim) => claim.id);
  const explicitlySupported = [...new Set([
    ...directlySupported,
    ...supportsClaimIds.filter((id) => change.claims.some((claim) => claim.id === id))
  ])];
  const gateClaimId = claimRefs[0] ?? `${gate.id}:${command.id}`;
  return normalizeEvidence({
    id: `evidence-${gate.id}-${command.id}-${shortDigest({ git: git.contentDigest, result })}`,
    claim: {
      id: gateClaimId,
      statement: `Gate ${gate.name ?? gate.id} command ${command.id} satisfies: ${claimRefs.join(", ")}.`,
      refs: claimRefs
    },
    supportsClaimIds: explicitlySupported,
    directSupportsClaimIds: directlySupported,
    directSupportBindings: directlySupportedClaims.map((claim) => ({
      claimId: claim.id,
      claimStatement: claim.statement
    })),
    supportBindings: cloneJson(supportBindings),
    oracle: cloneJson(command.oracle),
    observation: {
      status: result.exitCode === 0 ? "passed" : "failed",
      exitCode: result.exitCode,
      stdout: result.stdout,
      stderr: result.stderr,
      ...(result.signal ? { signal: result.signal } : {}),
      ...(result.truncated ? { truncated: true } : {})
    },
    provenance: {
      kind: "gate-command",
      observedAt,
      changeId: change.id,
      gateId: gate.id,
      commandId: command.id,
      command: command.command,
      verificationSubjectDigest,
      projectModelDigest: model.digest,
      git: gitProvenance(git)
    },
    applicability: gateEvidenceApplicability(command.applicability, change.primaryModule),
    discriminatoryPower: cloneJson(command.discriminatoryPower),
    residualUncertainty: cloneJson(command.residualUncertainty)
  });
}

function gateEvidenceApplicability(configured, primaryModule) {
  const value = cloneJson(configured);
  const conditions = value && typeof value === "object" && !Array.isArray(value)
    ? value
    : { description: value };
  return {
    ...conditions,
    module: primaryModule
  };
}

function compileEvidenceCoverageMappingIndex(obligations, evaluationBudget) {
  const exactRoutes = new WeakMap();
  const builtinSourceIds = new WeakMap();
  const crossRoutes = new WeakMap();
  for (const obligation of obligations) {
    consumeEvidenceCoverageWork(evaluationBudget);
    if (!obligation || typeof obligation !== "object" || Array.isArray(obligation)) continue;
    const mapping = obligation.mapping;
    if (!mapping || typeof mapping !== "object" || Array.isArray(mapping)) continue;
    if (mapping.kind === "exact-contract-claim") {
      const routeKeys = new Set();
      for (const route of mapping.routes ?? []) {
        consumeEvidenceCoverageWork(evaluationBudget);
        const key = evidenceRouteKey(route);
        if (key !== "\u0000") routeKeys.add(key);
      }
      exactRoutes.set(obligation, routeKeys);
      continue;
    }
    if (mapping.kind === "builtin-oracle") {
      const sourceIds = new Set();
      for (const sourceId of mapping.sourceIds ?? []) {
        consumeEvidenceCoverageWork(evaluationBudget);
        const exact = readString(sourceId);
        if (exact) sourceIds.add(exact);
      }
      builtinSourceIds.set(obligation, sourceIds);
      continue;
    }
    if (mapping.kind !== "cross-claim") continue;
    const declaredSourceClaimIds = new Set();
    for (const sourceClaimId of mapping.sourceClaimIds ?? []) {
      consumeEvidenceCoverageWork(evaluationBudget);
      const exact = readString(sourceClaimId);
      if (exact) declaredSourceClaimIds.add(exact);
    }
    const byRoute = new Map();
    const seen = new Set();
    for (const route of mapping.sourceRoutes ?? []) {
      consumeEvidenceCoverageWork(evaluationBudget);
      const sourceClaimId = readString(route?.sourceClaimId);
      const gateId = readString(route?.gateId);
      const commandId = readString(route?.commandId);
      if (!sourceClaimId || !gateId || !commandId
        || !declaredSourceClaimIds.has(sourceClaimId)) continue;
      const exact = { sourceClaimId, gateId, commandId };
      const digest = canonicalDigest(exact);
      if (seen.has(digest)) continue;
      seen.add(digest);
      const key = evidenceRouteKey(exact);
      if (!byRoute.has(key)) byRoute.set(key, []);
      byRoute.get(key).push(exact);
    }
    for (const routes of byRoute.values()) {
      routes.sort((left, right) => left.sourceClaimId.localeCompare(right.sourceClaimId));
    }
    crossRoutes.set(obligation, byRoute);
  }
  return { exactRoutes, builtinSourceIds, crossRoutes };
}

function matchingIndexedSourceRoutesForEvidence({
  obligation,
  evidence,
  envelopeClaimRefs,
  mappingIndex,
  evaluationBudget
}) {
  const candidates = mappingIndex.crossRoutes.get(obligation)?.get(
    evidenceRouteKey(evidence?.provenance)
  ) ?? [];
  const matches = [];
  for (const route of candidates) {
    consumeEvidenceCoverageWork(evaluationBudget);
    if (envelopeClaimRefs.has(route.sourceClaimId)) matches.push(route);
  }
  return matches;
}

function evidenceRouteKey(value) {
  return `${readString(value?.gateId) ?? ""}\u0000${readString(value?.commandId) ?? ""}`;
}

function consumeEvidenceCoverageWork(budget, units = 1) {
  budget.observed += units;
  if (budget.observed > EVIDENCE_COVERAGE_EVALUATION_LIMIT) {
    throw domainError(
      "EVIDENCE_COVERAGE_EVALUATION_LIMIT_EXCEEDED",
      "Evidence coverage evaluation exceeded a declared hard work bound.",
      {
        limit: EVIDENCE_COVERAGE_EVALUATION_LIMIT,
        observed: budget.observed
      },
      413
    );
  }
}

function readEvidenceCoverageWorkBudget(value) {
  if (value === undefined) return { observed: 0 };
  if (!value || typeof value !== "object" || Array.isArray(value)
    || !Number.isSafeInteger(value.observed) || value.observed < 0) {
    throw domainError(
      "EVIDENCE_COVERAGE_INPUT_INVALID",
      "Evidence coverage workBudget must expose a non-negative safe-integer observation count.",
      { location: "workBudget" }
    );
  }
  return value;
}

function assertEvidenceCoverageOptionalCollection(value, location) {
  if (value === undefined || value === null) return;
  assertEvidenceCoverageCollection(value, location);
}

function assertEvidenceCoverageCollection(value, location) {
  if (!Array.isArray(value)) {
    throw domainError(
      "EVIDENCE_COVERAGE_INPUT_INVALID",
      "Evidence coverage inputs require array-shaped collections.",
      { location }
    );
  }
  if (value.length > EVIDENCE_COVERAGE_COLLECTION_LIMIT) {
    throw domainError(
      "EVIDENCE_COVERAGE_LIMIT_EXCEEDED",
      "Evidence coverage inputs exceeded a declared hard collection bound.",
      {
        location,
        limit: EVIDENCE_COVERAGE_COLLECTION_LIMIT,
        observed: value.length
      },
      413
    );
  }
}

function indexEvidenceIdentities(value) {
  const counts = new Map();
  for (const item of value) {
    const id = readString(item?.id);
    if (id) counts.set(id, (counts.get(id) ?? 0) + 1);
  }
  return {
    duplicateIds: [...counts]
      .filter(([, count]) => count > 1)
      .map(([id]) => id)
      .sort()
  };
}

function indexVerificationObligations(value) {
  const byId = new Map();
  const byClaimId = new Map();
  const duplicateIds = new Set();
  const duplicateClaimIds = new Set();
  for (const obligation of Array.isArray(value) ? value : []) {
    const id = readString(obligation?.id);
    const claimId = readString(obligation?.claimId);
    if (id) {
      if (byId.has(id)) duplicateIds.add(id);
      else byId.set(id, obligation);
    }
    if (claimId) {
      if (byClaimId.has(claimId)) duplicateClaimIds.add(claimId);
      else byClaimId.set(claimId, obligation);
    }
  }
  for (const id of duplicateIds) byId.delete(id);
  for (const [claimId, obligation] of byClaimId) {
    if (duplicateIds.has(readString(obligation?.id))) byClaimId.delete(claimId);
  }
  for (const claimId of duplicateClaimIds) byClaimId.delete(claimId);
  return {
    byId,
    byClaimId,
    duplicateIds: [...duplicateIds].sort(),
    duplicateClaimIds: [...duplicateClaimIds].sort()
  };
}

function indexClaims(value) {
  const byId = new Map();
  const duplicateIds = new Set();
  for (const claim of Array.isArray(value) ? value : []) {
    const id = readString(claim?.id);
    if (!id) continue;
    if (byId.has(id)) duplicateIds.add(id);
    else byId.set(id, claim);
  }
  for (const id of duplicateIds) byId.delete(id);
  return { byId, duplicateIds: [...duplicateIds].sort() };
}

function indexAuthorityBindings(value) {
  const byObligationId = new Map();
  const conflicts = new Set();
  for (const binding of Array.isArray(value) ? value : []) {
    const obligationId = readString(binding?.obligationId);
    const authorityDecisionDigest = readString(binding?.authorityDecisionDigest);
    if (!obligationId || !DIGEST_PATTERN.test(authorityDecisionDigest ?? "")) continue;
    if (byObligationId.has(obligationId)
      && byObligationId.get(obligationId) !== authorityDecisionDigest) {
      conflicts.add(obligationId);
      continue;
    }
    byObligationId.set(obligationId, authorityDecisionDigest);
  }
  for (const obligationId of conflicts) byObligationId.delete(obligationId);
  return byObligationId;
}

function indexTrustedEvidenceBindings(value) {
  const byEvidenceId = new Map();
  const conflicts = new Set();
  for (const binding of value) {
    const evidenceId = readString(binding?.id);
    const evidenceDigest = readString(binding?.digest);
    if (!evidenceId || !DIGEST_PATTERN.test(evidenceDigest ?? "")) continue;
    if (byEvidenceId.has(evidenceId) && byEvidenceId.get(evidenceId) !== evidenceDigest) {
      conflicts.add(evidenceId);
      continue;
    }
    byEvidenceId.set(evidenceId, evidenceDigest);
  }
  for (const evidenceId of conflicts) byEvidenceId.delete(evidenceId);
  return {
    byEvidenceId,
    conflictingEvidenceIds: [...conflicts].sort()
  };
}

function claimHasExactGateRoute(obligations, claimId, gateId, commandId) {
  const obligation = indexVerificationObligations(obligations).byClaimId.get(claimId);
  return obligation?.mapping?.kind === "exact-contract-claim"
    && routeMatchesPair(obligation.mapping.routes, gateId, commandId);
}

function routeMatchesPair(routes, gateId, commandId) {
  const exactGateId = readString(gateId);
  const exactCommandId = readString(commandId);
  return Boolean(exactGateId && exactCommandId && Array.isArray(routes)
    && routes.some((route) => readString(route?.gateId) === exactGateId
      && readString(route?.commandId) === exactCommandId));
}

function readEvidenceEnvelopeClaimRefs(evidence) {
  return Array.isArray(evidence?.claim?.refs)
    ? [...new Set(evidence.claim.refs.map(readString).filter(Boolean))]
    : [];
}

export function isKnowledgeClosureComplete(value) {
  return validateKnowledgeClosure(value).valid;
}

export function validateKnowledgeClosure(value) {
  const errors = [];
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { valid: false, errors: ["Knowledge Closure must be an object."] };
  }
  if (value.status !== "complete") {
    errors.push("Knowledge Closure status must be complete.");
  }
  if (value.noNewKnowledge === true) {
    if (!readString(value.rationale)) {
      errors.push("noNewKnowledge requires a rationale.");
    }
    return { valid: errors.length === 0, errors, mode: "no-new-knowledge", entries: [] };
  }

  const entries = Array.isArray(value.entries)
    ? value.entries
    : Array.isArray(value.dispositions)
      ? value.dispositions
      : Array.isArray(value.items) ? value.items : [];
  if (entries.length === 0) {
    errors.push("Knowledge Closure requires at least one entry, or noNewKnowledge with rationale.");
  }
  const allowedKinds = new Set(KNOWLEDGE_CLOSURE_ENTRY_KINDS);
  entries.forEach((entry, index) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`Knowledge Closure entry ${index + 1} must be an object.`);
      return;
    }
    const kind = readString(entry.kind) ?? readString(entry.classification);
    if (!allowedKinds.has(kind)) {
      errors.push(`Knowledge Closure entry ${index + 1} has invalid kind.`);
    }
    const refs = Array.isArray(entry.refs) ? entry.refs.filter(readString) : [];
    if (refs.length === 0 && !readString(entry.statement)) {
      errors.push(`Knowledge Closure entry ${index + 1} requires refs or statement.`);
    }
    if (!readString(entry.rationale)) {
      errors.push(`Knowledge Closure entry ${index + 1} requires rationale.`);
    }
  });
  return { valid: errors.length === 0, errors, mode: "entries", entries: cloneJson(entries) };
}

export function normalizeAuthorityDecision(value, observedAt) {
  if (typeof value === "string" && value.trim()) {
    return {
      status: "invalid",
      rawDecision: value.trim(),
      decidedAt: observedAt
    };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return value;
  }
  return {
    ...cloneJson(value),
    status: value.status ?? value.decision ?? "approved",
    authority: value.authority ?? value.authorityId ?? value.role,
    decidedBy: value.decidedBy ?? value.actor ?? value.authority ?? value.authorityId,
    decisionType: value.decisionType ?? value.type ?? value.scope ?? "case-decision",
    decidedAt: value.decidedAt ?? observedAt
  };
}

export function validateAuthorityDecision(value, expectedAuthorities = [], authorityDeclarations = []) {
  const errors = [];
  if (!value || typeof value !== "object") {
    errors.push("An Authority Decision is required.");
  } else {
    if (value.status !== "approved" && value.status !== "accepted") {
      errors.push("Authority Decision must be approved.");
    }
    if (!readString(value.authority) || !readString(value.decidedBy)) {
      errors.push("Authority Decision requires authority and decidedBy.");
    }
    if (expectedAuthorities.length > 0 && value.authority && !expectedAuthorities.includes(value.authority)) {
      errors.push(`Authority ${value.authority} is not one of: ${expectedAuthorities.join(", ")}.`);
    }
    const decisionType = value.decisionType;
    const allowedTypes = new Set(AUTHORITY_DECISION_TYPES);
    if (!allowedTypes.has(decisionType)) {
      errors.push("decisionType must be case-decision, normative-amendment, or waiver.");
    } else if (decisionType === "case-decision") {
      if (!readString(value.rationale)) {
        errors.push("A Case Decision requires rationale.");
      }
    } else if (decisionType === "normative-amendment") {
      if (!Array.isArray(value.amendmentRefs) || value.amendmentRefs.filter(readString).length === 0) {
        errors.push("A Normative Amendment requires amendmentRefs.");
      }
      if (!readString(value.rationale)) {
        errors.push("A Normative Amendment requires rationale.");
      }
    } else if (decisionType === "waiver") {
      if (!readString(value.reason)) errors.push("A Waiver requires reason.");
      if (!isSubstantive(value.expiresAt ?? value.expiresWhen)) errors.push("A Waiver requires expiry.");
      if (!isSubstantive(value.scope)) errors.push("A Waiver requires scope.");
      if (!Array.isArray(value.compensatingControls) || value.compensatingControls.length === 0) {
        errors.push("A Waiver requires compensatingControls.");
      }
    }
    const declaration = authorityDeclarations.find((authority) => (
      (typeof authority === "string" ? authority : readString(authority?.id)) === value.authority
    ));
    const allowedDecisions = Array.isArray(declaration?.may)
      ? declaration.may.filter(readString)
      : [];
    if (declaration && allowedDecisions.length > 0 && !allowedDecisions.includes(decisionType)) {
      errors.push(`Authority ${value.authority} may not issue ${decisionType} Decisions.`);
    }
  }
  return { valid: errors.length === 0, errors };
}

export function compileAuthorityDecisionOptions(expectedAuthorities = [], authorityDeclarations = []) {
  const declarations = new Map((Array.isArray(authorityDeclarations) ? authorityDeclarations : [])
    .map((authority) => [
      typeof authority === "string" ? authority : readString(authority?.id),
      authority
    ])
    .filter(([authorityRef]) => Boolean(authorityRef)));
  return [...new Set((Array.isArray(expectedAuthorities) ? expectedAuthorities : [])
    .map(readString)
    .filter(Boolean))]
    .sort(compareCodeUnits)
    .flatMap((authorityRef) => {
      const declaration = declarations.get(authorityRef);
      const declaredTypes = Array.isArray(declaration?.may)
        ? declaration.may.map(readString).filter((type) => AUTHORITY_DECISION_TYPES.includes(type))
        : [];
      const allowedTypes = declaredTypes.length > 0
        ? [...new Set(declaredTypes)]
        : [...AUTHORITY_DECISION_TYPES];
      return allowedTypes.sort(compareCodeUnits).map((decisionType) => ({
        authorityRef,
        decisionType,
        requiredFields: authorityDecisionRequiredFields(decisionType)
      }));
    });
}

function authorityDecisionRequiredFields(decisionType) {
  if (decisionType === "case-decision") return ["decidedBy", "rationale"];
  if (decisionType === "normative-amendment") {
    return ["amendmentRefs", "decidedBy", "rationale"];
  }
  return ["compensatingControls", "decidedBy", "expiresAt", "reason", "scope"];
}

function compareCodeUnits(left, right) {
  return left === right ? 0 : left < right ? -1 : 1;
}

export function readExpectedAuthorities(model, change) {
  const declared = new Set();
  const projectAuthorities = model.projectDocument?.authorities?.decision;
  for (const authority of Array.isArray(projectAuthorities) ? projectAuthorities : []) {
    const id = typeof authority === "string" ? authority : readString(authority?.id);
    if (id) declared.add(id);
  }
  const selectedOutcomeIds = new Set(Array.isArray(change.planRefs) ? change.planRefs : []);
  const usesIntegrityOutcome = Array.isArray(model.plan?.outcomes)
    && model.plan.outcomes.some((outcome) => (
      selectedOutcomeIds.has(outcome?.id) && outcome?.kind === "integrity-maintenance"
    ));
  const usesOutcomeException = (Array.isArray(change.outcomeAlignment?.exceptions)
      && change.outcomeAlignment.exceptions.length > 0)
    || (Array.isArray(change.compilerInput?.outcomeExceptions)
      && change.compilerInput.outcomeExceptions.length > 0);
  if (change.changeKind === "plan-amendment" || usesIntegrityOutcome || usesOutcomeException) {
    const planAuthority = readString(model.plan?.authority);
    return planAuthority ? [planAuthority] : [];
  }
  const primaryModule = model.modules.find((module) => module.id === change.primaryModule);
  const moduleAuthority = readString(primaryModule?.decisionAuthority)
    ?? readString(primaryModule?.authority);
  if (moduleAuthority) {
    return [moduleAuthority];
  }
  return [...declared];
}

function normalizeEvidenceClaim(value) {
  if (typeof value === "string" && value.trim()) {
    return { id: `claim-${shortDigest(value.trim())}`, statement: value.trim() };
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw domainError("EVIDENCE_CLAIM_INVALID", "Evidence Claim must be a string or object.");
  }
  const statement = readString(value.statement) ?? readString(value.description);
  if (!statement) {
    throw domainError("EVIDENCE_CLAIM_INVALID", "Evidence Claim requires a statement.");
  }
  return {
    ...cloneJson(value),
    id: readString(value.id) ?? `claim-${shortDigest(statement)}`,
    statement
  };
}

function gitProvenance(git) {
  return {
    head: git.head,
    branch: git.branch,
    dirty: git.dirty,
    status: git.status,
    contentDigest: git.contentDigest,
    untracked: git.untracked
  };
}

function isSubstantive(value) {
  if (typeof value === "string") return Boolean(value.trim());
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object" && Object.keys(value).length > 0);
}

function isPositiveObservation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const status = readString(value.status)?.toLowerCase();
  return status === "passed" || status === "satisfied" || status === "success";
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function shortDigest(value) {
  return canonicalDigest(value).slice("sha256:".length, "sha256:".length + 16);
}

function domainError(code, message, details, statusCode = 422) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  if (details) error.details = details;
  return error;
}
