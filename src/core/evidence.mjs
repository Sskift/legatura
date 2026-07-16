import { canonicalDigest, cloneJson } from "./canonical.mjs";

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
  { approvedObligationIds = [], verificationSubjectDigest, trustedEvidenceBindings = [] } = {}
) {
  const covered = new Set();
  const approved = new Set(approvedObligationIds);
  const claimById = new Map(claims.map((claim) => [claim.id, claim]));
  const trustedDigests = new Map(trustedEvidenceBindings
    .filter((binding) => readString(binding?.id) && readString(binding?.digest))
    .map((binding) => [binding.id, binding.digest]));
  const untrustedEvidenceIds = [];
  const staleEvidenceIds = [];
  const mismatchedClaimEvidenceIds = [];
  for (const item of evidence) {
    if (!isPositiveObservation(item.observation)) {
      continue;
    }
    if (trustedDigests.get(item.id) !== canonicalDigest(item)) {
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
    const matchingClaim = claimById.get(item.claim?.id);
    if (matchingClaim && item.claim?.statement === matchingClaim.statement) {
      covered.add(item.claim.id);
    } else if (matchingClaim) {
      mismatchedClaimEvidenceIds.push(item.id);
    }
    for (const binding of item.directSupportBindings ?? []) {
      const directClaim = claimById.get(binding?.claimId);
      if (directClaim && binding?.claimStatement === directClaim.statement) {
        covered.add(binding.claimId);
      } else if (directClaim) {
        mismatchedClaimEvidenceIds.push(item.id);
      }
    }
    for (const binding of item.supportBindings ?? []) {
      if (approved.has(binding?.obligationId) && claimById.has(binding?.claimId)) {
        covered.add(binding.claimId);
      }
    }
  }
  const uncoveredClaimIds = claims.map((claim) => claim.id).filter((id) => !covered.has(id));
  return {
    satisfied: claims.length > 0 && uncoveredClaimIds.length === 0,
    coveredClaimIds: [...covered],
    uncoveredClaimIds,
    untrustedEvidenceIds,
    staleEvidenceIds,
    mismatchedClaimEvidenceIds
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
    return requested && authoritative?.statement === requested.statement ? [requested] : [];
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
  const allowedKinds = new Set(["model-amendment", "model-gap", "ephemeral"]);
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
    const allowedTypes = new Set(["case-decision", "normative-amendment", "waiver"]);
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
  if (change.changeKind === "plan-amendment" || usesIntegrityOutcome) {
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

function domainError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = 422;
  if (details) error.details = details;
  return error;
}
