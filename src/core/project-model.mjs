import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { types as utilTypes } from "node:util";
import { canonicalDigest, cloneJson } from "./canonical.mjs";
import {
  compileClaimGateRouteIndex,
  INTEGRITY_CHANGE_KINDS,
  projectCompiledClaimGateRouteIndex,
  projectCompiledModuleClaimGateIndex
} from "./change-compiler.mjs";
import { normalizeGateCommand } from "./command-runner.mjs";
import {
  assertKnowledgeGapProofContractsPreserved,
  compileAllowedOutcomeTransitionRoutes,
  compileClaimGateRoutes,
  inspectBlockedOutcomeRouteReachability,
  validateOutcomeTransitionLedger
} from "./outcome-transitions.mjs";

export {
  assertKnowledgeGapProofContractsPreserved,
  compileClaimGateRouteIndex,
  compileClaimGateRoutes,
  projectCompiledClaimGateRouteIndex,
  projectCompiledModuleClaimGateIndex
};

const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;
export async function loadProjectModel(repoPath) {
  const root = path.join(repoPath, ".legatura");
  const projectDocument = await readOptionalJson(path.join(root, "project.json"));
  const modules = await readJsonCollection(path.join(root, "modules"), "modules");
  const contracts = await readJsonCollection(path.join(root, "contracts"), "contracts");
  const gates = await readJsonCollection(path.join(root, "gates"), "gates");
  const plan = await readOptionalJson(path.join(root, "plan.json"));
  const knowledgeGapDocument = await readOptionalJson(path.join(root, "knowledge-gaps.json"));
  const knowledgeGaps = Array.isArray(knowledgeGapDocument)
    ? knowledgeGapDocument
    : Array.isArray(knowledgeGapDocument?.gaps) ? knowledgeGapDocument.gaps : [];
  const model = {
    root,
    project: projectDocument?.project ?? projectDocument ?? null,
    projectDocument: projectDocument ?? null,
    modules,
    contracts,
    gates,
    plan: plan ?? null,
    knowledgeGaps,
    files: [
      ...(projectDocument ? [".legatura/project.json"] : []),
      ...modules.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
      ...contracts.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
      ...gates.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
      ...(plan !== undefined ? [".legatura/plan.json"] : []),
      ...(knowledgeGapDocument ? [".legatura/knowledge-gaps.json"] : [])
    ].sort()
  };

  return {
    ...model,
    digest: projectModelContentDigest(model)
  };
}

export function projectModelContentDigest(model) {
  return canonicalDigest(stripSourceMetadata(model));
}

export function validateProjectModel(model, options = {}) {
  const claimGateRouteProductRequest = readClaimGateRouteProductRequest(options);
  let claimGateRoutesByClaim = claimGateRouteProductRequest.supplied
    && claimGateRouteProductRequest.claimRefs !== undefined
    ? projectClaimGateRoutes(model, claimGateRouteProductRequest)
    : null;
  const errors = [];
  const warnings = [];
  if (!model.project || typeof model.project !== "object") {
    errors.push(issue("project.missing", ".legatura/project.json", "Project Model requires a project object."));
  } else if (!readId(model.project)) {
    errors.push(issue("project.id.missing", ".legatura/project.json", "Project requires a non-empty id."));
  }

  const moduleIndex = validateUniqueIds("module", model.modules, errors);
  const contractIndex = validateUniqueIds("contract", model.contracts, errors);
  const gateIndex = validateUniqueIds("gate", model.gates, errors);
  validateGlobalIds(moduleIndex, contractIndex, gateIndex, errors);

  const factAuthorities = new Set(
    asArray(model.projectDocument?.authorities?.fact)
      .map(readId)
      .filter(Boolean)
  );
  const decisionAuthorities = new Set(
    asArray(model.projectDocument?.authorities?.decision)
      .map((authority) => readReference(authority))
      .filter(Boolean)
  );
  const normativeSources = new Set(
    asArray(model.projectDocument?.normativeSources)
      .map(readId)
      .filter(Boolean)
  );
  const claimIndex = new Map();

  for (const module of model.modules) {
    const location = module.sourceFile ?? `module:${readId(module) ?? "unknown"}`;
    if (module.status !== "governed" && module.status !== "provisional" && module.status !== "opaque") {
      errors.push(issue("module.status.invalid", location, "Module status must be governed, provisional, or opaque."));
    }

    if (module.status === "governed") {
      if (!hasPaths(module.paths)) {
        errors.push(issue("module.paths.missing", location, "A governed Module requires paths.include."));
      }
      if (!isSubstantive(module.interface)) {
        errors.push(issue("module.interface.missing", location, "A governed Module requires a substantive interface."));
      }
      const factAuthority = readReference(module.factAuthority);
      if (!factAuthority) {
        errors.push(issue("module.fact-authority.missing", location, "A governed Module requires factAuthority."));
      } else if (factAuthorities.size > 0 && !factAuthorities.has(factAuthority)) {
        errors.push(issue("module.fact-authority.unknown", location, `Unknown factAuthority: ${factAuthority}.`));
      }
    }

    const decisionAuthority = readReference(module.decisionAuthority ?? module.authority);
    if (decisionAuthority && !decisionAuthorities.has(decisionAuthority)) {
      errors.push(issue(
        "module.decision-authority.unknown",
        location,
        `Unknown decisionAuthority: ${decisionAuthority}.`
      ));
    }

    for (const dependency of asArray(module.dependencies)) {
      const moduleId = readReference(dependency, ["module", "moduleId", "target", "id"]);
      if (!moduleId) {
        errors.push(issue("module.dependency.invalid", location, "A Module dependency requires a module reference."));
      } else if (!moduleIndex.has(moduleId)) {
        errors.push(issue("module.dependency.unknown", location, `Unknown dependency Module: ${moduleId}.`));
      }
      const contractId = readReference(dependency, ["via", "contract", "contractId"]);
      if (!contractId) {
        errors.push(issue("module.dependency.contract.missing", location, "A Module dependency requires a via Contract."));
      } else if (!contractIndex.has(contractId)) {
        errors.push(issue("module.dependency.contract.unknown", location, `Unknown dependency Contract: ${contractId}.`));
      } else {
        const contract = contractIndex.get(contractId);
        const owner = readReference(contract.owner, ["module", "moduleId", "id"]);
        if (moduleId && owner !== moduleId) {
          errors.push(issue(
            "module.dependency.contract.owner-mismatch",
            location,
            `Dependency Contract ${contractId} is owned by ${owner ?? "(missing)"}, not ${moduleId}.`
          ));
        }
        const consumers = asArray(contract.consumers)
          .map((consumer) => readReference(consumer, ["module", "moduleId", "id"]))
          .filter(Boolean);
        if (consumers.length > 0 && !consumers.includes(readId(module))) {
          warnings.push(issue(
            "module.dependency.contract.consumer-undeclared",
            location,
            `Module ${readId(module)} consumes ${contractId} but is not listed in Contract consumers.`
          ));
        }
      }
    }

    for (const contractId of asArray(module.publicContracts).map(readReference).filter(Boolean)) {
      if (!contractIndex.has(contractId)) {
        errors.push(issue("module.contract.unknown", location, `Unknown public Contract: ${contractId}.`));
      } else {
        const owner = readReference(contractIndex.get(contractId)?.owner, ["module", "moduleId", "id"]);
        if (owner !== readId(module)) {
          errors.push(issue(
            "module.contract.owner-mismatch",
            location,
            `Public Contract ${contractId} is owned by ${owner ?? "(missing)"}, not ${readId(module)}.`
          ));
        }
      }
    }
  }

  for (const contract of model.contracts) {
    const location = contract.sourceFile ?? `contract:${readId(contract) ?? "unknown"}`;
    const owner = readReference(contract.owner, ["module", "moduleId", "id"]);
    if (!owner) {
      errors.push(issue("contract.owner.missing", location, "Contract requires an owner Module."));
    } else if (!moduleIndex.has(owner)) {
      errors.push(issue("contract.owner.unknown", location, `Unknown Contract owner Module: ${owner}.`));
    }

    for (const consumer of asArray(contract.consumers)) {
      const moduleId = readReference(consumer, ["module", "moduleId", "id"]);
      if (!moduleId || !moduleIndex.has(moduleId)) {
        errors.push(issue("contract.consumer.unknown", location, `Unknown Contract consumer Module: ${moduleId ?? "(missing)"}.`));
      }
    }

    if (!Array.isArray(contract.claims) || contract.claims.length === 0) {
      errors.push(issue("contract.claims.missing", location, "Contract requires at least one Claim."));
    } else {
      validateUniqueIds(`claim in ${readId(contract) ?? "contract"}`, contract.claims, errors, location);
      for (const claim of contract.claims) {
        const claimId = readId(claim);
        if (claimId) {
          if (claimIndex.has(claimId)) {
            errors.push(issue("claim.id.duplicate", location, `Contract Claim id must be globally unique: ${claimId}.`));
          } else {
            claimIndex.set(claimId, { contractId: readId(contract), claim });
          }
        }
        if (!readString(claim?.statement)) {
          errors.push(issue("contract.claim.statement.missing", location, "Every Contract Claim requires a statement."));
        }
      }
    }

    for (const sourceId of asArray(contract.normativeSources).map(readReference).filter(Boolean)) {
      if (normativeSources.size > 0 && !normativeSources.has(sourceId)) {
        errors.push(issue("contract.normative-source.unknown", location, `Unknown normative source: ${sourceId}.`));
      }
    }
  }

  for (const gate of model.gates) {
    const location = gate.sourceFile ?? `gate:${readId(gate) ?? "unknown"}`;
    const commands = Array.isArray(gate.commands) ? gate.commands : gate.command ? [gate] : [];
    if (commands.length === 0) {
      errors.push(issue("gate.commands.missing", location, "Gate requires at least one command definition."));
      continue;
    }
    validateUniqueIds(`gate command in ${readId(gate) ?? "gate"}`, commands, errors, location);
    for (const command of commands) {
      const commandLocation = `${location}#${readId(command) ?? "command"}`;
      if (command.appliesTo !== undefined) {
        if (!Array.isArray(command.appliesTo)
          || command.appliesTo.length === 0
          || !command.appliesTo.every(readString)) {
          errors.push(issue(
            "gate.command.applies-to.invalid",
            commandLocation,
            "Gate command appliesTo must be a non-empty list of Module ids."
          ));
        } else {
          for (const moduleId of command.appliesTo) {
            if (!moduleIndex.has(moduleId)) {
              errors.push(issue(
                "gate.command.applies-to.unknown",
                commandLocation,
                `Gate command appliesTo references unknown Module: ${moduleId}.`
              ));
            }
          }
        }
      }
      if (command.applicability
        && typeof command.applicability === "object"
        && !Array.isArray(command.applicability)
        && (Object.hasOwn(command.applicability, "module")
          || Object.hasOwn(command.applicability, "modules"))) {
        errors.push(issue(
          "gate.command.applicability.module-scope",
          commandLocation,
          "Gate command Module scope belongs only in appliesTo; applicability describes non-Module conditions."
        ));
      }
      if (!normalizeGateCommand(command.command)) {
        errors.push(issue("gate.command.missing", commandLocation, "Gate command must be executable."));
      }
      if (command.timeoutMs !== undefined
        && (!Number.isFinite(command.timeoutMs) || command.timeoutMs <= 0)) {
        errors.push(issue(
          "gate.command.timeout.invalid",
          commandLocation,
          "Gate command timeoutMs must be a positive finite number when declared."
        ));
      }
      if (!Array.isArray(command.claimRefs) || command.claimRefs.length === 0 || !command.claimRefs.every(readString)) {
        errors.push(issue("gate.claim.missing", commandLocation, "Gate command requires at least one Claim reference."));
      } else {
        const duplicateClaimRefs = command.claimRefs.filter((claimRef, index, values) => (
          values.indexOf(claimRef) !== index
        ));
        if (duplicateClaimRefs.length > 0) {
          errors.push(issue(
            "gate.claim.duplicate",
            commandLocation,
            `Gate command Claim references must be unique: ${[...new Set(duplicateClaimRefs)].sort().join(", ")}.`
          ));
        }
        for (const claimRef of command.claimRefs) {
          if (!claimIndex.has(claimRef)) {
            errors.push(issue("gate.claim.unknown", commandLocation, `Gate command references unknown Contract Claim: ${claimRef}.`));
          }
        }
      }
      if (!isSubstantive(command.oracle)
        || !readString(command.oracle?.kind)
        || !readString(command.oracle?.description)) {
        errors.push(issue("gate.oracle.missing", commandLocation, "Gate command requires oracle.kind and oracle.description."));
      }
      for (const field of ["applicability", "discriminatoryPower", "residualUncertainty"]) {
        if (!isSubstantive(command[field])) {
          errors.push(issue(`gate.${field}.missing`, commandLocation, `Gate command requires ${field}.`));
        }
      }
    }
  }

  const changePolicy = model.projectDocument?.changePolicy ?? {};
  for (const field of ["defaultGate", "fullGate"]) {
    const gateId = readString(changePolicy[field]);
    if (gateId && !gateIndex.has(gateId)) {
      errors.push(issue(
        `change-policy.${field}.unknown`,
        ".legatura/project.json",
        `changePolicy.${field} references unknown Gate: ${gateId}.`
      ));
    }
  }
  const fullGateBefore = asArray(changePolicy.fullGateBefore).map(readString).filter(Boolean);
  if (fullGateBefore.length > 0 && !readString(changePolicy.fullGate)) {
    errors.push(issue(
      "change-policy.full-gate.missing",
      ".legatura/project.json",
      "changePolicy.fullGateBefore requires changePolicy.fullGate."
    ));
  }
  validateOutcomePolicy(changePolicy, errors);

  if (claimGateRouteProductRequest.supplied && !claimGateRoutesByClaim) {
    const proofClaimRefs = collectKnowledgeGapProofClaimRefs({
      knowledgeGaps: model.knowledgeGaps,
      claimIndex
    });
    claimGateRoutesByClaim = projectClaimGateRoutes(model, {
      ...claimGateRouteProductRequest,
      claimRefs: proofClaimRefs
    });
  }

  validateKnowledgeGaps({
    model,
    knowledgeGaps: model.knowledgeGaps,
    claimIndex,
    plan: model.plan,
    suppliedClaimGateRoutesByClaim: claimGateRoutesByClaim
  }, errors);

  validateDevelopmentPlan(model, claimIndex, decisionAuthorities, errors);

  validateAssuranceBoundary(model, moduleIndex, errors, warnings);

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    counts: {
      modules: model.modules.length,
      contracts: model.contracts.length,
      gates: model.gates.length,
      planOutcomes: asArray(model.plan?.outcomes).length,
      knowledgeGaps: model.knowledgeGaps.length
    },
    ...(claimGateRoutesByClaim ? { claimGateRoutesByClaim } : {})
  };
}

function projectClaimGateRoutes(model, request) {
  return projectCompiledClaimGateRouteIndex(request.index, {
    model,
    claimRefs: request.claimRefs,
    ...(request.limits === undefined ? {} : { limits: request.limits })
  }).routesByClaim;
}

function validateKnowledgeGaps({
  model,
  knowledgeGaps,
  claimIndex,
  plan,
  suppliedClaimGateRoutesByClaim
}, errors) {
  const seen = new Set();
  const gapIndex = new Map();
  const proofClaimOwners = new Map();
  const proofClaimRouteIndex = compileKnowledgeGapProofClaimRouteIndex({
    model,
    knowledgeGaps,
    claimIndex,
    suppliedClaimGateRoutesByClaim
  }, errors);
  for (const [index, gap] of asArray(knowledgeGaps).entries()) {
    const gapId = readId(gap);
    const location = `.legatura/knowledge-gaps.json#${gapId ?? index}`;
    if (!gapId) {
      errors.push(issue("knowledge-gap.id.missing", location, "Every Knowledge Gap requires a stable id."));
      continue;
    }
    if (seen.has(gapId)) {
      errors.push(issue("knowledge-gap.id.duplicate", location, `Duplicate Knowledge Gap id: ${gapId}.`));
      continue;
    }
    seen.add(gapId);
    gapIndex.set(gapId, gap);
    if (!readString(gap?.statement)) {
      errors.push(issue("knowledge-gap.statement.missing", location, "Every Knowledge Gap requires a substantive statement."));
    }
    if (Object.hasOwn(gap, "proofClaimRefs")) {
      if (!Array.isArray(gap.proofClaimRefs) || gap.proofClaimRefs.length === 0) {
        errors.push(issue(
          "knowledge-gap.proof-claim.invalid",
          location,
          "Knowledge Gap proofClaimRefs must be a non-empty list of exact Contract Claim ids."
        ));
      } else {
        const localRefs = new Set();
        for (const rawReference of gap.proofClaimRefs) {
          const reference = readString(rawReference);
          if (typeof rawReference !== "string" || reference !== rawReference) {
            errors.push(issue(
              "knowledge-gap.proof-claim.invalid",
              location,
              "Knowledge Gap proofClaimRefs entries must be exact non-empty Contract Claim ids."
            ));
            continue;
          }
          if (localRefs.has(reference)) {
            errors.push(issue(
              "knowledge-gap.proof-claim.duplicate",
              location,
              `Knowledge Gap proofClaimRefs repeats ${reference}.`
            ));
            continue;
          }
          localRefs.add(reference);
          if (!claimIndex.has(reference)) {
            errors.push(issue(
              "knowledge-gap.proof-claim.unknown",
              location,
              `Knowledge Gap proofClaimRefs references unknown Contract Claim: ${reference}.`
            ));
          } else if (proofClaimRouteIndex
            && !hasExecutableGateRoute(proofClaimRouteIndex, reference)) {
            errors.push(issue(
              "knowledge-gap.proof-claim.gate-route-missing",
              location,
              `Knowledge Gap proof Claim ${reference} requires at least one executable Gate command route at declaration time.`
            ));
          }
          const owner = proofClaimOwners.get(reference);
          if (owner && owner !== gapId) {
            errors.push(issue(
              "knowledge-gap.proof-claim.shared",
              location,
              `Closure proof Claim ${reference} is already owned by Knowledge Gap ${owner}.`
            ));
          } else {
            proofClaimOwners.set(reference, gapId);
          }
        }
      }
    }
    if (!["open", "closed"].includes(gap?.status)) {
      errors.push(issue("knowledge-gap.status.invalid", location, "Knowledge Gap status must be open or closed."));
      continue;
    }
    if (gap.status !== "closed") continue;
    if (!readString(gap.resolution) || !readString(gap.reopenTrigger)) {
      errors.push(issue(
        "knowledge-gap.closure.incomplete",
        location,
        "A closed Knowledge Gap requires resolution and reopenTrigger."
      ));
    }
    if (!Array.isArray(gap.closedBy) || gap.closedBy.length === 0) {
      errors.push(issue(
        "knowledge-gap.closed-by.missing",
        location,
        "A closed Knowledge Gap requires at least one Accepted Package reference."
      ));
      continue;
    }
    const refs = new Set();
    for (const reference of gap.closedBy) {
      const changeId = readString(reference?.changeId);
      const acceptanceDigest = readString(reference?.acceptanceDigest);
      const key = `${changeId ?? ""}\u0000${acceptanceDigest ?? ""}`;
      if (!reference || typeof reference !== "object" || Array.isArray(reference)
        || Object.keys(reference).some((field) => !["changeId", "acceptanceDigest"].includes(field))
        || !changeId || !DIGEST_PATTERN.test(acceptanceDigest ?? "")) {
        errors.push(issue(
          "knowledge-gap.closed-by.invalid",
          location,
          "Knowledge Gap closedBy entries require only changeId and a canonical sha256 acceptanceDigest."
        ));
      } else if (refs.has(key)) {
        errors.push(issue(
          "knowledge-gap.closed-by.duplicate",
          location,
          "Knowledge Gap closedBy Package references must be unique."
        ));
      }
      refs.add(key);
    }
  }

  validateKnowledgeGapBlockers({ knowledgeGaps, gapIndex, plan }, errors);

  for (const outcome of asArray(plan?.outcomes)) {
    for (const criterion of asArray(outcome?.acceptance?.criteria)) {
      const directClaimRefs = new Set(asArray(criterion?.claimRefs).map(readString).filter(Boolean));
      for (const gapRef of asArray(criterion?.gapRefs).map(readString).filter(Boolean)) {
        const gap = gapIndex.get(gapRef);
        const overlap = asArray(gap?.proofClaimRefs)
          .map(readString)
          .filter((reference) => reference && directClaimRefs.has(reference));
        if (overlap.length > 0) {
          errors.push(issue(
            "knowledge-gap.proof-claim.criterion-overlap",
            `.legatura/plan.json#${readId(criterion) ?? readId(outcome) ?? "criterion"}`,
            `Criterion direct claimRefs and Knowledge Gap ${gapRef} proofClaimRefs must be disjoint: ${[...new Set(overlap)].sort().join(", ")}.`
          ));
        }
      }
    }
  }
}

function validateKnowledgeGapBlockers({ knowledgeGaps, gapIndex, plan }, errors) {
  const outcomeIndex = new Map(asArray(plan?.outcomes)
    .map((outcome) => [readId(outcome), outcome])
    .filter(([outcomeId]) => Boolean(outcomeId)));
  const allowedRoutes = compileAllowedOutcomeTransitionRoutes(plan);
  const graph = new Map([...gapIndex.keys()].map((gapRef) => [gapRef, []]));

  for (const [index, gap] of asArray(knowledgeGaps).entries()) {
    const gapId = readId(gap);
    if (!gapId || !gapIndex.has(gapId)) continue;
    const location = `.legatura/knowledge-gaps.json#${gapId ?? index}`;
    const hasGapBlockers = Object.hasOwn(gap, "blocksGapClosureRefs");
    const hasRouteBlockers = Object.hasOwn(gap, "blocksOutcomeTransitionRoutes");
    if (!hasGapBlockers && !hasRouteBlockers) continue;

    if (!Array.isArray(gap.proofClaimRefs) || gap.proofClaimRefs.length === 0) {
      errors.push(issue(
        "knowledge-gap.blocker-source.proof-contract-missing",
        location,
        `Knowledge Gap ${gapId} must own a governed Closure Contract before declaring blocker relations.`
      ));
    }

    if (hasGapBlockers) {
      const references = gap.blocksGapClosureRefs;
      if (!Array.isArray(references) || references.length === 0) {
        errors.push(issue(
          "knowledge-gap.blocked-gap.invalid",
          location,
          "blocksGapClosureRefs must be a non-empty canonical list of exact Knowledge Gap ids."
        ));
      } else {
        const seen = new Set();
        for (const rawReference of references) {
          const reference = readString(rawReference);
          if (typeof rawReference !== "string" || reference !== rawReference) {
            errors.push(issue(
              "knowledge-gap.blocked-gap.invalid",
              location,
              "blocksGapClosureRefs entries must be exact non-empty Knowledge Gap ids."
            ));
            continue;
          }
          if (seen.has(reference)) {
            errors.push(issue(
              "knowledge-gap.blocked-gap.duplicate",
              location,
              `blocksGapClosureRefs repeats ${reference}.`
            ));
            continue;
          }
          seen.add(reference);
          if (reference === gapId) {
            errors.push(issue(
              "knowledge-gap.blocked-gap.self",
              location,
              `Knowledge Gap ${gapId} cannot block its own closure.`
            ));
          } else if (!gapIndex.has(reference)) {
            errors.push(issue(
              "knowledge-gap.blocked-gap.unknown",
              location,
              `blocksGapClosureRefs references unknown Knowledge Gap: ${reference}.`
            ));
          } else {
            if (gap?.status === "open" && gapIndex.get(reference)?.status === "closed") {
              errors.push(issue(
                "knowledge-gap.blocked-gap.already-closed",
                location,
                `Open Knowledge Gap ${gapId} cannot block already-closed Knowledge Gap ${reference}.`
              ));
            }
            graph.get(gapId).push(reference);
          }
        }
      }
    }

    if (hasRouteBlockers) {
      const descriptors = gap.blocksOutcomeTransitionRoutes;
      if (!Array.isArray(descriptors) || descriptors.length === 0) {
        errors.push(issue(
          "knowledge-gap.blocked-route.invalid",
          location,
          "blocksOutcomeTransitionRoutes must be a non-empty list of exact Outcome route descriptors."
        ));
      } else {
        const seen = new Set();
        for (const descriptor of descriptors) {
          const keys = descriptor && typeof descriptor === "object" && !Array.isArray(descriptor)
            ? Object.keys(descriptor).sort()
            : [];
          const outcomeRef = readString(descriptor?.outcomeRef);
          const from = readString(descriptor?.from);
          const to = readString(descriptor?.to);
          const exact = keys.length === 3
            && keys[0] === "from"
            && keys[1] === "outcomeRef"
            && keys[2] === "to"
            && descriptor.outcomeRef === outcomeRef
            && descriptor.from === from
            && descriptor.to === to;
          if (!exact || !outcomeRef || !from || !to) {
            errors.push(issue(
              "knowledge-gap.blocked-route.invalid",
              location,
              "Each blocked Outcome route must contain only exact non-empty outcomeRef, from, and to strings."
            ));
            continue;
          }
          const key = `${outcomeRef}\u0000${from}\u0000${to}`;
          if (seen.has(key)) {
            errors.push(issue(
              "knowledge-gap.blocked-route.duplicate",
              location,
              `blocksOutcomeTransitionRoutes repeats ${outcomeRef} ${from}->${to}.`
            ));
            continue;
          }
          seen.add(key);
          if (!outcomeIndex.has(outcomeRef)) {
            errors.push(issue(
              "knowledge-gap.blocked-route.outcome-unknown",
              location,
              `Blocked Outcome route references unknown Outcome: ${outcomeRef}.`
            ));
          }
          if (!allowedRoutes.has(`${from}->${to}`)) {
            errors.push(issue(
              "knowledge-gap.blocked-route.forbidden",
              location,
              `Frozen transition policy does not allow blocked route ${from}->${to}.`
            ));
          }
          if (gap?.status === "open" && outcomeIndex.has(outcomeRef)
            && allowedRoutes.has(`${from}->${to}`)) {
            const reachability = inspectBlockedOutcomeRouteReachability(plan, { outcomeRef, from, to });
            if (!reachability.valid) {
              errors.push(issue(
                reachability.reason === "blocked-route-transition-already-recorded"
                  ? "knowledge-gap.blocked-route.already-transitioned"
                  : "knowledge-gap.blocked-route.state-bypassed",
                location,
                reachability.reason === "blocked-route-transition-already-recorded"
                  ? `Open Knowledge Gap ${gapId} cannot block an Outcome route already present in the Transition ledger.`
                  : `Outcome ${outcomeRef} status ${reachability.currentStatus ?? "unknown"} is neither before ${from} nor reachable from it without consuming blocked edge ${from}->${to}.`
              ));
            }
          }
        }
      }
    }
  }

  const visiting = new Set();
  const visited = new Set();
  const stack = [];
  const reported = new Set();
  const visit = (gapRef) => {
    if (visited.has(gapRef)) return;
    if (visiting.has(gapRef)) {
      const start = stack.indexOf(gapRef);
      const cycle = [...stack.slice(start), gapRef];
      const signature = [...new Set(cycle)].sort().join("\u0000");
      if (!reported.has(signature)) {
        reported.add(signature);
        errors.push(issue(
          "knowledge-gap.blocker-cycle",
          `.legatura/knowledge-gaps.json#${gapRef}`,
          `Knowledge Gap blocker relations must be acyclic: ${cycle.join(" -> ")}.`
        ));
      }
      return;
    }
    visiting.add(gapRef);
    stack.push(gapRef);
    for (const targetRef of graph.get(gapRef) ?? []) visit(targetRef);
    stack.pop();
    visiting.delete(gapRef);
    visited.add(gapRef);
  };
  for (const gapRef of [...graph.keys()].sort()) visit(gapRef);
}

function compileKnowledgeGapProofClaimRouteIndex({
  model,
  knowledgeGaps,
  claimIndex,
  suppliedClaimGateRoutesByClaim
}, errors) {
  const claimRefs = collectKnowledgeGapProofClaimRefs({ knowledgeGaps, claimIndex });
  if (claimRefs.length === 0) return new Map();
  if (suppliedClaimGateRoutesByClaim) return suppliedClaimGateRoutesByClaim;
  try {
    const product = compileClaimGateRouteIndex(model, { claimRefs });
    return projectCompiledClaimGateRouteIndex(product, { model, claimRefs }).routesByClaim;
  } catch (error) {
    errors.push(issue(
      "knowledge-gap.proof-claim.route-index-invalid",
      ".legatura/knowledge-gaps.json",
      `Knowledge Gap proof Claim routes could not be compiled safely: ${readString(error?.code) ?? "unknown-error"}.`
    ));
    return null;
  }
}

function collectKnowledgeGapProofClaimRefs({ knowledgeGaps, claimIndex }) {
  return [...new Set(asArray(knowledgeGaps).flatMap((gap) => (
    asArray(gap?.proofClaimRefs)
      .filter((claimRef) => (
        typeof claimRef === "string"
          && readString(claimRef) === claimRef
          && claimIndex.has(claimRef)
      ))
  )))].sort();
}

function readClaimGateRouteProductRequest(options) {
  if (options === undefined) {
    return { supplied: false, index: null, claimRefs: undefined, limits: undefined };
  }
  if (!options || typeof options !== "object" || Array.isArray(options)
    || utilTypes.isProxy(options)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(options))) {
    throw invalidClaimGateRouteProductRequest(
      "Project Model validation options must be a plain process-local object."
    );
  }
  const allowed = new Set(["claimGateRouteIndex", "claimRefs", "limits"]);
  for (const key in options) {
    if (Object.hasOwn(options, key) && !allowed.has(key)) {
      throw invalidClaimGateRouteProductRequest(
        "Project Model validation options contain unsupported fields."
      );
    }
  }
  const supplied = Object.hasOwn(options, "claimGateRouteIndex");
  const index = readClaimGateRouteProductOption(options, "claimGateRouteIndex");
  const suppliedClaimRefs = readClaimGateRouteProductOption(options, "claimRefs");
  const limits = readClaimGateRouteProductOption(options, "limits");
  if (!supplied && (suppliedClaimRefs !== undefined || limits !== undefined)) {
    throw invalidClaimGateRouteProductRequest(
      "Claim coverage and limits require a compiler-produced Claim Gate route product."
    );
  }
  return { supplied, index, claimRefs: suppliedClaimRefs, limits };
}

function readClaimGateRouteProductOption(options, field) {
  if (!Object.hasOwn(options, field)) return undefined;
  const descriptor = Object.getOwnPropertyDescriptor(options, field);
  if (!descriptor || !Object.hasOwn(descriptor, "value")) {
    throw invalidClaimGateRouteProductRequest(
      "Project Model validation options cannot contain accessor properties."
    );
  }
  return descriptor.value;
}

function invalidClaimGateRouteProductRequest(message) {
  const error = new Error(message);
  error.code = "CLAIM_GATE_ROUTE_INDEX_REUSE_INVALID";
  error.statusCode = 422;
  return error;
}

function hasExecutableGateRoute(routeIndex, claimRef) {
  return asArray(routeIndex.get(claimRef)).some((route) => (
    Boolean(normalizeGateCommand(route.command)) && route.effectiveModuleRefs.length > 0
  ));
}

export function publicProjectModel(model) {
  return cloneJson({
    project: model.project,
    projectDocument: model.projectDocument,
    modules: stripSources(model.modules),
    contracts: stripSources(model.contracts),
    gates: stripSources(model.gates),
    plan: model.plan,
    knowledgeGaps: model.knowledgeGaps,
    files: model.files,
    digest: model.digest
  });
}

function validateDevelopmentPlan(model, claimIndex, decisionAuthorities, errors) {
  const location = ".legatura/plan.json";
  const required = model.projectDocument?.changePolicy?.requirePlanRefs === true;
  const plan = model.plan;

  if (!plan || typeof plan !== "object" || Array.isArray(plan)) {
    if (required) {
      errors.push(issue("plan.missing", location, "changePolicy.requirePlanRefs requires a Development Plan."));
    }
    return;
  }

  if (!readId(plan)) {
    errors.push(issue("plan.id.missing", location, "Development Plan requires a non-empty id."));
  }
  if (!readString(plan.northStar)) {
    errors.push(issue("plan.north-star.missing", location, "Development Plan requires a substantive northStar."));
  }
  const planAuthority = readReference(plan.authority);
  if (!planAuthority) {
    errors.push(issue("plan.authority.missing", location, "Development Plan requires a decision authority."));
  } else if (!decisionAuthorities.has(planAuthority)) {
    errors.push(issue("plan.authority.unknown", location, `Unknown Development Plan authority: ${planAuthority}.`));
  } else {
    const declaration = asArray(model.projectDocument?.authorities?.decision)
      .find((authority) => readReference(authority) === planAuthority);
    const allowedDecisions = asArray(declaration?.may).map(readString).filter(Boolean);
    if (!allowedDecisions.includes("normative-amendment")) {
      errors.push(issue(
        "plan.authority.amendment-forbidden",
        location,
        `Development Plan authority ${planAuthority} must be allowed to issue normative-amendment Decisions.`
      ));
    }
  }

  if (!Array.isArray(plan.outcomes) || plan.outcomes.length === 0) {
    errors.push(issue("plan.outcomes.missing", location, "Development Plan requires at least one Outcome."));
    return;
  }

  const allowedStatuses = new Set(["achieved", "active", "planned", "conditional", "retired"]);
  const outcomeIndex = new Map();
  for (const outcome of plan.outcomes) {
    const outcomeId = readId(outcome);
    const outcomeLocation = `${location}#${outcomeId ?? "outcome"}`;
    if (!outcomeId) {
      errors.push(issue("plan.outcome.id.missing", outcomeLocation, "Every Development Plan Outcome requires a stable id."));
      continue;
    }
    if (!/^LGT-[0-9]{3,}$/u.test(outcomeId)) {
      errors.push(issue("plan.outcome.id.unstable", outcomeLocation, `Outcome id must use the stable LGT-nnn form: ${outcomeId}.`));
    }
    if (outcomeIndex.has(outcomeId)) {
      errors.push(issue("plan.outcome.id.duplicate", outcomeLocation, `Duplicate Development Plan Outcome id: ${outcomeId}.`));
      continue;
    }
    outcomeIndex.set(outcomeId, outcome);
  }

  const stageIndex = validatePlanStages(plan, outcomeIndex, allowedStatuses, errors, location);
  validatePlanOutcomeControl(plan, stageIndex, outcomeIndex, errors, location);
  validatePlanDependencyCycles(outcomeIndex, errors, location);

  const gapIds = new Set(asArray(model.knowledgeGaps).map(readId).filter(Boolean));
  const alignmentMode = readString(model.projectDocument?.changePolicy?.outcomeAlignmentMode);
  let activeOutcomes = 0;
  for (const outcome of plan.outcomes) {
    const outcomeId = readId(outcome);
    const outcomeLocation = `${location}#${outcomeId ?? "outcome"}`;
    if (outcome?.status === "active") {
      activeOutcomes += 1;
    }
    if (!allowedStatuses.has(outcome?.status)) {
      errors.push(issue(
        "plan.outcome.status.invalid",
        outcomeLocation,
        "Outcome status must be achieved, active, planned, conditional, or retired."
      ));
    }
    if (!readString(outcome?.outcome)) {
      errors.push(issue("plan.outcome.statement.missing", outcomeLocation, "Every Outcome requires a substantive outcome statement."));
    }
    const stageId = readReference(outcome?.stage);
    if (!stageId) {
      errors.push(issue("plan.outcome.stage.missing", outcomeLocation, "Every Outcome requires a stage reference."));
    } else if (!stageIndex.has(stageId)) {
      errors.push(issue("plan.outcome.stage.unknown", outcomeLocation, `Unknown Development Plan stage: ${stageId}.`));
    } else if (!asArray(stageIndex.get(stageId)?.outcomeRefs).map(readReference).includes(outcomeId)) {
      errors.push(issue("plan.outcome.stage.unlisted", outcomeLocation, `Stage ${stageId} does not list Outcome ${outcomeId}.`));
    }

    if (outcome?.dependsOn !== undefined && !Array.isArray(outcome.dependsOn)) {
      errors.push(issue("plan.outcome.dependencies.invalid", outcomeLocation, "Outcome dependsOn must be a list of Outcome ids."));
    }
    for (const dependency of asArray(outcome?.dependsOn)) {
      const dependencyId = readReference(dependency);
      if (!dependencyId) {
        errors.push(issue("plan.outcome.dependency.invalid", outcomeLocation, "Outcome dependsOn entries must reference an Outcome id."));
      } else if (dependencyId === outcomeId) {
        errors.push(issue("plan.outcome.dependency.self", outcomeLocation, `Outcome ${outcomeId} cannot depend on itself.`));
      } else if (!outcomeIndex.has(dependencyId)) {
        errors.push(issue("plan.outcome.dependency.unknown", outcomeLocation, `Unknown dependency Outcome: ${dependencyId}.`));
      } else if (["active", "achieved"].includes(outcome?.status)
        && outcomeIndex.get(dependencyId)?.status !== "achieved") {
        errors.push(issue(
          "plan.outcome.dependency.unsatisfied",
          outcomeLocation,
          `${capitalize(outcome.status)} Outcome ${outcomeId} depends on ${dependencyId}, which is not achieved.`
        ));
      }
    }

    if (outcome?.kind === "integrity-maintenance") {
      const allowedKinds = asArray(outcome.allowedChangeKinds).map(readString).filter(Boolean);
      if (allowedKinds.length === 0 || allowedKinds.some((kind) => !INTEGRITY_CHANGE_KINDS.includes(kind))) {
        errors.push(issue(
          "plan.outcome.integrity-kinds.invalid",
          outcomeLocation,
          "An integrity-maintenance Outcome requires only the supported integrity repair Change kinds."
        ));
      }
    }

    const exitCriteria = outcome?.acceptance?.exitCriteria;
    if (!Array.isArray(exitCriteria) || exitCriteria.length === 0 || !exitCriteria.every(readString)) {
      errors.push(issue(
        "plan.outcome.acceptance.exit-criteria.missing",
        outcomeLocation,
        "Every Outcome requires at least one substantive acceptance.exitCriteria entry."
      ));
    }

    validatePlanReferences(outcome?.acceptance?.claimRefs, claimIndex, {
      errors,
      location: outcomeLocation,
      invalidCode: "plan.outcome.claim.invalid",
      unknownCode: "plan.outcome.claim.unknown",
      kind: "Contract Claim"
    });
    validatePlanReferences(outcome?.acceptance?.gapRefs, gapIds, {
      errors,
      location: outcomeLocation,
      invalidCode: "plan.outcome.gap.invalid",
      unknownCode: "plan.outcome.gap.unknown",
      kind: "Knowledge Gap"
    });
    validateOutcomeCriteria({
      outcome,
      outcomeId,
      location: outcomeLocation,
      claimIndex,
      gapIds,
      alignmentMode,
      errors
    });
  }

  const transitionValidation = validateOutcomeTransitionLedger(plan, model.knowledgeGaps);
  errors.push(...transitionValidation.errors);

  if (activeOutcomes === 0) {
    errors.push(issue("plan.active.missing", location, "Development Plan requires at least one active Outcome."));
  }
}

function validateOutcomePolicy(changePolicy, errors) {
  if (Object.hasOwn(changePolicy, "outcomeAlignmentMode")) {
    const value = readString(changePolicy.outcomeAlignmentMode);
    if (!value || !["declared", "enforced"].includes(value)) {
      errors.push(issue(
        "change-policy.outcomeAlignmentMode.invalid",
        ".legatura/project.json",
        "changePolicy.outcomeAlignmentMode must be declared or enforced."
      ));
    }
  }
  if (Object.hasOwn(changePolicy, "outcomeTransitionMode")) {
    const value = readString(changePolicy.outcomeTransitionMode);
    if (!value || !["declared", "enforced"].includes(value)) {
      errors.push(issue(
        "change-policy.outcomeTransitionMode.invalid",
        ".legatura/project.json",
        "changePolicy.outcomeTransitionMode must be declared or enforced."
      ));
    }
  }
  const alignmentMode = readString(changePolicy.outcomeAlignmentMode);
  const criterionSelection = readString(changePolicy.outcomeCriterionSelection);
  const declaresCriterionSelection = Object.hasOwn(changePolicy, "outcomeCriterionSelection");
  if (
    (declaresCriterionSelection || alignmentMode)
    && criterionSelection !== "unique-claim-match-or-explicit-hint"
  ) {
    errors.push(issue(
      "change-policy.outcome-criterion-selection.invalid",
      ".legatura/project.json",
      "Outcome alignment requires outcomeCriterionSelection unique-claim-match-or-explicit-hint."
    ));
  }
}

function validateOutcomeCriteria({
  outcome,
  outcomeId,
  location,
  claimIndex,
  gapIds,
  alignmentMode,
  errors
}) {
  const criteria = outcome?.acceptance?.criteria;
  if (!outcomeId) return;
  const required = alignmentMode === "enforced"
    && outcome?.status === "active"
    && outcome?.kind !== "integrity-maintenance";
  if (criteria === undefined) {
    if (required) {
      errors.push(issue(
        "plan.outcome.criteria.required",
        location,
        `Enforced active Outcome ${outcomeId} requires stable acceptance.criteria.`
      ));
    }
    return;
  }
  if (!Array.isArray(criteria) || criteria.length === 0) {
    errors.push(issue(
      "plan.outcome.criteria.invalid",
      location,
      "Outcome acceptance.criteria must be a non-empty list of Criterion objects."
    ));
    return;
  }

  const seenIds = new Set();
  const seenStatements = new Set();
  const criterionClaimRefs = new Set();
  const criterionGapRefs = new Set();
  const expectedId = new RegExp(`^${escapeRegExp(outcomeId)}-C[1-9][0-9]*$`, "u");
  for (const criterion of criteria) {
    const criterionId = readId(criterion);
    const criterionLocation = `${location}#${criterionId ?? "criterion"}`;
    if (!criterionId || !expectedId.test(criterionId)) {
      errors.push(issue(
        "plan.outcome.criterion.id.invalid",
        criterionLocation,
        `Criterion id must use the stable ${outcomeId}-Cnn form.`
      ));
    } else if (seenIds.has(criterionId)) {
      errors.push(issue(
        "plan.outcome.criterion.id.duplicate",
        criterionLocation,
        `Duplicate Criterion id: ${criterionId}.`
      ));
    } else {
      seenIds.add(criterionId);
    }

    const statement = readString(criterion?.statement);
    if (!statement) {
      errors.push(issue(
        "plan.outcome.criterion.statement.missing",
        criterionLocation,
        "Every Criterion requires a substantive statement."
      ));
    } else if (seenStatements.has(statement)) {
      errors.push(issue(
        "plan.outcome.criterion.statement.duplicate",
        criterionLocation,
        "Criterion statements must be unique within an Outcome."
      ));
    } else {
      seenStatements.add(statement);
    }

    validateCriterionReferences({
      criterion,
      field: "claimRefs",
      index: claimIndex,
      kind: "Contract Claim",
      location: criterionLocation,
      codePrefix: "plan.outcome.criterion.claim",
      union: criterionClaimRefs,
      errors
    });
    validateCriterionReferences({
      criterion,
      field: "gapRefs",
      index: gapIds,
      kind: "Knowledge Gap",
      location: criterionLocation,
      codePrefix: "plan.outcome.criterion.gap",
      union: criterionGapRefs,
      errors
    });
  }

  const exitCriteria = asArray(outcome?.acceptance?.exitCriteria).map(readString).filter(Boolean);
  if (!sameStringSet([...seenStatements], exitCriteria)) {
    errors.push(issue(
      "plan.outcome.criteria.statement-mirror",
      location,
      "Stable Criterion statements must exactly mirror acceptance.exitCriteria."
    ));
  }
  const acceptanceClaimRefs = asArray(outcome?.acceptance?.claimRefs).map(readReference).filter(Boolean);
  if (!sameStringSet([...criterionClaimRefs], acceptanceClaimRefs)) {
    errors.push(issue(
      "plan.outcome.criteria.claim-union",
      location,
      "Criterion claimRefs must exactly cover the Outcome acceptance.claimRefs set."
    ));
  }
  const acceptanceGapRefs = asArray(outcome?.acceptance?.gapRefs).map(readReference).filter(Boolean);
  if (!sameStringSet([...criterionGapRefs], acceptanceGapRefs)) {
    errors.push(issue(
      "plan.outcome.criteria.gap-union",
      location,
      "Criterion gapRefs must exactly cover the Outcome acceptance.gapRefs set."
    ));
  }
}

function validateCriterionReferences({ criterion, field, index, kind, location, codePrefix, union, errors }) {
  const refs = criterion?.[field];
  if (!Array.isArray(refs) || !refs.every(readString)) {
    errors.push(issue(`${codePrefix}.invalid`, location, `Criterion ${field} must be a list of ${kind} ids.`));
    return;
  }
  const seen = new Set();
  for (const value of refs) {
    const reference = readReference(value);
    if (seen.has(reference)) {
      errors.push(issue(`${codePrefix}.duplicate`, location, `Criterion ${field} repeats ${reference}.`));
      continue;
    }
    seen.add(reference);
    union.add(reference);
    if (!index.has(reference)) {
      errors.push(issue(`${codePrefix}.unknown`, location, `Unknown ${kind}: ${reference}.`));
    }
  }
}

function sameStringSet(left, right) {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return leftSet.size === left.length
    && rightSet.size === right.length
    && leftSet.size === rightSet.size
    && [...leftSet].every((value) => rightSet.has(value));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function validatePlanOutcomeControl(plan, stageIndex, outcomeIndex, errors, location) {
  if (plan.principles !== undefined
    && (!Array.isArray(plan.principles) || plan.principles.length === 0 || !plan.principles.every(readString))) {
    errors.push(issue("plan.principles.invalid", location, "Development Plan principles must be a non-empty list of substantive statements."));
  }

  if (plan.coreCompletion !== undefined) {
    const completionStage = readReference(plan.coreCompletion?.stage);
    if (!completionStage || !stageIndex.has(completionStage)) {
      errors.push(issue(
        "plan.core-completion.stage.unknown",
        location,
        `Development Plan coreCompletion must reference a declared stage: ${completionStage ?? "(missing)"}.`
      ));
    }
    if (!readString(plan.coreCompletion?.definition)) {
      errors.push(issue("plan.core-completion.definition.missing", location, "Development Plan coreCompletion requires a substantive definition."));
    }
  }

  if (plan.referenceAcceptanceScenario !== undefined) {
    const scenario = plan.referenceAcceptanceScenario;
    if (!readId(scenario) || !readString(scenario?.topology)) {
      errors.push(issue(
        "plan.reference-scenario.identity.invalid",
        location,
        "A referenceAcceptanceScenario requires an id and substantive topology."
      ));
    }
    if (!Array.isArray(scenario?.mustDemonstrate)
      || scenario.mustDemonstrate.length === 0
      || !scenario.mustDemonstrate.every(readString)) {
      errors.push(issue(
        "plan.reference-scenario.acceptance.missing",
        location,
        "A referenceAcceptanceScenario requires a non-empty mustDemonstrate list."
      ));
    }
  }

  if (plan.bootstrapBaseline !== undefined) {
    const bootstrap = plan.bootstrapBaseline;
    const outcomeRefs = asArray(bootstrap?.outcomeRefs).map(readReference).filter(Boolean);
    const unknownOutcomeRefs = outcomeRefs.filter((outcomeId) => !outcomeIndex.has(outcomeId));
    if (!/^[a-f0-9]{40}$/u.test(readString(bootstrap?.head) ?? "")
      || outcomeRefs.length === 0
      || unknownOutcomeRefs.length > 0
      || !readString(bootstrap?.rationale)
      || !readString(bootstrap?.residualUncertainty)) {
      errors.push(issue(
        "plan.bootstrap.invalid",
        location,
        "A bootstrapBaseline requires an exact Git head, known Outcome refs, rationale, and residual uncertainty."
      ));
    }
  }
}

function validatePlanStages(plan, outcomeIndex, allowedStatuses, errors, location) {
  const stageIndex = new Map();
  if (!Array.isArray(plan.stages) || plan.stages.length === 0) {
    errors.push(issue("plan.stages.missing", location, "Development Plan requires at least one stage."));
    return stageIndex;
  }
  const listedOutcomes = new Set();
  for (const stage of plan.stages) {
    const stageId = readId(stage);
    const stageLocation = `${location}#stage:${stageId ?? "unknown"}`;
    if (!stageId) {
      errors.push(issue("plan.stage.id.missing", stageLocation, "Every Development Plan stage requires an id."));
      continue;
    }
    if (stageIndex.has(stageId)) {
      errors.push(issue("plan.stage.id.duplicate", stageLocation, `Duplicate Development Plan stage id: ${stageId}.`));
      continue;
    }
    stageIndex.set(stageId, stage);
    if (!allowedStatuses.has(stage.status)) {
      errors.push(issue("plan.stage.status.invalid", stageLocation, "Stage status must use a Development Plan Outcome status."));
    }
    if (!Array.isArray(stage.outcomeRefs) || stage.outcomeRefs.length === 0) {
      errors.push(issue("plan.stage.outcome-refs.missing", stageLocation, "Every stage requires at least one Outcome reference."));
      continue;
    }
    for (const reference of stage.outcomeRefs) {
      const outcomeId = readReference(reference);
      if (!outcomeId || !outcomeIndex.has(outcomeId)) {
        errors.push(issue("plan.stage.outcome.unknown", stageLocation, `Unknown stage Outcome: ${outcomeId ?? "(missing)"}.`));
        continue;
      }
      if (listedOutcomes.has(outcomeId)) {
        errors.push(issue("plan.stage.outcome.duplicate", stageLocation, `Outcome ${outcomeId} is listed by more than one stage.`));
      }
      listedOutcomes.add(outcomeId);
      if (readReference(outcomeIndex.get(outcomeId)?.stage) !== stageId) {
        errors.push(issue("plan.stage.outcome.mismatch", stageLocation, `Outcome ${outcomeId} does not declare stage ${stageId}.`));
      }
    }
    const outcomeStatuses = stage.outcomeRefs
      .map(readReference)
      .map((outcomeId) => outcomeIndex.get(outcomeId)?.status)
      .filter(Boolean);
    const hasOutcomeHandoff = outcomeStatuses.includes("achieved")
      && outcomeStatuses.some((status) => ["planned", "conditional"].includes(status));
    const statusMatches = stage.status === "active"
      ? outcomeStatuses.includes("active") || hasOutcomeHandoff
      : outcomeStatuses.length > 0 && outcomeStatuses.every((status) => status === stage.status);
    if (!statusMatches) {
      errors.push(issue(
        "plan.stage.status.mismatch",
        stageLocation,
        `Stage ${stageId} status ${stage.status} does not match its Outcome statuses.`
      ));
    }
  }
  return stageIndex;
}

function validatePlanDependencyCycles(outcomeIndex, errors, location) {
  const visiting = new Set();
  const visited = new Set();
  const path = [];
  let reported = false;

  function visit(outcomeId) {
    if (reported || visited.has(outcomeId)) return;
    if (visiting.has(outcomeId)) {
      const start = path.indexOf(outcomeId);
      const cycle = [...path.slice(start), outcomeId];
      errors.push(issue(
        "plan.outcome.dependency.cycle",
        `${location}#${outcomeId}`,
        `Development Plan Outcome dependencies must be acyclic: ${cycle.join(" -> ")}.`
      ));
      reported = true;
      return;
    }
    visiting.add(outcomeId);
    path.push(outcomeId);
    for (const dependency of asArray(outcomeIndex.get(outcomeId)?.dependsOn).map(readReference).filter(Boolean)) {
      if (outcomeIndex.has(dependency)) visit(dependency);
    }
    path.pop();
    visiting.delete(outcomeId);
    visited.add(outcomeId);
  }

  for (const outcomeId of outcomeIndex.keys()) visit(outcomeId);
}

function validatePlanReferences(references, index, options) {
  if (references === undefined) {
    return;
  }
  if (!Array.isArray(references)) {
    options.errors.push(issue(options.invalidCode, options.location, `${options.kind} references must be a list.`));
    return;
  }
  for (const reference of references) {
    const id = readReference(reference);
    if (!id) {
      options.errors.push(issue(options.invalidCode, options.location, `${options.kind} reference requires an id.`));
    } else if (!index.has(id)) {
      options.errors.push(issue(options.unknownCode, options.location, `Unknown ${options.kind}: ${id}.`));
    }
  }
}

function validateAssuranceBoundary(model, moduleIndex, errors, warnings) {
  const boundary = model.projectDocument?.assuranceBoundary;
  for (const state of ["governed", "provisional"]) {
    for (const entry of asArray(boundary?.[state])) {
      const moduleId = readReference(entry, ["module", "moduleId", "id"]);
      if (!moduleId || !moduleIndex.has(moduleId)) {
        errors.push(issue("assurance.module.unknown", ".legatura/project.json", `Unknown ${state} assurance Module: ${moduleId ?? "(missing)"}.`));
      } else if (moduleIndex.get(moduleId).status !== state) {
        errors.push(issue("assurance.module.status-mismatch", ".legatura/project.json", `Assurance state ${state} disagrees with Module ${moduleId}.`));
      }
    }
  }
  for (const entry of asArray(boundary?.opaque)) {
    const moduleId = readReference(entry, ["module", "moduleId", "id"]);
    if (moduleId && !moduleIndex.has(moduleId)) {
      warnings.push(issue("assurance.opaque.unmodeled", ".legatura/project.json", `Opaque dependency is intentionally unmodeled: ${moduleId}.`));
    } else if (moduleId && moduleIndex.get(moduleId).status !== "opaque") {
      errors.push(issue("assurance.module.status-mismatch", ".legatura/project.json", `Assurance state opaque disagrees with Module ${moduleId}.`));
    }
  }
}

function validateUniqueIds(kind, entries, errors, fallbackLocation) {
  const index = new Map();
  for (const entry of entries) {
    const location = entry?.sourceFile ?? fallbackLocation ?? kind;
    const id = readId(entry);
    if (!id) {
      errors.push(issue(`${kind}.id.missing`, location, `${capitalize(kind)} requires a non-empty id.`));
      continue;
    }
    if (index.has(id)) {
      errors.push(issue(`${kind}.id.duplicate`, location, `Duplicate ${kind} id: ${id}.`));
      continue;
    }
    index.set(id, entry);
  }
  return index;
}

function validateGlobalIds(moduleIndex, contractIndex, gateIndex, errors) {
  const seen = new Map();
  for (const [kind, index] of [["module", moduleIndex], ["contract", contractIndex], ["gate", gateIndex]]) {
    for (const id of index.keys()) {
      if (seen.has(id)) {
        errors.push(issue("model.id.duplicate", index.get(id).sourceFile ?? kind, `Model id ${id} is reused by ${seen.get(id)} and ${kind}.`));
      } else {
        seen.set(id, kind);
      }
    }
  }
}

async function readJsonCollection(directory, key) {
  let names;
  try {
    names = await readdir(directory);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return [];
    }
    throw error;
  }

  const entries = [];
  for (const name of names.filter((entry) => entry.endsWith(".json")).sort()) {
    const fullPath = path.join(directory, name);
    const value = await readRequiredJson(fullPath);
    const values = Array.isArray(value)
      ? value
      : Array.isArray(value?.[key]) ? value[key] : [value];
    for (const entry of values) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
        throw modelError("MODEL_DOCUMENT_INVALID", `Expected an object in ${fullPath}.`, { file: fullPath });
      }
      entries.push({ ...entry, sourceFile: path.posix.join(".legatura", key, name) });
    }
  }
  return entries;
}

async function readOptionalJson(filePath) {
  try {
    return await readRequiredJson(filePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

async function readRequiredJson(filePath) {
  const text = await readFile(filePath, "utf8");
  try {
    return JSON.parse(text);
  } catch (error) {
    throw modelError("MODEL_JSON_INVALID", `Invalid JSON in ${filePath}: ${error.message}`, { file: filePath });
  }
}

function stripSourceMetadata(model) {
  return {
    projectDocument: model.projectDocument,
    modules: stripSources(model.modules),
    contracts: stripSources(model.contracts),
    gates: stripSources(model.gates),
    plan: model.plan,
    knowledgeGaps: model.knowledgeGaps
  };
}

function stripSources(entries) {
  return entries.map(({ sourceFile: _sourceFile, ...entry }) => entry);
}

function hasPaths(value) {
  if (Array.isArray(value)) {
    return value.some(readString);
  }
  if (typeof value === "string") {
    return Boolean(readString(value));
  }
  return value && typeof value === "object"
    && Array.isArray(value.include)
    && value.include.some(readString);
}

function isSubstantive(value) {
  if (typeof value === "string") {
    return Boolean(value.trim());
  }
  if (Array.isArray(value)) {
    return value.length > 0 && value.some(isSubstantive);
  }
  return Boolean(value && typeof value === "object" && Object.keys(value).length > 0);
}

function readId(value) {
  return readString(value?.id);
}

function readReference(value, keys = ["id", "module", "moduleId", "contract", "contractId", "target"]) {
  if (typeof value === "string") {
    return readString(value);
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  for (const key of keys) {
    const candidate = readString(value[key]);
    if (candidate) {
      return candidate;
    }
  }
  return undefined;
}

function readString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function issue(code, location, message) {
  return { code, location, message };
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function modelError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = 422;
  error.details = details;
  return error;
}
