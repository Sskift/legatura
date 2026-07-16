import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { canonicalDigest, cloneJson } from "./canonical.mjs";
import { INTEGRITY_CHANGE_KINDS } from "./change-compiler.mjs";
import { normalizeGateCommand } from "./command-runner.mjs";

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
    digest: canonicalDigest(stripSourceMetadata(model))
  };
}

export function validateProjectModel(model) {
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
      if (!Array.isArray(command.claimRefs) || command.claimRefs.length === 0 || !command.claimRefs.every(readString)) {
        errors.push(issue("gate.claim.missing", commandLocation, "Gate command requires at least one Claim reference."));
      } else {
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
    }
  };
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
  }

  if (activeOutcomes === 0) {
    errors.push(issue("plan.active.missing", location, "Development Plan requires at least one active Outcome."));
  }
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
    const statusMatches = stage.status === "active"
      ? outcomeStatuses.includes("active")
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
