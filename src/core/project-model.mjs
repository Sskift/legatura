import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import { canonicalDigest, cloneJson } from "./canonical.mjs";
import { normalizeGateCommand } from "./command-runner.mjs";

export async function loadProjectModel(repoPath) {
  const root = path.join(repoPath, ".legatura");
  const projectDocument = await readOptionalJson(path.join(root, "project.json"));
  const modules = await readJsonCollection(path.join(root, "modules"), "modules");
  const contracts = await readJsonCollection(path.join(root, "contracts"), "contracts");
  const gates = await readJsonCollection(path.join(root, "gates"), "gates");
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
    knowledgeGaps,
    files: [
      ...(projectDocument ? [".legatura/project.json"] : []),
      ...modules.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
      ...contracts.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
      ...gates.flatMap((entry) => entry.sourceFile ? [entry.sourceFile] : []),
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

  validateAssuranceBoundary(model, moduleIndex, errors, warnings);

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    counts: {
      modules: model.modules.length,
      contracts: model.contracts.length,
      gates: model.gates.length,
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
    knowledgeGaps: model.knowledgeGaps,
    files: model.files,
    digest: model.digest
  });
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
