import assert from "node:assert/strict";
import test from "node:test";

import {
  ARCHITECTURE_PROFILE_LIMITS,
  compileArchitectureProfile
} from "../../src/core/architecture-profile.mjs";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import {
  compileClaimGateRouteIndex,
  compileClaimGateRoutes
} from "../../src/core/change-compiler.mjs";
import {
  loadProjectModel,
  projectModelContentDigest,
  validateProjectModel
} from "../../src/core/project-model.mjs";

const PROFILE_CLAIM = "architecture-profile-relations-are-exact";
const SECOND_PROFILE_SOURCE_CLAIM = "context-capsule-cannot-broaden-scope";

test("Architecture Profiles preserve exact typed relations without aggregating assurance", async () => {
  const model = await loadProjectModel(process.cwd());
  const source = profileSource(model);
  const changeFacts = createChangeFacts(model, source);
  const profile = compileArchitectureProfile({ model, source, changeFacts });
  assert.equal(model.digest, projectModelContentDigest(model));
  const allClaimRefs = model.contracts
    .flatMap((contract) => contract.claims)
    .map((claim) => claim.id);
  const routeIndex = compileClaimGateRouteIndex(model, { claimRefs: allClaimRefs });
  assert.deepEqual([...routeIndex.keys()], [...new Set(allClaimRefs)].sort());
  for (const claimRef of allClaimRefs) {
    assert.deepEqual(
      routeIndex.get(claimRef),
      compileClaimGateRoutes(model, claimRef),
      `indexed routes for ${claimRef} remain exact with the scalar compiler Interface`
    );
  }

  const reorderedFacts = structuredClone(changeFacts);
  reorderedFacts.reverse();
  for (const fact of reorderedFacts) {
    fact.contributions.reverse();
    fact.evidence.reverse();
  }
  assert.deepEqual(
    compileArchitectureProfile({ model, source, changeFacts: reorderedFacts }),
    profile,
    "normalized Change-fact ordering must not alter the graph or digest"
  );

  const criterion = profile.entities.criteria.find((item) => item.id === "LGT-010-C1");
  assert.equal(criterion.outcomeRef, "LGT-010");
  assert.ok(profile.relations.criterionClaims.some((relation) => (
    relation.criterionRef === criterion.id
      && relation.claimRef === "project-model-references-are-consistent"
  )));
  const profileRoute = routeIndex.get(PROFILE_CLAIM)[0];
  const routeRelation = profile.relations.claimGateRoutes.find((relation) => (
    relation.claimRef === PROFILE_CLAIM
  ));
  const compiledRoute = profile.entities.routes.find((route) => route.id === routeRelation.routeRef);
  assert.equal(compiledRoute.gateRef, profileRoute.gateId);
  assert.equal(compiledRoute.commandRef, profileRoute.commandId);
  assert.equal(compiledRoute.routeDigest, canonicalDigest(profileRoute));
  assert.equal(compiledRoute.commandDigest, canonicalDigest(profileRoute.command));
  assert.equal(Object.hasOwn(compiledRoute, "command"), false, "command argv remains detail-only");

  assert.equal(profile.relations.contributions.length, 1);
  assert.equal(profile.relations.contributions[0].semantics, "relevance-only");
  assert.equal(profile.relations.currentEvidenceClaimAssociations.length, 2);
  assert.equal(profile.relations.historicalEvidenceClaimAssociations.length, 1);
  const unsupportedCurrencies = new Set(["stale", "invalid"]);
  const associatedEvidenceRefs = new Set([
    ...profile.relations.currentEvidenceClaimAssociations,
    ...profile.relations.historicalEvidenceClaimAssociations
  ].map((relation) => relation.evidenceRef));
  for (const evidence of profile.entities.evidence) {
    if (unsupportedCurrencies.has(evidence.currency)) {
      assert.equal(associatedEvidenceRefs.has(evidence.id), false);
    }
  }
  const crossClaim = profile.relations.currentEvidenceClaimAssociations.find(
    (relation) => relation.associationKind === "cross-claim"
  );
  assert.equal(crossClaim.sourceClaimRef, PROFILE_CLAIM);
  assert.equal(crossClaim.targetClaimRef, "project-model-references-are-consistent");
  assert.match(crossClaim.authorityDecisionDigest, /^sha256:/u);
  const crossEvidence = profile.entities.evidence.find((item) => item.id === crossClaim.evidenceRef);
  assert.deepEqual(crossEvidence.claimEnvelopeRefs, [PROFILE_CLAIM]);

  const multiSourceModel = structuredClone(model);
  const multiSourceCommand = multiSourceModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  multiSourceCommand.claimRefs.push(SECOND_PROFILE_SOURCE_CLAIM);
  multiSourceModel.digest = projectModelContentDigest(multiSourceModel);
  const multiSource = profileSource(multiSourceModel);
  const multiSourceFacts = createChangeFacts(multiSourceModel, multiSource);
  const multiSourceEvidence = multiSourceFacts[0].evidence[0];
  multiSourceEvidence.claimEnvelopeRefs.push(SECOND_PROFILE_SOURCE_CLAIM);
  multiSourceEvidence.claimAssociations.push({
    ...structuredClone(multiSourceEvidence.claimAssociations[1]),
    sourceClaimRef: SECOND_PROFILE_SOURCE_CLAIM
  });
  const multiSourceProfile = compileArchitectureProfile({
    model: multiSourceModel,
    source: multiSource,
    changeFacts: multiSourceFacts
  });
  const multiSourceRouteIndex = compileClaimGateRouteIndex(multiSourceModel, {
    claimRefs: [PROFILE_CLAIM, SECOND_PROFILE_SOURCE_CLAIM]
  });
  const sharedCommandRoutes = [PROFILE_CLAIM, SECOND_PROFILE_SOURCE_CLAIM]
    .map((claimRef) => multiSourceRouteIndex.get(claimRef).find((route) => (
      route.gateId === "architecture-profile"
        && route.commandId === multiSourceCommand.id
    )));
  assert.ok(sharedCommandRoutes.every(Boolean));
  assert.equal(
    canonicalDigest(sharedCommandRoutes[0].command),
    canonicalDigest(sharedCommandRoutes[1].command)
  );
  assert.notEqual(canonicalDigest(sharedCommandRoutes[0]), canonicalDigest(sharedCommandRoutes[1]));
  for (const route of sharedCommandRoutes) {
    const routeRelation = multiSourceProfile.relations.claimGateRoutes.find((relation) => (
      relation.claimRef === route.claimRef
        && multiSourceProfile.entities.routes.some((item) => (
          item.id === relation.routeRef
            && item.gateRef === route.gateId
            && item.commandRef === route.commandId
        ))
    ));
    const projectedRoute = multiSourceProfile.entities.routes.find(
      (item) => item.id === routeRelation?.routeRef
    );
    assert.equal(projectedRoute?.routeDigest, canonicalDigest(route));
    assert.equal(projectedRoute?.commandDigest, canonicalDigest(route.command));
  }
  const untouchedSecondRoute = structuredClone(sharedCommandRoutes[1]);
  sharedCommandRoutes[0].command[0] = "alias-probe";
  sharedCommandRoutes[0].oracle.aliasProbe = true;
  assert.deepEqual(
    sharedCommandRoutes[1],
    untouchedSecondRoute,
    "fanout routes do not share mutable command or metadata aliases"
  );
  const sharedObligationRelations = multiSourceProfile.relations.currentEvidenceClaimAssociations
    .filter((relation) => relation.obligationRef === "profile-cross-claim-obligation");
  assert.deepEqual(
    sharedObligationRelations.map((relation) => relation.sourceClaimRef).sort(),
    [PROFILE_CLAIM, SECOND_PROFILE_SOURCE_CLAIM].sort(),
    "one obligation retains every distinct exact source Claim route"
  );
  assert.ok(profile.entities.residuals.some((item) => item.ownerKind === "route"));
  assert.ok(profile.entities.residuals.some((item) => item.ownerKind === "evidence"));
  assert.ok(profile.entities.gaps.some((item) => item.id === "architecture-acceptance-profile-not-projected"));
  assertProfileContainsNoAggregateOrBody(profile);

  const { profileDigest, ...content } = profile;
  assert.equal(profileDigest, canonicalDigest(content));
  assert.ok(Buffer.byteLength(JSON.stringify(profile), "utf8") <= ARCHITECTURE_PROFILE_LIMITS.profileBytes);
});

test("Architecture Profile compilation fails closed on ambiguous, dangling, forged, or unbounded facts", async () => {
  const model = await loadProjectModel(process.cwd());
  const source = profileSource(model);
  const legalFacts = createChangeFacts(model, source);
  const allClaimRefs = model.contracts
    .flatMap((contract) => contract.claims)
    .map((claim) => claim.id);
  assert.throws(
    () => compileClaimGateRouteIndex(model, {
      claimRefs: allClaimRefs,
      limits: { routes: 1 }
    }),
    (error) => (
      error?.code === "CLAIM_GATE_ROUTE_INDEX_LIMIT_EXCEEDED"
        && error?.statusCode === 413
        && error?.details?.dimension === "routes"
    ),
    "a caller-tightened route budget fails closed inside the shared compiler Interface"
  );
  const unmatchedModel = structuredClone(model);
  const oversizedUnmatchedText = "unmatched".repeat(512);
  unmatchedModel.gates.unshift({
    id: oversizedUnmatchedText,
    appliesTo: [oversizedUnmatchedText],
    commands: [{ id: oversizedUnmatchedText, claimRefs: ["unselected-claim"] }]
  });
  unmatchedModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands.unshift({ id: oversizedUnmatchedText, claimRefs: ["unselected-claim"] });
  assert.deepEqual(
    compileClaimGateRouteIndex(unmatchedModel, { claimRefs: [PROFILE_CLAIM] })
      .get(PROFILE_CLAIM),
    compileClaimGateRoutes(model, PROFILE_CLAIM),
    "unmatched Gate and command fields remain outside selected Claim route semantics"
  );
  const accessorModel = structuredClone(model);
  const accessorCommand = accessorModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  const specialOracle = JSON.parse(
    '{"__proto__":{"polluted":true},"constructor":"exact","toJSON":"literal"}'
  );
  let accessorHits = 0;
  Object.defineProperty(accessorCommand, "oracle", {
    configurable: true,
    enumerable: true,
    get() {
      accessorHits += 1;
      return specialOracle;
    }
  });
  assert.throws(
    () => compileClaimGateRouteIndex(accessorModel, { claimRefs: [PROFILE_CLAIM] }),
    (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID"
  );
  assert.equal(accessorHits, 0, "route indexing rejects accessors without executing them");
  Object.defineProperty(accessorCommand, "oracle", {
    configurable: true,
    enumerable: true,
    value: specialOracle,
    writable: true
  });
  const specialRoute = compileClaimGateRouteIndex(accessorModel, {
    claimRefs: [PROFILE_CLAIM]
  }).get(PROFILE_CLAIM).find((route) => (
    route.gateId === "architecture-profile" && route.commandId === accessorCommand.id
  ));
  assert.ok(specialRoute);
  assert.deepEqual(specialRoute.oracle, specialOracle);
  assert.equal(Object.hasOwn(specialRoute.oracle, "__proto__"), true);
  assert.throws(
    () => validateProjectModel(model, {
      claimGateRouteIndexRequest: new Map([[PROFILE_CLAIM, []]])
    }),
    (error) => error?.code === "CLAIM_GATE_ROUTE_INDEX_INPUT_INVALID"
  );
  const forgedModel = structuredClone(model);
  const forgedClaim = forgedModel.contracts
    .flatMap((contract) => contract.claims)
    .find((claim) => claim.id === PROFILE_CLAIM);
  forgedClaim.statement = `${forgedClaim.statement} Forged without rebinding the digest.`;
  const oversizedModel = structuredClone(model);
  const oversizedCommand = oversizedModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  oversizedCommand.claimRefs = Array.from(
    { length: ARCHITECTURE_PROFILE_LIMITS.refsPerFact + 1 },
    () => PROFILE_CLAIM
  );
  const oversizedArgvModel = structuredClone(model);
  const oversizedArgvCommand = oversizedArgvModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  oversizedArgvCommand.command = {
    command: "node",
    args: Array.from(
      { length: ARCHITECTURE_PROFILE_LIMITS.refsPerFact + 1 },
      () => "--version"
    )
  };
  const oversizedArgTextModel = structuredClone(model);
  const oversizedArgTextCommand = oversizedArgTextModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  oversizedArgTextCommand.command = [
    "node",
    "x".repeat(ARCHITECTURE_PROFILE_LIMITS.textBytes + 1)
  ];
  const oversizedMetadataModel = structuredClone(model);
  const oversizedMetadataCommand = oversizedMetadataModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  oversizedMetadataCommand.oracle.unbounded = Array.from(
    { length: ARCHITECTURE_PROFILE_LIMITS.refsPerFact + 1 },
    () => "opaque-oracle-detail"
  );
  const overDepthModel = structuredClone(model);
  const overDepthCommand = overDepthModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  let nestedOracleValue = "bounded-leaf";
  for (let depth = 0; depth <= ARCHITECTURE_PROFILE_LIMITS.depth; depth += 1) {
    nestedOracleValue = [nestedOracleValue];
  }
  overDepthCommand.oracle.nested = nestedOracleValue;
  const exoticArrayModel = structuredClone(model);
  const exoticArrayCommand = exoticArrayModel.gates
    .find((gate) => gate.id === "architecture-profile")
    .commands[0];
  const exoticOracle = ["exit-code-zero"];
  Object.defineProperty(exoticOracle, "toJSON", {
    enumerable: false,
    value() {
      return 1n;
    }
  });
  exoticArrayCommand.oracle = exoticOracle;
  const oversizedClosureModel = structuredClone(model);
  oversizedClosureModel.knowledgeGaps[0].closedBy = Array.from(
    { length: ARCHITECTURE_PROFILE_LIMITS.refsPerFact + 1 },
    (_, index) => ({
      changeId: `historical-change-${index}`,
      acceptanceDigest: canonicalDigest(`historical-acceptance-${index}`)
    })
  );
  const attacks = [
    {
      name: "array JSON hook before metadata cloning",
      code: "ARCHITECTURE_PROFILE_INPUT_INVALID",
      model: exoticArrayModel,
      source,
      facts: legalFacts
    },
    {
      name: "metadata nesting depth before recursive validation or cloning",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: overDepthModel,
      source,
      facts: legalFacts
    },
    {
      name: "raw Knowledge Gap closure history before validation",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: oversizedClosureModel,
      source,
      facts: legalFacts
    },
    {
      name: "raw route metadata before compiler cloning",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: oversizedMetadataModel,
      source,
      facts: legalFacts
    },
    {
      name: "raw argv bytes before command display allocation",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: oversizedArgTextModel,
      source,
      facts: legalFacts
    },
    {
      name: "raw object-form argv cardinality before command normalization",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: oversizedArgvModel,
      source,
      facts: legalFacts
    },
    {
      name: "raw Model cardinality before semantic validation",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      model: oversizedModel,
      source,
      facts: legalFacts
    },
    {
      name: "Project Model content mutation with retained digest",
      code: "ARCHITECTURE_PROFILE_SOURCE_MISMATCH",
      model: forgedModel,
      source,
      facts: legalFacts
    },
    {
      name: "source mismatch",
      code: "ARCHITECTURE_PROFILE_SOURCE_MISMATCH",
      source: { ...source, projectModelDigest: canonicalDigest("different-model") },
      facts: legalFacts
    },
    {
      name: "dangling Criterion",
      code: "ARCHITECTURE_PROFILE_DANGLING_REFERENCE",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].contributions[0].criterionRef = "LGT-010-missing";
      })
    },
    {
      name: "duplicate Change identity",
      code: "ARCHITECTURE_PROFILE_DUPLICATE_IDENTITY",
      source,
      facts: [...legalFacts, structuredClone(legalFacts[0])]
    },
    {
      name: "forged route",
      code: "ARCHITECTURE_PROFILE_ROUTE_MISMATCH",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].claimAssociations[0].commandId = "forged-command";
      })
    },
    {
      name: "legacy approval label",
      code: "ARCHITECTURE_PROFILE_INPUT_INVALID",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].claimAssociations[1].kind = "authority-approved-cross-claim";
      })
    },
    {
      name: "cross-Claim association without authority binding",
      code: "ARCHITECTURE_PROFILE_INPUT_INVALID",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        delete facts[0].evidence[0].claimAssociations[1].authorityDecisionDigest;
      })
    },
    {
      name: "current Evidence with sealed acceptance identity",
      code: "ARCHITECTURE_PROFILE_EVIDENCE_FACT_INVALID",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].acceptanceDigest = canonicalDigest("forged-sealed-identity");
      })
    },
    {
      name: "direct association with cross-Claim authority field",
      code: "ARCHITECTURE_PROFILE_INPUT_INVALID",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].claimAssociations[0].authorityDecisionDigest = canonicalDigest("forged");
      })
    },
    {
      name: "conflicting duplicate obligation identity",
      code: "ARCHITECTURE_PROFILE_OBLIGATION_CONFLICT",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        const duplicate = structuredClone(facts[0].evidence[0].claimAssociations[0]);
        duplicate.obligationDigest = canonicalDigest("conflicting-obligation-content");
        facts[0].evidence[0].claimAssociations.push(duplicate);
      })
    },
    {
      name: "exact duplicate association occurrence",
      code: "ARCHITECTURE_PROFILE_DUPLICATE_IDENTITY",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].claimAssociations.push(
          structuredClone(facts[0].evidence[0].claimAssociations[0])
        );
      })
    },
    {
      name: "non-JSON Evidence residual metadata",
      code: "ARCHITECTURE_PROFILE_INPUT_INVALID",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].residualUncertainty = [1n];
      })
    },
    {
      name: "unbounded Change facts",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      source,
      facts: Array.from(
        { length: ARCHITECTURE_PROFILE_LIMITS.changes + 1 },
        (_, index) => ({
          schemaVersion: 1,
          sourceSnapshotDigest: source.snapshotDigest,
          id: `bounded-change-${index}`,
          state: "Candidate",
          primaryModuleRef: "project-model",
          contributions: [],
          evidence: []
        })
      )
    },
    {
      name: "unbounded Evidence Claim envelope",
      code: "ARCHITECTURE_PROFILE_LIMIT_EXCEEDED",
      source,
      facts: mutateFacts(legalFacts, (facts) => {
        facts[0].evidence[0].claimEnvelopeRefs = Array.from(
          { length: ARCHITECTURE_PROFILE_LIMITS.refsPerFact + 1 },
          () => PROFILE_CLAIM
        );
      })
    }
  ];

  for (const attack of attacks) {
    assert.throws(
      () => compileArchitectureProfile({
        model: attack.model ?? model,
        source: attack.source,
        changeFacts: attack.facts
      }),
      (error) => error?.code === attack.code,
      attack.name
    );
  }

  for (const forbiddenField of ["score", "body", "package", "output"]) {
    const forbiddenModel = structuredClone(model);
    const profileGate = forbiddenModel.gates.find((gate) => gate.id === "architecture-profile");
    profileGate.commands[0].applicability[forbiddenField] = { forged: true };
    forbiddenModel.digest = projectModelContentDigest(forbiddenModel);
    const forbiddenSource = profileSource(forbiddenModel);
    assert.throws(
      () => compileArchitectureProfile({
        model: forbiddenModel,
        source: forbiddenSource,
        changeFacts: []
      }),
      (error) => error?.code === "ARCHITECTURE_PROFILE_AGGREGATE_FORBIDDEN",
      `forbidden Profile field ${forbiddenField}`
    );
  }
});

function createChangeFacts(model, source) {
  const route = compileClaimGateRoutes(model, PROFILE_CLAIM)[0];
  const acceptanceDigest = canonicalDigest("sealed-acceptance");
  const commonProvenance = {
    kind: "gate-command",
    gateId: route.gateId,
    commandId: route.commandId,
    projectModelDigest: source.projectModelDigest,
    gitContentDigest: source.gitContentDigest,
    verificationSubjectDigest: canonicalDigest("verification-subject")
  };
  const directAssociation = {
    kind: "direct",
    targetClaimRef: PROFILE_CLAIM,
    sourceClaimRef: PROFILE_CLAIM,
    obligationRef: "profile-direct-obligation",
    obligationDigest: canonicalDigest("profile-direct-obligation"),
    gateId: route.gateId,
    commandId: route.commandId
  };
  const crossClaimAssociation = {
    kind: "cross-claim",
    targetClaimRef: "project-model-references-are-consistent",
    sourceClaimRef: PROFILE_CLAIM,
    obligationRef: "profile-cross-claim-obligation",
    obligationDigest: canonicalDigest("profile-cross-claim-obligation"),
    authorityDecisionDigest: canonicalDigest("profile-cross-claim-authority-decision"),
    gateId: route.gateId,
    commandId: route.commandId
  };
  return [{
    schemaVersion: 1,
    sourceSnapshotDigest: source.snapshotDigest,
    id: "profile-change",
    state: "EvidenceReady",
    primaryModuleRef: "project-model",
    contributions: [{
      contributionRef: "profile-contribution",
      origin: "current-record",
      outcomeRef: "LGT-010",
      criterionRef: "LGT-010-C1",
      moduleRef: "project-model",
      claimRefs: ["project-model-references-are-consistent"],
      bindingDigest: canonicalDigest("profile-contribution")
    }],
    evidence: [
      evidenceFact({
        evidenceRef: "profile-current",
        currency: "current",
        origin: "current-record",
        provenance: commonProvenance,
        claimAssociations: [directAssociation, crossClaimAssociation]
      }),
      evidenceFact({
        evidenceRef: "profile-historical",
        currency: "sealed-historical",
        origin: "sealed-package",
        acceptanceDigest,
        provenance: commonProvenance,
        claimAssociations: [directAssociation]
      }),
      evidenceFact({
        evidenceRef: "profile-stale",
        currency: "stale",
        origin: "current-record",
        provenance: commonProvenance,
        claimAssociations: []
      }),
      evidenceFact({
        evidenceRef: "profile-invalid",
        currency: "invalid",
        origin: "current-record",
        provenance: { kind: "reported-incident" },
        claimAssociations: []
      })
    ]
  }];
}

function evidenceFact({
  evidenceRef,
  currency,
  origin,
  acceptanceDigest,
  provenance,
  claimAssociations
}) {
  return {
    evidenceRef,
    evidenceDigest: canonicalDigest({ evidenceRef, currency, origin }),
    origin,
    ...(acceptanceDigest ? { acceptanceDigest } : {}),
    currency,
    observationStatus: currency === "invalid" ? "untrusted" : "passed",
    provenance,
    claimEnvelopeRefs: [PROFILE_CLAIM],
    claimAssociations,
    residualUncertainty: [`Residual for ${evidenceRef}.`]
  };
}

function profileSource(model) {
  return {
    snapshotDigest: canonicalDigest("profile-snapshot"),
    projectModelDigest: model.digest,
    gitContentDigest: canonicalDigest("profile-git"),
    changeStoreDigest: canonicalDigest("profile-store")
  };
}

function mutateFacts(value, mutation) {
  const copy = structuredClone(value);
  mutation(copy);
  return copy;
}

function assertProfileContainsNoAggregateOrBody(value) {
  const forbidden = new Set([
    "coverage",
    "confidence",
    "body",
    "commandoutput",
    "greenlight",
    "health",
    "overall",
    "output",
    "package",
    "percentage",
    "progress",
    "ready",
    "satisfied",
    "score",
    "stderr",
    "stdout"
  ]);
  visit(value);

  function visit(item) {
    if (Array.isArray(item)) {
      for (const entry of item) visit(entry);
      return;
    }
    if (!item || typeof item !== "object") return;
    for (const [key, nested] of Object.entries(item)) {
      const normalized = key.toLowerCase().replace(/[^a-z]/gu, "");
      assert.equal(forbidden.has(normalized), false, `Profile emitted forbidden field ${key}`);
      visit(nested);
    }
  }
}
