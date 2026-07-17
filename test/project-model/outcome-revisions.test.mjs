import assert from "node:assert/strict";
import test from "node:test";
import { canonicalDigest } from "../../src/core/canonical.mjs";
import {
  compileOutcomePlanAmendment,
  OUTCOME_PLAN_AMENDMENT_LIMITS,
  validateOutcomeRevisionLedger
} from "../../src/core/outcome-evolution.mjs";

const AUTHORITY = "governance-maintainer";
const TARGET = "LGT-200";
const OTHER = "LGT-300";
const FIELD_PATHS = [
  "id",
  "stage",
  "outcome",
  "dependsOn",
  "kind",
  "allowedChangeKinds",
  "acceptance.activationCriterionRefs",
  "acceptance.criteria",
  "acceptance.exitCriteria",
  "acceptance.claimRefs",
  "acceptance.gapRefs",
  "nonGoals"
];

test("Outcome Plan Amendment compiles one exact bounded pre-activation Revision", () => {
  const fixture = revisionFixture();
  const first = compileOutcomePlanAmendment(fixture);
  const second = compileOutcomePlanAmendment(fixture);

  assert.deepEqual(second, first);
  assert.equal(first.schemaVersion, 1);
  assert.equal(first.status, "complete");
  assert.equal(first.amendmentKind, "revision");
  assert.equal(first.requiredAuthorityRef, AUTHORITY);
  assert.equal(first.baselinePlanDigest, canonicalDigest(fixture.governanceBaseline.plan));
  assert.equal(first.currentPlanDigest, canonicalDigest(fixture.currentModel.plan));
  assert.deepEqual(first.appendedTransitions, []);
  assert.deepEqual(first.activationBindings, []);
  assert.equal(first.appendedRevisions.length, 1);

  const compiled = first.appendedRevisions[0];
  const expected = fixture.currentModel.plan.outcomeRevisions.at(-1);
  assert.equal(compiled.id, `${TARGET}-R3`);
  assert.deepEqual(compiled.previousDefinition, expected.previousDefinition);
  assert.equal(compiled.previousDefinitionDigest, canonicalDigest(expected.previousDefinition));
  assert.equal(compiled.currentDefinitionDigest, outcomeDefinitionDigest(
    fixture.currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET)
  ));
  assert.deepEqual(compiled.changedFields, [
    "acceptance.criteria",
    "dependsOn",
    "nonGoals",
    "outcome"
  ]);
  assert.match(compiled.bindingDigest, /^sha256:[a-f0-9]{64}$/u);
  assert.match(first.digest, /^sha256:[a-f0-9]{64}$/u);

  assert.deepEqual(
    validateOutcomeRevisionLedger(fixture.currentModel.plan, new Set([AUTHORITY])),
    { valid: true, errors: [] }
  );
  const laterAuthority = clone(fixture.currentModel.plan);
  laterAuthority.authority = "successor-governance-maintainer";
  assert.equal(validateOutcomeRevisionLedger(
    laterAuthority,
    new Set([AUTHORITY, laterAuthority.authority])
  ).valid, true, "historical Revisions remain bound to their original Authority");

  const nonGoalOnly = revisionFixture();
  const target = nonGoalOnly.currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET);
  target.outcome = targetDefinition(2).outcome;
  target.dependsOn = targetDefinition(2).dependsOn;
  target.acceptance.criteria = targetDefinition(2).acceptance.criteria;
  const revision = nonGoalOnly.currentModel.plan.outcomeRevisions.at(-1);
  revision.currentDefinitionDigest = outcomeDefinitionDigest(target);
  revision.changedFields = ["nonGoals"];
  const nonGoalCompilation = compileOutcomePlanAmendment(nonGoalOnly);
  assert.deepEqual(nonGoalCompilation.appendedRevisions[0].changedFields, ["nonGoals"]);
  assert.notEqual(
    nonGoalCompilation.appendedRevisions[0].currentDefinitionDigest,
    nonGoalCompilation.appendedRevisions[0].previousDefinitionDigest
  );
});

test("Outcome Plan Amendment rejects history, lifecycle, authorization, and resource attacks", () => {
  const activation = activationFixture();
  const activated = compileOutcomePlanAmendment(activation);
  assert.equal(activated.amendmentKind, "transition");
  assert.equal(activated.status, "complete");
  assert.deepEqual(activated.activationBindings, [{
    transitionId: `${TARGET}-T1`,
    outcomeRef: TARGET,
    frozenDefinitionDigest: outcomeDefinitionDigest(
      activation.governanceBaseline.plan.outcomes.find((outcome) => outcome.id === TARGET)
    )
  }]);

  const attacks = [
    {
      name: "delete frozen prefix",
      code: "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      mutate: ({ currentModel }) => currentModel.plan.outcomeRevisions.shift()
    },
    {
      name: "reorder frozen prefix",
      code: "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      mutate: ({ currentModel }) => currentModel.plan.outcomeRevisions.splice(
        0,
        2,
        currentModel.plan.outcomeRevisions[1],
        currentModel.plan.outcomeRevisions[0]
      )
    },
    {
      name: "rewrite frozen prefix",
      code: "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions[0].rationale = "Rewrite already accepted history maliciously.";
      }
    },
    {
      name: "skip the next stable Revision id",
      code: "OUTCOME_REVISION_LEDGER_REWRITE_FORBIDDEN",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).id = `${TARGET}-R4`;
      }
    },
    {
      name: "omit the Revision for a definition delta",
      code: "OUTCOME_REVISION_REQUIRED",
      mutate: ({ currentModel }) => currentModel.plan.outcomeRevisions.pop()
    },
    {
      name: "append a no-op Revision",
      code: "OUTCOME_REVISION_NOOP",
      mutate: ({ currentModel }) => {
        const target = currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET);
        Object.assign(target, clone(targetDefinition(2)), { status: "planned" });
        const revision = currentModel.plan.outcomeRevisions.at(-1);
        revision.currentDefinitionDigest = outcomeDefinitionDigest(target);
        revision.changedFields = [];
      }
    },
    {
      name: "drop a field from the complete previous definition",
      code: "OUTCOME_REVISION_DEFINITION_INVALID",
      mutate: ({ currentModel }) => {
        delete currentModel.plan.outcomeRevisions.at(-1).previousDefinition.nonGoals;
      }
    },
    {
      name: "forge the previous digest",
      code: "OUTCOME_REVISION_PRIOR_MISMATCH",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).previousDefinitionDigest = canonicalDigest("forged");
      }
    },
    {
      name: "forge the current digest",
      code: "OUTCOME_REVISION_CURRENT_MISMATCH",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).currentDefinitionDigest = canonicalDigest("forged");
      }
    },
    {
      name: "forge compiler-owned changed fields",
      code: "OUTCOME_REVISION_CURRENT_MISMATCH",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).changedFields = ["outcome"];
      }
    },
    {
      name: "forge the Candidate Governance Baseline binding",
      code: "OUTCOME_REVISION_BINDING_INVALID",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).governanceBaselineDigest = canonicalDigest("forged");
      }
    },
    {
      name: "revise an active Outcome",
      code: "OUTCOME_REVISION_STATUS_FORBIDDEN",
      mutate: ({ governanceBaseline, currentModel }) => {
        governanceBaseline.plan.outcomes.find((outcome) => outcome.id === TARGET).status = "active";
        currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET).status = "active";
        reseal(governanceBaseline);
      }
    },
    {
      name: "rewrite a terminal Outcome definition",
      code: "OUTCOME_REVISION_STATUS_FORBIDDEN",
      mutate: ({ governanceBaseline, currentModel }) => {
        governanceBaseline.plan.outcomes.find((outcome) => outcome.id === TARGET).status = "retired";
        currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET).status = "retired";
        reseal(governanceBaseline);
      }
    },
    {
      name: "mix a Revision with another Outcome Transition",
      code: "OUTCOME_REVISION_TRANSITION_MIXED",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomes.find((outcome) => outcome.id === OTHER).status = "active";
        currentModel.plan.outcomeTransitions.push({
          id: `${OTHER}-T1`,
          outcomeRef: OTHER,
          from: "planned",
          to: "active",
          rationale: "Attempt to hide an unrelated activation beside a Revision.",
          packageRefs: [],
          criterionAssessments: [],
          gapDispositions: []
        });
      }
    },
    {
      name: "change a definition during activation",
      fixture: activationFixture,
      code: "OUTCOME_REVISION_TRANSITION_MIXED",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomes.find((outcome) => outcome.id === TARGET).outcome = "Changed while activating.";
      }
    },
    {
      name: "self-authorize through planRefs",
      code: "OUTCOME_PLAN_SELF_AUTHORIZATION_FORBIDDEN",
      mutate: ({ change }) => {
        change.planRefs = ["LGT-018"];
      }
    },
    {
      name: "exceed the Revision ledger bound",
      code: "OUTCOME_PLAN_LIMIT_EXCEEDED",
      limitId: "revision-entries",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions = Array.from(
          { length: OUTCOME_PLAN_AMENDMENT_LIMITS.revisionEntries + 1 },
          () => ({})
        );
      }
    },
    {
      name: "exceed the Transition ledger bound",
      code: "OUTCOME_PLAN_LIMIT_EXCEEDED",
      limitId: "transition-entries",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeTransitions = Array.from(
          { length: OUTCOME_PLAN_AMENDMENT_LIMITS.transitionEntries + 1 },
          () => ({})
        );
      }
    },
    {
      name: "exceed the complete definition byte bound",
      code: "OUTCOME_PLAN_LIMIT_EXCEEDED",
      limitId: "outcome-definition-bytes",
      mutate: ({ currentModel }) => {
        currentModel.plan.outcomeRevisions.at(-1).previousDefinition.outcome = "x".repeat(
          OUTCOME_PLAN_AMENDMENT_LIMITS.definitionBytes + 1
        );
      }
    }
  ];

  for (const attack of attacks) {
    const fixture = (attack.fixture ?? revisionFixture)();
    attack.mutate(fixture);
    assert.throws(
      () => compileOutcomePlanAmendment(fixture),
      (error) => error.code === attack.code
        && (!attack.limitId || error.details?.limitId === attack.limitId),
      attack.name
    );
  }

  const forgedStatic = revisionFixture();
  forgedStatic.currentModel.plan.outcomeRevisions[1].currentDefinitionDigest = canonicalDigest("fork");
  const validation = validateOutcomeRevisionLedger(
    forgedStatic.currentModel.plan,
    new Set([AUTHORITY])
  );
  assert.equal(validation.valid, false);
  assert.equal(validation.errors.length, 1);
  assert.equal(validation.errors[0].code, "plan.outcome-revision.invalid");
  assert.equal(validation.errors[0].details.causeCode, "OUTCOME_REVISION_CURRENT_MISMATCH");
});

function revisionFixture() {
  const definition0 = targetDefinition(0);
  const definition1 = targetDefinition(1);
  const definition2 = targetDefinition(2);
  const definition3 = targetDefinition(3);
  const revisions = [
    revisionRecord(1, definition0, definition1),
    revisionRecord(2, definition1, definition2)
  ];
  const baselinePlan = plan({ target: definition2, status: "planned", revisions });
  const governanceBaseline = sealedBaseline(baselinePlan);
  const appendedRevision = revisionRecord(3, definition2, definition3);
  appendedRevision.amendmentChangeId = "revise-planned-outcome";
  appendedRevision.governanceBaselineDigest = governanceBaseline.digest;
  const currentPlan = plan({
    target: definition3,
    status: "planned",
    revisions: [...revisions, appendedRevision]
  });
  const catalog = sealedCatalog();
  return {
    change: {
      id: "revise-planned-outcome",
      changeKind: "plan-amendment",
      planRefs: [],
      priorAcceptedPackages: catalog
    },
    governanceBaseline,
    currentModel: currentModel(currentPlan),
    priorAcceptedPackages: catalog,
    resolvedPackages: []
  };
}

function activationFixture() {
  const base = revisionFixture();
  const currentPlan = clone(base.governanceBaseline.plan);
  currentPlan.outcomes.find((outcome) => outcome.id === TARGET).status = "active";
  currentPlan.outcomeTransitions.push({
    id: `${TARGET}-T1`,
    outcomeRef: TARGET,
    from: "planned",
    to: "active",
    rationale: "Activate the independently revised and frozen Outcome definition.",
    packageRefs: [],
    criterionAssessments: [],
    gapDispositions: []
  });
  return {
    ...base,
    change: { ...base.change, id: "activate-revised-outcome" },
    currentModel: currentModel(currentPlan)
  };
}

function plan({ target, status, revisions }) {
  return {
    schemaVersion: 1,
    id: "revision-test-plan",
    northStar: "Prove exact Outcome evolution semantics.",
    authority: AUTHORITY,
    outcomes: [
      { ...clone(target), status },
      { ...otherDefinition(), status: "planned" }
    ],
    outcomeRevisions: clone(revisions),
    outcomeTransitions: []
  };
}

function targetDefinition(version) {
  const baseCriterion = {
    id: `${TARGET}-C1`,
    statement: "The exact Outcome definition remains recoverable.",
    claimRefs: ["revision-exact"],
    gapRefs: []
  };
  const definitions = [
    {
      outcome: "Initial speculative capability.",
      dependsOn: [],
      criteria: [baseCriterion],
      exitCriteria: [baseCriterion.statement],
      nonGoals: ["Initial non-goal"]
    },
    {
      outcome: "Clarified speculative capability.",
      dependsOn: [],
      criteria: [baseCriterion],
      exitCriteria: [baseCriterion.statement],
      nonGoals: ["Initial non-goal"]
    },
    {
      outcome: "Clarified speculative capability.",
      dependsOn: [],
      criteria: [baseCriterion],
      exitCriteria: [baseCriterion.statement, "The compiler derives every binding."],
      nonGoals: ["Initial non-goal"]
    },
    {
      outcome: "Executable bounded revision capability.",
      dependsOn: [OTHER],
      criteria: [{
        ...baseCriterion,
        statement: "The exact complete Outcome definition and history remain recoverable."
      }],
      exitCriteria: [baseCriterion.statement, "The compiler derives every binding."],
      nonGoals: ["Generic event buses", "Task planning"]
    }
  ];
  const selected = definitions[version];
  return {
    id: TARGET,
    stage: "S1",
    outcome: selected.outcome,
    dependsOn: selected.dependsOn,
    kind: null,
    allowedChangeKinds: [],
    acceptance: {
      activationCriterionRefs: [],
      criteria: selected.criteria,
      exitCriteria: selected.exitCriteria.slice().sort(),
      claimRefs: ["revision-exact"],
      gapRefs: []
    },
    nonGoals: selected.nonGoals.slice().sort()
  };
}

function otherDefinition() {
  return {
    id: OTHER,
    stage: "S1",
    outcome: "An unrelated planned Outcome.",
    dependsOn: [],
    kind: null,
    allowedChangeKinds: [],
    acceptance: {
      activationCriterionRefs: [],
      criteria: [{
        id: `${OTHER}-C1`,
        statement: "The unrelated Outcome remains separate.",
        claimRefs: ["other-exact"],
        gapRefs: []
      }],
      exitCriteria: ["The unrelated Outcome remains separate."],
      claimRefs: ["other-exact"],
      gapRefs: []
    },
    nonGoals: ["Revision coupling"]
  };
}

function revisionRecord(number, previousDefinition, currentDefinition) {
  return {
    id: `${TARGET}-R${number}`,
    outcomeRef: TARGET,
    amendmentChangeId: `accepted-revision-${number}`,
    governanceBaselineDigest: canonicalDigest({ acceptedRevision: number }),
    previousDefinition: clone(previousDefinition),
    previousDefinitionDigest: canonicalDigest(previousDefinition),
    currentDefinitionDigest: canonicalDigest(currentDefinition),
    changedFields: changedFields(previousDefinition, currentDefinition),
    rationale: `Revision ${number} preserves prior meaning while refining the bounded capability.`,
    requiredAuthorityRef: AUTHORITY
  };
}

function changedFields(previousDefinition, currentDefinition) {
  return FIELD_PATHS.filter((field) => (
    canonicalDigest(readPath(previousDefinition, field))
      !== canonicalDigest(readPath(currentDefinition, field))
  )).sort();
}

function outcomeDefinitionDigest(outcome) {
  const definition = clone(outcome);
  delete definition.status;
  return canonicalDigest(definition);
}

function sealedBaseline(planValue) {
  const snapshot = {
    schemaVersion: 1,
    modelDigest: canonicalDigest({ project: "revision-test" }),
    project: { id: "revision-test" },
    projectDocument: {
      project: { id: "revision-test" },
      changePolicy: { outcomeTransitionMode: "enforced" }
    },
    modules: [],
    contracts: [],
    gates: [],
    plan: clone(planValue),
    knowledgeGaps: [],
    files: [".legatura/plan.json"]
  };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function currentModel(planValue) {
  return {
    project: { id: "revision-test" },
    projectDocument: {
      project: { id: "revision-test" },
      changePolicy: { outcomeTransitionMode: "enforced" }
    },
    modules: [],
    contracts: [],
    gates: [],
    plan: clone(planValue),
    knowledgeGaps: []
  };
}

function sealedCatalog() {
  const snapshot = { schemaVersion: 1, entries: [] };
  return { ...snapshot, digest: canonicalDigest(snapshot) };
}

function reseal(governanceBaseline) {
  const { digest: _discarded, ...snapshot } = governanceBaseline;
  governanceBaseline.digest = canonicalDigest(snapshot);
}

function readPath(value, path) {
  return path.split(".").reduce((current, segment) => current?.[segment], value);
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}
