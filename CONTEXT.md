# Legatura

Legatura governs software changes made by replaceable workers while preserving project knowledge, explicit authority, and verifiable acceptance.

## Language

**Change**:
The governed unit that binds an intent, a baseline, a ChangeSet, verification obligations, evidence, decisions, and residual uncertainty.
_Avoid_: Task, agent run, chat

**ChangeSet**:
The exact repository content difference observed for a Change, including both committed and uncommitted paths.
_Avoid_: Agent output, claimed patch

**Project Model**:
The versioned, machine-consumed account of a repository's Modules, Contracts, Gates, authorities, assurance coverage, and known gaps.
_Avoid_: Documentation bundle, prompt

**Project Atlas**:
The human-readable projection of the Project Model and scanned repository facts.
_Avoid_: Architecture document

**Governance Baseline**:
The exact Project Model and source revision whose rules govern a Change; a Change cannot weaken its own baseline.
_Avoid_: Latest config

**Assurance Boundary**:
The declared limit of what the Project Model can currently govern, classified as Governed, Provisional, or Opaque.
_Avoid_: Coverage percentage

**Context Capsule**:
The smallest authorized initial view that gives a worker the target Module, public Contracts, relevant decisions, and verification obligations.
_Avoid_: Prompt dump, complete context

**Context Expansion**:
A recorded request to read beyond a Context Capsule, including its reason and any resulting impact change.
_Avoid_: Browsing freely

**Verification Obligation**:
A risk-proportional claim that must be supported before a Change can be accepted.
_Avoid_: Test list

**Claim**:
A falsifiable statement whose truth an acceptance decision is asked to rely on.
_Avoid_: Assertion, success message

**Gate**:
A project-declared verification route that maps executable observations to exact Claims.
_Avoid_: Test suite, CI job

**Oracle**:
The independent means by which Evidence distinguishes a Claim-satisfying result from a plausible failure.
_Avoid_: Command output, worker opinion

**Evidence**:
Support for a Claim that binds an Oracle, Observation, Provenance, Applicability, Discriminatory Power, and Residual Uncertainty.
_Avoid_: Green command, test output

**Residual Uncertainty**:
The relevant doubt that remains after Evidence is observed and must stay visible to the acceptance authority.
_Avoid_: Hidden risk, confidence score

**Knowledge Closure**:
The condition that future-relevant knowledge from a Change is captured as a Model Amendment, a Model Gap, or deliberately ephemeral provenance.
_Avoid_: Documentation complete

**Accepted Change Package**:
The content-addressed record proving exactly which intent, baseline, ChangeSet, evidence, decisions, waivers, and model updates were accepted.
_Avoid_: Agent report, pull request summary

**Decision Authority**:
The role allowed to create or amend normative project truth or grant a scoped waiver.
_Avoid_: Reviewer, approver

**Fact Authority**:
The unique source that owns a descriptive fact consumed by other Modules or projections.
_Avoid_: Source of truth

**Worker**:
A replaceable executor that receives a Context Capsule and capabilities for one Change; it is never the object of governance.
_Avoid_: Agent identity
