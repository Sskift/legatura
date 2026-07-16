# Legatura

[![CI](https://github.com/Sskift/legatura/actions/workflows/ci.yml/badge.svg)](https://github.com/Sskift/legatura/actions/workflows/ci.yml)

Legatura—Italian for *binding*—is a local-first control plane for trusted multi-agent software changes. It governs the **Change**, not the worker: every accepted result is bound to an exact repository baseline, declared project knowledge, risk-proportional verification, evidence, and authority decisions.

The MVP is deliberately narrow and runnable:

- load and validate a repository's existing `.legatura` Project Model;
- bind ordinary Changes to active Outcomes in a versioned Development Plan;
- show a Project Atlas, assurance boundary, knowledge gaps, and gate health;
- create and compile a Change into a Context Capsule, Impact Set, and Verification Obligations;
- run declared minimum gates and preserve structured evidence;
- require Knowledge Closure and an authority decision before producing an Accepted Change Package.

Run it against a modeled repository:

```bash
git clone https://github.com/Sskift/legatura.git
cd legatura
npm ci
npm run check
node src/cli.mjs open /path/to/repository
```

Then open the local URL printed by the command. The workbench binds only to `127.0.0.1` and has no cloud dependency.

The visible product is one local workbench with three connected views:

1. **Project Atlas** — the living module map, contracts, assurance boundary, knowledge gaps, and available gates.
2. **Change Workspace** — an intent compiled into a bounded Context Capsule, Impact Set, write scope, and Verification Obligations.
3. **Acceptance Review** — claim-bound Evidence, residual uncertainty, Knowledge Closure, and the exact authority decision required to seal an Accepted Change Package.

The internal shape is intentionally small:

```text
versioned Project Model ──► Change compiler ──► Change kernel
          ▲                       │                  │
          │                       ▼                  ▼
   versioned Closure       Context Capsule     Evidence + decision
          │                                          │
          └──────────── next Change ◄──── Accepted Change Package
```

Legatura models its own repository with the same mechanism:

| Module | Responsibility | Assurance |
|---|---|---|
| Assurance Runtime | Exact Git/process observations and canonical digests | Provisional |
| Project Model Compiler | Model validation, bounded context, impact, and verification planning | Governed |
| Change Kernel | Change lifecycle, Evidence coverage, acceptance, and integration integrity | Governed |
| Local Workbench | CLI, loopback HTTP interface, browser projection, and package delivery | Provisional |

The versioned definitions live in [`.legatura/`](.legatura/). Development is governed by the machine-readable [Long-Term Plan](.legatura/plan.json): it defines the north star, permanent Outcome IDs, dependencies, exit criteria, non-goals, and the reference scenario that marks the trusted local 1+n core complete. Provisional and opaque areas are intentional model states, not hidden completeness claims; their concrete expansion triggers live in [`.legatura/knowledge-gaps.json`](.legatura/knowledge-gaps.json).

Workers and agents are intended to be replaceable clients of this kernel. This MVP compiles the bounded Context Capsule and rejects undeclared or semantically altered Contract Claims, but it does not yet deliver that capsule to a worker or enforce filesystem capabilities. Worker execution is a later adapter, not a property claimed here. No submitted Evidence—including Evidence that merely labels itself as a Gate result—can ratify its own output.

## Project Model

A modeled repository owns its durable knowledge under `.legatura/`:

```text
.legatura/
  project.json          project identity, policy, and authorities
  plan.json             long-term Outcomes, dependencies, and exit criteria
  modules/*.json        ownership, paths, interfaces, and assurance status
  contracts/*.json      public behavior and falsifiable claims
  gates/*.json          executable verification with claim mappings
  knowledge-gaps.json   explicit unknowns, owners, and expansion triggers
  runtime/              local Change records; normally ignored by Git
```

The assurance boundary has three honest states:

- `governed`: the interface and verification authority are sufficient for routine change;
- `provisional`: useful knowledge exists, but the Change must expand context or preserve uncertainty;
- `opaque`: the framework will not infer safe write scope without an explicit decision.

Project Model files are normative. Changing them is itself a Change and requires a `normative-amendment` decision naming every amended file.

The Development Plan is not a task backlog. A normal Change must reference an already active Outcome from its frozen Governance Baseline; a planned Outcome is activated by an earlier `plan-amendment` Change that can modify only `.legatura/**`, references no Outcome, and cannot carry implementation. Existing Outcome ids and statements are permanent; achieved or retired state cannot be reopened, and achieved acceptance records cannot be rewritten. Other planned details evolve only through separately reviewed amendments. `LGT-099` is a standing integrity path, but the compiler accepts it only for a supported repair kind that binds a protected Claim to complete failed Evidence, and Plan authority must review it—it is not a feature escape hatch.

The current bootstrap enforces referential alignment, active status, frozen-plan binding, amendment isolation, exact Contract-visible Claim-to-Criterion Outcome Contributions, non-progress exceptions bound to Plan authority, acceptance-time rederivation, exact integrity Evidence, and Evidence-bound Outcome Transitions. A Contribution proves reviewable relevance, not that an exit Criterion is satisfied. A Transition separately binds a Candidate-frozen catalog of prior sealed Accepted Packages, exact Gate Evidence, Knowledge Gap dispositions, and Plan-authority assessments, then re-resolves those facts before Gates and acceptance. The remaining LGT-010 limit is the explicit `architecture-acceptance-profile-not-projected` Knowledge Gap; the local single-writer Store is also not authenticated multi-writer history.

## Evidence, not test volume

A passing command is not automatically evidence for every claim. Evidence is usable only when it records:

- the exact claim and verification subject it supports;
- an independent oracle and its observation;
- applicability to the affected module and contract;
- provenance from a built-in oracle or declared gate command;
- discriminatory power: what plausible failure it would reject;
- residual uncertainty that remains after it passes.

Minimum gates answer “what is the smallest high-confidence check for this exact Change?” Commands are selected by primary Module, while unscoped commands apply everywhere. Full gates answer “is the integrated or release candidate healthy as a whole?” Policy may require the former before acceptance and the latter before integration.

Permanent tests are admitted by plausible failure and Contract Claim—not by feature count or coverage targets. The placement, replacement, and deletion rules are normative in [TESTING.md](TESTING.md).

## What the MVP already enforces

- frozen governance and Git baselines for each Change;
- bounded module write scope and explicit treatment of pre-existing dirty paths;
- exact claim-to-obligation-to-evidence mappings;
- no coverage from failed, stale, incomplete, or worker-self-reported Evidence;
- Knowledge Closure before acceptance;
- durable Closure for model amendments and gaps: runtime-only notes cannot masquerade as future project knowledge;
- authority type and subject binding;
- exact active Outcome Contributions or explicit non-progress exceptions requiring frozen Plan authority;
- canonical Accepted Change Package digests and invalidation after content changes;
- minimum/full Gate separation, sealed Accepted packages, and post-acceptance integration assurance.

## Trust boundary

The target repository's `.legatura` directory is executable governance input. Gate commands run locally with the repository as their working directory. Only use Project Models from repositories you trust.

This MVP is not yet an agent runtime or a security sandbox. It does not spawn workers, enforce OS-level file capabilities, isolate concurrent Changes into separate worktrees, or authenticate the person named in a local authority decision. Runtime records and digests are local integrity controls, not signed attestations against an attacker who controls the same OS account. Those are explicit adapter seams for later worker execution, worktree leasing, and identity/signature providers—not properties claimed by this version.

## Repository status

Legatura is an early MVP. The GitHub repository is public for inspection and collaboration, while the npm package remains marked `private` to prevent accidental publication. No reuse license has been selected yet; until a `LICENSE` is added, the source remains under default copyright.

Please report security-sensitive findings through GitHub's private vulnerability reporting rather than a public issue; see [SECURITY.md](SECURITY.md).
