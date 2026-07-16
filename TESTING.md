# Testing Policy

Tests are durable Oracle routes, not an inventory of completeness.

## Admission

A permanent test is admitted only when it does at least one of these:

1. distinguishes a falsifiable Contract Claim from a plausible failure that no current test rejects;
2. reproduces an escaped failure through the owning Module Interface; or
3. characterizes behavior at a real adapter or platform seam.

Before adding it, the Change must answer: which Claim is protected, which plausible failure is rejected, and why an existing Interface scenario cannot be strengthened or replaced. This reasoning belongs to the Change; per-test governance annotations are not required.

A bug reproducer is temporary by default. Promote it to the permanent suite only when the failure remains structurally plausible. Otherwise retain the Observation as Change Evidence and remove the reproducer after acceptance.

## Placement

The Module Interface is the test surface. Tests assert observable behavior through that Interface, not private implementation state.

Tests live under `test/<module-id>/`. A cross-Module scenario lives under `test/integration/` and runs only in the full Gate. Each test has one owner, although another Module may select it as focused verification. Do not mirror the source tree or create one test file per source file.

## Replace, do not layer

Every test addition triggers an overlap review. Strengthen or replace an existing Interface scenario before adding another.

Delete or merge a test when its Claim is retired, a stronger Interface scenario subsumes it, it observes only implementation detail, the represented failure is no longer plausible, or ordinary internal refactoring repeatedly requires changing it. Update Gate mappings in the same Change.

## Minimum and full Gates

The minimum Gate runs before acceptance. It executes only commands whose `appliesTo` includes the Change's primary Module; unscoped commands apply to every Module. `appliesTo` is the only configured Module scope; Evidence records the actual Change Module automatically, while `applicability` describes non-Module conditions. Each selected command must map its observations to exact Claim references. If a command protects several tightly coupled Claims, it remains one verification route rather than being split merely to optimize test count.

The full Gate reuses the durable suites and adds repository, integration, and package checks. It runs once against the sealed Accepted Change Package before integration, build, or release. It is not the normal development loop and does not justify a duplicate full-only behavioral suite.

## Evidence

A test definition is an Oracle route. A test run produces an Observation. Neither is Evidence by itself.

A passing Gate run becomes Evidence only when bound to the exact verification subject, Claim, applicability, provenance, discriminatory power, and residual uncertainty. It cannot support an unrelated Claim.

A test added or materially changed by the same Change cannot be its sole Oracle for new behavior unless the Claim and Oracle semantics already exist in the frozen Governance Baseline or are independently authorized.

## No volume targets

Coverage percentage, test count, assertion count, snapshot count, and mutation score are never acceptance targets or Gate conditions. Coverage tools may be used diagnostically to locate a suspected blind spot; their numbers do not establish confidence.
