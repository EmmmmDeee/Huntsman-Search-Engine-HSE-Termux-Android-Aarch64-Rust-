# Huntsman End-to-End Refactor — Dependency-Ordered Implementation Plan

**Base:** `feef60ab48ffe4be599c2ef0f678600cdaffc2aa`
**Target:** Android → Termux → ARM64/aarch64
**Language:** Rust for Huntsman logic; host configuration only where unavoidable
**Runtime LLM:** none

## Execution rule

For every task:

```text
REPRODUCE → FAILING TEST → MINIMAL CHANGE → TARGETED PASS
→ FALSIFY → REGRESS → COMPARE → RETAIN/ROLLBACK
```

Do not advance a semantic cutover because code merely builds. Record the
verification class: repository, host, cross-build, or real Termux device.

## Tranche 0 — Compile the architectural invariants

1. Apply `0001-auto-update-single-authority.patch`.
2. Apply `0002-rust-evidence-health-eval-foundations.patch`.
3. Apply `0003-register-refactor-core-modules.patch`.
4. Apply `0004-architecture-audit-repository-invariants.patch`.
5. Run formatting and the root test suite.
6. Run:
   `cargo run --bin architecture-audit -- --repo-invariants .`
7. Deliberately reintroduce one stale toolchain fixture and one duplicated
   auto-update predicate in a disposable worktree; require the invariant gate
   to fail.
8. Revert the mutations and require the gate to pass.

Acceptance: one auto-update authority, non-vacuous Rust repository invariant
audit, no scan semantic change.

## Tranche 1 — IntelligenceLedger shadow integration

Rebase and verify `metamorphic_intelligence_hse.patch` against the exact base.
Do not replace live promotion semantics yet.

Required evidence:
- deterministic persisted scan → ledger projection;
- existing scan remains unchanged;
- projection records evidence ancestry and independent lineage;
- projection round-trip is stable;
- discrepancies between legacy confidence and ledger state are measurable.

Only after `hse eval` can characterize the difference may a production cutover
be proposed.

## Tranche 2 — Causal source outcomes

Integrate `core::source_outcome` at the module execution boundary.

Required changes:
- persist causal outcome alongside/behind existing module outcome events;
- map transport errors without pretending an HTTP 2xx is query success;
- let provider contracts refine `Inconclusive` into `Success`, `ValidZero`,
  schema/semantic drift, etc.;
- update scraper health to consume causal state while preserving its existing
  API/doctor/UI consumers;
- keep legacy streak fields during migration until compatibility is proven.

Required tests:
- auth rejection never becomes parser drift;
- rate-limit backoff is distinct from dead-source quarantine;
- known valid zero remains healthy;
- zero-yield anomaly is not proof of absence;
- source recovery clears quarantine;
- old event histories remain readable.

## Tranche 3 — Evidence ancestry and reversible identity

Integrate `core::evidence_ancestry` and `core::identity_resolution`.

Required changes:
- persist root source/corpus family;
- derived/recall/mirror evidence carries parents;
- correlator independence counts root families, not module names;
- identity decisions preserve support and contradiction;
- only `Match` satisfying the merge policy can auto-merge;
- `Probable` and `Possible` remain hypotheses.

Hard gate: a false identity bridge must be detectable and reversible.

## Tranche 4 — Provider contracts

Extend existing `ProviderDescriptor`; do not create a second registry.

Re-derive every provider change from current official documentation or observed
responses. Revalidation patches in this bundle are inputs, not pre-approved
truth.

Priorities:
- HudsonRock current schema;
- AHPRA interaction contract;
- redirects/protocol drift;
- Reddit rate limiting;
- Wayback timeout semantics;
- Anubis response semantics;
- breach corpus source-family canonicalization;
- LeakBase safe import;
- query-pack expansion only after contracts are verified.

## Tranche 5 — Scheduler and termination

Wire `core::termination` into the sole live ROI/round scheduler.

Do not add another frontier.

Persist explicit termination reasons:
`FixedPoint`, `MaxDepth`, `TimeLimit`, `RequestBudget`, `ProviderBudget`,
`ResourceLimit`, `MarginalGainLimit`, `Cancelled`, `FatalError`.

`FixedPoint` requires no admissible, delayed, in-flight, or newly derivable
work.

## Tranche 6 — Evidence-first geo and radar

Revalidate and apply the EvidenceFirstGeo patch only after current geo scoring
is characterized. Treat its 5% maximum geo bonus as a benchmark candidate, not
an unquestioned constant.

Preserve explicit `GeoConverge` until `hse eval` shows a replacement is better.

Sensor/radar acceptance requires real Termux device execution. Distinguish
permission/bridge/tool/timeout/true-empty states.

## Tranche 7 — Native competitive evaluation

Build application/CLI orchestration around `core::eval`.

Conditions:
- M*: deterministic manual replay, never called a live human;
- R: retrieval-only;
- F: full Huntsman;
- A: controlled ablations.

Structural requirements:
- condition-isolated stores;
- runner accepts visible case, never sealed truth;
- score only finalized results;
- false merges and cascade size are hard non-compensatory gates;
- deterministic artifact hashes and seeded bootstrap;
- verdict exactly `PROMOTE | REPAIR | REPLACE | ROLLBACK | HOLD`;
- host results never imply Termux performance.

## Tranche 8 — Storage, release, and real-device convergence

Revalidate the Termux artifact patch, then require:
- migration/restart/recovery tests;
- exact source/binary revision match;
- checksums/provenance;
- clean install;
- idempotent reinstall;
- state/credential preservation;
- upgrade and rollback;
- Android aarch64 cross-build;
- real Termux `hse-test`, `hse doctor`, representative scans;
- resource-budget evidence.

## Completion

The refactor is not complete while a high-impact ledger entry is marked
`UNVERIFIED`, `PARTIAL`, or `BLOCKED` without explicit reason. No superiority
claim ships until controlled evaluation supports it.
