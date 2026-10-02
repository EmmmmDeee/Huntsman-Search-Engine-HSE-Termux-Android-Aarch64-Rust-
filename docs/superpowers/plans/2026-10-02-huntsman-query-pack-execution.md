# Huntsman Query Pack Execution Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute the 15-query Huntsman upgrade program in order, preserving verified progress and prioritizing objective-level gains for Termux Android ARM64.

**Architecture:** Work on one isolated branch. Each material capability change gets a RED → GREEN → regression cycle and a separate commit. Evidence-only stages record findings without forcing code changes. Hard external constraints, especially live handset execution, are explicitly separated from repository-removable constraints.

**Tech Stack:** Rust 1.87+, blocking `ureq` transport, GitHub Actions, Android NDK aarch64 cross-build, existing evidence/provenance modules.

**Spec:** User-approved query pack from the current conversation.

## Global Constraints

- Termux Android ARM64 is the primary runtime.
- Rust-only runtime unless unavoidable.
- No runtime LLM dependency.
- Preserve provenance, uncertainty, and evidence ancestry.
- Do not claim handset/runtime verification without live handset evidence.
- Authorized active reconnaissance may perform bounded discovery/fingerprinting, but not exploitation, brute force, credential attacks, destructive actions, or stealth/evasion.
- Existing immutable `legacy/` snapshots remain untouched.

## Review Focus

- Cross-origin or private-network requests must not leak credentials or bypass egress policy.
- Active probing must stop at deterministic request/byte budgets.
- Extracted pivots are observations/candidates, never promoted directly into consequential claims.
- Synthetic adversarial tests must exercise false merges, duplicate evidence roots, stale/conflicting evidence, and parser drift.
- Changes must remain buildable under Rust 1.87 and Android `aarch64-linux-android`.

---

### Task 1: Re-establish the dominant constraint
- [ ] Verify current `main`, CI, Android artifact path, and outstanding hard external limits.
- [ ] Rank removable internal constraints by expected system gain.

### Task 2: Authorized active reconnaissance
**Files:** create `src/active_probe.rs`, modify `src/lib.rs`, modify `src/main.rs`, add focused tests.
- [ ] RED: prove bounded probe planning/fingerprinting/pivot extraction is absent.
- [ ] GREEN: add deterministic same-origin web probe plan, response fingerprinting, normalized pivot extraction, provenance, and budgets.
- [ ] Integrate `probe URL` CLI command using the existing guarded transport.
- [ ] Run full stable/MSRV/Android CI.

### Task 3: Query and pivot expansion
- [ ] Add a typed, scored candidate-expansion frontier over verified entities/observations.
- [ ] Deduplicate and suppress dominated pivots.

### Task 4: Source-universe audit
- [ ] Audit current source definitions and identify highest-value missing lawful sources.
- [ ] Implement only sources whose marginal information contribution justifies maintenance cost.

### Task 5: Adversarial identity-resolution benchmark
- [ ] Add synthetic hard cases and metric reporting for false merges/splits and calibration.
- [ ] Repair the weakest demonstrated decision boundary.

### Task 6: Proof-carrying evidence chain
- [ ] Trace query → source → request → response → parser → observation → derivation → claim.
- [ ] Repair the highest-consequence provenance/invalidation gap.

### Task 7: Parser robustness campaign
- [ ] Add drift/truncation/WAF/empty-success/malformed fixture tests to active parsers.
- [ ] Repair the highest-impact parser failure class.

### Task 8: Value-of-information scheduling
- [ ] Add a deterministic ranking model for candidate actions.
- [ ] Benchmark against static ordering using fixtures.

### Task 9: Coverage-gap discovery
- [ ] Build an objective-level capability-gap report based on operational reachability, not module presence.
- [ ] Implement the highest-value missing reachable capability.

### Task 10: Hostile false-positive campaign
- [ ] Construct misleading-but-plausible fixtures.
- [ ] Block demonstrated weak-correlation promotion paths without materially degrading legitimate recall.

### Task 11: Termux resource optimizer
- [ ] Add measurements that can execute on a handset.
- [ ] Record live handset optimization as externally blocked until actual Android execution evidence exists.

### Task 12: Frontier architecture challenge
- [ ] Compare incremental refactor, subsystem replacement, clean-core migration, and ground-up rebuild against measured evidence.
- [ ] Select by expected long-term system value, not change minimization.

### Task 13: Competitive capability benchmark
- [ ] Compare Huntsman with reproducible OSINT workflow tasks and objective metrics.
- [ ] Attack the largest demonstrated deficit that is feasible within the repository.

### Task 14: Autonomous reconstruction decision
- [ ] Classify major subsystems KEEP/REPAIR/REFACTOR/UNIFY/REPLACE/REBUILD/REMOVE based on evidence.
- [ ] Execute the highest-value resulting change.

### Task 15: Maximum-value final pass
- [ ] Re-rank all remaining constraints and opportunities.
- [ ] Execute the strongest remaining positive-value repository action.
- [ ] Verify, falsify, and report residual hard external limits.
