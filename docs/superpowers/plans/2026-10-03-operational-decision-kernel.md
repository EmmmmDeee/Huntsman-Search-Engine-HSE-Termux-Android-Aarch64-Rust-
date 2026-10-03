# Operational Decision Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a pure deterministic decision kernel that filters inadmissible actions, eliminates dominated alternatives, ranks eligible actions by expected decision value, and selects or terminates with an inspectable record.

**Architecture:** Repair the existing ROI independence primitive first, then add `src/decision_policy.rs` as a pure orchestration layer over normalized candidate/state snapshots. No I/O or live dispatcher changes are included in this slice.

**Tech Stack:** Rust 1.87+ / stable, existing crate only, no new dependency.

**Spec:** `docs/superpowers/specs/2026-10-03-operational-decision-kernel-design.md`

## Global Constraints

- Rust only; no runtime LLM.
- Preserve no-root Termux Android aarch64 behavior.
- No new network/filesystem/subprocess I/O in policy code.
- Hard eligibility precedes ranking.
- Raw source/provider count must not imply evidentiary independence.
- Same inputs must produce deterministic output.

## Review Focus

- Unknown independence must not be treated optimistically.
- NaN/non-finite score inputs must not destabilize ordering.
- Equal-score candidates must tie-break deterministically.
- All-ineligible candidate sets must terminate cleanly.
- Dominance must not eliminate a candidate that is better on a risk/cost dimension.

---

### Task 1: Remove Source-Count Independence Proxy

**Files:**
- Modify: `src/roi.rs`

**Interfaces:**
- Produces: `DispatchUtilityInputs.independent_root_count: Option<u32>` and lineage-aware `expected_independence`.

- [ ] Add a failing test proving that changing raw `source_count` alone does not change `expected_independence`.
- [ ] Run CI and confirm the test fails against current behavior.
- [ ] Add `independent_root_count: Option<u32>`; derive independence only from that field, with unknown treated conservatively.
- [ ] Update existing ROI test fixtures and explanation text.
- [ ] Run full CI and confirm green.

### Task 2: Add Hard Eligibility and Candidate Contracts

**Files:**
- Create: `src/decision_policy.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Produces: `ActionCandidate`, `DecisionState`, `Eligibility`, `IneligibilityReason`, and `evaluate_eligibility`.

- [ ] Write failing unit tests for dependency, permission, feasibility, precondition, explicit block, and eligible cases.
- [ ] Run CI and confirm RED.
- [ ] Implement minimal pure contracts and eligibility logic.
- [ ] Export the module from `src/lib.rs`.
- [ ] Run full CI and confirm GREEN.

### Task 3: Add Dominance, EDV Ranking, Selection, and Termination

**Files:**
- Modify: `src/decision_policy.rs`

**Interfaces:**
- Produces: `Decision`, `DecisionRecord`, `rank_actions`, and deterministic `select_action`.

- [ ] Write failing tests for dominated-action removal, higher-EDV selection, stable ties, all-ineligible termination, and non-positive-EDV termination.
- [ ] Run CI and confirm RED.
- [ ] Implement dominance filtering, finite EDV calculation, deterministic ranking, selection, and terminal reasons.
- [ ] Ensure decision records expose score components and rejection/elimination reasons used by the actual decision.
- [ ] Run full CI and confirm GREEN.

### Task 4: Adversarial and Regression Ratchet

**Files:**
- Modify: `src/decision_policy.rs`
- Modify only if needed: repository contract tests under `tests/`

**Interfaces:**
- Consumes: all Task 1-3 public policy interfaces.

- [ ] Add adversarial tests: high score + missing permission rejects; derivative evidence cannot inflate independence; healthy-but-zero-impact action loses; degraded-but-unique positive action may remain eligible; many low-value actions lose to one high-value action; NaN/non-finite inputs fail closed or normalize deterministically.
- [ ] Run full CI on Rust 1.87/stable plus Android aarch64 cross-build.
- [ ] Compare branch with `main`; verify no live-dispatch/network behavior changed.
- [ ] Retain only if all proof obligations are green.
