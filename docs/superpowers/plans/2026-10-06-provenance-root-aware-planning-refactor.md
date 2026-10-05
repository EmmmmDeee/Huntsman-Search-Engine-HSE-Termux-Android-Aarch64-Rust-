# Provenance-Root-Aware Planning Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace source-count-based/unknown independence semantics with a typed, canonical-provenance-root-aware planner contract that can reward demonstrated independent ancestry without allowing multiplicity, copies, or unknown lineage to manufacture corroboration.

**Architecture:** Huntsman's existing evidence/provenance/ancestry subsystem remains the sole authority for evidentiary ancestry. ROI becomes a pure consumer of a typed `EvidentiaryIndependence` value, and the planner receives/derives that value through an explicit context rather than inferring independence from source count or controller metadata. Unknown and shared ancestry fail closed; only at least two demonstrated distinct canonical roots earn bounded positive utility.

**Tech Stack:** Rust; existing Huntsman evidence ancestry/provenance, planner, ROI and CI infrastructure; no new runtime dependency.

**Spec:** `docs/superpowers/specs/2026-10-06-goat-adaptive-investigation-engine-design.md`

## Global Constraints

- Runtime remains LLM-free and Rust-native.
- Do not create a second evidence graph, provenance store, entity database, module registry, or claim system.
- Controller/adjudication firewall remains absolute: planning utility never becomes target-world evidence.
- Unknown ancestry earns zero positive independence credit.
- Shared/common-root ancestry earns zero positive independence credit.
- Positive independence credit requires at least two demonstrated distinct canonical roots.
- Source count is diagnostic multiplicity only and cannot establish independence.
- Preserve adaptive-disabled/static behavior and existing planner determinism.
- No new `unsafe` and no new dependency unless independently justified.
- Android AArch64 cross-build remains a required regression gate; physical Termux runtime remains a separate acceptance gate.

## Review Focus

- A hundred aliases/copies of one root must score exactly like one shared root for independence.
- Missing ancestry must remain `Unknown`, never guessed independent.
- One demonstrated root must not be mislabeled independent.
- Two or more genuinely distinct roots must receive bounded monotonic credit without exceeding 1.0.
- Planner context absent at legacy/static call sites must fail closed without changing unrelated ranking semantics.

---

### Task 1: Typed independence semantics in ROI

**Files:**
- Modify: `src/roi.rs`
- Test: `tests/roi_provenance_independence.rs`
- Test: `tests/roi_independence.rs`

**Interfaces:**
- Produces: `pub enum EvidentiaryIndependence { Unknown, SharedRoot, DemonstratedIndependentRoots { distinct_roots: u32 } }`
- Produces: `EvidentiaryIndependence::utility_credit(self) -> f64`
- Changes: `DispatchUtilityInputs` gains `pub evidentiary_independence: EvidentiaryIndependence`
- Removes from decision semantics: `source_count` as an input to `expected_independence`.

- [ ] **Step 1: Verify the existing RED contract**

Run: `cargo test --test roi_provenance_independence --locked`

Expected: FAIL because `EvidentiaryIndependence` and `evidentiary_independence` do not yet exist.

- [ ] **Step 2: Implement the minimal typed state**

In `src/roi.rs`, add the enum and a pure credit function. Exact semantics:

`Unknown -> 0.0`

`SharedRoot -> 0.0`

`DemonstratedIndependentRoots { distinct_roots: 0 | 1 } -> 0.0`

For `distinct_roots >= 2`, return a monotonic bounded value in `(0, 1]`; use `1.0 - 1.0 / distinct_roots as f64` so the prior saturating shape is retained only after independence has actually been demonstrated.

- [ ] **Step 3: Refactor dispatch utility input**

Add `evidentiary_independence` to `DispatchUtilityInputs`; compute `expected_independence` only from `utility_credit()`. Keep `source_count` temporarily only if required for diagnostics/backward migration, and ensure it has no effect on final utility.

- [ ] **Step 4: Strengthen tests**

Assert: unknown == shared == one-root == 0; two roots > 0; three roots > two roots; very large root count <= 1; changing `source_count` alone cannot change `expected_independence` or `final_utility`.

- [ ] **Step 5: Verify targeted tests**

Run: `cargo test --test roi_provenance_independence --test roi_independence --locked`

Expected: PASS.

- [ ] **Step 6: Commit**

`git commit -am "refactor(roi): type evidentiary independence"`

### Task 2: Planner independence context

**Files:**
- Modify: `src/planner.rs`
- Modify tests colocated in `src/planner.rs` or existing planner integration tests.

**Interfaces:**
- Produces: `PlannerEvidenceContext`, keyed by the canonical target/entity identity already used at the planner boundary, returning `EvidentiaryIndependence`.
- Consumes: `EvidentiaryIndependence` from Task 1.
- Default behavior: missing context -> `EvidentiaryIndependence::Unknown`.

- [ ] **Step 1: Add failing planner tests**

Tests must prove that no context fails closed, shared-root context gives zero independence credit, and demonstrated independent-root context reaches `PlannedDispatch.utility.expected_independence`.

- [ ] **Step 2: Add the smallest explicit evidence context**

Use an immutable planner input/context; do not let ROI query storage or global state. Preserve deterministic ordering.

- [ ] **Step 3: Migrate `planned_module`**

Replace the hard-coded `source_count: 0` epistemic placeholder with the typed context value. Do not alter cost/quota/reliability/GEO/duplicate semantics.

- [ ] **Step 4: Verify planner tests**

Run the narrowest planner test target available, then `cargo test planner --locked` if planner tests are unit-scoped.

Expected: PASS with legacy/no-context behavior remaining fail-closed.

- [ ] **Step 5: Commit**

`git commit -am "refactor(planner): consume typed evidence independence"`

### Task 3: Canonical ancestry adapter

**Files:**
- Modify: existing evidence ancestry/provenance module only as needed for a read-only query API.
- Modify: `src/planner.rs` or the existing orchestration boundary that has both canonical evidence state and planner access.
- Add/modify focused ancestry tests.

**Interfaces:**
- Produces: a pure/read-only function that maps canonical ancestry for the relevant entity/target to `EvidentiaryIndependence`.
- Must not duplicate ancestry state in planner/ROI.

- [ ] **Step 1: Write adversarial ancestry tests**

Cases: duplicate reports with same root -> `SharedRoot`; transformed/republished descendants of same root -> `SharedRoot`; unknown/incomplete ancestry -> `Unknown`; two demonstrated distinct roots -> `DemonstratedIndependentRoots { distinct_roots: 2 }`; three distinct roots -> count 3.

- [ ] **Step 2: Implement the adapter at the canonical ancestry boundary**

Count distinct demonstrated roots, not observations, providers, URLs, transformations, or reports. If ancestry completeness is insufficient to establish distinct roots, return `Unknown` rather than guessing.

- [ ] **Step 3: Wire orchestration to planner context**

Populate `PlannerEvidenceContext` from canonical state before planning. Keep planner and ROI storage-agnostic.

- [ ] **Step 4: Verify targeted ancestry + planner tests**

Expected: all adversarial cases PASS and planner ranking reflects only demonstrated root independence.

- [ ] **Step 5: Commit**

`git commit -am "feat(planner): derive independence from canonical provenance roots"`

### Task 4: Remove obsolete multiplicity semantics and audit output

**Files:**
- Modify: `src/roi.rs`
- Modify: `src/planner.rs`
- Modify tests referencing `source_count` in dispatch utility.

**Interfaces:**
- `DispatchUtility.explanation` explicitly states the typed ancestry state and root count when known.
- `source_count` is removed from `DispatchUtilityInputs` if no remaining non-epistemic consumer requires it.

- [ ] **Step 1: Add failing audit test**

Assert explanation distinguishes `Unknown`, `SharedRoot`, and `DemonstratedIndependentRoots { distinct_roots: 2 }` and never describes raw source multiplicity as independence.

- [ ] **Step 2: Remove obsolete field/logic**

Delete `source_count` from utility inputs if migration is complete. If retained elsewhere, rename/document it as diagnostic multiplicity and keep it outside independence calculation.

- [ ] **Step 3: Verify targeted tests**

Run ROI and planner test targets. Expected: PASS.

- [ ] **Step 4: Commit**

`git commit -am "refactor(roi): remove multiplicity from independence semantics"`

### Task 5: Full falsification and regression gate

**Files:**
- Modify only if a discovered regression requires a minimal repair.

**Interfaces:**
- No new interface; this task proves the refactor's contract.

- [ ] **Step 1: Format**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Check all targets/features**

Run: `cargo check --all-targets --all-features --locked`

Expected: PASS.

- [ ] **Step 3: Clippy**

Run: `cargo clippy --all-targets --all-features --locked -- -D warnings`

Expected: PASS.

- [ ] **Step 4: Full tests**

Run: `cargo test --all-features --locked`

Expected: PASS.

- [ ] **Step 5: Android AArch64 cross-build**

Run the repository's existing Android AArch64 CI/build gate on the same commit.

Expected: PASS.

- [ ] **Step 6: Attempt to falsify the change**

Explicitly exercise: 1 vs 100 same-root copies; unknown ancestry; one root; two roots; many roots; duplicate dispatch; source failure; deterministic repeated planning. None may create target-world evidence, and only demonstrated distinct roots may change independence utility.

- [ ] **Step 7: Inspect final diff**

Confirm no unrelated refactor, new evidence store, new dependency, `unsafe`, or accidental lockfile change.

- [ ] **Step 8: Record completion status**

Use `VERIFIED COMPLETE` for this refactor only if all host/CI gates above pass. Do not claim physical Termux runtime verification unless it was actually executed on-device.
