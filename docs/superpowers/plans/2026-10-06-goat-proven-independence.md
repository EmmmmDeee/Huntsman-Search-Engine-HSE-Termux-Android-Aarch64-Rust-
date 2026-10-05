# GOAT Proven Independence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Huntsman fail closed on proof-route independence: distinct provider/root labels remain `Unknown` unless explicit, versioned evidence proves independence, while known shared ancestry remains dependent.

**Architecture:** Extend the canonical `EvidenceAncestryGraph` rather than introducing a second provenance authority. Add explicit independence evidence and bounded conservative route counting, then make canonical claim assessment use proven independent routes instead of raw distinct-root cardinality. Preserve the flat-lineage path as diagnostic-only and preserve shadow comparison as observational.

**Tech Stack:** Rust 1.87 MSRV + stable CI, serde, `BTreeMap`/`BTreeSet`, existing Huntsman ancestry/claim modules, GitHub Actions Android aarch64 API-24 cross-build.

**Spec:** `docs/superpowers/specs/2026-10-06-goat-epistemic-core-design.md`

## Global Constraints

- Runtime core remains deterministic safe Rust; `#![deny(unsafe_code)]` stays intact.
- Primary deployment remains unprivileged Android/Termux aarch64.
- MSRV remains Rust 1.87 unless separately approved and verified.
- Do not add a parallel provenance or evidence-fusion subsystem.
- Unknown ancestry or independence must never strengthen a claim.
- Different providers, URLs, domains, datasets, labels, or disjoint recorded root families are not proof of independence.
- Known shared ancestry collapses duplicate proof routes.
- Verification remains separate from exploration/confidence scoring.
- Compatibility APIs may remain diagnostic but cannot retain epistemic promotion authority.
- Resource-bounded independence search may under-credit or mark incomplete; it may never over-credit.
- No runtime LLM and no new network dependency.

## Review Focus

- Two distinct root-family labels with no explicit independence evidence remain `Unknown` and cannot satisfy a two-route policy.
- Explicit independence evidence referencing missing, identical, non-root, or invalid nodes is rejected.
- Independence evidence is symmetric and duplicate-safe regardless of insertion/query order.
- Shared upstream ancestry dominates any independence assertion and remains `KnownDependent`.
- Persisted graph state is revalidated on deserialization; invalid independence records cannot bypass constructors.

---

### Task 0: Introduce the stable retrieval artifact identifier

**Files:**
- Create: `src/retrieval_artifact.rs`
- Modify: `src/lib.rs`
- Test: `src/retrieval_artifact.rs` unit tests

**Interfaces:**
- Produce: `ArtifactId(pub String)` with `Debug`, `Clone`, `PartialEq`, `Eq`, `PartialOrd`, `Ord`, `Hash`, `Serialize`, `Deserialize`, and `From<&str>`.
- Do not implement the Phase-2 `RetrievalArtifact` record yet.

- [ ] **Step 1: Write the failing ID round-trip test**

```rust
#[test]
fn artifact_id_round_trips_as_transparent_string() {
    let id = ArtifactId::from("sha256:abc");
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, "\"sha256:abc\"");
    assert_eq!(serde_json::from_str::<ArtifactId>(&json).unwrap(), id);
}
```

- [ ] **Step 2: Run the focused test and verify failure**

Run: `cargo test --locked retrieval_artifact::tests -- --nocapture`

Expected: FAIL because the module/type does not exist.

- [ ] **Step 3: Implement `ArtifactId` and export the module**

Create only the transparent ID type and `From<&str>` implementation. Add `pub mod retrieval_artifact;` to `src/lib.rs`.

- [ ] **Step 4: Run the focused test**

Run: `cargo test --locked retrieval_artifact::tests -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/retrieval_artifact.rs src/lib.rs
git commit -m "feat(epistemic): add stable retrieval artifact id"
```

### Task 1: Add explicit independence evidence to the canonical ancestry authority

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Test: `src/evidence_ancestry.rs` unit tests

**Interfaces:**
- Consume: `crate::retrieval_artifact::ArtifactId`.
- Produce: `IndependenceState::{ProvenIndependent, KnownDependent, Unknown}`.
- Produce: `IndependenceBasis::{DistinctAuthenticatedPrimaryOrigins, DistinctDirectSensorObservations, ExplicitUpstreamProvenance}`.
- Produce: `IndependenceEvidence { left_root: EvidenceNodeId, right_root: EvidenceNodeId, basis: IndependenceBasis, method_id: String, method_version: u32, supporting_artifact_ids: BTreeSet<ArtifactId>, observed_at_unix: u64 }`.
- Produce: `EvidenceAncestryGraph::insert_independence_evidence(IndependenceEvidence) -> Result<(), AncestryError>`.
- Produce: `EvidenceAncestryGraph::independence_state(&EvidenceNodeId, &EvidenceNodeId) -> Result<IndependenceState, AncestryError>`.
- Preserve: existing `root_families`, `independent_support_count`, and `are_independent` as compatibility/diagnostic APIs, but Task 3 removes them from verification authority.

- [ ] **Step 1: Write failing unit tests for conservative independence semantics**

Add tests named:

```rust
fn disjoint_root_labels_are_unknown_without_explicit_independence()
fn shared_root_is_known_dependent_even_if_labels_differ()
fn explicit_valid_independence_is_symmetric()
fn invalid_independence_evidence_is_rejected()
fn deserialization_cannot_bypass_independence_validation()
```

Assertions must cover: `Unknown` for unproven disjoint roots, `KnownDependent` for a common root, symmetric `ProvenIndependent`, rejection of same-root/missing-root/non-root/empty-method/version-zero evidence, and serde revalidation.

- [ ] **Step 2: Run focused tests and verify failure for missing interfaces**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: FAIL because independence evidence/state APIs do not exist.

- [ ] **Step 3: Implement canonical pair storage and validation**

Store evidence under an ordered `(EvidenceNodeId, EvidenceNodeId)` key inside `EvidenceAncestryGraph` with `#[serde(default)]`. Extend `RawGraph` and `TryFrom<RawGraph>` so both nodes and independence records are reinserted through validating APIs.

`insert_independence_evidence` must require:
- two distinct ids;
- both ids exist;
- both referenced nodes are roots (`parents.is_empty()` and `derived == false`);
- non-empty `method_id` after trim;
- `method_version > 0`;
- at least one supporting artifact id.

Duplicate canonical pairs may replace only an exactly identical record; conflicting evidence for the same pair returns a typed `AncestryError` rather than silently overwriting.

- [ ] **Step 4: Implement conservative query semantics**

`independence_state(a, b)` resolves reachable roots for both nodes:
- any shared root => `KnownDependent`;
- missing/cyclic ancestry => existing error/fail closed;
- if each side resolves to exactly one distinct root, return `ProvenIndependent` only when accepted explicit evidence exists for that root pair;
- every other disjoint case => `Unknown`.

- [ ] **Step 5: Run focused ancestry tests**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/evidence_ancestry.rs
git commit -m "feat(epistemic): require evidence for source independence"
```

### Task 2: Add bounded conservative independent-route counting

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Test: `src/evidence_ancestry.rs` unit tests

**Interfaces:**
- Consume: `EvidenceAncestryGraph::independence_state`.
- Produce: `IndependenceRouteCount { proven: usize, incomplete: bool }`.
- Produce: `EvidenceAncestryGraph::proven_independent_route_count<'a>(ids: impl IntoIterator<Item=&'a EvidenceNodeId>, required: usize, max_search_states: usize) -> Result<IndependenceRouteCount, AncestryError>`.

- [ ] **Step 1: Write failing route-count tests**

Add tests named:

```rust
fn two_disjoint_unproven_roots_count_as_one_route()
fn two_explicitly_independent_roots_count_as_two_routes()
fn mirror_nodes_over_one_root_count_as_one_route()
fn three_roots_can_satisfy_two_when_one_proven_pair_exists()
fn search_budget_exhaustion_is_incomplete_and_never_strengthens()
fn required_zero_and_one_have_bounded_semantics()
```

- [ ] **Step 2: Run focused tests and verify failure**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: FAIL because route-count APIs do not exist.

- [ ] **Step 3: Implement deterministic bounded subset search**

Resolve and deduplicate provenance roots first. For `required == 0`, return `{ proven: 0, incomplete: false }`; for `required == 1`, one resolved root is sufficient without pairwise independence evidence. For larger requirements, deterministically search combinations for a mutually `ProvenIndependent` subset, stopping once `required` is proven or `max_search_states` is exhausted. `Unknown` pairs never count. On budget exhaustion return only the proven lower bound and `incomplete: true`.

- [ ] **Step 4: Run focused ancestry tests**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/evidence_ancestry.rs
git commit -m "feat(epistemic): count only proven independent routes"
```

### Task 3: Make canonical claim verification depend on proven independence

**Files:**
- Modify: `src/claim_policy.rs`
- Modify: `tests/claim_ancestry.rs`
- Modify: `tests/claim_defeat.rs` only if assessment construction requires compatibility updates
- Test: `tests/claim_ancestry.rs`

**Interfaces:**
- Consume: `EvidenceAncestryGraph::proven_independent_route_count`.
- Preserve: `VerificationPolicy::min_proven_roots` as the compatibility field name for this migration slice; canonical verification interprets it as minimum proven independent routes.
- Extend: `ClaimAssessment` with `distinct_resolved_roots: usize` and `independence_incomplete: bool`, both serde-defaulted.
- Add: `VerificationBlocker::IncompleteIndependenceProof`.
- Semantics: `ClaimAssessment::proven_roots` becomes the conservative number of proof routes established under independence semantics, not raw root-family cardinality.

- [ ] **Step 1: Write failing integration tests for false corroboration**

Add/modify tests named:

```rust
fn disjoint_root_labels_do_not_satisfy_two_route_policy_without_independence_evidence()
fn explicit_independence_can_satisfy_two_route_policy()
fn known_shared_origin_stays_one_route()
fn independence_search_truncation_blocks_verification()
```

Retain existing tests for missing bindings, cycles, mirrors, and derived-root inheritance.

- [ ] **Step 2: Run claim ancestry tests and verify the unproven-disjoint case fails on current behavior**

Run: `cargo test --locked --test claim_ancestry -- --nocapture`

Expected: FAIL because two distinct graph roots currently count as two proven roots.

- [ ] **Step 3: Route canonical assessment through proven route counting**

In `assess_claim_with_ancestry`:
- collect resolved roots diagnostically;
- preserve unresolved-support accounting;
- set `distinct_resolved_roots` to raw distinct resolved root count;
- compute `proven_roots` using bounded independence search with a module constant `MAX_INDEPENDENCE_SEARCH_STATES`;
- set `independence_incomplete` and blocker `IncompleteIndependenceProof` when the search budget is exhausted;
- never use flat `SourceLineage`, provider ids, root-family cardinality alone, or conclusion confidence to satisfy multi-route independence.

The flat `assess_claim` path remains diagnostic-only and blocked by `CanonicalAncestryRequired`.

- [ ] **Step 4: Run claim suites**

Run: `cargo test --locked --test claim_ancestry --test claim_policy --test claim_defeat -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/claim_policy.rs tests/claim_ancestry.rs tests/claim_defeat.rs
git commit -m "fix(epistemic): block unproven corroboration"
```

### Task 4: Preserve shadow diagnostics and regression visibility

**Files:**
- Modify: `src/shadow_assessment.rs`
- Modify: `tests/shadow_assessment.rs`

**Interfaces:**
- Consume: extended `ClaimAssessment`.
- Produce: stable reason code `blocker:insufficient_independent_support` for unproven disjoint roots.
- Produce: stable reason code `blocker:incomplete_independence_proof` for bounded-search truncation.
- Preserve: shadow comparison remains read-only and cannot affect scheduling or stored claim state.

- [ ] **Step 1: Add failing shadow tests**

Add fixtures for:
- stored legacy `Verified` + two unproven disjoint roots + two-route policy => policy `Supported` and `blocker:insufficient_independent_support`;
- forced independence-search truncation => policy not `Verified` and `blocker:incomplete_independence_proof`.

- [ ] **Step 2: Run shadow tests and verify failure**

Run: `cargo test --locked --test shadow_assessment -- --nocapture`

Expected: FAIL until updated assessment diagnostics are projected.

- [ ] **Step 3: Update shadow projection without mutating stored state**

Add the new blocker code. Expose `distinct_resolved_roots`, `proven_independent_routes`, and `independence_incomplete` only if required to make the shadow report auditable; do not change scheduling or stored claim state.

- [ ] **Step 4: Run shadow tests**

Run: `cargo test --locked --test shadow_assessment -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/shadow_assessment.rs tests/shadow_assessment.rs
git commit -m "test(epistemic): expose unproven independence in shadow assessment"
```

### Task 5: Phase-1 verification and non-regression gate

**Files:**
- No product changes unless verification exposes a defect caused by Tasks 0-4.

**Interfaces:**
- Produces: verified Phase-1 state suitable for Phase-2 retrieval-attempt planning.

- [ ] **Step 1: Run formatting**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Run stable clippy exactly as CI does**

Run: `cargo clippy --all-targets --locked -- -D warnings`

Expected: PASS.

- [ ] **Step 3: Run MSRV and stable locked tests**

Run under Rust 1.87 and stable: `cargo test --locked`

Expected: PASS on both toolchains.

- [ ] **Step 4: Verify generated artifacts remain unchanged**

Run: `cargo run --locked -- check` followed by `git diff --exit-code -- var/`

Expected: PASS/no diff.

- [ ] **Step 5: Verify release build**

Run: `cargo build --release --locked`

Expected: PASS.

- [ ] **Step 6: Verify Android aarch64 API-24 cross-build using `.github/workflows/ci.yml` contract**

Build target `aarch64-linux-android`, verify AArch64 ELF and `/system/bin/linker64`, and verify staged SHA-256. This proves cross-build artifact correctness only; it does not prove real handset execution.

- [ ] **Step 7: Inspect differential impact**

Confirm demotions are attributable to `Unknown` independence rather than parser/network regressions, and confirm one-route policies preserve prior verified behavior when other obligations are satisfied.
