# GOAT Proof-Route Independence Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove false corroboration from Huntsman's consequential claim-verification and identity-resolution paths by requiring explicit, versioned proof-route independence rather than treating disjoint source-family labels as independent witnesses.

**Architecture:** Preserve `EvidenceAncestryGraph` as the sole provenance authority and retain existing label/family APIs only for diagnostics and legacy differential tests. Add a tri-state proof-route relation plus explicit `IndependenceEvidence`; verification and auto-merge consume only proven-independent routes, while unknown relationships fail closed. Count proven routes with a deterministic bounded exact maximum-clique search over claim-local roots; exhaustion/oversize is a blocker, never a strengthening signal.

**Tech Stack:** Rust 2024 edition, MSRV 1.87, serde/serde_json/thiserror, in-tree deterministic collections, GitHub Actions Android aarch64 cross-build.

**Spec:** `docs/superpowers/specs/2026-10-06-goat-epistemic-core-design.md` — Phase 1 only.

## Global Constraints

- Safe Rust only; repository lint `unsafe_code = "deny"` remains intact.
- No new runtime dependency unless a failing acceptance test proves one necessary.
- Preserve Rust 1.87 MSRV and Android aarch64 cross-buildability.
- Preserve `EvidenceAncestryGraph` as the sole canonical provenance graph; no parallel truth graph.
- Different providers, URLs, datasets, domains, source-family labels, hashes, or timestamps do not establish independence by themselves.
- Shared ancestry is dependent; missing/invalid/cyclic ancestry cannot produce `ProvenIndependent`.
- `ProvenIndependent` requires explicit admissible `IndependenceEvidence` under a recognized method id/version.
- Unknown method ids/versions and `OtherVersionedRule` without a registered rule fail closed.
- Copies, mirrors, derivations, transforms, relabeling, information loss, and truncation cannot increase proven independent routes.
- Legacy `are_independent` and `independent_support_count` remain compatibility/diagnostic APIs only and may not promote verification or automatic merge state after cutover.
- Exploration confidence may retain legacy diversity diagnostics but must not be treated as claim truth.

## Review Focus

- Two disjoint roots with different labels but no independence proof must remain `Unknown` and cannot satisfy a two-route gate.
- Explicit independence evidence must bind the exact canonical root pair; evidence for a different pair must not leak across claims/routes.
- Unknown/malformed method ids or versions, empty method ids, and missing supporting proof references must fail closed without panic.
- A support set larger than the deterministic exact-search bound must block strengthening rather than return a partial count as complete.
- Removing independence evidence or replacing it with copies/transforms must never strengthen claim state or enable auto-merge.

---

### Task 1: Canonical proof-route independence model

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Test: `src/evidence_ancestry.rs` module tests

**Interfaces:**
- Produces: `IndependenceState`, `IndependenceBasis`, `IndependenceEvidence`, `IndependenceEvidenceSet`, `EvidenceAncestryGraph::root_ids`, `EvidenceAncestryGraph::proof_route_relationship`, and `EvidenceAncestryGraph::proven_independent_support_count`.
- Compatibility: existing `root_families`, `are_independent`, and `independent_support_count` retain current diagnostic behavior and are explicitly documented as non-verification APIs.

- [ ] **Step 1: Write failing tri-state relationship tests**

Add tests asserting:
- shared canonical root -> `KnownDependent`;
- two disjoint roots with empty `IndependenceEvidenceSet` -> `Unknown`;
- admissible evidence for the exact root pair -> `ProvenIndependent`;
- evidence for another root pair -> `Unknown`;
- unknown method/version -> `Unknown`;
- missing parent/cycle still returns ancestry failure and can never produce `ProvenIndependent`.

- [ ] **Step 2: Run the focused tests and require RED**

Run: `cargo test --locked evidence_ancestry -- --nocapture`
Expected: FAIL because the new types/APIs do not exist.

- [ ] **Step 3: Implement the minimal canonical model**

Add exact public types:

```rust
pub enum IndependenceState { ProvenIndependent, KnownDependent, Unknown }
pub enum IndependenceBasis {
    DistinctAuthenticatedPrimaryOrigins,
    DistinctDirectSensorObservations,
    ExplicitUpstreamProvenance,
    OtherVersionedRule(String),
}
pub struct IndependenceEvidence {
    pub left_root: EvidenceNodeId,
    pub right_root: EvidenceNodeId,
    pub basis: IndependenceBasis,
    pub method_id: String,
    pub method_version: u32,
    pub supporting_artifact_ids: BTreeSet<String>,
    pub observed_at_unix: u64,
}
pub struct IndependenceEvidenceSet { /* deterministic canonical pair index */ }
```

Recognized v1 method ids are fixed constants owned by `evidence_ancestry`; unknown ids/versions fail closed. Canonicalize root-pair ordering on insertion so `(a,b)` and `(b,a)` are identical. Reject empty ids/method ids, self-pairs, non-root endpoints, and empty supporting proof references.

Add:

```rust
pub fn root_ids(&self, id: &EvidenceNodeId) -> Result<BTreeSet<EvidenceNodeId>, AncestryError>;
pub fn proof_route_relationship(
    &self,
    a: &EvidenceNodeId,
    b: &EvidenceNodeId,
    independence: &IndependenceEvidenceSet,
) -> Result<IndependenceState, AncestryError>;
```

Shared root ids -> `KnownDependent`; disjoint roots -> `ProvenIndependent` only when every proof route needed by the relationship has admissible exact-pair evidence; otherwise `Unknown`.

- [ ] **Step 4: Add bounded exact proven-route counting tests**

Assert:
- N copies/derivations of one root count as one route;
- three roots with only one proven pair do not count as three independent routes;
- a fully proven three-root clique counts three;
- adding an unknown relation cannot increase the count;
- input above the deterministic search bound fails closed.

- [ ] **Step 5: Implement deterministic bounded maximum-clique counting**

Add:

```rust
pub fn proven_independent_support_count<'a>(
    &self,
    ids: impl IntoIterator<Item = &'a EvidenceNodeId>,
    independence: &IndependenceEvidenceSet,
) -> Result<usize, AncestryError>;
```

Build the relation graph over unique canonical roots and compute the exact maximum clique using deterministic branch-and-bound with a fixed node-visit/search bound. Add an explicit ancestry/error variant for search exhaustion/oversize. Never return a partial count as complete.

- [ ] **Step 6: Run focused tests GREEN**

Run: `cargo test --locked evidence_ancestry -- --nocapture`
Expected: PASS.

- [ ] **Step 7: Commit**

Commit: `refactor(epistemic): add explicit proof-route independence`

### Task 2: Cut claim verification over to proven routes

**Files:**
- Modify: `src/claim_policy.rs`
- Modify: `src/shadow_assessment.rs`
- Modify: `tests/claim_ancestry.rs`
- Modify: `tests/claim_defeat.rs` only where signatures require it

**Interfaces:**
- Consumes: Task 1 `IndependenceEvidenceSet` and `proven_independent_support_count`.
- Produces: `IntelligenceLedger::assess_claim_with_proof_routes(...)` as the only verification-capable ancestry path.

- [ ] **Step 1: Write RED claim tests**

Add tests asserting:
- two disjoint roots with no independence evidence remain `Supported` with an independence blocker;
- the same claim becomes `Verified` only after exact-pair admissible independence evidence is supplied and all other obligations pass;
- removing that evidence demotes the claim again;
- invalid/unknown method evidence never verifies;
- search-limit failure blocks verification.

- [ ] **Step 2: Run targeted claim tests RED**

Run: `cargo test --locked --test claim_ancestry -- --nocapture`
Expected: FAIL under current disjoint-root promotion semantics.

- [ ] **Step 3: Add verification-capable API and blockers**

Add:

```rust
pub fn assess_claim_with_proof_routes(
    &self,
    claim_id: &ClaimId,
    policy: &VerificationPolicy,
    graph: &EvidenceAncestryGraph,
    bindings: &BTreeMap<EvidenceId, EvidenceNodeId>,
    independence: &IndependenceEvidenceSet,
) -> Result<ClaimAssessment, LedgerError>;
```

Add explicit blockers for missing/unproven independence and bounded-search failure. Keep `assess_claim_with_ancestry` as a compatibility diagnostic that cannot produce `Verified`; document this in code.

Expose both observed distinct roots and proven independent routes in `ClaimAssessment` without reusing one number for two meanings.

- [ ] **Step 4: Migrate shadow assessment**

`shadow_assessment` must call `assess_claim_with_proof_routes`, accepting the independence set explicitly. No verification-capable caller may use legacy family counts.

- [ ] **Step 5: Run claim + shadow tests GREEN**

Run: `cargo test --locked claim_ -- --nocapture`
Run: `cargo test --locked shadow_assessment -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit: `refactor(claims): require proven proof-route independence`

### Task 3: Cut identity auto-merge over to proven routes

**Files:**
- Modify: `src/identity_resolution.rs`
- Modify: `src/lineage.rs`
- Modify: relevant identity/lineage tests in the same modules and `tests/lineage_legacy.rs` only where compatibility expectations are intentionally diagnostic

**Interfaces:**
- Consumes: Task 1 `IndependenceEvidenceSet` and proven-route count.
- Produces: auto-merge decisions that can pass independence gates only through explicit proof.

- [ ] **Step 1: Write RED auto-merge tests**

Assert:
- `Match + 0.99 + two disjoint roots + no independence evidence` is held;
- exact admissible independence evidence for those roots allows auto-merge when all other gates pass;
- a copied/mirrored second observation cannot satisfy the gate;
- deleting independence evidence turns a previous auto-merge candidate into held;
- unknown method/version and search-limit failures are explicit hold reasons.

- [ ] **Step 2: Run focused identity/lineage tests RED**

Run: `cargo test --locked identity_resolution -- --nocapture`
Run: `cargo test --locked lineage -- --nocapture`
Expected: at least the disjoint-root/no-proof test fails under current semantics.

- [ ] **Step 3: Change the merge authority**

Replace consequential use of legacy family counts with APIs that require `&IndependenceEvidenceSet`. Add explicit hold reasons for unproven independence/evaluation failure. Preserve `independent_support_families` only as diagnostic compatibility data and do not use it to authorize merge.

- [ ] **Step 4: Change lineage bridging**

`resolve_with_lineage` must accept/pass an `IndependenceEvidenceSet` (or provide a compatibility wrapper that supplies an empty set and therefore fails closed). Lineage labels may construct provenance roots but may not manufacture independence evidence.

- [ ] **Step 5: Run focused tests GREEN**

Run: `cargo test --locked identity_resolution -- --nocapture`
Run: `cargo test --locked lineage -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Commit**

Commit: `refactor(identity): gate auto-merge on proven independence`

### Task 4: Prove there is no consequential legacy-independence consumer

**Files:**
- Modify: `src/confidence.rs` documentation/tests only if needed to state exploratory-only semantics
- Modify: `tests/pipeline.rs` to use proven-route APIs in any consequential assertion
- Test: repository-wide code search + focused integration tests

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: Phase-1 cutover invariant: legacy boolean/count independence APIs cannot promote claims or identities.

- [ ] **Step 1: Add/adjust integration tests**

Pin one end-to-end path where two differently labelled roots without independence proof cannot reach `Verified` or `AutoMerge`, then add proof evidence and show the intended promotion.

- [ ] **Step 2: Search all legacy API consumers**

Search for `are_independent(` and `independent_support_count(`. Every active-code consumer must be classified explicitly:
- diagnostic/exploration only -> retain with documentation;
- verification/merge capable -> migrate to proven-route API.

Expected allowed active consumer after cutover: exploratory confidence only, if retained.

- [ ] **Step 3: Run pipeline/integration tests**

Run: `cargo test --locked --test pipeline -- --nocapture`
Run: `cargo test --locked --test claim_ancestry -- --nocapture`
Expected: PASS.

- [ ] **Step 4: Commit**

Commit: `test(epistemic): enforce proof-route cutover`

### Task 5: Falsification, non-regression, and platform verification

**Files:**
- Modify only if a failing gate proves a necessary repair.

**Interfaces:**
- Consumes: complete Phase-1 refactor.
- Produces: evidence for merge readiness; no acceptance based solely on compilation.

- [ ] **Step 1: Run property/falsification suite**

Require tests for duplicate invariance, information-loss monotonicity, evidence-removal monotonicity, unknown-method fail-closed behavior, shared-root dependence, disjoint-label unknown state, explicit-proof promotion, and bounded-search fail-closed behavior.

- [ ] **Step 2: Run repository quality gates**

Run:
- `cargo fmt --check`
- `cargo check --locked --all-targets --all-features`
- `cargo clippy --locked --all-targets --all-features -- -D warnings`
- `cargo test --locked --all-features`

Expected: all PASS.

- [ ] **Step 3: Verify MSRV and Android aarch64 CI**

Require GitHub CI success for stable, Rust 1.87, and Android aarch64 release/ELF validation. Cross-build success must not be reported as real-handset execution.

- [ ] **Step 4: Differential review**

Confirm intentional strictness changes only: claims/merges that previously passed solely because roots had different labels are now held/Supported unless explicit independence proof exists. No unrelated retrieval, HIBP, installer, or source-adapter behavior changes.

- [ ] **Step 5: Final branch review and PR**

Review the complete diff against `main`; reject accidental edits to legacy reference trees or production deployment configuration. Open a PR only after all required gates are green.
