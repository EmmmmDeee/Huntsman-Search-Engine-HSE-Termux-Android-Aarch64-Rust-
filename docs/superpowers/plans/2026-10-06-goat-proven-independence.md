# GOAT Proven Independence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Huntsman fail closed on proof-route independence: distinct provider/root labels remain `Unknown` unless explicit, versioned evidence proves independence, while known shared ancestry remains dependent.

**Architecture:** Extend the canonical `EvidenceAncestryGraph` rather than introducing a second provenance authority. Add explicit pairwise independence evidence plus conservative proof-route counting, then make canonical claim assessment use proven independent routes instead of raw distinct root-family count. Preserve current flat-lineage assessment as diagnostic-only and keep shadow comparison observational.

**Tech Stack:** Rust, serde, `BTreeMap`/`BTreeSet`, existing Huntsman ancestry/claim modules, cargo test/clippy/fmt.

**Spec:** `docs/superpowers/specs/2026-10-06-goat-epistemic-core-design.md`

## Global Constraints

- Runtime core remains deterministic safe Rust; `#![deny(unsafe_code)]` stays intact.
- Primary deployment remains unprivileged Android/Termux aarch64.
- Do not add a parallel provenance or evidence-fusion subsystem.
- Unknown ancestry or independence must never strengthen a claim.
- Different providers, URLs, domains, datasets, labels, or disjoint recorded root families are not proof of independence.
- Known shared ancestry collapses duplicate proof routes.
- Verification must remain separate from exploration/confidence scoring.
- Compatibility APIs may remain diagnostic but cannot retain epistemic promotion authority.
- No runtime LLM and no new network dependency.

## Review Focus

- Two distinct root-family labels with no explicit independence evidence must remain `Unknown` and must not satisfy a two-route policy.
- Explicit independence evidence must not be accepted if it references missing, identical, non-root, or otherwise invalid provenance nodes.
- Independence evidence must be symmetric and duplicate-safe regardless of insertion/query order.
- A shared upstream root must dominate conflicting or stale independence assertions and remain `KnownDependent`.
- Serialization/deserialization must preserve independence evidence without allowing invalid graph state to bypass insertion validation.

---

### Task 1: Add explicit independence evidence to the canonical ancestry authority

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Test: `src/evidence_ancestry.rs` unit tests

**Interfaces:**
- Produce: `IndependenceState::{ProvenIndependent, KnownDependent, Unknown}`.
- Produce: `IndependenceBasis::{DistinctAuthenticatedPrimaryOrigins, DistinctDirectSensorObservations, ExplicitUpstreamProvenance}`.
- Produce: `IndependenceEvidence { left_root: EvidenceNodeId, right_root: EvidenceNodeId, basis: IndependenceBasis, method_id: String, method_version: u32, supporting_evidence_ids: BTreeSet<String>, observed_at_unix: u64 }`.
- Produce: `EvidenceAncestryGraph::insert_independence_evidence(IndependenceEvidence) -> Result<(), AncestryError>`.
- Produce: `EvidenceAncestryGraph::independence_state(&EvidenceNodeId, &EvidenceNodeId) -> Result<IndependenceState, AncestryError>`.
- Preserve: existing `root_families`, `independent_support_count`, and `are_independent` only as compatibility/diagnostic APIs until Task 3 removes them from verification authority.

- [ ] **Step 1: Write failing unit tests for conservative independence semantics**

Add tests asserting:

```rust
#[test]
fn disjoint_root_labels_are_unknown_without_explicit_independence() { /* state == Unknown */ }

#[test]
fn shared_root_is_known_dependent_even_if_labels_differ() { /* state == KnownDependent */ }

#[test]
fn explicit_valid_independence_is_symmetric() { /* a,b and b,a == ProvenIndependent */ }

#[test]
fn invalid_independence_evidence_is_rejected() { /* same root, missing root, empty method, version 0 */ }

#[test]
fn deserialization_cannot_bypass_independence_validation() { /* invalid stored evidence fails */ }
```

- [ ] **Step 2: Run the focused tests and verify they fail for missing interfaces**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: FAIL because `IndependenceState`, `IndependenceEvidence`, and insertion/query APIs do not yet exist.

- [ ] **Step 3: Implement explicit independence evidence inside `EvidenceAncestryGraph`**

Use a canonical ordered pair key derived from the two root node ids so evidence is symmetric and duplicate-safe. `insert_independence_evidence` must require two distinct existing root nodes (`parents.is_empty()` and `derived == false`), non-empty `method_id`, and `method_version > 0`; invalid input returns a typed `AncestryError`. Add serde defaults and revalidation in `TryFrom<RawGraph>` so persisted data cannot bypass these rules.

`independence_state(a, b)` semantics:
- resolve each node to its reachable roots;
- any shared root -> `KnownDependent`;
- unresolved/missing/cyclic ancestry -> existing error/fail closed;
- for single-root-vs-single-root, return `ProvenIndependent` only when explicit accepted evidence exists for that canonical pair;
- otherwise `Unknown`.

- [ ] **Step 4: Run the focused ancestry tests**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/evidence_ancestry.rs
git commit -m "feat(epistemic): require evidence for source independence"
```

### Task 2: Add conservative independent-route counting

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Test: `src/evidence_ancestry.rs` unit tests

**Interfaces:**
- Consume: `EvidenceAncestryGraph::independence_state` from Task 1.
- Produce: `EvidenceAncestryGraph::proven_independent_route_count<'a>(ids: impl IntoIterator<Item=&'a EvidenceNodeId>, required: usize) -> Result<usize, AncestryError>`.

- [ ] **Step 1: Write failing tests for route-count semantics**

Add tests asserting:

```rust
#[test]
fn two_disjoint_unproven_roots_count_as_one_route() { /* required=2 => count 1 */ }

#[test]
fn two_explicitly_independent_roots_count_as_two_routes() { /* count 2 */ }

#[test]
fn mirror_nodes_over_one_root_count_as_one_route() { /* count 1 */ }

#[test]
fn three_roots_can_satisfy_two_when_one_proven_pair_exists() { /* count >= 2 */ }

#[test]
fn required_zero_is_zero_and_required_one_needs_only_one_resolved_root() { /* bounded semantics */ }
```

- [ ] **Step 2: Run focused tests and verify failure**

Run: `cargo test --locked evidence_ancestry::tests -- --nocapture`

Expected: FAIL because `proven_independent_route_count` does not exist.

- [ ] **Step 3: Implement deterministic bounded route counting**

For `required <= 1`, return `min(distinct_resolved_roots, required)`. For larger requirements, search deterministically for a mutually `ProvenIndependent` subset only up to `required`; do not treat `Unknown` pairs as independent. Stop once `required` routes are proven. This may under-credit unresolved cases but must never over-credit them. Keep the search bounded by the policy requirement rather than enumerating every maximal clique.

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
- Modify: `tests/claim_defeat.rs` only if constructor/assessment fields require compatibility updates
- Test: `tests/claim_ancestry.rs`

**Interfaces:**
- Consume: `EvidenceAncestryGraph::proven_independent_route_count`.
- Preserve: `VerificationPolicy::min_proven_roots` as the compatibility field name for this migration slice; verification semantics interpret it as the minimum number of proven independent proof routes.
- Extend: `ClaimAssessment` with `distinct_resolved_roots: usize` while `proven_roots` becomes the number of proof routes accepted under explicit independence semantics. Keep serde defaults for persisted compatibility.

- [ ] **Step 1: Write failing integration tests pinning the false-corroboration boundary**

Add/modify tests asserting:

```rust
#[test]
fn disjoint_root_labels_do_not_satisfy_two_route_policy_without_independence_evidence() {
    /* two root nodes, no common parent, no independence evidence => proven_roots == 1; Supported */
}

#[test]
fn explicit_independence_can_satisfy_two_route_policy() {
    /* add valid independence evidence => proven_roots == 2; Verified */
}

#[test]
fn known_shared_origin_stays_one_route_even_if_independence_record_is_absent_or_conflicting() {
    /* shared ancestor => one route */
}
```

Retain existing tests for missing bindings, cycles, and derived-root inheritance.

- [ ] **Step 2: Run claim ancestry tests and verify the new unproven-disjoint test fails on current behavior**

Run: `cargo test --locked --test claim_ancestry -- --nocapture`

Expected: FAIL because two distinct graph roots currently count as two proven roots.

- [ ] **Step 3: Route canonical assessment through proven independent-route counting**

In `assess_claim_with_ancestry`:
- collect resolved root node ids/families diagnostically;
- preserve unresolved-support accounting;
- compute `distinct_resolved_roots` separately;
- compute `proven_roots` via `graph.proven_independent_route_count(..., policy.min_proven_roots)`;
- continue to fail closed on missing bindings, missing nodes, cycles, or empty roots;
- never use flat `SourceLineage`, provider ids, source-family cardinality, or conclusion confidence to satisfy independence.

Do not make the flat `assess_claim` path verification-capable; it remains blocked by `CanonicalAncestryRequired`.

- [ ] **Step 4: Run claim-policy and ancestry suites**

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
- Test: `tests/shadow_assessment.rs`

**Interfaces:**
- Consume: extended `ClaimAssessment` from Task 3.
- Produce: stable reason code `blocker:insufficient_independent_support` for unproven disjoint roots.
- Preserve: shadow comparison remains read-only and cannot affect scheduling or stored claim state.

- [ ] **Step 1: Add a failing shadow test for legacy-overcredit detection**

Add a fixture where legacy/current stored state is `Verified`, canonical ancestry has two disjoint unproven roots, policy requires two routes, and shadow assessment reports policy `Supported` plus `blocker:insufficient_independent_support`.

- [ ] **Step 2: Run shadow tests and verify failure if diagnostics do not expose the demotion**

Run: `cargo test --locked --test shadow_assessment -- --nocapture`

Expected: FAIL until the updated assessment fields and reason path are integrated.

- [ ] **Step 3: Update shadow projection without changing stored state**

Keep existing blocker-code mapping stable. Add only the minimum diagnostic fields needed to expose distinct resolved roots versus proven independent routes if the existing `ShadowAssessment` view cannot make the distinction auditable.

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
- No product file changes unless verification reveals a defect attributable to Tasks 1-4.

**Interfaces:**
- Produces: verified Phase-1 state suitable for Phase 2 planning.

- [ ] **Step 1: Run formatting**

Run: `cargo fmt --check`

Expected: PASS.

- [ ] **Step 2: Run clippy under the repository contract**

Run: `cargo clippy --locked --all-targets --all-features -- -D warnings`

Expected: PASS, or document a repository/toolchain blocker without weakening code to silence an unrelated environment defect.

- [ ] **Step 3: Run the full locked test suite**

Run: `cargo test --locked`

Expected: PASS.

- [ ] **Step 4: Verify release build**

Run: `cargo build --locked --release`

Expected: PASS.

- [ ] **Step 5: Verify Android aarch64 cross-build using the repository's existing pinned/toolchain workflow**

Expected: cross-build/ELF checks PASS. Do not claim real handset execution from cross-build success.

- [ ] **Step 6: Inspect differential impact**

Confirm that any claim demotions are explainable by `Unknown` independence rather than parser/network regressions, and that one-root policies preserve prior verified behavior where all other obligations are satisfied.

- [ ] **Step 7: Commit any verification-only fixture/documentation corrections**

```bash
git add <only-files-required-by-verification>
git commit -m "test(epistemic): verify proven-independence migration"
```
