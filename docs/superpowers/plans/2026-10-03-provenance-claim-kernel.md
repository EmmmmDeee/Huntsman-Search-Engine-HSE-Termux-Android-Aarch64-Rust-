# Provenance-Rooted Claim Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace source-count/confidence claim promotion with conservative provenance-aware, policy-governed claim assessment while preserving verified Huntsman platform behavior and existing ROI ownership.

**Architecture:** Migrate in reversible slices. First repair unknown-ancestry over-crediting in the current ledger. Then add versioned claim policies and structured defeat semantics, make `EvidenceAncestryGraph` the single ancestry authority, and expose blockers/information requirements to the existing ROI layer. Keep current confidence/eval semantics as exploration-only until shadow comparison proves a safe production cutover.

**Tech Stack:** Rust 1.87 MSRV, serde, deterministic `BTreeMap`/`BTreeSet`, existing `EvidenceAncestryGraph`, `IntelligenceLedger`, current CI and Android aarch64 cross-build path.

**Spec:** `docs/superpowers/specs/2026-10-03-provenance-claim-kernel-design.md`

## Global Constraints

- Primary deployment remains unprivileged Android/Termux aarch64.
- Runtime reasoning remains deterministic Rust and bounded for mobile resources.
- Existing `egress` / `http` / `fetch` / `keys` ownership boundaries remain authoritative.
- Unknown provenance, dependency, identity, chronology, authority, applicability, or coverage remains unknown.
- Duplicates, transformations, correlations, aggregation, and derivations cannot create independent evidence.
- Consequential invariants must be enforced below provider/caller control.
- Claim assessment must be reproducible from evidence plus versioned policy.
- Existing ROI/termination remains the sole collection scheduling authority.
- Production semantic cutover occurs only after shadow comparison and claim-specific acceptance evidence.

## Review Focus

1. Evidence with no known origin must never become independent merely because provider/source labels differ.
2. Mixed known/unknown ancestry must preserve known roots while explicitly reporting unresolved support.
3. Caller-set conclusion confidence must not satisfy a missing mandatory proof obligation.
4. Contradictory-looking evidence with non-overlapping time/scope must not automatically reject a claim.
5. Any bounded/truncated proof computation must fail conservative: incomplete may hold/weaken but never promote.

---

### Task 1: Repair unknown-ancestry independence semantics

**Files:**
- Modify: `src/intelligence.rs`
- Test: `src/intelligence.rs`

**Interfaces:**
- Produces: `SupportIndependence { proven_roots: BTreeSet<String>, unresolved: BTreeSet<EvidenceId> }`
- Produces: `IntelligenceLedger::support_independence(&ClaimId) -> Result<SupportIndependence, LedgerError>`
- Compatibility: `independent_source_count(&ClaimId)` remains temporarily, returning only `proven_roots.len()`.

- [ ] **Step 1: Write the failing tests**
  Add `unknown_origin_does_not_create_independent_support`, `mixed_known_and_unknown_support_preserves_only_proven_roots`, and `shared_known_origin_counts_once`.
- [ ] **Step 2: Run focused tests and confirm failure**
  Run `cargo test --locked intelligence::tests::unknown_origin_does_not_create_independent_support intelligence::tests::mixed_known_and_unknown_support_preserves_only_proven_roots intelligence::tests::shared_known_origin_counts_once`.
  Expected: unknown-origin tests fail because current `SourceLineage::independence_key()` falls back to `source_id`.
- [ ] **Step 3: Implement conservative ancestry summary**
  Replace epistemic use of `independence_key()` with `known_origin_key(&self) -> Option<&str>`. Unknown origins enter `unresolved`; they never create proven roots. Keep duplicate detection separate from epistemic independence.
- [ ] **Step 4: Run `cargo test --locked intelligence::tests`**
  Expected: PASS.
- [ ] **Step 5: Commit**
  Commit message: `fix(intelligence): keep unknown ancestry unresolved`.

### Task 2: Introduce policy-governed claim assessment

**Files:**
- Modify: `src/intelligence.rs`
- Test: `src/intelligence.rs`

**Interfaces:**
- Create: `PredicateId(pub String)`.
- Create: `VerificationPolicy { id: String, version: u32, min_proven_roots: usize, require_resolved_ancestry: bool, required_natures: BTreeSet<EvidenceNature> }`.
- Create: `VerificationBlocker::{UnknownAncestry, MissingRequiredEvidenceNature, InsufficientIndependentSupport, UndefeatedDefeater}`.
- Create: `ClaimAssessment { epistemic: ClaimState, blockers: BTreeSet<VerificationBlocker>, proven_roots: usize, unresolved_support: usize }`.
- Create: `IntelligenceLedger::assess_claim(&ClaimId, &VerificationPolicy) -> Result<ClaimAssessment, LedgerError>`.
- Compatibility: preserve legacy `Claim.confidence` field for serialization/read compatibility, but `assess_claim` must not use `confidence.conclusion`.

- [ ] **Step 1: Write failing tests**
  Add `confidence_cannot_verify_without_required_evidence_nature`, `policy_can_verify_one_direct_observation`, and `unknown_ancestry_blocks_policy_that_requires_resolution`.
- [ ] **Step 2: Run focused tests and confirm failure**
  Expected: current universal source-count/confidence state machine cannot satisfy policy-specific assertions.
- [ ] **Step 3: Implement `VerificationPolicy`, blockers, and `assess_claim`**
  State is derived only from mandatory policy obligations and proven support. `Verified` requires all mandatory obligations satisfied; unresolved mandatory ancestry blocks promotion.
- [ ] **Step 4: Keep legacy `recompute_claim_state` as a shadow/compatibility path**
  Do not silently switch production semantics yet. Add comments/tests marking it legacy and ensure new tests call `assess_claim` directly.
- [ ] **Step 5: Run `cargo test --locked intelligence::tests`**
  Expected: PASS.
- [ ] **Step 6: Commit**
  Commit message: `feat(intelligence): add policy-governed claim assessment`.

### Task 3: Replace generic contradiction with structured defeat

**Files:**
- Modify: `src/intelligence.rs`
- Test: `src/intelligence.rs`

**Interfaces:**
- Create: `DefeatKind::{Rebut, Undermine, Undercut, Supersede, Compatible, UnknownRelation}`.
- Create: `Defeat { evidence_id: EvidenceId, kind: DefeatKind, temporal_overlap: Option<bool>, rationale: String }`.
- Add: `Claim.defeats: Vec<Defeat>` with serde default.
- Add: `IntelligenceLedger::attach_defeat(&ClaimId, Defeat) -> Result<(), LedgerError>`.
- `VerificationBlocker::UndefeatedDefeater` applies only to `Rebut`, `Undermine`, or `Undercut`; `Supersede`, `Compatible`, and `UnknownRelation` do not automatically reject.

- [ ] **Step 1: Write failing tests**
  Add `compatible_different_time_does_not_reject`, `rebuttal_blocks_verification`, and `undercutter_blocks_dependent_claim_without_creating_new_witness`.
- [ ] **Step 2: Confirm tests fail**
  Expected: current contradiction path treats any contradiction as rejection.
- [ ] **Step 3: Implement structured defeat and policy interaction**
  Preserve legacy `contradictions` for compatibility reads during migration, but new assessment uses `defeats`.
- [ ] **Step 4: Run intelligence tests**
  Expected: PASS.
- [ ] **Step 5: Commit**
  Commit message: `feat(intelligence): model structured claim defeat`.

### Task 4: Make `EvidenceAncestryGraph` the single provenance authority

**Files:**
- Modify: `src/evidence_ancestry.rs`
- Modify: `src/intelligence.rs`
- Test: both modules

**Interfaces:**
- Add: `EvidenceRecord.ancestry_node_id: Option<EvidenceNodeId>` with serde default.
- Add: `IntelligenceLedger::assess_claim_with_ancestry(&ClaimId, &VerificationPolicy, &EvidenceAncestryGraph) -> Result<ClaimAssessment, LedgerError>`.
- Remove epistemic dependence on duplicated `ancestry_root_families` data after migration tests prove parity; retain compatibility deserialization only as needed.

- [ ] **Step 1: Write failing tests**
  Add `mirrors_in_ancestry_graph_count_as_one_route`, `missing_ancestry_node_blocks_resolved_policy`, `derived_node_inherits_parent_roots`, and `cycle_fails_closed`.
- [ ] **Step 2: Confirm failures against split-authority model**
- [ ] **Step 3: Route proof-root resolution through `EvidenceAncestryGraph`**
  Missing node/cycle is unresolved/error, never independence. Derived nodes may not create additional root families.
- [ ] **Step 4: Add regression test that provider/source relabeling does not change proof roots**
- [ ] **Step 5: Run `cargo test --locked evidence_ancestry intelligence`**
  Expected: PASS.
- [ ] **Step 6: Commit**
  Commit message: `refactor(intelligence): unify claim provenance on ancestry graph`.

### Task 5: Add conservative negative-evidence coverage semantics

**Files:**
- Modify: `src/intelligence.rs`
- Test: `src/intelligence.rs`

**Interfaces:**
- Replace epistemic use of binary `ProviderOutcome` with `CoverageObservation { provider_id, claim_id, outcome, evidence_classes, query_scope, temporal_scope, completeness, recorded_at_unix }`.
- Create: `CoverageOutcome::{Positive, CleanNegative, Partial, Failed, NotAttempted, NotApplicable}`.
- Create: `CoverageCompleteness::{Complete, MateriallyComplete, Partial, Unknown}`.
- Add: policy hook `requires_negative_coverage: bool` and assessment blocker `IncompleteCoverage`.

- [ ] **Step 1: Write failing tests**
  Add `failed_collection_is_not_negative_evidence`, `partial_coverage_cannot_close_required_negative_obligation`, and `clean_negative_counts_only_when_scope_and_completeness_are_applicable`.
- [ ] **Step 2: Confirm failure**
- [ ] **Step 3: Implement conservative coverage evaluation while preserving compatibility reader for existing provider observations**
- [ ] **Step 4: Run intelligence tests**
- [ ] **Step 5: Commit**
  Commit message: `feat(intelligence): gate negative evidence on coverage capability`.

### Task 6: Add minimal proof environments and conservative bounds

**Files:**
- Create: `src/proof.rs`
- Modify: `src/lib.rs`
- Modify: `src/intelligence.rs`
- Test: `src/proof.rs`, `src/intelligence.rs`

**Interfaces:**
- Create: `AssumptionId(pub String)`, `DerivationId(pub String)`, `DependencyDomainId(pub String)`.
- Create: `MinimalProofEnvironment { assertions: BTreeSet<EvidenceId>, roots: BTreeSet<String>, dependencies: BTreeSet<DependencyDomainId>, derivations: BTreeSet<DerivationId>, assumptions: BTreeSet<AssumptionId> }`.
- Create: `minimalize_environments(Vec<MinimalProofEnvironment>, max_environments: usize, max_cardinality: usize) -> ProofEnvironmentSet`.
- Create: `ProofEnvironmentSet { environments: Vec<MinimalProofEnvironment>, incomplete: bool }`.

- [ ] **Step 1: Write failing property/unit tests**
  Pin idempotence, superset elimination, derived-root non-generation, deterministic ordering, and `incomplete=true` when bounds truncate enumeration.
- [ ] **Step 2: Implement minimal antichain/subsumption logic**
- [ ] **Step 3: Integrate environment summary into `ClaimAssessment` without changing ROI ownership**
- [ ] **Step 4: Verify truncation can never promote a claim**
- [ ] **Step 5: Run `cargo test --locked proof intelligence`**
- [ ] **Step 6: Commit**
  Commit message: `feat(proof): add bounded minimal proof environments`.

### Task 7: Shadow comparison and migration evidence

**Files:**
- Create: `src/shadow_assessment.rs`
- Modify: `src/lib.rs`
- Modify: `src/intelligence.rs`
- Test: `src/shadow_assessment.rs`
- Modify: `docs/RECONSTRUCTION_2026-10-02.md`

**Interfaces:**
- Create: `ShadowAssessment { legacy_state: ClaimState, policy_state: ClaimState, blockers: BTreeSet<VerificationBlocker>, reason_codes: BTreeSet<String> }`.
- Create: `compare_legacy_and_policy(...) -> ShadowAssessment`.

- [ ] **Step 1: Add fixtures covering duplicate providers, unknown ancestry, direct primary evidence, derived-only support, temporal compatibility, and negative-coverage gaps**
- [ ] **Step 2: Implement deterministic shadow comparison**
- [ ] **Step 3: Assert every state difference has a machine-readable reason code**
- [ ] **Step 4: Document observed semantic differences without claiming superiority unless the proof obligation is met**
- [ ] **Step 5: Commit**
  Commit message: `test(intelligence): add shadow adjudication evidence`.

### Task 8: Full regression, platform build proof, and cutover decision

**Files:**
- Modify only where verification exposes defects.
- Update design/reconstruction docs with demonstrated results.

**Interfaces:**
- No new runtime interface unless required by a verified defect.

- [ ] **Step 1: Run `cargo fmt --check`**
- [ ] **Step 2: Run `cargo clippy --all-targets -- -D warnings`**
- [ ] **Step 3: Run `cargo test --locked`**
- [ ] **Step 4: Run `cargo run --locked -- check` and `git diff --exit-code -- var/`**
- [ ] **Step 5: Verify Android aarch64 CI/cross-build remains intact; do not call this handset verification**
- [ ] **Step 6: Falsify invariants with mutation/adversarial fixtures: unknown→different provider, duplicate copies, ancestry loss, cycle, derivation chain, stale/non-overlapping temporal evidence, partial coverage, proof-environment truncation**
- [ ] **Step 7: Decide cutover**
  Cut over only if policy assessment improves epistemic correctness without unacceptable regression, performance, or migration cost. Otherwise retain shadow mode and record the exact blocker.
- [ ] **Step 8: Commit verification evidence**
  Commit message: `docs: record provenance claim kernel verification`.

## Stop Conditions

Stop implementation only when one of these is demonstrated:

- acceptance criteria are verified at the applicable layers;
- no remaining material positive-value action exists;
- the design is falsified and a stronger alternative is identified;
- implementation is blocked by an external dependency that cannot be resolved in this invocation.

Do not equate source compilation, host tests, Android cross-build, handset execution, live-provider behavior, or operational effectiveness; each requires its own evidence.