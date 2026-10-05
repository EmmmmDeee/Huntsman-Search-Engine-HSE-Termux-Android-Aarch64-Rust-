# Huntsman Runtime Integration Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the largest coherent set of reconstructed Huntsman modules into one bounded, provenance-preserving investigation runtime without manufacturing dependencies or weakening verified security/resource invariants.

**Architecture:** Add a thin upper-layer composition root in `src/pipeline.rs`; keep planning, collection normalization, evidence/identity, graph analysis, and export logic in existing domain modules. New orchestration types carry immutable limits, explicit truncation/incompleteness, deterministic plans, and one shared analysis snapshot. `main.rs` remains a CLI shell and existing diagnostic commands remain available.

**Tech Stack:** Rust 1.87 MSRV + current stable, serde/serde_json already present, existing Huntsman HTTP/fetch/egress/store/graph/intelligence modules, Android AArch64 CI.

**Spec:** `docs/superpowers/specs/2026-10-05-integration-spine-design.md`

## Global Constraints

- Safe Rust only; preserve `#![deny(unsafe_code)]`.
- No new runtime or heavyweight dependency unless existing code cannot satisfy a demonstrated requirement.
- Preserve collector != upstream origin != independent corroboration.
- `source_registry` routes remain lead-only and cannot support claims until observed material enters the evidence path.
- Failed, unavailable, WAF-blocked, rate-limited, truncated, not-attempted, and not-applicable providers must not become clean negatives.
- Confidence thresholds alone never establish proof or independent corroboration.
- Work must remain bounded for Termux/Android ARM64; truncation must be explicit in the outcome.
- Existing guarded HTTP, egress, credential-origin, response-classification, redaction, and atomic/bounded I/O boundaries remain authoritative.
- Pure transformations and externally visible output must be deterministic where practical.
- Preserve the verified base behavior from commit `22be0defe24cdc04daf216cdb2dae358535f5c3c` unless an intentional improvement has a regression test.

## Review Focus

1. **Malformed/Unicode-confusable seeds:** reject or canonicalize deterministically; never create malformed targets or panics. Task 1 owns tests.
2. **Mirrored/relayed evidence:** two collectors for one upstream dataset must remain one independent lineage. Task 4 owns tests.
3. **Provider failure/truncation:** timeout/WAF/missing credential/truncated response cannot read as clean negative or exhaustive coverage. Tasks 3 and 4 own tests.
4. **Resource saturation:** target/entity/relation/dispatch/archive/cross-scan caps must stop boundedly and surface exact truncation flags rather than silently dropping work. Tasks 1, 3, and 5 own tests.
5. **Repeatability:** identical in-memory input and limits must produce stable ordering/plans/reports across repeated runs. Tasks 2 and 5 own tests.

---

## File Structure

- Create `src/pipeline.rs` — composition root, shared pipeline types, pure bounded orchestration, final `PipelineOutcome`.
- Create `src/planner.rs` — deterministic dispatch planning across dependency/module metadata, ROI, source routes, keyed-service metadata, budget/quota/duplicate gates.
- Create `src/collection.rs` — common collection-event/observation envelope and conversions into coverage/evidence-safe intermediate state; no sockets.
- Modify `src/lib.rs` — export `pipeline`, `planner`, `collection` modules.
- Modify `src/main.rs` — add thin `investigate` CLI path only; no domain logic duplication.
- Modify `src/intelligence.rs` only if necessary to accept/share a prebuilt graph; measure first and retain current API if rebuild cost is immaterial.
- Modify `src/archive.rs` — add conversion of merged archive records into provenance-bearing observations/entities, preserving archive interest as metadata only.
- Modify `src/coverage.rs` — only if needed to accept the common collection event without semantic duplication.
- Modify `src/session.rs`, `src/store.rs`, `src/ledger.rs`, `src/stix.rs`, `src/navigator.rs`, `src/gexf.rs`, `src/snake_graph.rs`, `src/json.rs` only at the adapter seams needed for one shared final state; do not duplicate truth.
- Create `tests/pipeline.rs` — end-to-end in-memory pipeline, adversarial provenance, limits, determinism, and exporter-state tests.
- Create `tests/planner.rs` — dispatch eligibility/economics/ordering tests.
- Create `tests/collection_bridge.rs` — provider outcome, truncation, upstream lineage, coverage conversion tests.
- Create `tests/fixtures/runtime_module_dispositions.tsv` — explicit runtime classification of production modules.
- Modify `tests/architecture_doc.rs` — enforce every production module is classified and every required runtime module is reachable through an approved class.
- Modify `tests/cli.rs` — `investigate` command behavior.
- Modify `ARCHITECTURE.md` and `README.md` after implementation behavior is fixed.

---

### Task 1: Pipeline Core, Input Normalization, and Structural Limits

**Files:**
- Create: `src/pipeline.rs`
- Modify: `src/lib.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub enum InvestigationMode { Offline, GuardedNetwork }`
  - `pub struct InvestigationInput { pub scan_id: String, pub seeds: Vec<String>, pub mode: InvestigationMode }`
  - `pub struct PipelineLimits { pub max_targets: usize, pub max_entities: usize, pub max_relations: usize, pub max_dispatches: usize, pub max_response_bytes: usize, pub max_archive_captures: usize, pub max_cross_scan_frontier: usize, pub max_cross_scan_visited: usize, pub max_generation: u32, pub max_export_bytes: usize, pub max_concurrent: usize }`
  - `impl Default for PipelineLimits` using constrained defaults: targets `256`, entities `4096`, relations `8192`, dispatches `512`, response bytes `4 * 1024 * 1024` (match `http::DEFAULT_MAX_BODY`), archive captures `4096`, cross-scan frontier `128`, cross-scan visited `512`, generation `4`, export bytes `8 * 1024 * 1024`, concurrency `4`.
  - `pub struct NormalizedSeed { pub raw: String, pub kind: EntityKind, pub value: String }`
  - `pub enum SeedRejection { Empty, Unsupported, Invalid(String) }`
  - `pub struct SeedNormalization { pub accepted: Vec<NormalizedSeed>, pub rejected: Vec<(String, SeedRejection)>, pub truncated: bool }`
  - `pub fn normalize_seeds(input: &InvestigationInput, limits: &PipelineLimits) -> SeedNormalization`
- Consumes existing classifier/canonical/validation/entity helpers; caller-specified type assertions are not trusted.

- [ ] **Step 1: Write failing tests for normalization and limits**

Add tests named:
- `normalize_seeds_is_deterministic_and_bounded`
- `malformed_and_empty_seeds_are_explicit_rejections`
- `unicode_confusable_or_whitespace_only_seed_never_panics`
- `duplicate_canonical_seeds_are_deduplicated`

Assertions: accepted seeds are stably ordered, duplicate canonical values appear once, `max_targets` truncation sets `truncated=true`, rejected input retains the original raw value and typed reason.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test --locked --test pipeline normalize_seeds -- --nocapture`
Expected: FAIL because pipeline types/functions do not exist.

- [ ] **Step 3: Implement the minimal core types and `normalize_seeds`**

Use existing classification/canonicalization/validation functions. Do not perform I/O. Use ordered collections for deduplication/output stability.

- [ ] **Step 4: Export the module and run focused tests**

Run: `cargo test --locked --test pipeline`
Expected: PASS for Task 1 tests.

- [ ] **Step 5: Run strict local gates for changed code**

Run: `cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings`
Expected: PASS.

- [ ] **Step 6: Commit**

`git add src/pipeline.rs src/lib.rs tests/pipeline.rs && git commit -m "feat: add bounded investigation pipeline core"`

---

### Task 2: Deterministic Dispatch Planner

**Files:**
- Create: `src/planner.rs`
- Modify: `src/lib.rs`
- Test: `tests/planner.rs`

**Interfaces:**
- Consumes: `NormalizedSeed`, `PipelineLimits`, `dependency::{Module, ModuleGraph, Target, TargetKind}`, `module::ProviderDescriptor`, `roi::{DispatchUtility, DispatchUtilityInputs}`, `source_registry::SourceRoute`, `service_defs::ServiceDef`.
- Produces:
  - `pub enum DispatchExclusion { Unsupported, Duplicate, Budget, QuotaExhausted, UnknownPaidCost, ResourceLimit }`
  - `pub enum DispatchAction { Module { module_index: usize }, Route { source_id: &'static str, url: String }, ServiceProbe { service: &'static str } }`
  - `pub struct PlannedDispatch { pub target: Target, pub action: DispatchAction, pub utility: Option<DispatchUtility>, pub rationale: Vec<String> }`
  - `pub struct ExcludedDispatch { pub target: Target, pub provider_id: String, pub reason: DispatchExclusion }`
  - `pub struct DispatchPlan { pub selected: Vec<PlannedDispatch>, pub excluded: Vec<ExcludedDispatch>, pub truncated: bool }`
  - `pub struct PlannerPolicy { pub budget_usd: Option<f64>, pub allow_unknown_paid_cost: bool, pub convex_budget: bool }`
  - `pub fn build_dispatch_plan(modules: &[std::sync::Arc<dyn Module>], seeds: &[NormalizedSeed], limits: &PipelineLimits, policy: &PlannerPolicy) -> DispatchPlan`

- [ ] **Step 1: Write failing planner tests**

Tests:
- `planner_uses_dependency_graph_and_roi_ordering`
- `planner_excludes_duplicate_module_target_pair`
- `planner_blocks_exhausted_quota`
- `planner_blocks_unknown_paid_cost_under_budget`
- `lead_routes_are_planned_as_leads_not_evidence`
- `planner_output_is_stable_across_repeated_runs`

Use stub `Module` implementations local to the test. Assert exact ordering/exclusion reasons; do not assert arbitrary score values except where inputs fully determine them.

- [ ] **Step 2: Run planner tests and verify RED**

Run: `cargo test --locked --test planner`
Expected: FAIL because planner module does not exist.

- [ ] **Step 3: Implement planner composition**

Build one `ModuleGraph`, map normalized kinds to `TargetKind`, use existing ROI/provider gates, append `source_registry` routes as `LeadOnly` dispatches, and cap selected dispatches at `limits.max_dispatches`. Do not execute network calls.

- [ ] **Step 4: Run planner and pipeline tests**

Run: `cargo test --locked --test planner --test pipeline`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/planner.rs src/lib.rs tests/planner.rs && git commit -m "feat: compose deterministic dispatch planning"`

---

### Task 3: Common Collection Bridge and Coverage Semantics

**Files:**
- Create: `src/collection.rs`
- Modify: `src/lib.rs`
- Modify: `src/coverage.rs` only if conversion helpers cannot live cleanly in `collection.rs`
- Test: `tests/collection_bridge.rs`

**Interfaces:**
- Produces:
  - `pub struct UpstreamOrigin { pub provider: Option<String>, pub dataset: Option<String>, pub artifact: Option<String> }`
  - `pub struct CollectionEvent { pub scan_id: String, pub provider_id: String, pub target: Target, pub outcome: source_outcome::SourceOutcomeKind, pub finding_count: usize, pub truncated: bool, pub started_at_unix: u64, pub finished_at_unix: u64, pub credential_fingerprint: Option<String>, pub upstream: Option<UpstreamOrigin> }`
  - `pub struct RawObservation { pub provider_id: String, pub upstream: Option<UpstreamOrigin>, pub target: Target, pub kind: EntityKind, pub value: String, pub summary: String, pub attributes: BTreeMap<String,String>, pub observed_at_unix: Option<u64> }`
  - `pub struct ObservationBatch { pub events: Vec<CollectionEvent>, pub observations: Vec<RawObservation>, pub truncated: bool }`
  - `pub fn coverage_events(batch: &ObservationBatch) -> Vec<coverage::Event>`
- No transport implementation is added here. Existing provider/collector code adapts into this envelope incrementally.

- [ ] **Step 1: Write failing collection-bridge tests**

Tests:
- `failed_timeout_waf_and_auth_required_are_not_clean_negative`
- `truncated_success_is_marked_incomplete`
- `upstream_origin_survives_collection_bridge`
- `coverage_conversion_is_deterministic`
- `huge_observation_batch_is_capped_by_pipeline_limits_without_false_completeness`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked --test collection_bridge`
Expected: FAIL because collection module does not exist.

- [ ] **Step 3: Implement event/observation envelope and coverage conversion**

Map only semantically resolved zero-result outcomes to clean negative; propagate all failure/unavailable classes and `truncated=true` explicitly. Preserve upstream metadata verbatim but never treat it as trusted independence until lineage normalization.

- [ ] **Step 4: Run bridge + existing coverage/source-outcome tests**

Run: `cargo test --locked --test collection_bridge coverage source_outcome`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/collection.rs src/lib.rs src/coverage.rs tests/collection_bridge.rs && git commit -m "feat: add provenance-safe collection bridge"`

---

### Task 4: Evidence, Lineage, Identity, and Correlation Integration

**Files:**
- Modify: `src/pipeline.rs`
- Use existing: `src/entity.rs`, `src/evidence_ancestry.rs`, `src/lineage.rs`, `src/identity_resolution.rs`, `src/resolve.rs`, `src/coref.rs`, `src/correlator.rs`, `src/relation.rs`, `src/union_find.rs`, `src/coverage.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub struct AnalysisSnapshot { pub entities: Vec<Entity>, pub relations: Vec<EntityRelation>, pub coverage: Vec<coverage::ProviderCoverage>, pub ancestry: EvidenceAncestryGraph, pub truncated: bool }`
  - `pub fn normalize_observations(batch: ObservationBatch, limits: &PipelineLimits) -> Result<AnalysisSnapshot, Error>`
- Each `RawObservation` becomes provenance-bearing `Evidence`; `UpstreamOrigin` maps into stable lineage/ancestry roots. Collector ID is retained as relay/source metadata but does not automatically become the root family.

- [ ] **Step 1: Write failing provenance/identity tests**

Tests:
- `two_collectors_one_upstream_root_count_once`
- `independent_upstream_roots_can_raise_corroboration`
- `spoofed_source_family_cannot_manufacture_independence`
- `missing_upstream_origin_stays_unknown_not_independent`
- `contradictory_observations_remain_explicit`
- `invalid_or_missing_identity_probability_never_auto_merges`
- `cyclic_ancestry_is_rejected`

- [ ] **Step 2: Run RED against focused tests**

Run: `cargo test --locked --test pipeline provenance -- --nocapture`
Expected: FAIL until normalization integration exists.

- [ ] **Step 3: Implement observation normalization into evidence/ancestry/identity state**

Reuse existing canonical provenance family logic and ancestry validation; do not add a second confidence or merge model. Cap entities and relations with explicit truncation.

- [ ] **Step 4: Run lineage/corroboration/identity regressions**

Run: `cargo test --locked --test pipeline --test corroboration_key`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs tests/pipeline.rs && git commit -m "feat: connect evidence lineage and identity pipeline"`

---

### Task 5: Shared Analysis Snapshot Fan-Out, Archives, and Termination

**Files:**
- Modify: `src/pipeline.rs`
- Modify: `src/archive.rs`
- Modify: `src/intelligence.rs` only if profiling demonstrates a worthwhile shared-graph API
- Use existing: `graph`, `community`, `profiles`, `timeline`, `exposure`, `leads`, `pivot`, `cross_scan`, `metrics`, `gap`, `intelligence`, `termination`
- Test: `tests/pipeline.rs`
- Test: `tests/archive_model.rs`

**Interfaces:**
- Produces:
  - `pub struct InvestigationReport { pub intelligence: intelligence::IntelligenceReport, pub metrics: metrics::ScanMetrics, pub gaps: gap::GapReport, pub pivots: Vec<pivot::PivotScore>, pub cross_scan: Option<cross_scan::CrossScanCategory>, pub coverage: coverage::CoverageVerdict, pub termination: Option<termination::TerminationDecision>, pub truncated: bool }`
  - `pub fn analyze_snapshot<S: cross_scan::CrossScanStore>(snapshot: &AnalysisSnapshot, store: Option<&S>, limits: &PipelineLimits) -> Result<InvestigationReport, Error>`
  - `pub fn archive_records_to_observations(records: &[archive::ArchiveRecord], scan_id: &str, max: usize) -> ObservationBatch`
- Archive interests remain tags/attributes, never proof of exposed secrets or compromise.

- [ ] **Step 1: Write failing analysis/archive tests**

Tests:
- `snapshot_fans_out_to_intelligence_metrics_gaps_and_pivots`
- `analysis_is_repeatable_for_identical_snapshot`
- `cross_scan_limits_are_forwarded_exactly`
- `archive_capture_becomes_url_domain_document_observations_with_dataset_provenance`
- `archive_interest_is_metadata_not_claim_verification`
- `archive_capture_cap_sets_truncated`
- `termination_never_claims_fixed_point_when_truncated_or_delayed_work_exists`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked --test pipeline --test archive_model`
Expected: new tests fail.

- [ ] **Step 3: Implement analysis fan-out and archive conversion**

Call existing domain APIs from one coordinator. Do not refactor every graph consumer merely to share a graph unless measurement shows material Termux benefit.

- [ ] **Step 4: Run focused tests and full library tests**

Run: `cargo test --locked --lib && cargo test --locked --test pipeline --test archive_model`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs src/archive.rs src/intelligence.rs tests/pipeline.rs tests/archive_model.rs && git commit -m "feat: connect archive and graph intelligence analysis"`

---

### Task 6: One Final State for Persistence and Export

**Files:**
- Modify: `src/pipeline.rs`
- Modify as needed: `src/session.rs`, `src/store.rs`, `src/ledger.rs`, `src/json.rs`, `src/stix.rs`, `src/navigator.rs`, `src/gexf.rs`, `src/snake_graph.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub struct PipelineArtifacts { pub ledger_path: Option<PathBuf>, pub session_path: Option<PathBuf>, pub json: Option<Vec<u8>>, pub stix: Option<Vec<u8>>, pub navigator: Option<Vec<u8>>, pub gexf: Option<Vec<u8>>, pub snake_graph: Option<Vec<u8>>, pub truncated: bool }`
  - `pub struct PipelineOutcome { pub normalized: SeedNormalization, pub dispatch_plan: DispatchPlan, pub snapshot: AnalysisSnapshot, pub report: InvestigationReport, pub artifacts: PipelineArtifacts, pub incomplete_reasons: Vec<String> }`
  - `pub fn export_outcome(outcome: &PipelineOutcome, root: &Path, limits: &PipelineLimits) -> Result<PipelineArtifacts, Error>`
- All exporters consume the same snapshot/report; no exporter can recompute evidence truth.

- [ ] **Step 1: Write failing shared-state/export tests**

Tests:
- `all_exporters_observe_same_entity_and_relation_state`
- `export_byte_cap_is_enforced_and_reported`
- `atomic_store_path_remains_bounded_and_symlink_safe`
- `repeated_export_is_deterministic_for_fixed_timestamps_fixture`
- `no_exporter_promotes_lead_only_route_to_evidence`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked --test pipeline export -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Implement export adapter composition**

Reuse existing serializers/builders and `fsio`/`Store`; add adapter functions rather than duplicate serialization models.

- [ ] **Step 4: Run persistence/export regression suites**

Run: `cargo test --locked --test pipeline && cargo test --locked --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs src/session.rs src/store.rs src/ledger.rs src/json.rs src/stix.rs src/navigator.rs src/gexf.rs src/snake_graph.rs tests/pipeline.rs && git commit -m "feat: unify pipeline persistence and exports"`

---

### Task 7: Thin `investigate` CLI and Representative End-to-End Path

**Files:**
- Modify: `src/main.rs`
- Test: `tests/cli.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- CLI: `huntsman-recon investigate <SEED> [SEED ...]`
- `main.rs` constructs `InvestigationInput`, default `PipelineLimits`, and the composition root; it prints a concise summary from `PipelineOutcome`.
- Offline mode is the deterministic default for the first full-path test; guarded network collection occurs only through existing transport/fetch layers when explicitly selected and legitimately available.

- [ ] **Step 1: Write failing CLI tests**

Tests:
- `investigate_requires_at_least_one_seed`
- `investigate_offline_runs_full_in_memory_path`
- `investigate_reports_rejections_and_truncation`
- `existing_fetch_sources_classify_people_commands_still_work`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked --test cli investigate -- --nocapture`
Expected: FAIL because command does not exist.

- [ ] **Step 3: Add thin CLI wiring**

No planning/evidence/analysis logic belongs in `main.rs`; call pipeline APIs and map typed errors to existing exit-code conventions.

- [ ] **Step 4: Run CLI and acceptance suites**

Run: `cargo test --locked --test cli --test accept --test pipeline`
Expected: PASS.

- [ ] **Step 5: Run one representative guarded real path if the environment legitimately permits it**

Run through the existing guarded transport with a public/keyless source and a harmless public test target. Record the exact command and output in the PR description. If network/DNS access is unavailable, mark this acceptance item `UNVERIFIED: external environment`, do not replace it with a mock and do not block the offline pipeline proof.

- [ ] **Step 6: Commit**

`git add src/main.rs tests/cli.rs tests/pipeline.rs && git commit -m "feat: add high-level investigate command"`

---

### Task 8: Runtime Reachability Classification and Orphan Enforcement

**Files:**
- Create: `tests/fixtures/runtime_module_dispositions.tsv`
- Modify: `tests/architecture_doc.rs`
- Modify: `ARCHITECTURE.md`
- Test: `tests/architecture_doc.rs`

**Interfaces:**
- Manifest columns: `module\tclass\trationale`
- Allowed classes: `runtime`, `adapter`, `exporter`, `leaf`, `diagnostic`, `reference`.
- Every production `src/*.rs` module except `lib.rs`/`main.rs` must have exactly one row.
- `runtime` modules required by the pipeline spec must be referenced from the composition path or a declared runtime subcomponent; the test remains data-driven and does not pretend to compute a Rust call graph.

- [ ] **Step 1: Write failing architecture tests**

Tests:
- `every_production_module_has_runtime_disposition`
- `no_duplicate_runtime_dispositions`
- `runtime_integration_spine_modules_are_declared_runtime`
- `reference_modules_are_not_counted_as_runtime_coverage`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked --test architecture_doc runtime_disposition -- --nocapture`
Expected: FAIL until manifest is complete.

- [ ] **Step 3: Classify every production module**

Use evidence from imports/runtime paths/tests. Do not label a module `runtime` merely to maximize the count. For useful orphans uncovered by the manifest, either wire them through an existing seam in this task or classify them honestly with rationale for a later tranche.

- [ ] **Step 4: Update architecture documentation to match executable state**

Document the integration spine, its module classes, and the fact that reachability classification is an audited manifest rather than a fake static call-graph parser.

- [ ] **Step 5: Run architecture/disposition tests**

Run: `cargo test --locked --test architecture_doc --test dispositions`
Expected: PASS.

- [ ] **Step 6: Commit**

`git add tests/fixtures/runtime_module_dispositions.tsv tests/architecture_doc.rs ARCHITECTURE.md && git commit -m "test: enforce runtime module reachability dispositions"`

---

### Task 9: Documentation, Differential Verification, and Final Completion Gate

**Files:**
- Modify: `README.md`
- Modify: `docs/RECONSTRUCTION_2026-10-02.md` only where current behavior supersedes it
- Modify: `docs/DISPOSITIONS.md` if module dispositions materially change
- No production-code change unless verification exposes a causal defect.

**Interfaces:**
- No new API. This task proves the branch state.

- [ ] **Step 1: Update user-facing documentation from verified behavior**

Document `investigate`, bounded defaults, truncation semantics, provenance/independence guarantees, and offline-vs-network behavior. Do not document planned/unverified capabilities as implemented.

- [ ] **Step 2: Run stable format/static/test gates**

Run:
`cargo fmt --check`
`cargo clippy --all-targets --locked -- -D warnings`
`cargo test --locked`
Expected: all PASS.

- [ ] **Step 3: Run MSRV gate**

Run under Rust 1.87: `cargo test --locked`
Expected: PASS.

- [ ] **Step 4: Run artifact-stability gate**

Run repository's existing committed-artifact stability check used by CI.
Expected: PASS with no unexpected diff.

- [ ] **Step 5: Run Android AArch64 release gate**

Run repository CI/build path for Android AArch64 release and verify output is an AArch64 ELF.
Expected: PASS.

- [ ] **Step 6: Differential/regression comparison to verified base**

Compare fixed existing CLI/check fixtures and committed acceptance artifacts against base `22be0defe24cdc04daf216cdb2dae358535f5c3c`. Any difference must be either byte-identical where compatibility is required or covered by a test/documented intentional improvement.

- [ ] **Step 7: Adversarial falsification sweep**

Run the focused tests for malformed seeds, mirrored lineage, source-family spoofing, provider failures, truncation, queue/resource saturation, archive cap, cross-scan caps, unknown paid cost, exhausted quota, WAF response, credential-origin mismatch, repeated execution determinism, and cyclic ancestry.
Expected: PASS.

- [ ] **Step 8: Review branch diff for accidental capability loss**

Verify no existing low-level diagnostic command was removed and no existing security/resource boundary was bypassed.

- [ ] **Step 9: Commit documentation/verification-only changes**

`git add README.md ARCHITECTURE.md docs/RECONSTRUCTION_2026-10-02.md docs/DISPOSITIONS.md && git commit -m "docs: document integrated investigation runtime"`

- [ ] **Step 10: Final exact-head CI verification**

Push the exact branch head and require green CI for stable, Rust 1.87, artifact stability, and Android AArch64. Do not claim completion from earlier commits.

---

## Completion Criteria

The implementation is complete only when the exact final branch head demonstrates:

1. stable `cargo fmt --check` PASS;
2. stable strict Clippy PASS;
3. stable `cargo test --locked` PASS;
4. Rust 1.87 `cargo test --locked` PASS;
5. Android AArch64 release/ELF PASS;
6. artifact stability PASS;
7. architecture/reachability tests PASS;
8. representative in-memory seed -> plan -> observations -> evidence/lineage -> identity/relations -> graph/intelligence/metrics/gaps/pivots -> export path PASS;
9. provenance independence adversarial tests PASS;
10. resource truncation surfaced explicitly PASS;
11. all selected exporters consume one shared final state PASS;
12. no verified base capability silently lost;
13. one legitimate guarded live path verified if environment access exists, otherwise explicitly recorded as externally unverified.
