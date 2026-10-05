# Huntsman Runtime Integration Spine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connect the largest coherent set of reconstructed Huntsman modules into one bounded, provenance-preserving investigation runtime without manufacturing dependencies or weakening verified security/resource invariants.

**Architecture:** Add a thin upper-layer composition root in `src/pipeline.rs`, with focused planning and collection-envelope modules. Existing domain modules remain authoritative for HTTP/egress, evidence, lineage, identity, graph analysis, storage, and export. `main.rs` remains a shell over the composition root.

**Tech Stack:** Rust 1.87 MSRV + current stable, existing serde/serde_json and Huntsman modules, Android AArch64 CI.

**Spec:** `docs/superpowers/specs/2026-10-05-integration-spine-design.md`

## Global Constraints

- Safe Rust only; preserve `#![deny(unsafe_code)]`.
- No heavyweight runtime/framework or new dependency unless an existing primitive cannot satisfy a demonstrated requirement.
- Preserve collector != upstream origin != independent corroboration.
- `source_registry` routes remain discovery leads, never evidence.
- `SourceOutcomeKind::ValidZero` is the only generic zero-result outcome that can map to a clean negative; `Inconclusive`, failures, WAF, auth, drift, rate limits, and truncation must remain unresolved/incomplete.
- Confidence thresholds alone never establish proof or independent corroboration.
- Work is explicitly bounded for Termux/Android ARM64; reaching a bound must surface in the final outcome.
- Existing guarded HTTP, egress, credential-origin, response classification, redaction, and bounded/atomic I/O remain authoritative.
- Pure transformations and externally visible ordering are deterministic where practical.
- Preserve verified base behavior from `22be0defe24cdc04daf216cdb2dae358535f5c3c` unless an intentional difference has a regression test.

## Review Focus

1. **Malformed/Unicode-confusable seeds:** deterministic rejection/canonicalization; no malformed targets or panics. Task 1.
2. **Mirrored evidence:** multiple collectors relaying one upstream dataset count as one independent lineage. Task 4.
3. **Failure/truncation:** unavailable/WAF/rate-limited/auth/truncated execution never becomes clean negative or exhaustive coverage. Tasks 3-4.
4. **Resource saturation:** target/entity/relation/dispatch/archive/cross-scan ceilings stop boundedly and expose incompleteness. Tasks 1, 3, 5.
5. **Repeatability:** identical fixed inputs and timestamps yield identical plans/reports/exports. Tasks 2, 5, 6.

---

## File Structure

- Create `src/pipeline.rs` — shared pipeline types, normalization, composition, final outcome.
- Create `src/planner.rs` — deterministic dispatch planning and explicit exclusion reasons.
- Create `src/collection.rs` — common provider execution/observation envelope; no sockets.
- Modify `src/module.rs` — one shared descriptor derivation path for both `ModuleSpec` and `dependency::Module`.
- Modify `src/lib.rs` — export new modules.
- Modify `src/main.rs` — thin `investigate` command.
- Modify `src/archive.rs` — archive records -> provenance-bearing observations.
- Modify existing evidence/analysis/export modules only at narrow adapter seams proven necessary.
- Create `tests/pipeline.rs`, `tests/planner.rs`, `tests/collection_bridge.rs`.
- Create `tests/fixtures/runtime_module_dispositions.tsv`; modify `tests/architecture_doc.rs`.
- Update `ARCHITECTURE.md` and `README.md` only after executable behavior is fixed.

---

### Task 1: Pipeline Core, Seed Normalization, and Structural Limits

**Files:**
- Create: `src/pipeline.rs`
- Modify: `src/lib.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub enum InvestigationMode { Offline, GuardedNetwork }`
  - `pub struct InvestigationInput { pub scan_id: String, pub seeds: Vec<String>, pub mode: InvestigationMode }`
  - `pub struct PipelineLimits { pub max_targets: usize, pub max_entities: usize, pub max_relations: usize, pub max_dispatches: usize, pub max_response_bytes: usize, pub max_archive_captures: usize, pub max_cross_scan_frontier: usize, pub max_cross_scan_visited: usize, pub max_generation: u32, pub max_export_bytes: usize, pub max_concurrent: usize }`
  - Default limits: targets `256`, entities `4096`, relations `8192`, dispatches `512`, response bytes `http::DEFAULT_MAX_BODY` (`4 MiB`), archive captures `4096`, cross-scan frontier `128`, cross-scan visited `512`, generation `4`, export bytes `8 MiB`, concurrency `4`.
  - `pub struct NormalizedSeed { pub raw: String, pub kind: EntityKind, pub value: String }`
  - `pub enum SeedRejection { Empty, Unsupported, Invalid(String) }`
  - `pub struct SeedNormalization { pub accepted: Vec<NormalizedSeed>, pub rejected: Vec<(String, SeedRejection)>, pub truncated: bool }`
  - `pub fn normalize_seeds(input: &InvestigationInput, limits: &PipelineLimits) -> SeedNormalization`

- [ ] **Step 1: Write failing tests**

Add `normalize_seeds_is_deterministic_and_bounded`, `malformed_and_empty_seeds_are_explicit_rejections`, `unicode_confusable_or_whitespace_only_seed_never_panics`, and `duplicate_canonical_seeds_are_deduplicated`.

Assert canonical duplicates collapse, accepted ordering is stable, `max_targets` sets `truncated=true`, and rejected input preserves raw text + reason.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test pipeline normalize_seeds -- --nocapture`
Expected: FAIL because pipeline API does not exist.

- [ ] **Step 3: Implement minimal pure normalization**

Use existing classifier/canonical/validation/entity functions; ordered collections only; no I/O.

- [ ] **Step 4: Verify GREEN + static checks**

Run: `cargo test --locked --test pipeline && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs src/lib.rs tests/pipeline.rs && git commit -m "feat: add bounded investigation pipeline core"`

---

### Task 2: Unify Provider Metadata and Build the Deterministic Dispatch Planner

**Files:**
- Create: `src/planner.rs`
- Modify: `src/module.rs`
- Modify: `src/lib.rs`
- Test: `tests/planner.rs`

**Interfaces:**
- Add to `module.rs`:
  - `pub fn derive_dependency_provider_descriptor(module: &dyn crate::dependency::Module) -> ProviderDescriptor`
  - Refactor descriptor construction through one internal helper so `ModuleSpec` and `dependency::Module` do not drift semantically.
- Planner produces:
  - `pub struct DispatchKey { pub provider_id: String, pub target_kind: TargetKind, pub target_value: String }`
  - `pub enum DispatchExclusion { Unsupported, MissingCredential, Duplicate, Budget, QuotaExhausted, UnknownPaidCost, ResourceLimit }`
  - `pub enum DispatchAction { Module { module_index: usize }, Route { source_id: &'static str, url: String } }`
  - `pub struct PlannedDispatch { pub key: DispatchKey, pub target: Target, pub action: DispatchAction, pub utility: Option<DispatchUtility>, pub rationale: Vec<String> }`
  - `pub struct ExcludedDispatch { pub key: DispatchKey, pub reason: DispatchExclusion }`
  - `pub struct DispatchPlan { pub selected: Vec<PlannedDispatch>, pub excluded: Vec<ExcludedDispatch>, pub truncated: bool }`
  - `pub struct PlannerPolicy { pub budget_usd: Option<f64>, pub allow_unknown_paid_cost: bool, pub convex_budget: bool }`
  - `pub struct PlannerContext { pub available_services: BTreeSet<String>, pub quota_remaining: BTreeMap<String, bool>, pub already_dispatched: BTreeSet<DispatchKey> }`
  - `pub fn build_dispatch_plan(modules: &[Arc<dyn Module>], seeds: &[NormalizedSeed], limits: &PipelineLimits, policy: &PlannerPolicy, context: &PlannerContext) -> DispatchPlan`

`service_defs` participates by mapping configured keyed-service names into `PlannerContext.available_services`; probing credentials remains a diagnostic action, not an automatic investigation dispatch.

- [ ] **Step 1: Write failing descriptor/planner tests**

Add `dependency_module_descriptor_matches_module_spec_rules`, `planner_uses_dependency_graph_and_roi_ordering`, `planner_blocks_missing_credentials`, `planner_excludes_duplicate_module_target_pair`, `planner_blocks_exhausted_quota`, `planner_blocks_unknown_paid_cost_under_budget`, `lead_routes_remain_lead_only`, and `planner_output_is_stable`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test planner`
Expected: FAIL.

- [ ] **Step 3: Implement shared descriptor derivation and planner**

Build one `ModuleGraph`; derive provider metadata through `module.rs`; calculate ROI with existing `roi` functions; use `source_registry` only for `Route` lead actions; enforce `max_dispatches` and explicit exclusions.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test --locked --test planner --test pipeline && cargo clippy --all-targets --locked -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/planner.rs src/module.rs src/lib.rs tests/planner.rs && git commit -m "feat: unify provider planning and dispatch economics"`

---

### Task 3: Common Collection Bridge and Truthful Coverage

**Files:**
- Create: `src/collection.rs`
- Modify: `src/lib.rs`
- Modify: `src/coverage.rs` only if a conversion belongs there more cleanly
- Test: `tests/collection_bridge.rs`

**Interfaces:**
- Produces:
  - `pub struct UpstreamOrigin { pub provider: Option<String>, pub dataset: Option<String>, pub artifact: Option<String> }`
  - `pub struct CollectionEvent { pub scan_id: String, pub provider_id: String, pub target: Target, pub outcome: SourceOutcomeKind, pub finding_count: usize, pub truncated: bool, pub started_at_unix: u64, pub finished_at_unix: u64, pub credential_fingerprint: Option<String>, pub upstream: Option<UpstreamOrigin> }`
  - `pub struct RawObservation { pub provider_id: String, pub upstream: Option<UpstreamOrigin>, pub target: Target, pub kind: EntityKind, pub value: String, pub summary: String, pub attributes: BTreeMap<String, String>, pub observed_at_unix: Option<u64> }`
  - `pub struct ObservationBatch { pub events: Vec<CollectionEvent>, pub observations: Vec<RawObservation>, pub truncated: bool }`
  - `pub fn coverage_events(batch: &ObservationBatch) -> Vec<coverage::Event>`
  - `pub fn enforce_observation_limit(batch: ObservationBatch, max_observations: usize) -> ObservationBatch`

- [ ] **Step 1: Write failing bridge tests**

Add `only_valid_zero_maps_to_clean_negative`, `failure_classes_never_map_to_clean_negative`, `truncated_success_is_incomplete`, `upstream_origin_survives_bridge`, `coverage_conversion_is_deterministic`, and `observation_cap_sets_truncated`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test collection_bridge`
Expected: FAIL.

- [ ] **Step 3: Implement envelope + conservative conversion**

`Success` requires findings; `ValidZero` may become clean negative; `Inconclusive` and every failure/drift/auth/WAF/rate-limit state remain unresolved. Preserve upstream metadata without treating it as trusted independence.

- [ ] **Step 4: Verify GREEN + existing outcome tests**

Run: `cargo test --locked --test collection_bridge && cargo test --locked source_outcome coverage`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/collection.rs src/lib.rs src/coverage.rs tests/collection_bridge.rs && git commit -m "feat: add provenance-safe collection bridge"`

---

### Task 4: Evidence, Lineage, Identity, and Correlation Integration

**Files:**
- Modify: `src/pipeline.rs`
- Use existing: `entity`, `confidence`, `evidence_ancestry`, `lineage`, `assurance`, `credential_origin`, `coverage`, `identity`, `identity_resolution`, `resolve`, `coref`, `correlator`, `relation`, `union_find`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub struct AnalysisSnapshot { pub entities: Vec<Entity>, pub relations: Vec<EntityRelation>, pub coverage: Vec<coverage::ProviderCoverage>, pub ancestry: EvidenceAncestryGraph, pub truncated: bool }`
  - `pub fn normalize_observations(batch: ObservationBatch, limits: &PipelineLimits) -> Result<AnalysisSnapshot, Error>`

Upstream provider/dataset/artifact creates the ancestry/root family when present; the collector remains relay metadata. Unknown upstream origin remains unknown and must not manufacture a second family.

- [ ] **Step 1: Write failing provenance/identity tests**

Add `two_collectors_one_upstream_root_count_once`, `independent_upstream_roots_can_raise_corroboration`, `spoofed_source_family_cannot_manufacture_independence`, `missing_upstream_origin_does_not_manufacture_independence`, `contradictory_observations_remain_explicit`, `invalid_or_missing_probability_never_auto_merges`, and `cyclic_ancestry_is_rejected`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test pipeline lineage -- --nocapture`
Expected: FAIL until normalization path exists.

- [ ] **Step 3: Implement normalization by composing existing evidence/lineage/identity rules**

Do not add a second confidence or merge model. Enforce entity/relation caps and carry `truncated` forward.

- [ ] **Step 4: Verify GREEN + corroboration regressions**

Run: `cargo test --locked --test pipeline --test corroboration_key`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs tests/pipeline.rs && git commit -m "feat: connect evidence lineage and identity runtime"`

---

### Task 5: Analysis Fan-Out, Archives, Cross-Scan Bounds, and Termination

**Files:**
- Modify: `src/pipeline.rs`
- Modify: `src/archive.rs`
- Modify: `src/intelligence.rs` only if measurement shows material benefit from a shared-graph API
- Test: `tests/pipeline.rs`
- Test: `tests/archive_model.rs`

**Interfaces:**
- Produces:
  - `pub struct InvestigationReport { pub intelligence: intelligence::IntelligenceReport, pub metrics: metrics::ScanMetrics, pub gaps: gap::GapReport, pub pivots: Vec<pivot::PivotScore>, pub cross_scan: Option<cross_scan::CrossScanCategory>, pub coverage: coverage::CoverageVerdict, pub termination: Option<termination::TerminationReason>, pub truncated: bool }`
  - `pub fn analyze_snapshot<S: cross_scan::CrossScanStore>(snapshot: &AnalysisSnapshot, store: Option<&S>, limits: &PipelineLimits) -> Result<InvestigationReport, Error>`
  - `pub fn archive_records_to_observations(records: &[archive::ArchiveRecord], scan_id: &str, max: usize) -> ObservationBatch`

- [ ] **Step 1: Write failing analysis/archive tests**

Add `snapshot_fans_out_to_intelligence_metrics_gaps_and_pivots`, `analysis_is_repeatable`, `cross_scan_limits_are_forwarded_exactly`, `archive_record_becomes_provenance_bearing_observations`, `archive_interest_is_metadata_not_verification`, `archive_cap_sets_truncated`, and `termination_never_claims_fixed_point_when_truncated_or_work_remains`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test pipeline --test archive_model`
Expected: new tests FAIL.

- [ ] **Step 3: Implement composition**

Call existing `intelligence`, `metrics`, `gap`, `pivot`, `cross_scan`, and `termination` APIs. Map `PipelineLimits.max_cross_scan_*` into `CrossScanOptions`. Convert archive records into URL/domain/document observations with archive source/dataset/collection/capture/source-URL provenance; archive interest remains metadata only.

- [ ] **Step 4: Verify GREEN + library regression**

Run: `cargo test --locked --lib && cargo test --locked --test pipeline --test archive_model`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs src/archive.rs src/intelligence.rs tests/pipeline.rs tests/archive_model.rs && git commit -m "feat: connect archive and graph intelligence analysis"`

---

### Task 6: One Shared Final State for Persistence and Export

**Files:**
- Modify: `src/pipeline.rs`
- Modify only as needed: `src/session.rs`, `src/store.rs`, `src/ledger.rs`, `src/json.rs`, `src/stix.rs`, `src/navigator.rs`, `src/gexf.rs`, `src/snake_graph.rs`
- Test: `tests/pipeline.rs`

**Interfaces:**
- Produces:
  - `pub struct PipelineArtifacts { pub ledger_path: Option<PathBuf>, pub session_path: Option<PathBuf>, pub json: Option<Vec<u8>>, pub stix: Option<Vec<u8>>, pub navigator: Option<Vec<u8>>, pub gexf: Option<Vec<u8>>, pub snake_graph: Option<Vec<u8>>, pub truncated: bool }`
  - `pub struct PipelineOutcome { pub normalized: SeedNormalization, pub dispatch_plan: DispatchPlan, pub snapshot: AnalysisSnapshot, pub report: InvestigationReport, pub artifacts: PipelineArtifacts, pub incomplete_reasons: Vec<String> }`
  - `pub fn export_outcome(outcome: &PipelineOutcome, root: &Path, limits: &PipelineLimits) -> Result<PipelineArtifacts, Error>`

- [ ] **Step 1: Write failing export-state tests**

Add `all_exporters_observe_same_entity_relation_state`, `export_byte_cap_is_enforced_and_reported`, `atomic_store_path_remains_bounded_and_symlink_safe`, `fixed_timestamp_exports_are_deterministic`, and `lead_only_route_never_appears_as_evidence`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test pipeline export -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Implement adapter composition**

Reuse existing serializers/builders and `Store`/`fsio`; exporters receive the same snapshot/report and may filter presentation only.

- [ ] **Step 4: Verify GREEN**

Run: `cargo test --locked --test pipeline && cargo test --locked --lib`
Expected: PASS.

- [ ] **Step 5: Commit**

`git add src/pipeline.rs src/session.rs src/store.rs src/ledger.rs src/json.rs src/stix.rs src/navigator.rs src/gexf.rs src/snake_graph.rs tests/pipeline.rs && git commit -m "feat: unify investigation persistence and exports"`

---

### Task 7: Thin `investigate` CLI and Representative Runtime Path

**Files:**
- Modify: `src/main.rs`
- Test: `tests/cli.rs`
- Test: `tests/pipeline.rs`

**Interface:** `huntsman-recon investigate <SEED> [SEED ...]`

- [ ] **Step 1: Write failing CLI tests**

Add `investigate_requires_seed`, `investigate_offline_runs_full_in_memory_path`, `investigate_reports_rejections_and_truncation`, and `existing_diagnostic_commands_remain_available`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test cli investigate -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Add thin CLI wiring**

`main.rs` constructs input/limits/context, calls pipeline APIs, and maps typed failure to current exit-code conventions. Domain logic stays out of the CLI.

- [ ] **Step 4: Verify CLI + acceptance**

Run: `cargo test --locked --test cli --test accept --test pipeline`
Expected: PASS.

- [ ] **Step 5: Exercise one legitimate guarded public path if environment access exists**

Use the existing guarded transport against a harmless public/keyless target. Record the exact command/result. If DNS/network is unavailable, mark this criterion `UNVERIFIED: external environment`; do not substitute a mock and call it live proof.

- [ ] **Step 6: Commit**

`git add src/main.rs tests/cli.rs tests/pipeline.rs && git commit -m "feat: add high-level investigate command"`

---

### Task 8: Runtime Reachability Classification and Orphan Enforcement

**Files:**
- Create: `tests/fixtures/runtime_module_dispositions.tsv`
- Modify: `tests/architecture_doc.rs`
- Modify: `ARCHITECTURE.md`

**Manifest:** `module<TAB>class<TAB>rationale`; allowed classes are `runtime`, `adapter`, `exporter`, `leaf`, `diagnostic`, `reference`.

- [ ] **Step 1: Write failing architecture tests**

Add `every_production_module_has_runtime_disposition`, `no_duplicate_runtime_dispositions`, `integration_spine_modules_are_runtime`, and `reference_modules_do_not_count_as_runtime_coverage`.

- [ ] **Step 2: Verify RED**

Run: `cargo test --locked --test architecture_doc runtime_disposition -- --nocapture`
Expected: FAIL until the manifest is complete.

- [ ] **Step 3: Classify every production module from evidence**

Do not label files runtime solely to improve the count. Useful orphans discovered here may be wired through an existing seam; otherwise retain an honest class/rationale for a later tranche.

- [ ] **Step 4: Update `ARCHITECTURE.md` from actual executable state**

Document the integration spine and manifest policy; do not claim a fake static Rust call graph.

- [ ] **Step 5: Verify architecture/disposition gates**

Run: `cargo test --locked --test architecture_doc --test dispositions`
Expected: PASS.

- [ ] **Step 6: Commit**

`git add tests/fixtures/runtime_module_dispositions.tsv tests/architecture_doc.rs ARCHITECTURE.md && git commit -m "test: enforce runtime module dispositions"`

---

### Task 9: Documentation, Differential Verification, and Exact-Head Completion Gate

**Files:**
- Modify: `README.md`
- Modify only where superseded: `docs/RECONSTRUCTION_2026-10-02.md`, `docs/DISPOSITIONS.md`

- [ ] **Step 1: Document only verified behavior**

Document `investigate`, bounded defaults, truncation, provenance/independence semantics, and offline-vs-network behavior.

- [ ] **Step 2: Run stable format/static/test gates**

Run:
- `cargo fmt --check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test --locked`

Expected: all PASS.

- [ ] **Step 3: Run Rust 1.87 gate**

Run: `cargo test --locked` under Rust 1.87.
Expected: PASS.

- [ ] **Step 4: Run existing committed-artifact stability gate**

Expected: PASS with no unexpected diff.

- [ ] **Step 5: Run Android AArch64 release/ELF gate**

Use the repository CI/build path.
Expected: PASS and output identified as AArch64 ELF.

- [ ] **Step 6: Differential comparison against verified base**

Compare existing CLI/check fixtures and committed acceptance artifacts against `22be0defe24cdc04daf216cdb2dae358535f5c3c`. Every difference must be either compatibility-preserving or covered by an explicit intentional-improvement test.

- [ ] **Step 7: Run adversarial sweep**

Exercise malformed/confusable seeds, mirrored lineage, source-family spoofing, provider failures, WAF/rate limit/auth, truncation, resource caps, archive cap, cross-scan caps, unknown paid cost, exhausted quota, credential-origin mismatch, cyclic ancestry, and repeated execution determinism.
Expected: PASS.

- [ ] **Step 8: Review final diff for accidental capability loss**

Existing low-level diagnostic commands and verified security/resource boundaries must remain intact.

- [ ] **Step 9: Commit documentation-only changes**

`git add README.md ARCHITECTURE.md docs/RECONSTRUCTION_2026-10-02.md docs/DISPOSITIONS.md && git commit -m "docs: document integrated investigation runtime"`

- [ ] **Step 10: Push exact final head and require green CI**

Completion claims must map to this exact commit, not an earlier green state.

---

## Completion Criteria

The exact final branch head must demonstrate:

1. stable format PASS;
2. stable strict Clippy PASS;
3. stable tests PASS;
4. Rust 1.87 tests PASS;
5. Android AArch64 release/ELF PASS;
6. committed-artifact stability PASS;
7. runtime-disposition/architecture tests PASS;
8. in-memory seed -> plan -> observations -> evidence/lineage -> identity/relations -> graph/intelligence/metrics/gaps/pivots -> export path PASS;
9. adversarial provenance/independence tests PASS;
10. explicit resource truncation propagation PASS;
11. selected exporters consume one shared final state PASS;
12. no verified base capability silently lost;
13. one guarded live path verified when legitimate environment access exists, otherwise explicitly recorded as externally unverified.
