# Archive Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Rust-native collector boundary and a bounded Wayback + Common Crawl archive-intelligence vertical slice that emits provenance-bearing URL entities without manufacturing lineage independence.

**Architecture:** Pure archive normalization and per-dataset merge logic lives in L3; Wayback/Common Crawl guarded-fetch clients live in L4; the generic collector contract and archive orchestration live in L5. All network traffic uses the existing `fetch::fetch` + injected `http::Transport` path. `dataset` carries stable upstream-family identity; per-crawl, per-record and presentation locators remain non-counting provenance.

**Tech Stack:** Rust 2024, MSRV 1.87, existing `serde`, `serde_json`, `thiserror`, `ureq`; no async runtime; `#![deny(unsafe_code)]`.

**Spec:** `docs/superpowers/specs/2026-10-05-archive-collector-design.md`

## Global Constraints

- Rust-first; no copied/adapted FreeOSINTUI implementation, tables, or implementation data.
- `unsafe_code = "deny"` remains true.
- Termux/Android aarch64 remains first-class.
- No new socket-opening path; archive clients use `fetch::fetch` over injected `http::Transport`.
- Current transport body cap (`http::DEFAULT_MAX_BODY`, 4 MiB) remains the hard outer bound; parser row limits add an inner bound.
- `source_registry::EvidenceRole::LeadOnly` remains unchanged.
- Countable archive datasets are exactly stable upstream roots: `internet_archive_wayback` and `common_crawl`. A Common Crawl `CC-MAIN-*` ID is `collection`, never `dataset`.
- `source_url`, collection IDs, row locators, capture counts, classifications and generated pivots never create independent families.
- Partial source failure preserves valid results from successful sources.
- Zero limits are deterministic no-work states, not invented validation failures; resulting truncation/no-work state must remain explicit.
- No live network dependency in CI.
- No result is silently dropped, truncated or misattributed; local caps propagate explicit truncation state.

## Review Focus

1. **Archive URL ambiguity:** default ports, scheme differences, host case/trailing dot, query preservation, invalid/non-http schemes.
2. **False corroboration:** repeated Wayback captures and multiple Common Crawl collections/rows must not create additional independent families.
3. **Partial/truncated bodies:** `Response::truncated`, row caps and entity caps must propagate and never imply absence.
4. **Malformed mixed input:** one malformed row/NDJSON line must not erase valid neighbors unless the provider envelope itself is unusable.
5. **Provider asymmetry:** Wayback success + Common Crawl failure, and the reverse, must retain successful evidence and expose the failed source outcome.

---

### Task 1: Pure archive model, normalization and per-dataset aggregation

**Files:**
- Create: `src/archive.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/archive.rs`

**Interfaces:**
- Produces: `ArchiveSource`, `ArchiveUrlKey`, `ArchiveCapture`, `ArchiveDatasetObservation`, `ArchiveRecord`, `ArchiveInterest`.
- Produces functions: `parse_archive_url`, `merge_captures`, `classify_archive_path`.
- Consumed by Tasks 2, 3 and 5. No network/entity dependencies.

- [ ] **Step 1: Write failing URL-normalization tests**

Add:
- `archive_url_key_ignores_scheme_host_case_trailing_dot_and_default_port`
- `archive_url_key_preserves_non_default_port_path_and_query`
- `archive_url_rejects_non_http_invalid_and_hostless_values`

Pin that `http://Example.COM.:80/a?x=1` and `https://example.com/a?x=1` have the same archive key; `:8443`, a different path, or a different query does not.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked archive::tests::archive_url -- --nocapture`
Expected: FAIL because module/API is absent.

- [ ] **Step 3: Implement the minimal URL model**

```rust
pub enum ArchiveSource { Wayback, CommonCrawl }

pub struct ArchiveUrlKey {
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

pub fn parse_archive_url(raw: &str) -> Option<ArchiveUrlKey>;
```

Reuse existing HTTP parsing where sufficient. Add no URL crate unless tests demonstrate the current primitives cannot implement the required semantics correctly.

- [ ] **Step 4: Run GREEN**

Run: `cargo test --locked archive::tests::archive_url -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Write failing aggregation/classification tests**

Add:
- `merge_retains_one_observation_per_dataset_family`
- `merge_keeps_first_last_count_and_deterministic_collection_order_per_dataset`
- `unknown_status_or_mime_is_not_invented`
- `same_dataset_multiple_captures_remain_one_dataset_observation`
- `wayback_and_commoncrawl_remain_separate_dataset_observations`
- `interest_classification_marks_patterns_without_asserting_security_facts`
- `interest_classification_has_near_miss_negatives`

- [ ] **Step 6: Run RED**

Run: `cargo test --locked archive::tests -- --nocapture`
Expected: the new tests FAIL because aggregation/classification are absent.

- [ ] **Step 7: Implement minimal capture/aggregate/record types**

```rust
pub struct ArchiveCapture {
    pub source: ArchiveSource,
    pub dataset: String,
    pub collection: Option<String>,
    pub original_url: String,
    pub key: ArchiveUrlKey,
    pub captured_at: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub digest: Option<String>,
    pub source_url: Option<String>,
}

pub struct ArchiveDatasetObservation {
    pub source: ArchiveSource,
    pub dataset: String,
    pub collections: Vec<String>,
    pub first_seen: String,
    pub last_seen: String,
    pub capture_count: usize,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub digest: Option<String>,
    pub source_urls: Vec<String>,
}

pub struct ArchiveRecord {
    pub key: ArchiveUrlKey,
    pub representative_url: String,
    pub observations: Vec<ArchiveDatasetObservation>,
    pub interests: Vec<ArchiveInterest>,
}

pub enum ArchiveInterest {
    Document,
    ArchiveOrBackup,
    ConfigurationLike,
    ScriptLike,
    AdminAuthApiLike,
    Parameterized,
}

pub fn merge_captures(captures: Vec<ArchiveCapture>) -> Vec<ArchiveRecord>;
pub fn classify_archive_path(path: &str, query: &str) -> Vec<ArchiveInterest>;
```

One `ArchiveRecord` may contain multiple dataset observations; never flatten them into one synthetic archive source.

- [ ] **Step 8: Verify Task 1**

Run: `cargo test --locked archive::tests -- --nocapture && cargo fmt --check`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add src/archive.rs src/lib.rs
git commit -m "feat(archive): add normalized archive record model"
```

### Task 2: Wayback CDX guarded client

**Files:**
- Create: `src/wayback.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/wayback.rs`

**Interfaces:**
- Consumes: Task 1 archive types, `fetch::fetch`, `http::{Request, Transport}`, `source_outcome::{SourceExecutionOutcome, SourceOutcomeKind}`.
- Produces: `WaybackQuery`, `WaybackResult`, `wayback_lookup`.

- [ ] **Step 1: Write failing request/parser tests**

Add:
- `wayback_request_is_https_domain_scoped_and_bounded`
- `wayback_parser_accepts_valid_rows_and_isolates_malformed_rows`
- `wayback_empty_valid_response_is_valid_zero`
- `wayback_body_truncation_propagates`

Pin required CDX fields, wildcard subdomain scope and row limit. Assert no request is ever made to a returned live URL.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked wayback::tests -- --nocapture`
Expected: FAIL because module/API is absent.

- [ ] **Step 3: Implement minimal client**

```rust
pub struct WaybackQuery<'a> {
    pub domain: &'a str,
    pub row_limit: usize,
}

pub struct WaybackResult {
    pub captures: Vec<ArchiveCapture>,
    pub outcome: SourceExecutionOutcome,
    pub response_sha256: Option<String>,
    pub truncated: bool,
}

pub fn wayback_lookup<T: Transport + ?Sized>(
    transport: &T,
    query: &WaybackQuery<'_>,
    now_unix: u64,
) -> Result<WaybackResult, Error>;
```

Call `fetch::fetch` with no credential. Refine a validated 2xx parse to `Success` or `ValidZero`; never treat HTTP 200 alone as evidence.

- [ ] **Step 4: Write failing causal-outcome tests**

Add:
- `wayback_transport_failure_stays_transport_outcome`
- `wayback_non_2xx_never_emits_capture_evidence`
- `wayback_unusable_envelope_is_parser_drift`
- `wayback_zero_row_limit_is_explicit_no_work_and_sends_nothing`

- [ ] **Step 5: Run RED, implement outcome mapping, rerun GREEN**

Run: `cargo test --locked wayback::tests -- --nocapture`
Expected after implementation: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wayback.rs src/lib.rs
git commit -m "feat(archive): add guarded Wayback CDX client"
```

### Task 3: Common Crawl guarded client with one stable lineage root

**Files:**
- Create: `src/commoncrawl.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/commoncrawl.rs`

**Interfaces:**
- Consumes: Task 1 archive types, `fetch::fetch`, injected `Transport`.
- Produces: `CommonCrawlLimits`, `CommonCrawlResult`, `commoncrawl_lookup`.
- Invariant: every emitted capture has `dataset == "common_crawl"`; `CC-MAIN-*` lives only in `collection`.

- [ ] **Step 1: Write failing metadata-selection tests**

Add:
- `collection_metadata_selects_newest_n_deterministically`
- `zero_collection_limit_sends_no_index_query`
- `crawl_id_is_collection_not_dataset`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked commoncrawl::tests -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Implement metadata selection contract**

```rust
pub struct CommonCrawlLimits {
    pub max_collections: usize,
    pub rows_per_collection: usize,
}

pub struct CommonCrawlResult {
    pub captures: Vec<ArchiveCapture>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    pub response_sha256: Vec<String>,
    pub truncated: bool,
}

pub fn commoncrawl_lookup<T: Transport + ?Sized>(
    transport: &T,
    domain: &str,
    limits: &CommonCrawlLimits,
    now_unix: u64,
) -> Result<CommonCrawlResult, Error>;
```

- [ ] **Step 4: Write failing NDJSON/failure-locality tests**

Add:
- `ndjson_valid_lines_survive_malformed_neighbors`
- `row_cap_marks_truncated_and_stops_materialization`
- `one_failed_collection_does_not_erase_successful_collections`
- `multiple_crawl_collections_keep_one_countable_dataset_family`
- `truncated_http_body_marks_result_truncated`
- `zero_rows_per_collection_sends_no_index_query_and_marks_no_work`

- [ ] **Step 5: Run RED then implement bounded index loop/parser**

Run: `cargo test --locked commoncrawl::tests -- --nocapture`
Expected after implementation: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/commoncrawl.rs src/lib.rs
git commit -m "feat(archive): add bounded Common Crawl client"
```

### Task 4: Generic collector contract

**Files:**
- Create: `src/collector.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/collector.rs`

**Interfaces:**
- Consumes: `entity::{Entity, EntityKind}`, `evidence_ancestry::EvidenceNodeId`, `graph::EntityRelation`, `http::Transport`, `source_outcome::SourceExecutionOutcome`.
- Produces: `CollectionLimits`, `ObservationReceipt`, `CollectorPivot`, `CollectionBatch`, `CollectorError`, `Collector`.

- [ ] **Step 1: Write failing contract tests**

Add:
- `zero_collection_limits_are_representable_without_panicking`
- `receipt_distinguishes_valid_zero_failure_and_truncation`
- `batch_can_retain_entities_when_one_receipt_failed`
- `pivot_parent_is_typed_evidence_node_id`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked collector::tests -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Implement minimal contract types**

```rust
pub struct CollectionLimits {
    pub max_entities: usize,
    pub max_requests: usize,
    pub max_rows_per_source: usize,
}

pub struct ObservationReceipt {
    pub source: String,
    pub dataset: Option<String>,
    pub collection: Option<String>,
    pub observed_at_unix: u64,
    pub response_sha256: Option<String>,
    pub parsed_rows: usize,
    pub truncated: bool,
    pub outcome: SourceExecutionOutcome,
}

pub struct CollectorPivot {
    pub entity: Entity,
    pub parent_observation: Option<EvidenceNodeId>,
}

pub struct CollectionBatch {
    pub collector_id: &'static str,
    pub selector_uid: String,
    pub receipts: Vec<ObservationReceipt>,
    pub entities: Vec<Entity>,
    pub relations: Vec<EntityRelation>,
    pub pivots: Vec<CollectorPivot>,
    pub truncated: bool,
}

pub enum CollectorError {
    UnsupportedKind(EntityKind),
    InvalidSelector(String),
    Internal(String),
}

pub trait Collector {
    fn id(&self) -> &'static str;
    fn accepts(&self, kind: &EntityKind) -> bool;
    fn collect<T: Transport + ?Sized>(
        &self,
        selector: &Entity,
        transport: &T,
        limits: &CollectionLimits,
        now_unix: u64,
    ) -> Result<CollectionBatch, CollectorError>;
}
```

Do not introduce trait-object machinery unless this slice demonstrates a need.

- [ ] **Step 4: Verify Task 4**

Run: `cargo test --locked collector::tests -- --nocapture && cargo clippy --all-targets --locked -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/collector.rs src/lib.rs
git commit -m "feat(collector): add provenance-aware collection contract"
```

### Task 5: Archive collector -> evidence, lineage and typed pivots

**Files:**
- Create: `src/archive_collector.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/archive_collector.rs`

**Interfaces:**
- Consumes: Tasks 1-4, `entity::{Evidence, EvidenceProvenance}`, `lineage::{Lineage, Observation}`, `evidence_ancestry::EvidenceNodeId`, existing canonical domain logic and in-tree SHA-256.
- Produces: `ArchiveCollector` implementing `Collector` for `EntityKind::Domain`.

- [ ] **Step 1: Write failing evidence-shape tests**

Add:
- `archive_collector_rejects_non_domain_before_transport`
- `wayback_evidence_uses_stable_wayback_dataset`
- `commoncrawl_evidence_uses_common_crawl_dataset_and_noncounting_collection`
- `source_url_collection_and_record_locator_do_not_replace_dataset_lineage`

Assert `Lineage::of(&evidence).family()` is exactly `internet_archive_wayback` or `common_crawl`.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected: FAIL.

- [ ] **Step 3: Implement minimal entity/evidence conversion**

For every `ArchiveRecord`, emit/merge an `EntityKind::Url`. For every `ArchiveDatasetObservation` inside it, attach a separate evidence record whose attributes include:
- `dataset` stable root;
- optional non-counting `collection` values;
- archive locator(s) as `source_url`;
- first/last seen;
- MIME/status when known;
- capture count;
- deterministic interest tags as derived metadata.

The evidence collector name may identify `wayback` or `commoncrawl`; independence comes from `dataset`, never `archive_collector`.

- [ ] **Step 4: Write failing adversarial independence tests**

Add:
- `ten_wayback_captures_are_one_independent_family`
- `two_commoncrawl_collections_are_one_independent_family`
- `wayback_plus_commoncrawl_are_two_distinct_roots`
- `tampered_stored_source_family_cannot_inflate_archive_independence`
- `interest_tags_are_derived_and_do_not_add_families`

Use ancestry-aware `lineage::resolve_with_lineage` for family-independence claims; use `Entity::source_count` only for claims about its specific legacy-compatible counting behavior.

- [ ] **Step 5: Run RED then implement ancestry/evidence wiring**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected after implementation: PASS.

- [ ] **Step 6: Write failing partial-provider/pivot/bounds tests**

Add:
- `wayback_success_commoncrawl_failure_keeps_wayback_entities`
- `commoncrawl_success_wayback_failure_keeps_commoncrawl_entities`
- `discovered_subdomain_is_candidate_pivot_with_parent_observation_id`
- `entity_cap_sets_batch_truncated_without_silent_claim_of_completeness`
- `zero_request_limit_sends_nothing_and_returns_explicit_truncated_no_work_batch`

- [ ] **Step 7: Run RED then implement bounded orchestration**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected after implementation: PASS.

- [ ] **Step 8: Commit**

```bash
git add src/archive_collector.rs src/lib.rs
git commit -m "feat(collector): collect passive archive evidence for domains"
```

### Task 6: Architecture map and invariant documentation

**Files:**
- Modify: `ARCHITECTURE.md`
- Modify: `tests/architecture_doc.rs`
- Modify if compile truth requires lineage documentation: `docs/LINEAGE.md`

**Interfaces:**
- Layer placement: `archive` L3; `wayback`, `commoncrawl` L4; `collector`, `archive_collector` L5.
- Required architecture result: no new upward edge.

- [ ] **Step 1: Pin the compiled modules in the architecture test before changing the doc**

Add the five modules to `PINNED_LAYERS` at their approved indices. Add a targeted source-boundary assertion only if the existing dependency/socket checks cannot prove the claim.

- [ ] **Step 2: Run RED against the stale document**

Run: `cargo test --locked --test architecture_doc -- --nocapture`
Expected: FAIL because `ARCHITECTURE.md` does not yet map the newly compiled modules.

- [ ] **Step 3: Update `ARCHITECTURE.md` to compiled truth**

Update module rows and current-state prose only for demonstrated behavior. Do not mark recursive scan, full domain recon, persistence/export or web UI restored by this slice.

- [ ] **Step 4: Run GREEN**

Run: `cargo test --locked --test architecture_doc -- --nocapture`
Expected: PASS and `Upward edges: none.` remains true. If an upward edge appears, fix code rather than normalizing the regression into documentation unless architecture review explicitly approves it.

- [ ] **Step 5: Commit**

```bash
git add ARCHITECTURE.md tests/architecture_doc.rs docs/LINEAGE.md
git commit -m "docs(architecture): map archive collector boundary"
```

### Task 7: Whole-slice verification and falsification

**Files:**
- No production changes unless a verification gate exposes a defect.
- Add a regression test only when a failing gate reveals an unpinned behavior.

- [ ] **Step 1: Formatting + strict lint**

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```
Expected: both exit 0.

- [ ] **Step 2: Full test suite**

Run: `cargo test --locked`
Expected: zero failures. Any failure must be reported by test name and localized before completion.

- [ ] **Step 3: Built-in verification path**

Run: `cargo run --locked -- check`
Expected: exit 0 and no unintended `var/` drift.

- [ ] **Step 4: Explicit lineage falsification**

```bash
cargo test --locked archive_collector::tests
cargo test --locked lineage
cargo test --locked corroboration
```
Expected: all applicable suites pass; no duplicate row, collection ID, locator or derived tag inflates an independent-family count.

- [ ] **Step 5: Prove no new network boundary**

Search compiled source for new imports/usages of `ureq`, `TcpStream`, `UdpSocket` and direct socket creation outside the existing HTTP boundary. Investigate every hit before claiming the boundary is preserved.

- [ ] **Step 6: Android aarch64 gate**

Run the repository's existing Android aarch64 cross-build/ELF verification locally if available or require the equivalent CI gate on the final PR head. Do not equate cross-build success with real handset execution.

- [ ] **Step 7: Optional bounded live receipt after all offline gates**

Run one neutral-domain lookup per public archive source with conservative limits. Record commit SHA, UTC, response hash, parsed count, truncation flag and causal outcome. CI must remain offline.

- [ ] **Step 8: Final branch review**

Compare branch vs base and verify:
- no FreeOSINTUI code/table copied;
- no unjustified dependency added;
- no architecture upward edge;
- no source/collection/record locator can manufacture corroboration;
- partial failures remain visible;
- all truncation remains visible;
- source-registry `LeadOnly` semantics remain unchanged.

- [ ] **Step 9: Commit only actual verification-driven corrections**

Use a narrow commit message such as `test(archive): pin collector lineage and truncation invariants` only if files changed.
