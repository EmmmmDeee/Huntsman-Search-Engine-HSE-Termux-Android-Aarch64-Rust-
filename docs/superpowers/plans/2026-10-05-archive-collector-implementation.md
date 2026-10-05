# Archive Collector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Rust-native collector boundary and a bounded Wayback + Common Crawl archive-intelligence vertical slice that emits provenance-bearing URL entities without manufacturing lineage independence.

**Architecture:** Pure archive normalization/merge logic lives in L3; Wayback/Common Crawl guarded fetch clients live in L4; the generic collector contract and archive orchestration live in L5. All network traffic uses the existing `fetch::fetch` + injected `http::Transport` path; `dataset` carries only stable upstream-family identity while per-crawl/per-record identifiers remain non-counting provenance.

**Tech Stack:** Rust 2024, MSRV 1.87, existing `serde`, `serde_json`, `thiserror`, `ureq`; no async runtime; `#![deny(unsafe_code)]`.

**Spec:** `docs/superpowers/specs/2026-10-05-archive-collector-design.md`

## Global Constraints

- Rust-first; no copied/adapted FreeOSINTUI implementation or tables.
- `unsafe_code = "deny"` remains true.
- Termux/Android aarch64 remains first-class.
- No new socket-opening path; archive clients use `fetch::fetch` over injected `http::Transport`.
- Current transport body cap (`http::DEFAULT_MAX_BODY`, 4 MiB) remains the hard outer bound; parser row limits add an inner bound.
- `source_registry::EvidenceRole::LeadOnly` remains unchanged.
- `dataset` is a stable countable upstream family: `internet_archive_wayback` or `common_crawl`; `collection`, `source_url`, row locators, and capture counts never create independence.
- Partial source failure preserves valid results from successful sources.
- No live network dependency in CI.
- No result is silently dropped/truncated/misattributed; local caps set an explicit truncation flag.

## Review Focus

1. **Archive URL ambiguity:** explicit default ports, host case/trailing dot, query preservation, invalid/non-http schemes must normalize deterministically without changing path/query identity.
2. **False corroboration:** repeated Wayback captures and multiple Common Crawl collections/rows must not produce additional independent families.
3. **Partial/truncated bodies:** `Response::truncated` and row caps must propagate into receipts and must never be interpreted as evidence of absence.
4. **Malformed mixed input:** one malformed archive row/NDJSON line must not erase valid rows unless the provider envelope itself is unusable.
5. **Provider asymmetry:** Wayback success + Common Crawl failure (and reverse where practical) must retain successful entities/evidence with failed-source outcome visible.

---

### Task 1: Pure archive record model and normalization

**Files:**
- Create: `src/archive.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/archive.rs`

**Interfaces:**
- Produces: `ArchiveSource`, `ArchiveCapture`, `ArchiveRecord`, `ArchiveInterest`, `parse_archive_url(&str) -> Option<ArchiveUrlKey>`, `merge_captures(Vec<ArchiveCapture>) -> Vec<ArchiveRecord>`, `classify_archive_path(&str, &str) -> Vec<ArchiveInterest>`.
- Consumes later: Tasks 2, 3, and 5 use these exact normalized types; no network or entity dependencies.

- [ ] **Step 1: Write failing normalization tests**

Add tests named:
- `archive_url_key_ignores_http_https_host_case_trailing_dot_and_default_port`
- `archive_url_key_preserves_non_default_port_path_and_query`
- `archive_url_rejects_non_http_invalid_and_hostless_values`

Assertions must prove `HTTP://Example.COM.:80/a?x=1` and `https://example.com/a?x=1` share the intended archive key, while `https://example.com:8443/a?x=1`, `/b`, or a different query do not.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked archive::tests::archive_url -- --nocapture`
Expected: FAIL because `archive` module/types/functions do not exist.

- [ ] **Step 3: Implement minimal archive URL model**

Implement in `src/archive.rs`:

```rust
pub enum ArchiveSource { Wayback, CommonCrawl }
pub struct ArchiveUrlKey { pub host: String, pub port: Option<u16>, pub path: String, pub query: String }
pub fn parse_archive_url(raw: &str) -> Option<ArchiveUrlKey>;
```

Use existing URL/HTTP parsing primitives where possible; do not add a URL crate unless the current parser cannot correctly satisfy the tests.

- [ ] **Step 4: Run GREEN for URL normalization**

Run: `cargo test --locked archive::tests::archive_url -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Write failing merge/classification tests**

Add tests named:
- `merge_keeps_first_last_count_and_deterministic_datasets`
- `unknown_status_or_mime_is_not_invented`
- `same_dataset_multiple_captures_remain_one_dataset`
- `interest_classification_marks_patterns_without_asserting_security_facts`
- `interest_classification_has_near_miss_negatives`

- [ ] **Step 6: Run RED for merge/classification**

Run: `cargo test --locked archive::tests -- --nocapture`
Expected: new tests FAIL because merge/classification are missing.

- [ ] **Step 7: Implement minimal capture/record/interest logic**

Define:

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

pub struct ArchiveRecord { /* first/last/count + ordered unique datasets/collections and latest-known metadata */ }
pub enum ArchiveInterest { Document, ArchiveOrBackup, ConfigurationLike, ScriptLike, AdminAuthApiLike, Parameterized }
pub fn merge_captures(captures: Vec<ArchiveCapture>) -> Vec<ArchiveRecord>;
pub fn classify_archive_path(path: &str, query: &str) -> Vec<ArchiveInterest>;
```

Keep classification tables Huntsman-authored and minimal; tests define behavior rather than copying another project's lists.

- [ ] **Step 8: Run Task 1 tests + format**

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
- Consumes: `archive::{ArchiveCapture, ArchiveSource, parse_archive_url}`, `fetch::fetch`, `http::{Request, Transport}`, `source_outcome::SourceExecutionOutcome`.
- Produces: `WaybackQuery`, `ArchiveFetchResult { captures: Vec<ArchiveCapture>, outcome: SourceExecutionOutcome, truncated: bool }`, `wayback_lookup<T: Transport + ?Sized>(...) -> Result<ArchiveFetchResult, Error>`.

- [ ] **Step 1: Write failing request-construction/parser tests**

Tests:
- `wayback_request_is_https_domain_scoped_and_bounded`
- `wayback_parser_accepts_valid_rows_and_skips_malformed_rows`
- `wayback_empty_valid_response_is_valid_zero`
- `wayback_response_truncation_propagates`

Pin the request to required CDX fields only, wildcard subdomain scope, deterministic row limit, and no live-target fetch.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked wayback::tests -- --nocapture`
Expected: FAIL because module/client is absent.

- [ ] **Step 3: Implement minimal request builder and parser**

Define:

```rust
pub struct WaybackQuery<'a> { pub domain: &'a str, pub row_limit: usize }
pub struct ArchiveFetchResult { pub captures: Vec<ArchiveCapture>, pub outcome: SourceExecutionOutcome, pub truncated: bool }
pub fn wayback_lookup<T: Transport + ?Sized>(transport: &T, query: &WaybackQuery<'_>, now_unix: u64) -> Result<ArchiveFetchResult, Error>;
```

Call `fetch::fetch(..., credential=None, ...)`; after provider-contract validation, refine 2xx/parsed outcomes to `Success` or `ValidZero`. Preserve transport/body truncation.

- [ ] **Step 4: Add failing transport/outcome tests**

Tests:
- `wayback_transport_failure_stays_a_causal_outcome`
- `wayback_non_2xx_never_becomes_evidence`
- `wayback_malformed_envelope_is_parser_drift`

Use a small fake `Transport`; assert on real `Request` and returned outcomes, not mock call counts alone.

- [ ] **Step 5: Run RED then implement outcome mapping**

Run: `cargo test --locked wayback::tests -- --nocapture`
Expected before implementation: FAIL on the new outcome assertions; after minimal mapping: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/wayback.rs src/lib.rs
git commit -m "feat(archive): add guarded Wayback CDX client"
```

### Task 3: Common Crawl guarded client with stable lineage root

**Files:**
- Create: `src/commoncrawl.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/commoncrawl.rs`

**Interfaces:**
- Consumes: Task 1 archive model, `fetch::fetch`, injected `Transport`.
- Produces: `CommonCrawlLimits`, `CommonCrawlResult`, `commoncrawl_lookup<T: Transport + ?Sized>(...)`.
- Invariant: every capture has `dataset == "common_crawl"`; specific `CC-MAIN-*` identifier is stored only in `collection`.

- [ ] **Step 1: Write failing collection-selection tests**

Tests:
- `collection_metadata_selects_newest_n_deterministically`
- `zero_collection_limit_sends_no_index_query`
- `crawl_id_is_collection_not_dataset`

Pin a conservative default `max_collections` and explicit per-collection row cap in `CommonCrawlLimits`.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked commoncrawl::tests -- --nocapture`
Expected: FAIL because module/types are absent.

- [ ] **Step 3: Implement metadata parse + deterministic selection**

Define:

```rust
pub struct CommonCrawlLimits { pub max_collections: usize, pub rows_per_collection: usize }
pub struct CommonCrawlResult { pub captures: Vec<ArchiveCapture>, pub outcomes: Vec<SourceExecutionOutcome>, pub truncated: bool }
pub fn commoncrawl_lookup<T: Transport + ?Sized>(transport: &T, domain: &str, limits: &CommonCrawlLimits, now_unix: u64) -> Result<CommonCrawlResult, Error>;
```

- [ ] **Step 4: Write failing NDJSON/failure-locality tests**

Tests:
- `ndjson_valid_lines_survive_malformed_neighbors`
- `row_cap_marks_truncated_and_stops_materialization`
- `one_failed_collection_does_not_erase_successful_collections`
- `multiple_crawl_collections_keep_one_countable_dataset_family`
- `truncated_http_body_marks_result_truncated`

- [ ] **Step 5: Run RED then implement minimal index loop/parser**

Run: `cargo test --locked commoncrawl::tests -- --nocapture`
Expected before code: FAIL; after implementation: PASS.

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
- Consumes: `entity::{Entity, EntityKind}`, `graph::EntityRelation`, `http::Transport`, `source_outcome::SourceExecutionOutcome`.
- Produces: `CollectionLimits`, `ObservationReceipt`, `CollectorPivot`, `CollectionBatch`, `CollectorError`, `Collector` trait.

- [ ] **Step 1: Write failing contract tests**

Tests:
- `collection_limits_reject_zero_global_caps_that_make_execution_ambiguous`
- `receipt_distinguishes_success_zero_failure_and_truncation`
- `batch_can_retain_entities_when_one_receipt_failed`

- [ ] **Step 2: Run RED**

Run: `cargo test --locked collector::tests -- --nocapture`
Expected: FAIL because contract is absent.

- [ ] **Step 3: Implement minimal contract types**

Use:

```rust
pub struct CollectionLimits { pub max_entities: usize, pub max_requests: usize, pub max_rows_per_source: usize }
pub struct ObservationReceipt { pub source: String, pub dataset: Option<String>, pub collection: Option<String>, pub observed_at_unix: u64, pub response_sha256: Option<String>, pub parsed_rows: usize, pub truncated: bool, pub outcome: SourceExecutionOutcome }
pub struct CollectorPivot { pub entity: Entity, pub parent_observation: Option<String> }
pub struct CollectionBatch { pub collector_id: &'static str, pub selector_uid: String, pub receipts: Vec<ObservationReceipt>, pub entities: Vec<Entity>, pub relations: Vec<EntityRelation>, pub pivots: Vec<CollectorPivot> }
pub trait Collector { fn id(&self) -> &'static str; fn accepts(&self, kind: &EntityKind) -> bool; fn collect<T: Transport + ?Sized>(&self, selector: &Entity, transport: &T, limits: &CollectionLimits, now_unix: u64) -> Result<CollectionBatch, CollectorError>; }
```

If object safety becomes necessary later, change the transport method to `&dyn Transport`; do not introduce dynamic dispatch without a demonstrated need in this slice.

- [ ] **Step 4: Run GREEN + clippy on module**

Run: `cargo test --locked collector::tests -- --nocapture && cargo clippy --all-targets --locked -- -D warnings`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/collector.rs src/lib.rs
git commit -m "feat(collector): add provenance-aware collection contract"
```

### Task 5: Archive collector converts observations into evidence, lineage, and pivots

**Files:**
- Create: `src/archive_collector.rs`
- Modify: `src/lib.rs`
- Test: unit tests inside `src/archive_collector.rs`

**Interfaces:**
- Consumes: Tasks 1-4 plus `entity::{Evidence, EvidenceProvenance}`, `lineage::{Lineage, Observation}`, `sha256`, canonical domain handling.
- Produces: `ArchiveCollector`, implementing `Collector` for `EntityKind::Domain`.

- [ ] **Step 1: Write failing evidence-shape tests**

Tests:
- `archive_collector_rejects_non_domain_before_transport`
- `wayback_evidence_uses_stable_wayback_dataset`
- `commoncrawl_evidence_uses_common_crawl_dataset_and_noncounting_collection`
- `source_url_and_collection_do_not_replace_dataset_lineage`

Assert `Lineage::of(&evidence).family()` is exactly `internet_archive_wayback` or `common_crawl` as appropriate.

- [ ] **Step 2: Run RED**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected: FAIL because collector is absent.

- [ ] **Step 3: Implement minimal entity/evidence conversion**

For each normalized URL record:
- emit/merge `EntityKind::Url`;
- attach one evidence item per upstream dataset family represented;
- attributes include `dataset`, optional `collection`, `source_url`, first/last seen, MIME/status, capture count, and deterministic interest tags;
- use `EvidenceProvenance::for_scan` or equivalent existing constructor; never use `archive_collector` as the countable family.

- [ ] **Step 4: Write failing independence/adversarial tests**

Tests:
- `ten_wayback_captures_are_one_independent_family`
- `two_commoncrawl_collections_are_one_independent_family`
- `wayback_plus_commoncrawl_are_two_distinct_roots`
- `tampered_stored_source_family_cannot_inflate_archive_independence`
- `interest_tags_are_derived_and_do_not_add_families`

Use `lineage::resolve_with_lineage` or `Entity::source_count` only where each exactly matches the claim being tested; prefer ancestry-aware lineage for independence claims.

- [ ] **Step 5: Run RED then implement merge/ancestry wiring**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected before final wiring: FAIL on independence cases; after implementation: PASS.

- [ ] **Step 6: Write failing partial-provider and pivot tests**

Tests:
- `wayback_success_commoncrawl_failure_keeps_wayback_entities`
- `commoncrawl_success_wayback_failure_keeps_commoncrawl_entities`
- `discovered_subdomain_is_candidate_pivot_with_parent_observation`
- `entity_limit_sets_truncation_without_silent_drop`

- [ ] **Step 7: Run RED then implement bounded orchestration**

Run: `cargo test --locked archive_collector::tests -- --nocapture`
Expected after implementation: PASS with receipts identifying failed/truncated sources.

- [ ] **Step 8: Commit**

```bash
git add src/archive_collector.rs src/lib.rs
git commit -m "feat(collector): collect passive archive evidence for domains"
```

### Task 6: Architecture map, invariants, and regression gates

**Files:**
- Modify: `ARCHITECTURE.md`
- Modify: `tests/architecture_doc.rs`
- Modify only if required by compile truth: `docs/LINEAGE.md`

**Interfaces:**
- Adds layer placement: `archive` L3; `wayback`, `commoncrawl` L4; `collector`, `archive_collector` L5.
- Adds no upward dependency edge.

- [ ] **Step 1: Write/update architecture assertions before doc claims**

Update `PINNED_LAYERS` only after modules exist, pinning the five new modules to their approved layers. Add targeted assertions if existing generic checks cannot prove that archive source clients use the guarded fetch path and that L4 does not depend on L5.

- [ ] **Step 2: Run RED against stale architecture doc**

Run: `cargo test --locked --test architecture_doc -- --nocapture`
Expected: FAIL because compiled modules are not yet represented/pinned in `ARCHITECTURE.md`.

- [ ] **Step 3: Update `ARCHITECTURE.md` to compiled truth**

Update module map and CURRENT text only for demonstrated behavior. Do not mark domain recon or recursive scan fully restored merely because archive collection exists.

- [ ] **Step 4: Run GREEN**

Run: `cargo test --locked --test architecture_doc -- --nocapture`
Expected: PASS with `Upward edges: none.` still true unless the dependency scanner proves otherwise; if an upward edge appears, fix code rather than documenting the regression unless architecture review explicitly approves it.

- [ ] **Step 5: Commit**

```bash
git add ARCHITECTURE.md tests/architecture_doc.rs docs/LINEAGE.md
git commit -m "docs(architecture): map archive collector boundary"
```

### Task 7: Whole-slice verification and falsification

**Files:**
- No production changes unless a gate exposes a defect.
- Add regression tests only when a failing gate reveals an unpinned behavior.

**Interfaces:**
- Consumes the complete slice.
- Produces verification evidence only; no claim of live-source success without a live receipt.

- [ ] **Step 1: Run formatting and strict lint**

Run:
```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
```
Expected: both exit 0.

- [ ] **Step 2: Run full test suite**

Run: `cargo test --locked`
Expected: 0 failures. Report every failure by name if not zero.

- [ ] **Step 3: Run built-in verification path**

Run: `cargo run --locked -- check`
Expected: exit 0 and no unintended `var/` drift.

- [ ] **Step 4: Falsify lineage independence explicitly**

Re-run the archive collector adversarial tests plus existing lineage/corroboration suites:
```bash
cargo test --locked archive_collector::tests
cargo test --locked lineage
cargo test --locked corroboration
```
Expected: all pass; no duplicate-row/crawl path can inflate family count.

- [ ] **Step 5: Verify no new network boundary**

Use repository search/static checks to prove no new `ureq`, `TcpStream`, `UdpSocket`, or socket-opening code appears outside the existing HTTP boundary. Any finding must be investigated before completion.

- [ ] **Step 6: Verify Android/Termux build path**

Run the repository's existing Android aarch64 cross-build/ELF gate or let CI run the same pinned gate on the PR head. Do not claim handset execution from cross-build alone.

- [ ] **Step 7: Optional bounded live receipt after offline gates**

Only after all offline gates pass, run one neutral-domain Wayback and Common Crawl lookup with conservative limits. Record commit SHA, UTC, response hash, result count, truncation flag, and exit/outcome. Do not make CI depend on it.

- [ ] **Step 8: Final branch review**

Compare the implementation branch against its base and verify:
- no FreeOSINTUI source/table copied;
- no new dependency unless separately justified;
- no architecture upward edge;
- no source/collection/record locator can manufacture corroboration;
- partial failures remain visible;
- truncation remains visible;
- source-registry LeadOnly semantics unchanged.

- [ ] **Step 9: Commit any verification-only fixture/doc corrections**

Use a narrowly scoped message such as:
```bash
git commit -m "test(archive): pin collector lineage and truncation invariants"
```
Only if files actually changed.
