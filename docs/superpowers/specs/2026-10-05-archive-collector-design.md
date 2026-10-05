# Collector Boundary + Archive Intelligence Design

Date: 2026-10-05
Branch: `design/archive-collector-boundary`
Target package: `huntsman-recon`
Status: DESIGN — no product-code changes in this document

## 1. Objective

Restore a production-grade causal bridge between Huntsman's source clients and its evidence/entity system, then prove that bridge with one high-value, keyless vertical slice: passive archive intelligence over the Internet Archive Wayback CDX API and Common Crawl indexes.

The design must preserve Huntsman's current architecture and epistemic invariants:

- Rust-first, `unsafe_code = "deny"`.
- Termux/Android aarch64 remains a first-class target.
- Network access remains confined to the guarded transport boundary.
- A generated lead is not evidence.
- A collector cannot manufacture independent corroboration merely by emitting multiple rows.
- Upstream dataset/source identity, not UI route count or provider-row count, determines lineage independence.
- No result may be silently dropped, truncated, or misattributed relative to the relevant legacy capability when differential fixtures exist.
- Pure parsing/normalization remains independently testable without network access.
- The implementation must be Huntsman-authored. FreeOSINTUI is used only as a competitive/reference capability survey; no FreeOSINTUI source is copied or adapted.

This slice intentionally does **not** attempt to restore every OSINT provider. It establishes the reusable collector contract and demonstrates it end-to-end with archive data.

## 2. Current-state constraints

Current `ARCHITECTURE.md` identifies the missing causal boundary: L4 source clients exist, L5 entity/lineage machinery exists, but there is no production collector layer joining selectors to source requests and source responses to provenance-bearing evidence.

Current useful components already exist and must be reused rather than duplicated:

- L1: `evidence_ancestry`, `confidence`, `identity_resolution`, `resolve`.
- L2: `http`, `fetch`, `classify`, `source_outcome`, `keys`.
- L3: canonicalisation and validators.
- L4: injected-transport source clients.
- L5: `entity`, `lineage`, `source_registry`, correlation and analysis.
- L7: ledger/store/export primitives.

`source_registry` remains discovery-only. Its `EvidenceRole::LeadOnly` contract is not weakened by this work.

## 3. Architectural decision

### 3.1 Layer placement

No new numerical layer is introduced.

Add:

- **L3** `archive` — pure archive record model, URL normalization, merge rules, archive-interest classification.
- **L4** `wayback` — request construction and response parsing for Wayback CDX.
- **L4** `commoncrawl` — Common Crawl collection discovery, index request construction and NDJSON parsing.
- **L5** `collector` — generic collector contracts and collection outcomes.
- **L5** `archive_collector` — domain-selector orchestration using the two L4 clients, converting observations into `Entity` + `Evidence` + ancestry-ready metadata.

This obeys the repository rule that a module may depend only on its own or lower layers.

### 3.2 Why not one module per complete tool

A FreeOSINTUI-style `footprint` feature combines acquisition, parsing, classification, presentation and pivots. That is appropriate for an interactive browser utility but would blur Huntsman's evidence boundary.

Huntsman instead separates:

```text
selector
  -> collector planning
  -> guarded transport
  -> source-specific response parser
  -> normalized observation
  -> provenance-bearing evidence/entity
  -> lineage/resolution
  -> typed pivots
```

Acquisition and analysis remain independently replaceable and testable.

## 4. Collector contract

### 4.1 Core types

`src/collector.rs` defines a small synchronous contract compatible with the existing blocking `ureq` transport model.

Proposed shape (illustrative, not a frozen signature):

```rust
pub trait Collector {
    fn id(&self) -> &'static str;
    fn accepts(&self, kind: &EntityKind) -> bool;

    fn collect(
        &self,
        selector: &Entity,
        transport: &dyn Transport,
        limits: &CollectionLimits,
    ) -> Result<CollectionBatch, CollectorError>;
}
```

`CollectionBatch` contains only material that can be verified or traced:

```rust
pub struct CollectionBatch {
    pub collector_id: &'static str,
    pub selector_uid: String,
    pub observations: Vec<ObservationReceipt>,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub pivots: Vec<CollectorPivot>,
    pub outcome: CollectionOutcome,
}
```

The exact relation/pivot types may reuse existing repository types where that avoids duplication.

### 4.2 Observation receipts

A collector must distinguish transport success from evidentiary success.

Each source response produces an `ObservationReceipt` containing at minimum:

- collector/source identifier;
- upstream dataset identifier when known;
- request origin/path identity sufficient for audit without embedding secrets;
- UTC/Unix observation time;
- response-body hash;
- HTTP/source outcome classification;
- parser result counts;
- truncation/pagination status;
- optional source-provided temporal bounds.

A `200` response with zero parsed records is a successful empty observation, not a failed request and not positive evidence.

### 4.3 Failure locality

Collectors return partial batches when some independent source requests succeed and others fail, unless the failure invalidates interpretation of the entire batch.

Example:

- Wayback succeeds, Common Crawl times out -> retain Wayback entities/evidence; batch outcome marks Common Crawl unavailable.
- Common Crawl index-list parsing fails -> Common Crawl contributes no evidence; Wayback remains valid.
- Domain selector is invalid -> fail before any network request; no batch entities.

This prevents one provider from collapsing an otherwise valid investigation.

## 5. Archive domain model (L3)

### 5.1 `ArchiveCapture`

A normalized capture record represents one upstream observation before cross-source merging:

```rust
pub struct ArchiveCapture {
    pub source: ArchiveSource,
    pub dataset: String,
    pub original_url: String,
    pub canonical_key: String,
    pub host: String,
    pub path: String,
    pub query: String,
    pub captured_at: String,
    pub status: Option<u16>,
    pub mime: Option<String>,
    pub digest: Option<String>,
}
```

`dataset` must identify the real upstream corpus where possible, for example:

- `internet_archive_wayback`
- `commoncrawl:CC-MAIN-2026-XX`

The collector name is **not** substituted for dataset identity.

### 5.2 URL normalization

For archive deduplication only:

- accept only HTTP/HTTPS URLs;
- lowercase hostnames;
- remove a trailing root dot from the hostname;
- treat explicit default ports as equivalent to omitted defaults;
- preserve path and query because different paths/query strings are distinct archived resources;
- reject `mailto:`, `javascript:`, invalid URLs and non-HTTP schemes;
- do not silently decode or re-encode path bytes in a way that changes resource identity.

The archive dedupe key is logically `host + normalized-port + path + query`.

The live URL is never fetched by archive normalization or classification.

### 5.3 Cross-capture merge

`ArchiveRecord` merges captures that share the same canonical archive key and retains:

- first observed capture time;
- last observed capture time;
- total capture count;
- set of upstream datasets/sources;
- latest-known status and MIME, without inventing a value when unknown;
- one or more archive locator(s) where available.

Important: merge is a presentation/storage operation. It does **not** convert N captures into N corroborating evidence families.

### 5.4 Interest classification

Classification is deterministic metadata, not proof of sensitivity.

Initial groups:

- document;
- archive/backup/database;
- configuration-like;
- script/source-like;
- admin/auth/API-like path;
- parameterized URL.

Names such as `.env`, `id_rsa`, `wp-config`, `.git`, `backup`, `sql`, `swagger` may raise an `interest` tag on an archived URL, but the tag means "interesting path pattern" only. It must not assert that a secret, credential or vulnerability exists.

## 6. Wayback client (L4)

`src/wayback.rs` is a pure request builder + response parser over an injected `http::Transport`.

Responsibilities:

- construct a bounded CDX query for a domain and subdomains;
- request fields needed by `ArchiveCapture` only;
- parse successful response rows defensively;
- reject malformed timestamps/status codes without panicking;
- expose explicit truncation/limit information when the API signals or local bounds cause it;
- never follow archive results to the live target;
- never create `Entity` or `Evidence` directly.

The client must be testable entirely with recorded response bytes and fake transport.

## 7. Common Crawl client (L4)

`src/commoncrawl.rs` performs two bounded operations:

1. Discover available Common Crawl indexes from the public collection metadata endpoint or consume an explicitly supplied collection in tests.
2. Query a bounded number of selected indexes for the target domain/subdomains and parse NDJSON records.

Resource constraints are mandatory because Termux is a first-class target.

Default policy for the first slice:

- query only the newest small number of collections (configurable, with a conservative default);
- cap response bytes per request using existing bounded-fetch mechanisms where available;
- cap parsed rows per collection;
- surface `truncated = true` whenever a local cap prevents complete consumption;
- deterministic collection ordering.

A truncated result is valid partial evidence but must remain visibly truncated in receipts and reports.

## 8. Archive collector (L5)

### 8.1 Input

Accept exactly `EntityKind::Domain` in the first implementation.

The selector is canonicalized using existing Huntsman domain normalization. Invalid/empty selectors fail before transport.

### 8.2 Acquisition

The collector independently attempts:

- Wayback CDX;
- selected Common Crawl indexes.

No source is required to succeed for another source's valid observations to be retained.

### 8.3 Evidence emission

For each normalized archived URL, emit or merge an `EntityKind::Url` entity with provenance-bearing evidence.

Example semantic content:

```text
EntityKind::Url
value: <canonical URL>
confidence: observation-level base confidence

Evidence.provenance.source = "wayback" | "commoncrawl"
Evidence.attributes:
  dataset = <upstream dataset id>
  source_url = <archive locator, when available>
  first_seen = <timestamp>
  last_seen = <timestamp>
  mime = <if known>
  http_status = <if known>
  capture_count = <count within that upstream dataset>
  archive_interest = <zero or more deterministic tags>
```

Dataset naming must be compatible with `lineage::Lineage::of` and its current admissible lineage fields. If the exact attribute key is not already accepted, the implementation must update lineage deliberately with adversarial tests; it must not smuggle independence through `source_url` or `source_id`, which current lineage intentionally excludes.

### 8.4 Independence rule

The collector must satisfy all of the following:

1. Ten Wayback captures of one URL do not become ten source families.
2. Two Common Crawl rows from the same crawl index do not become two source families merely because their record locators differ.
3. Wayback and Common Crawl may count as independent archive families only when lineage resolves them to genuinely distinct upstream roots.
4. A merged `ArchiveRecord` containing both sources must retain both roots rather than flattening provenance to `archive_collector`.
5. Generated classifications/tags (`config`, `admin`, etc.) are derived enrichment and never independent corroboration.

### 8.5 Pivots

The first slice emits bounded typed pivots, not arbitrary recursion:

- distinct discovered subdomain -> `EntityKind::Domain` candidate pivot;
- archived absolute URL -> already represented as URL entity;
- no automatic fetching of archived documents or live endpoints in this slice.

Pivots inherit ancestry from the observation that produced them.

## 9. Source registry interaction

The existing Wayback `LeadOnly` source route remains unchanged.

The new archive collector is not represented as an evidence-bearing `SourceDescriptor`; `source_registry` answers "where could an operator look?" while collectors answer "what did Huntsman actually retrieve and parse?"

A later registry extension may advertise collector availability separately, but must not overload `EvidenceRole::LeadOnly`.

## 10. Recursion boundary

This design prepares `scan` restoration but does not implement unbounded recursive scanning in the first PR.

The archive collector returns typed candidate pivots. A later orchestrator decides whether to schedule them using explicit limits:

- max depth;
- max entities;
- max requests;
- max bytes;
- per-source request caps;
- wall-clock/cancellation state where supported.

This keeps archive collection independently verifiable before recursive orchestration is reintroduced.

## 11. Error model

Add collector-specific errors only where existing `Error` variants cannot represent the condition without loss.

Required distinctions:

- invalid selector;
- transport unavailable/timeout;
- non-success upstream response classified through existing source-outcome machinery;
- malformed upstream data;
- local byte/row limit reached (not an error by itself; marks truncation);
- unsupported selector kind;
- internal invariant violation.

No error message may include credentials or secret-bearing headers.

## 12. Termux/resource requirements

The first implementation must avoid an async runtime and preserve the current small dependency set unless a new crate has clear net value.

Preferred order:

1. in-tree/safe-std implementation;
2. existing dependencies;
3. small, well-maintained Rust crate if implementing the primitive correctly in-tree would be materially worse.

All parsing must be streaming/bounded where responses can be large. Do not collect unbounded Common Crawl or Wayback result sets in memory.

No `unsafe` code.

## 13. Verification strategy

### 13.1 TDD requirement

Implementation begins with failing tests for contracts and boundary cases before product code.

### 13.2 Pure L3 tests

Cover at minimum:

- URL equivalence/non-equivalence;
- invalid/non-HTTP rejection;
- first/last/capture-count merge behavior;
- MIME/status unknown handling;
- deterministic source/dataset ordering;
- interest classification positives and near-miss negatives;
- no interest tag implies a security conclusion.

### 13.3 Wayback parser/client tests

Recorded/fake responses:

- valid rows;
- empty response;
- malformed row mixed with valid rows;
- invalid timestamps/status;
- response-size/row caps;
- transport failure;
- non-2xx outcome.

### 13.4 Common Crawl tests

Cover:

- collection metadata ordering;
- bounded newest-N selection;
- NDJSON parsing;
- malformed line isolation;
- deterministic truncation;
- multi-index dataset identity;
- failure of one collection does not erase successful collections.

### 13.5 Collector invariants

Adversarial tests must prove:

- duplicate captures do not inflate corroboration;
- duplicate record locators do not create lineage independence;
- tampering with stored `source_family` still cannot create independence (existing entity invariant remains effective);
- Wayback + Common Crawl roots remain distinguishable;
- derived subdomain pivots are ancestry-linked and not independent evidence;
- partial provider failure retains valid evidence from the surviving provider.

### 13.6 Architecture tests

Update `ARCHITECTURE.md` and `tests/architecture_doc.rs` expectations so every new compiled module is assigned to the correct existing layer and no upward edge is introduced.

### 13.7 Differential verification

Where legacy `hse` archive/domain behavior exists, capture one or more legacy golden fixtures before implementation and compare the same recorded inputs against the reconstructed path.

Acceptance remains:

- no legacy result silently dropped;
- no result truncated without an explicit truncation marker;
- no result attributed to the wrong source/dataset;
- intentional differences require a reviewed documented reason.

The new Common Crawl capability may exceed legacy behavior; superiority does not waive the no-regression checks for overlapping outputs.

### 13.8 Live receipt

After offline tests pass, perform one bounded live run against each public archive source using a neutral test domain and record:

- command/test harness identity;
- UTC time;
- commit SHA;
- response hash;
- exit/result status;
- result count and truncation flag.

Do not make CI depend on live availability.

## 14. Acceptance criteria for the first implementation PR

The slice is complete only when all are true:

1. `collector`, `archive`, `wayback`, `commoncrawl`, and `archive_collector` are compiled and architecture-mapped.
2. All network calls use the existing guarded/injected transport boundary; no new socket-opening path exists.
3. A domain can be collected from recorded Wayback + Common Crawl responses into provenance-bearing URL entities.
4. Upstream dataset identity survives into lineage-relevant evidence attributes.
5. Multiple rows/captures from one upstream root cannot inflate source-family count.
6. Partial source failure retains independent successful-source evidence.
7. Archive-interest classification is deterministic enrichment only.
8. Memory/row/byte limits are explicit and tested.
9. `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the full test suite pass on the implementation branch.
10. At least one bounded live receipt per source is captured outside CI, unless the source is externally unavailable; unavailability must be recorded rather than treated as a passing live test.
11. No FreeOSINTUI implementation code, data tables, or other Commons-Clause-covered material is copied into Huntsman.

## 15. Deliberately deferred work

Not part of the first implementation PR:

- full recursive `scan` orchestration;
- email-header forensics;
- lookalike-domain generation;
- GitHub evidence collector;
- reputation-provider federation;
- HIBP/XposedOrNot front-end restoration;
- downloading archived documents;
- live-target crawling/scanning;
- UI/report redesign;
- async runtime conversion.

These become follow-on slices after the collector boundary has passed end-to-end verification.

## 16. Strongest alternative considered

Alternative: implement archive functionality directly inside `source_registry` or a single `footprint` module.

Rejected because it would combine lead routing, network acquisition, parser semantics and evidence creation; weaken the `LeadOnly` distinction; make lineage mistakes easier; and produce a poor reusable boundary for later HIBP, GitHub, reputation and domain collectors.

Alternative: introduce a new L4.5 architecture layer.

Rejected because the existing invariant already permits an L5 collector to consume L4 clients and L5 entity types. Adding a new layer creates documentation/test churn without improving dependency direction.

## 17. Invalidation conditions

Revisit this design if implementation evidence shows any of the following:

- the existing `Transport` abstraction cannot support bounded streaming without unsafe or unbounded buffering;
- current lineage attributes cannot represent Common Crawl collection identity without creating a dependency cycle or violating legacy invariants;
- Wayback/Common Crawl APIs materially changed such that the proposed request/response separation is no longer accurate;
- a new module placement introduces an upward edge under `tests/architecture_doc.rs`;
- differential fixtures show that the proposed archive canonical key merges resources legacy/Huntsman must keep distinct.

In those cases preserve the objective and evidence invariants, then replace the affected mechanism rather than forcing the design.
