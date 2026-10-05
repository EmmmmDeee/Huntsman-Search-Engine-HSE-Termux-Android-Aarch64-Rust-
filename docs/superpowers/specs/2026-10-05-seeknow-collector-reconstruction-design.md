# SeekNow Collector Reconstruction Design

Date: 2026-10-05
Branch: `design/seeknow-collector-reconstruction`
Target package: `huntsman-recon`
Base: `22be0defe24cdc04daf216cdb2dae358535f5c3c` (`refactor/repository-reconstruction-2026-10-05`)
Status: DESIGN — no product-code changes in this document

## 1. Objective

Restore SeekNow/See-Know as a production-grade keyed breach/exposure source in the reconstructed Rust HSE while preserving the reconstruction's network, secret-handling, provenance, lineage, bounded-resource, and differential-verification invariants.

The implementation must make SeekNow usable through the reconstructed collector/evidence path rather than recreate the archived monolith's direct module architecture or introduce another binary-to-provider exception.

The first completed slice must:

- use the documented native REST API at `https://see-know.ru/api/v1`;
- support authenticated `/credits`, `/status`, `POST /search`, and `POST /search/deep`;
- accept the high-value selector kinds already supported by SeekNow universal search: email, username, phone, IP, domain, and person/name selectors where Huntsman's classifier can represent them;
- route every request through Huntsman's guarded `fetch` + injected `http::Transport` path;
- obtain the API key through the reconstructed key system from `HUNTSMAN_SEEKNOW_KEY` or an explicitly supplied keys file;
- never emit, persist, fingerprint, tail-log, or otherwise expose API-key material;
- distinguish valid zero, auth failure, entitlement failure, quota exhaustion, transient rate limit, transport failure, challenge/WAF, truncation, schema/parser drift, and positive success;
- preserve provider-returned source/database/breach/corpus provenance in evidence instead of treating the collector name as the upstream family;
- prevent duplicate rows or provider multiplexing from manufacturing independent corroboration;
- preserve the old `7dca720` behavior where it is correct, and intentionally tighten behavior where legacy semantics conflict with the reconstructed evidence/security invariants;
- remain safe Rust with no new runtime LLM or async runtime;
- remain viable on Termux/Android aarch64.

## 2. Authoritative state and behavioral oracle

The implementation base is the strongest verified reconstruction branch currently available, `refactor/repository-reconstruction-2026-10-05` at `22be0defe24cdc04daf216cdb2dae358535f5c3c`, not stale `main` and not `legacy/`.

The reconstruction architecture names legacy commit `7dca720` as the capability oracle. The older `legacy/hse-monolith-v1.41.0/` tree is a per-file historical reference only where `7dca720` lacks a path. SeekNow behavior therefore must be captured from `7dca720` when differential fixtures are produced.

Useful proven legacy behavior to retain where compatible:

- universal fast search and deep search are distinct;
- `limit=500` is used to request the documented maximum rows per universal-search call;
- fast and deep caches are logically distinct;
- typed search and auto-detect search are logically distinct;
- a fast positive hit must not be replaced by a deep-only path;
- transient rate limits are not equivalent to exhausted daily credits;
- provider-level error classification must inspect the provider envelope, not arbitrary leaked payload text;
- the client must not cache a failed or ambiguous empty as durable positive state;
- selector-specific GET endpoints can be restored later without changing the universal-search collector contract.

Legacy behavior deliberately not inherited as an invariant:

- key fingerprints persisted into evidence;
- automatic credential-bearing fallback across multiple provider domains;
- treating non-JSON or truncated provider output as an ordinary clean empty;
- returning an empty vector when execution was skipped because of key/budget state;
- any path that makes a failed/unknown provider state observationally indistinguishable from a validated zero-result response.

## 3. Relationship to the archive-collector design

The repository already has a design-only PR for a reusable collector boundary plus Wayback/Common Crawl. This SeekNow design must not invent a competing collector abstraction.

The shared collector contract is therefore the one already specified in `2026-10-05-archive-collector-design.md`:

```text
selector
  -> collector planning
  -> guarded fetch
  -> source-specific response parser
  -> normalized observation
  -> provenance-bearing evidence/entity
  -> lineage/resolution
  -> typed pivots
```

If the generic `collector.rs` boundary from the archive work lands first, SeekNow consumes it directly. If SeekNow is implemented first, it introduces only the minimal generic contract required by both designs, matching that prior design's semantics and names closely enough that the archive implementation can reuse it without migration churn.

`source_registry` remains discovery-only. A registry route is not evidence and is not the execution path for SeekNow.

## 4. Layer placement

No new architecture layer is introduced.

Add or reuse:

- **L4 `seeknow`** — request construction, guarded authenticated fetch, response-envelope parsing, result-row normalization, provider status/credit interpretation.
- **L5 `collector`** — shared collector contracts if not already present from the archive implementation.
- **L5 `seeknow_collector`** — selector-to-query planning; fast/deep orchestration; result-row to `Entity`/`Evidence` conversion; lineage-ready provenance; typed pivots; collection outcome aggregation.
- **Binary/CLI adapter** — explicit `seeknow` diagnostics and/or integration into the first reconstructed people-selector path, but the binary must not bypass the L5 collector to call L4 directly.

The L4 source client must not depend on L5 entity types. It returns source-domain records plus source outcomes. L5 owns evidence/entity interpretation.

## 5. Network and trust boundary

### 5.1 Only guarded network execution

All HTTP operations use:

```text
seeknow / seeknow_collector
  -> fetch::fetch
  -> injected http::Transport
  -> UreqTransport only at the real execution boundary
```

No direct `ureq`, `TcpStream`, curl subprocess, reqwest client, shell command, browser automation, or WebView path is added.

### 5.2 Primary origin

The built-in API base is:

`https://see-know.ru/api/v1`

Credential-bearing automatic rotation to `.xyz`, `.eu`, `.icu`, `.vip`, or other aliases is not performed.

If a base override is restored later, it must pass the existing endpoint/origin safety policy and then take exclusive effect. The API key is never silently retried on a host the operator did not choose.

### 5.3 Authentication

Use one configured credential slot:

`HUNTSMAN_SEEKNOW_KEY`

The API accepts `X-API-Key` and current documentation also describes `Authorization: Bearer`. HSE will standardize on `X-API-Key` unless live verification proves it incompatible.

The key must be placed through `fetch::Credential` or the equivalent reconstructed exact-origin credential abstraction, pinned to `https://see-know.ru:443`. It must not be manually interpolated into URLs, bodies, logs, errors, evidence attributes, cache keys, receipts, or diagnostics.

### 5.4 Redirects

Credential-bearing requests default to zero redirects unless current first-party API behavior requires a same-origin redirect. A redirect policy change is security-relevant and requires explicit tests proving:

- no key crosses origin;
- no downgrade to HTTP;
- no userinfo-derived authorization;
- no key reattachment after leaving the pinned origin.

## 6. L4 SeekNow client

### 6.1 Core request types

The source client exposes typed request/response structures rather than loose `serde_json::Value` at the collector boundary.

Proposed shape:

```rust
pub const API_BASE: &str = "https://see-know.ru/api/v1";
pub const SEARCH_LIMIT_MAX: u16 = 500;

pub enum SeekNowQueryType {
    Email,
    Phone,
    Username,
    Ip,
    Domain,
    Auto,
}

pub struct SeekNowSearch<'a> {
    pub query: &'a str,
    pub query_type: SeekNowQueryType,
    pub limit: u16,
}

pub struct SeekNowCredits {
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    pub reset: Option<String>,
    pub plan: Option<String>,
}

pub struct SeekNowStatus {
    pub service_status: Option<String>,
    pub raw_fields: BTreeMap<String, String>,
}

pub struct SeekNowResponseMeta {
    pub http_status: u16,
    pub response_sha256: String,
    pub truncated: bool,
    pub rate_limit_limit: Option<u64>,
    pub rate_limit_remaining: Option<u64>,
    pub rate_limit_reset: Option<String>,
}

pub struct SeekNowSearchResult {
    pub rows: Vec<SeekNowRow>,
    pub meta: SeekNowResponseMeta,
    pub outcome: SourceExecutionOutcome,
}
```

Exact fields may be adjusted to observed current responses, but the types must preserve unknown provider fields where they may carry provenance or entity values without converting the entire system back to untyped JSON.

### 6.2 Endpoints in the first slice

Implement:

- `GET /credits` — zero-credit account/plan diagnostic endpoint;
- `GET /status` — zero-credit service/status diagnostic endpoint;
- `POST /search` — fast universal search;
- `POST /search/deep` — deep universal search.

Do not implement the full documented endpoint matrix in the first PR. Discord, gaming, social-history, stealer, WHOIS, domain-intel, phone-intel, username-platform fanout, and Enterprise/Kurama endpoints are follow-on slices once the universal-search path is proven.

### 6.3 Request construction

Universal search JSON is:

```json
{"query":"<value>","type":"<type>","limit":500}
```

For `Auto`, omit `type` rather than serializing a fake value.

The body must be generated by `serde_json`, not manual string concatenation. This removes the legacy need for custom JSON escaping and makes malformed UTF-8/escaping behavior explicit through Rust strings and serde.

`limit` is clamped to `1..=500`; the production collector requests `500` unless an explicit collection limit is lower.

### 6.4 Response size and truncation

The existing `http::Response` hard body cap remains the outer bound. A truncated response must never be classified as `ValidZero`, even if no complete rows can be parsed.

If a 2xx body is truncated:

- parse complete records only when the parser can prove they are complete and structurally valid;
- keep those records as partial evidence;
- set explicit truncation/partial state;
- never infer absence from missing rows;
- never treat parser failure caused by truncation as a clean zero.

### 6.5 Provider envelope classification

Classify only provider-level envelope/status fields as auth/quota/rate-limit state. Do not search arbitrary result payload values for strings such as `invalid_api_key`, because leaked config data may legitimately contain them.

Required distinctions:

- `401` or provider `invalid_api_key` -> `AuthRejected`;
- `403` entitlement/plan denial -> `EntitlementDenied` unless response is independently classified as WAF/challenge;
- `429` with zero credit/daily-quota semantics -> `QuotaExhausted`;
- `429` burst throttle with credits remaining/ordinary rate-limit semantics -> `RateLimited`;
- `5xx` -> upstream unavailable/transient failure;
- challenge/WAF body -> `BotWaf`/existing source-outcome classification;
- malformed JSON or incompatible schema -> parser/schema drift;
- valid parsed zero rows -> `ValidZero`;
- valid positive rows -> `Success`.

Do not convert these distinctions into one generic `Error::Invalid` if the current source-outcome types can represent them more precisely.

### 6.6 Rate-limit headers

Capture when present:

- `X-RateLimit-Limit`;
- `X-RateLimit-Remaining`;
- `X-RateLimit-Reset`.

They are execution metadata, not evidence and not identity lineage.

## 7. Fast/deep orchestration

Fast and deep search are separate observations with separate response receipts.

Default algorithm:

1. Run fast `/search`.
2. If fast returns positive rows, retain them and stop the universal-search depth escalation for that selector.
3. If fast returns an authenticated, structurally valid, non-truncated `ValidZero`, run `/search/deep` once.
4. If fast returns auth, entitlement, quota, rate-limit exhaustion after bounded retries, transport failure, challenge, parser drift, schema drift, or truncation, do **not** reinterpret that condition as a zero and do not automatically spend a deep-search credit.
5. If deep succeeds, retain deep rows and both fast/deep execution receipts.
6. If fast valid-zero succeeds but deep fails, the overall collector result is partial/inconclusive, not an asserted absence.

A fast empty may be retried once only if a recorded differential/live fixture demonstrates the legacy server-side transient-empty behavior still exists. The retry is not assumed merely because `7dca720` documented it historically.

Transient 429/5xx/transport retries must use a bounded policy compatible with Termux resource limits. Retries reuse the logical operation budget and must not silently multiply paid credits beyond the explicit retry contract.

## 8. Selector planning

The first collector maps Huntsman selector kinds to SeekNow universal-search types:

| Huntsman selector | SeekNow type |
| --- | --- |
| `Email` | `email` |
| `Username` | `username` |
| `Phone` | `phone` |
| `IpAddress` | `ip` |
| `Domain` | `domain` |
| `Person` / name | auto-detect (`type` omitted) |

Unsupported selector kinds fail before any network request.

Normalize only through existing Huntsman canonicalization functions that do not destroy provider-relevant spelling. The request value and the evidence's raw provider spelling remain distinguishable from canonical entity values.

## 9. Normalized SeekNow row

The API is a federation and row schemas differ by upstream source. The L4 parser therefore retains a bounded normalized representation that separates provider metadata from potentially sensitive result fields.

Proposed shape:

```rust
pub struct SeekNowRow {
    pub upstream: SeekNowUpstream,
    pub fields: BTreeMap<String, SeekNowValue>,
    pub raw_source_index: Option<usize>,
}

pub struct SeekNowUpstream {
    pub source: Option<String>,
    pub database: Option<String>,
    pub breach: Option<String>,
    pub corpus: Option<String>,
    pub record_id: Option<String>,
}
```

The parser must enforce bounded field count, bounded string length for persisted attributes, and deterministic ordering. Oversized provider fields may be hashed/truncated for diagnostics but must never cause silent whole-record loss when useful bounded identity fields remain parseable.

The implementation must not surface plaintext passwords, authentication tokens, session cookies, API keys, or equivalent credential material into general entity pivots or ordinary CLI output. Such values may be represented only by non-secret metadata such as `credential_exposure_present=true`, field class, source corpus, and a cryptographic hash if later use requires stable deduplication. The first PR should prefer omission over inventing a credential-storage subsystem.

## 10. Evidence and provenance mapping

### 10.1 Collector vs upstream source

`seeknow` is the collector/provider aggregator. It is not automatically the independent upstream family for every row.

Evidence provenance must preserve enough fields to reconstruct:

- collector: SeekNow;
- endpoint/mode: fast or deep;
- provider response receipt/hash/time;
- upstream source/database/breach/corpus where the API supplies it;
- query kind without persisting secrets;
- row locator if provider supplies one;
- result fields used to create each entity.

### 10.2 Lineage family rule

Use the strongest explicit upstream identity supplied by the response, in this order unless fixtures show a better provider-native hierarchy:

1. `dataset` derived from an explicit breach/database/corpus identifier;
2. explicit independent `source` when no dataset/corpus identifier exists;
3. unattributed if the row does not expose a defensible upstream identity.

Do not synthesize a lineage family from:

- SeekNow collector name alone;
- fast vs deep mode;
- API hostname;
- record ID;
- row index;
- source URL;
- result count;
- query type;
- duplicate observations of the same dataset.

Two rows from the same named breach database count as one family even if one came from fast and one from deep. Two distinct upstream databases may count as separate families only when the provider explicitly identifies them as distinct origins and Huntsman's existing lineage rules accept those values.

### 10.3 Ambiguous provenance

If conflicting row fields claim different upstream families, mark lineage ambiguous rather than selecting whichever field yields more corroboration.

If provider metadata is absent, evidence remains usable but `Lineage::Unattributed`; it must not increase independent-family count.

## 11. Entity extraction

L5 `seeknow_collector` owns conversion from normalized rows to Huntsman entities.

Initial safe entity classes:

- Email;
- Username;
- Phone;
- IpAddress;
- Domain;
- Person/name when sufficiently structured;
- Organisation when explicitly labelled;
- Address/location when structurally valid and not merely a free-form leak blob;
- platform identifiers already represented by an existing `EntityKind`, if any.

Do not create password/token/cookie entities in the first slice.

Every entity generated from a row carries at least one evidence item with the original upstream family metadata. Deduplication by entity UID may merge entity shells, but evidence items from genuinely distinct upstream roots must remain separable.

Confidence values must come from existing HSE evidence/entity conventions or differential fixtures. Do not assign higher confidence merely because SeekNow returns many duplicate rows.

## 12. Collection result and source outcomes

The collector returns a `CollectionBatch` compatible with the shared collector design.

For SeekNow, the batch contains:

- entities;
- execution/observation receipts for credits/status only when explicitly requested, not on every search;
- fast/deep search receipts;
- source outcomes;
- typed pivots derived from safe entity fields;
- partial/truncation state.

Validated zero is an execution fact, not positive evidence. A zero-row result does not create an entity or a corroboration root.

## 13. Diagnostics

A small explicit diagnostic path is required before live evidence collection.

Recommended CLI surface:

```text
huntsman-recon seeknow status [--keys FILE]
huntsman-recon seeknow credits [--keys FILE]
huntsman-recon seeknow search KIND VALUE [--deep|--fast-only] [--keys FILE]
```

The CLI adapter calls the L5 collector/diagnostic adapter; it does not call L4 directly.

Output rules:

- never print the key or a key fingerprint;
- print HTTP/source outcome, mode, result count, truncation, and rate-limit metadata;
- raw result rows are not dumped wholesale;
- credential-like fields are redacted/omitted;
- positive entities print through existing stable entity rendering conventions where practical;
- validated zero must be visibly different from unavailable/auth-failed/partial.

Exit codes reuse current reconstructed conventions rather than inventing provider-specific codes:

- 64 usage;
- 65 invalid selector/data;
- 66 missing/unreadable credential input;
- 69 upstream unavailable/rate-limited/parser failure;
- 77 auth/entitlement/egress refusal where current CLI semantics already use that class.

Exact mapping must be pinned by CLI tests and architecture documentation.

## 14. Caching

No cross-scan shared positive-result cache is required in the first reconstruction PR.

Reason:

- current reconstruction already identifies response cache restoration as a separate partial capability;
- a new provider-local global cache would recreate the legacy cross-scan attribution hazard;
- correctness/provenance is higher value than avoiding a small number of paid requests until the shared cache boundary is restored.

Within one collector invocation, deduplicate identical `(mode, type, normalized-query)` operations so the same paid call is not issued twice.

When the shared response cache is later restored, its cache key must include source, endpoint/mode, query type, normalized query, and credential authority where required, and cache receipts must preserve the original observation time/response identity rather than pretending a cache hit is a fresh source observation.

## 15. Resource discipline

Termux is first-class.

Requirements:

- no async runtime;
- no background browser;
- bounded response body through existing transport cap;
- bounded result rows (`<=500` universal search request);
- bounded normalized fields per row;
- bounded persisted attribute length;
- bounded retry count;
- bounded deep-search escalation (maximum one deep call per universal-search selector in this slice);
- deterministic record/entity ordering before rendering/tests;
- preserve valid partial rows when one row is malformed, unless the provider envelope itself is unusable.

No new dependency should be added unless existing serde/HTTP primitives cannot implement the requirement correctly.

No `unsafe` code.

## 16. Differential verification

Before product implementation, capture recorded golden fixtures from legacy commit `7dca720` for at least:

- fast email search positive;
- fast username positive;
- fast domain/IP/phone positive where fixtures can be safely synthetic;
- auto/person query;
- fast validated zero;
- fast-zero -> deep-positive behavior if available in the oracle;
- transient rate limit;
- quota exhaustion;
- invalid key/plan denial;
- malformed/non-JSON provider output;
- duplicate rows from one upstream breach/database;
- rows containing provider-error-looking strings inside the leaked payload, proving they are not envelope failures.

Use synthetic/redacted fixtures. Do not commit real credentials, live passwords, tokens, cookies, or unnecessary third-party personal data.

Differential acceptance:

- every non-secret entity/value that legacy emitted from the fixture remains available unless a reviewed tightening intentionally removes unsafe credential material;
- no row gains a stronger lineage family than the response metadata supports;
- no result is silently truncated;
- intentional differences are documented beside the fixture.

## 17. Adversarial tests

The implementation must attempt to falsify the important claims.

Required tests include:

1. A result payload containing the string `invalid_api_key` does not disable the provider.
2. Two fast/deep rows from the same `database` remain one lineage family.
3. Ten duplicate rows do not increase family count or confidence as though ten independent sources existed.
4. Conflicting `database` and `breach` family values produce ambiguous lineage rather than whichever value maximizes confidence.
5. A truncated empty HTTP body cannot become `ValidZero`.
6. A malformed row beside valid rows does not erase the valid rows.
7. A malformed provider envelope cannot emit evidence.
8. A 403 challenge page is not mislabelled as an invalid API key.
9. A 429 burst throttle is not latched as daily quota exhaustion.
10. A final successful response with `credits_remaining=0` keeps its returned evidence; zero credits affect subsequent calls, not the data already paid for.
11. Missing key makes zero network requests.
12. Unsupported selector kind makes zero network requests.
13. Redirect or origin change never sends the key to another host.
14. Error text and debug output do not contain the configured key, key prefix/tail fingerprint, Authorization header, X-API-Key value, returned passwords, tokens, or cookies.
15. Unicode and confusable identity values do not panic and are passed through existing canonicalization rules.
16. Repeated execution on the same recorded response yields byte-stable normalized entity/evidence ordering.

## 18. Live verification

Offline tests prove parsing/contracts; they do not prove current API compatibility.

After offline gates pass and an operator-provided SeekNow API key is available, perform bounded live verification in this order:

1. `seeknow credits` — prove key acceptance and read current quota/plan metadata.
2. `seeknow status` — prove the API origin/status path.
3. Fast search for a neutral controlled identifier such as `example.com`, a synthetic domain if the provider accepts it, or an identifier the operator is authorized to investigate.
4. Only if fast is a validated zero, optionally run deep search for the same controlled identifier.

Record a live receipt containing:

- UTC time;
- commit SHA;
- endpoint/mode;
- request type but not the sensitive query value where unnecessary;
- HTTP/source outcome;
- response hash;
- result count;
- truncation flag;
- rate-limit metadata;
- CLI exit code.

Do not commit raw live response bodies containing breach data unless they are safely synthetic/redacted and explicitly suitable as fixtures.

CI must remain independent of live SeekNow availability and credentials.

## 19. Build and platform verification

Completion requires:

- `cargo fmt --check`;
- `cargo clippy --all-targets --locked -- -D warnings` on stable;
- `cargo test --locked` on stable;
- `cargo test --locked` on MSRV Rust 1.87;
- `cargo run --locked -- check` with no unintended artifact drift;
- architecture/documentation tests;
- secret scan on the branch diff;
- Android aarch64 release cross-build and ELF/linker verification using the repository's CI contract;
- no new socket-opening path;
- no `unsafe`.

## 20. Acceptance criteria

The first SeekNow reconstruction PR is complete only when all are true:

1. `seeknow` L4 client and `seeknow_collector` L5 adapter compile and are architecture-mapped.
2. The generic collector boundary is reused or introduced in a form compatible with the archive-collector design; no second competing collector trait exists.
3. All SeekNow HTTP operations pass through guarded `fetch` over an injected transport.
4. `HUNTSMAN_SEEKNOW_KEY` is loaded only through the reconstructed key system and is pinned to the intended origin.
5. `/credits`, `/status`, `/search`, and `/search/deep` have offline request/parser/outcome tests.
6. Email, username, phone, IP, domain, and person/name universal-search planning is implemented or explicitly rejected before network when Huntsman's current entity model cannot represent the selector.
7. Fast positive results stop unnecessary deep escalation; only validated fast zero may escalate to deep.
8. Auth, entitlement, rate-limit, quota, transport, WAF, parser/schema drift, truncation, valid zero, and success remain distinguishable.
9. Positive safe result fields become provenance-bearing HSE entities without exposing password/token/cookie material.
10. Explicit breach/database/corpus provenance survives into evidence and lineage; duplicate provider rows cannot manufacture independent corroboration.
11. A result with no defensible upstream family remains unattributed rather than using `seeknow` as a fabricated dataset.
12. Differential fixtures against `7dca720` cover the primary search semantics and document intentional tightenings.
13. Adversarial tests cover false auth markers in payloads, duplicate-family inflation, truncation, partial malformed input, and key leakage.
14. Full Rust/MSRV/static/architecture/secret-scan gates pass.
15. Android aarch64 build/ELF verification passes.
16. Live `/credits` and `/status` plus one bounded controlled search are demonstrated when a valid operator key is available; absent credentials are reported as the only live-verification blocker rather than pretending mocks prove the live API.

## 21. Deliberately deferred work

Not required for the first PR:

- full documented SeekNow endpoint matrix;
- stealer-log retrieval;
- Discord/Kurama Enterprise endpoints;
- gaming/platform-specific endpoints;
- direct password/token/cookie storage or display;
- browser/session automation;
- automatic multi-domain API fallback;
- global/persistent response cache;
- persistent key-pool rotation;
- recursive unified `scan` restoration beyond bounded typed pivots;
- web UI integration;
- asynchronous execution/runtime conversion.

These are follow-on slices only after the universal-search collector has passed differential, adversarial, platform, and live verification.

## 22. Strongest alternatives considered

### A. Port the whole legacy `util/see_know` tree

Rejected. It would restore obsolete curl-subprocess, global-budget/cache, old module-engine, fallback-domain, and async assumptions that conflict with the reconstruction. The legacy tree remains an oracle, not the architecture target.

### B. Add a direct `seeknow` CLI that calls L4

Rejected as the final design. It is faster as a temporary demo but creates the same binary->provider exception the architecture is trying to remove. The CLI should exercise the L5 collector instead.

### C. Browser/session automation when no API key exists

Rejected for the production reconstruction. The first-party REST API now exists and is the stronger, documented, lower-fragility interface. Browser automation would add Turnstile/session state, a heavier runtime, weaker determinism, and a wider credential/cookie boundary.

### D. Treat SeekNow as one independent source family

Rejected. SeekNow federates multiple upstream datasets/services. Collapsing all results to one family discards provenance; treating every returned row as independent manufactures corroboration. Explicit upstream dataset/source metadata must drive lineage where available.

### E. Deep search on every positive fast search

Rejected. It spends another credit and large latency without evidence that it improves the objective for every hit. The first slice escalates only from a validated fast zero.

## 23. Invalidation conditions

Revisit this design if implementation/live evidence proves any of the following:

- current first-party API authentication no longer accepts `X-API-Key`;
- `/search` and `/search/deep` response schemas cannot be normalized without losing material provenance;
- the provider no longer exposes defensible upstream dataset/source identifiers and therefore cannot support dataset-level lineage as designed;
- the reconstructed `fetch::Credential` abstraction cannot pin the key to the exact origin without a security regression;
- the shared collector contract from the archive work lands with materially different interfaces that are demonstrably superior;
- deep search demonstrably adds unique positive data after fast positive hits at a net value high enough to justify the extra credit/latency;
- the current 4 MiB transport cap routinely truncates useful universal-search responses such that a bounded streaming transport becomes necessary;
- Android aarch64 resource measurements show the normalized representation is too allocation-heavy;
- differential tests show an intentional legacy behavior omitted here is necessary for correctness rather than merely historical compatibility;
- first-party API documentation or live behavior materially changes the current endpoint, rate-limit, or auth contract.

When any invalidation condition fires, preserve the objective, evidence and security invariants and replace the affected mechanism rather than forcing this design.