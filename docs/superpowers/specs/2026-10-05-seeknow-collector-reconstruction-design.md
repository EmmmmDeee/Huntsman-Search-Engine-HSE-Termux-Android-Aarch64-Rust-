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

- use the documented REST API at `https://see-know.ru/api/v1`;
- support authenticated `/credits`, `/status`, `POST /search`, and `POST /search/deep`;
- support universal-search planning for email, username, phone, IP, domain, and person/name selectors already representable by Huntsman's entity model;
- route every request through Huntsman's guarded `fetch` + injected `http::Transport` path;
- obtain the API key through `Keys::resolve`/`Keys::get("HUNTSMAN_SEEKNOW_KEY")`;
- never print, persist, log, place in evidence, or otherwise expose the key or its fingerprint through SeekNow-facing output;
- distinguish valid zero, missing/rejected auth, entitlement denial, quota exhaustion, transient rate limit, transport failure, challenge/WAF, truncation, schema/parser drift, and positive success;
- preserve provider-returned source/database/breach/corpus provenance instead of treating the collector as the upstream family;
- prevent duplicate rows or provider multiplexing from manufacturing independent corroboration;
- preserve `7dca720` behavior where it remains correct and intentionally tighten behavior where it conflicts with reconstructed invariants;
- remain safe Rust with no runtime LLM or async runtime;
- remain viable on Termux/Android aarch64.

## 2. Authoritative state and oracle

Implementation starts from `refactor/repository-reconstruction-2026-10-05` at `22be0defe24cdc04daf216cdb2dae358535f5c3c`, the strongest currently verified reconstruction state.

Legacy commit `7dca720` is the behavioral/capability oracle. `legacy/hse-monolith-v1.41.0/` remains a historical per-file reference only where `7dca720` lacks a path.

Retain, where current evidence still supports them:

- separate fast and deep universal-search paths;
- `limit=500` maximum-row requests;
- typed and auto-detect searches as distinct operations;
- fast-positive results do not require deep escalation;
- transient rate limiting is not quota exhaustion;
- provider failures are classified from the provider envelope, not arbitrary result payload text;
- failed/ambiguous empties are not cached or treated as clean zeroes.

Do not inherit as invariants:

- key fingerprints persisted into evidence;
- credential-bearing automatic fallback across multiple provider domains;
- non-JSON/truncated provider output treated as an ordinary empty;
- budget/key skips returned as `Ok(Vec::new())`;
- any behavior that makes execution failure indistinguishable from validated zero.

## 3. Collector-boundary compatibility

The archive-collector design already specifies the reusable flow:

```text
selector
  -> collector planning
  -> guarded fetch
  -> source parser
  -> normalized observation
  -> provenance-bearing evidence/entity
  -> lineage/resolution
  -> typed pivots
```

SeekNow must reuse that contract rather than create a competing abstraction.

If `collector.rs` lands first from archive work, SeekNow consumes it directly. If SeekNow lands first, it introduces only the minimal generic contract already specified by the archive design so the archive implementation can reuse it unchanged or with mechanical naming reconciliation.

`source_registry` remains discovery-only and is not the evidence-producing execution path.

## 4. Layer placement

No new numerical layer.

- **L4 `seeknow`**: request construction, authenticated guarded fetch, provider-envelope parsing, result-row normalization, status/credit interpretation.
- **L5 `collector`**: shared collector contracts if not already present.
- **L5 `seeknow_collector`**: selector planning, fast/deep orchestration, row-to-entity/evidence conversion, lineage-ready provenance, typed pivots, aggregate collection outcome.
- **Binary adapter**: `seeknow` diagnostics/search commands call L5, never L4 directly.

L4 must not depend on L5 entity types.

## 5. Network, credential, and redirect boundary

All network execution is:

```text
seeknow_collector -> seeknow -> fetch::fetch -> injected http::Transport
```

No direct `ureq`, `TcpStream`, curl subprocess, reqwest, shell, browser automation, or WebView path is added.

Built-in API base:

`https://see-know.ru/api/v1`

No automatic credential-bearing rotation to `.xyz`, `.eu`, `.icu`, `.vip`, or other mirrors. A future operator base override must pass the existing endpoint/origin safety policy and then take exclusive effect.

Credential slot:

`HUNTSMAN_SEEKNOW_KEY`

Authentication uses `X-API-Key` unless live first-party verification proves it incompatible. Build the credential through `AuthenticationAuthority::operator_approved` + `fetch::Credential::new(..., AuthStyle::Header("X-API-Key"))`, using the `Secret` returned by `Keys::get`.

The existing fetch layer internally derives `CredentialFingerprint` to record whether an approved credential was sent and to classify authenticated 401s. SeekNow must **not** copy that fingerprint into its CLI, evidence, receipts, logs, cache keys, or persisted state. Removing fingerprint derivation globally is outside this slice because it is an existing fetch-boundary contract, not a SeekNow-specific requirement.

SeekNow credential-bearing requests set `FetchOptions { max_redirects: 0 }` in the first implementation. Any later redirect support is security-sensitive and must prove no cross-origin key transfer, HTTP downgrade, userinfo authorization, or key reattachment after leaving the approved origin.

## 6. Generic outcome model extension

The current `SourceOutcomeKind` lacks two causal states required to distinguish SeekNow failures truthfully. Extend it provider-generically with:

```rust
EntitlementDenied,
QuotaExhausted,
```

Semantics:

- `EntitlementDenied`: credentials were accepted/recognized but the account/plan is not authorized for the requested operation.
- `QuotaExhausted`: credentials are valid but the account's current credit/daily allowance is exhausted until the provider reset condition.

Update generic helpers:

- both are non-accepted outcomes;
- `EntitlementDenied` is non-retryable without an account/plan change and maps to an operator/investigate action, not `RequireCredential`;
- `QuotaExhausted` is non-immediately-retryable and maps to backoff/await-reset semantics;
- `RateLimited` remains the transient throttle state;
- architecture and source-outcome tests pin the distinction.

Do not encode entitlement or quota only in free-form `detail`; the type system must preserve the causal distinction.

## 7. L4 SeekNow client

### 7.1 Typed surface

Use typed request/result structures at the collector boundary.

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

`credits` and `status` use typed result structures but may retain bounded unknown scalar fields for forward compatibility.

### 7.2 First-slice endpoints

Implement only:

- `GET /credits`;
- `GET /status`;
- `POST /search`;
- `POST /search/deep`.

Defer Discord, gaming, stealer, social-history, WHOIS/domain-intel, platform fanout, and Enterprise/Kurama endpoints.

### 7.3 Request construction

Universal-search JSON is produced with `serde_json`, never manual escaping:

```json
{"query":"<value>","type":"<type>","limit":500}
```

For `Auto`, omit `type`.

Clamp explicit limits to `1..=500`. The production collector requests `500` unless an explicit collection limit is smaller.

### 7.4 Response bounds and truncation

The current `http::Response` body cap remains the outer memory bound.

A truncated response can never become `ValidZero`.

If a truncated 2xx body contains provably complete valid rows, retain those rows as partial evidence and mark truncation. Otherwise report parser/truncation failure. Missing rows from a truncated body never imply absence.

### 7.5 Provider-envelope classification

Inspect HTTP status plus provider-level `error`, `message`, success/credit fields. Never scan arbitrary result fields for provider-failure strings.

Required mapping:

- missing key before request -> command/collector missing-credential state, zero requests;
- 401 or provider `invalid_api_key` -> `AuthRejected` when a credential was sent;
- recognized credential + `plan_required`/equivalent -> `EntitlementDenied`;
- 429 or error envelope proving zero daily/credit allowance -> `QuotaExhausted`;
- ordinary 429 throttle / `rate_limit` without exhausted credits -> `RateLimited`;
- 5xx -> `Upstream5xx`;
- challenge body at any status -> `BotWaf`;
- malformed JSON -> `ParserDrift`;
- structurally valid but incompatible envelope -> `SchemaDrift`/`ProtocolDrift` as appropriate;
- valid parsed zero rows -> `ValidZero`;
- positive valid rows -> `Success`.

A successful response that spent the last credit (`success=true`, positive rows, `credits_remaining=0`) remains `Success`; its evidence is not discarded. Only subsequent exhausted calls classify as `QuotaExhausted`.

Capture `X-RateLimit-Limit`, `X-RateLimit-Remaining`, and `X-RateLimit-Reset` when present. They are execution metadata, never identity evidence.

## 8. Fast/deep orchestration

Fast and deep are separate observations/receipts.

1. Run `/search`.
2. Positive fast rows: retain and stop depth escalation.
3. Authenticated, structurally valid, non-truncated fast `ValidZero`: run `/search/deep` once.
4. Auth, entitlement, quota, rate-limit exhaustion after bounded retries, transport failure, WAF, parser/schema drift, or truncation: do not reinterpret as zero and do not spend a deep-search credit automatically.
5. Deep positive/zero retains both fast and deep execution receipts.
6. Fast valid-zero followed by deep failure is partial/inconclusive, not evidence of absence.

Do not preserve the legacy fast-empty retry unless a current live/recorded test reproduces the transient-empty behavior. If reproduced, one bounded retry is allowed and must be separately observable in the receipt.

Transient retries are bounded and cannot silently multiply paid requests beyond the explicit retry contract.

## 9. Selector planning

| Huntsman selector | SeekNow type |
| --- | --- |
| `Email` | `email` |
| `Username` | `username` |
| `Phone` | `phone` |
| `IpAddress` | `ip` |
| `Domain` | `domain` |
| `Person` | auto-detect; omit `type` |

Unsupported kinds fail before network execution.

Use existing canonicalization to validate/canonicalize selectors, while retaining raw spelling separately where evidence rendering needs it.

## 10. Normalized result rows

SeekNow federates upstream datasets with heterogeneous schemas. L4 keeps a bounded normalized row representation:

```rust
pub struct SeekNowRow {
    pub upstream: SeekNowUpstream,
    pub fields: BTreeMap<String, SeekNowValue>,
    pub raw_source_index: Option<usize>,
}

pub struct SeekNowUpstream {
    pub dbname: Vec<String>,
    pub breach: Vec<String>,
    pub source_db: Vec<String>,
    pub database_name: Vec<String>,
    pub dataset: Vec<String>,
    pub source: Vec<String>,
    pub record_id: Option<String>,
}
```

The field names deliberately align with `lineage::LINEAGE_FIELDS`. Preserve multiple values so ambiguity is visible rather than overwritten.

Bound:

- number of normalized fields per row;
- persisted string length;
- number of rows (`<=500` requested per universal call);
- diagnostic snippets.

Oversized nonessential fields can be omitted with explicit truncation metadata; a useful bounded identity field must not be silently dropped because an unrelated blob is huge.

Credential-like values returned by breach data—passwords, session tokens, cookies, API keys, authentication headers—are **not** general pivots and are not printed by default. The first slice records only exposure metadata such as credential-field presence/type when useful. It does not create a credential vault.

## 11. Provenance and lineage

`seeknow` is the collector, not the independent upstream origin.

Each evidence item retains:

- collector `seeknow`;
- endpoint/mode (`fast`/`deep`);
- observation time and response hash;
- provider-returned `dbname`/`breach`/`source_db`/`database_name`/`dataset` values;
- non-counting `source`, `record_id`, and row locator metadata where useful;
- bounded source fields that materially support the emitted entity.

Do not invent a new lineage precedence rule in `seeknow_collector`; use `Lineage::of` and its existing precedence:

`dbname -> breach -> source_db -> database_name -> dataset`.

If the deciding field has multiple distinct families, `Lineage::Ambiguous` is required. If no admissible dataset field is present, the observation is `Unattributed`. Provider `source` alone remains non-counting under the current lineage contract and must not be promoted just to increase corroboration.

Fast/deep mode, API hostname, record ID, row index, source URL, query type, collector name, or duplicate observations never create an independent family.

## 12. Entity extraction

L5 `seeknow_collector` maps normalized safe fields to existing `EntityKind`s.

Initial classes:

- Email;
- Username;
- Phone;
- IpAddress;
- Domain;
- Person when structurally labelled/validated;
- Organisation when explicitly labelled;
- Address when structurally valid and not merely an unbounded free-form blob;
- existing platform/device identifiers only when their current `EntityKind` and canonicalizer fit the value.

Do not create Password, Cookie, SessionToken, or arbitrary secret entities in this slice. Existing `Credential`/`ApiKey` entity kinds are not used for raw SeekNow secret values.

Deduplication may merge entity shells by UID, but evidence observations and distinct upstream roots remain separable.

Confidence comes from existing HSE conventions/differential evidence, never result count.

## 13. CLI and diagnostics

Recommended surface:

```text
huntsman-recon seeknow status [--keys FILE]
huntsman-recon seeknow credits [--keys FILE]
huntsman-recon seeknow search KIND VALUE [--deep|--fast-only] [--keys FILE]
```

All three call L5 adapters, not L4 directly.

Output includes outcome, mode, safe result count, truncation, and rate-limit metadata. It never dumps raw rows wholesale and never prints a key or credential fingerprint.

Validated zero must be visibly different from unavailable/auth-failed/partial.

Reuse current exit classes:

- 64 usage;
- 65 invalid selector/data;
- 66 missing/unreadable credential input;
- 69 upstream unavailable/rate-limited/parser failure/quota exhaustion;
- 77 auth rejection, entitlement denial, or egress refusal.

Pin exact mapping in CLI tests and README/architecture docs.

## 14. Cache policy

Do not add a provider-local cross-scan global cache in the first PR.

Within one collector invocation, deduplicate identical `(mode, query_type, canonical_query)` operations so the same paid call is not issued twice.

A later shared cache must include source, endpoint/mode, type, normalized query, and appropriate credential authority in its key, and must preserve the original observation identity/time rather than making a cache hit look fresh.

## 15. Termux/resource requirements

- no async runtime;
- no browser runtime;
- existing bounded HTTP body cap;
- <=500 requested universal rows per call;
- bounded row fields and attribute lengths;
- bounded retry count;
- at most one deep escalation per selector in this slice;
- deterministic ordering before rendering and fixture comparison;
- malformed neighbor rows do not erase valid rows unless the envelope is unusable;
- no new dependency unless existing serde/HTTP primitives are demonstrably insufficient;
- no `unsafe`.

## 16. Differential verification

Capture sanitized golden fixtures from `7dca720` before implementation for the strongest available subset of:

- positive fast email;
- positive fast username;
- phone/IP/domain positive cases using synthetic fixture content;
- auto/person query;
- valid fast zero;
- fast-zero/deep-positive if reproducible;
- transient rate limit;
- quota exhaustion;
- invalid key;
- plan/entitlement denial;
- malformed/non-JSON response;
- duplicate rows from one upstream database;
- payload text containing `invalid_api_key` that is not a provider envelope failure.

No fixture may contain a real API key, live password/token/cookie, or unnecessary third-party PII.

Differential acceptance:

- safe non-secret entities legacy emitted remain represented unless a documented tightening removes them;
- no result gains stronger lineage than response metadata permits;
- no result is silently truncated;
- every intentional difference is documented with the fixture.

## 17. Adversarial falsification

Tests must prove:

1. Payload string `invalid_api_key` does not disable the provider.
2. Fast/deep rows from one `database` remain one lineage family.
3. Duplicate rows cannot increase independent-family count as though independent sources existed.
4. Multiple values in one deciding lineage field become `Ambiguous`.
5. A truncated empty response cannot become `ValidZero`.
6. Malformed neighbor rows do not erase valid rows.
7. Malformed provider envelope emits no evidence.
8. 403 challenge page is `BotWaf`, not auth rejection.
9. Transient 429 is not quota exhaustion.
10. Positive response with `credits_remaining=0` retains evidence.
11. Missing key sends zero requests.
12. Unsupported selector sends zero requests.
13. Redirect/origin change cannot transfer the key.
14. SeekNow-facing errors/output contain neither key nor credential fingerprint nor returned passwords/tokens/cookies.
15. Unicode/confusable identity input cannot panic and is handled by existing canonicalizers.
16. Same recorded input produces deterministic normalized ordering.
17. `EntitlementDenied`, `QuotaExhausted`, and `RateLimited` remain distinct through serialization and health-action mapping.

## 18. Live verification

Offline tests do not prove current API compatibility.

When a valid operator SeekNow key is available, verify in order:

1. `seeknow credits`;
2. `seeknow status`;
3. fast search using a neutral/controlled authorized identifier;
4. deep only if fast is a validated zero or an explicit operator test requests it.

Record a receipt with UTC time, commit SHA, endpoint/mode, query kind (not sensitive value unless needed), outcome, response hash, safe result count, truncation, rate-limit metadata, and exit code.

Do not commit raw live breach bodies containing sensitive data.

CI never depends on live credentials/network availability.

## 19. Build/platform gate

Completion requires:

- `cargo fmt --check`;
- `cargo clippy --all-targets --locked -- -D warnings` on stable;
- `cargo test --locked` on stable;
- `cargo test --locked` on Rust 1.87;
- `cargo run --locked -- check` with no unintended artifact drift;
- architecture/documentation tests;
- branch-diff secret scan;
- Android aarch64 release cross-build and ELF/linker verification matching repository CI;
- no new socket-opening path;
- no `unsafe`.

## 20. Acceptance criteria

The first SeekNow reconstruction PR is complete only when:

1. `seeknow` L4 and `seeknow_collector` L5 compile and are architecture-mapped.
2. The shared collector boundary is reused or introduced compatibly with the archive-collector design; no second collector trait exists.
3. All HTTP operations pass through guarded `fetch` over injected transport.
4. `HUNTSMAN_SEEKNOW_KEY` comes only from the reconstructed keys system and is origin-bound through `Credential`.
5. SeekNow output/evidence/logging never exposes the key or its fingerprint.
6. `EntitlementDenied` and `QuotaExhausted` are added as provider-generic typed outcomes and remain distinct from `AuthRejected` and `RateLimited`.
7. `/credits`, `/status`, `/search`, and `/search/deep` have offline request/parser/outcome tests.
8. Email, username, phone, IP, domain, and person universal planning is implemented or rejected before network if unsupported by current canonicalization.
9. Fast positive stops deep; only validated fast zero automatically escalates.
10. Auth, entitlement, quota, transient rate limit, transport, WAF, parser/schema drift, truncation, valid zero, and success remain causally distinct.
11. Safe positive fields become provenance-bearing entities without raw credential material.
12. Existing `Lineage::of` derives upstream family from explicit dataset fields; duplicates cannot manufacture corroboration; absent dataset provenance stays unattributed.
13. Differential fixtures against `7dca720` cover primary search semantics and documented tightenings.
14. Adversarial tests cover false auth markers, duplicate-family inflation, truncation, malformed partial input, redirect credential isolation, and secret/fingerprint leakage.
15. Full static/test/MSRV/architecture/secret gates pass.
16. Android aarch64 build/ELF verification passes.
17. Live `/credits`, `/status`, and one bounded controlled search pass when a valid key is available; absent credentials remain a declared external blocker rather than being hidden by mocks.

## 21. Deferred work

- full SeekNow endpoint matrix;
- stealer-log retrieval;
- Enterprise/Kurama Discord endpoints;
- gaming/platform-specific endpoints;
- raw password/token/cookie storage or display;
- browser/session automation;
- automatic multi-domain API fallback;
- global response cache;
- persistent key-pool rotation;
- full recursive `scan` orchestration;
- web UI integration;
- async runtime conversion.

## 22. Alternatives rejected

**Port the entire legacy SeekNow tree:** rejected because it restores curl subprocesses, async/global-budget/cache assumptions, fallback-domain behavior, and old module-engine coupling.

**Direct binary-to-L4 SeekNow CLI:** rejected as the final design because it creates another architecture exception instead of restoring the collector boundary.

**Browser/session automation without API key:** rejected because the documented REST API is lower-fragility, deterministic, and materially safer to test and operate.

**Treat SeekNow as one upstream family:** rejected because it discards provider-reported dataset provenance.

**Treat every row/source label as independent:** rejected because it manufactures corroboration.

**Deep after every fast positive:** rejected because it adds paid latency without demonstrated universal decision value.

## 23. Invalidation conditions

Revisit the affected mechanism if evidence shows:

- `X-API-Key` is no longer accepted;
- response schemas cannot preserve material provenance in a bounded normalized form;
- no defensible upstream dataset fields are available;
- `fetch::Credential` cannot enforce the required origin boundary;
- the archive collector lands a materially superior shared collector interface;
- live evidence demonstrates high-value unique deep results after fast positives sufficient to justify changing escalation policy;
- the 4 MiB transport cap routinely destroys useful responses and bounded streaming becomes necessary;
- Android aarch64 measurements show the row representation is too allocation-heavy;
- differential tests demonstrate an omitted legacy behavior is necessary for correctness;
- first-party API behavior materially changes.

Preserve the objective and evidence/security invariants and replace only the invalidated mechanism.