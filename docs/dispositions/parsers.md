# Parsers disposition

## Rebuilt in this pass

- `src/atproto.rs`
- `src/breach.rs`
- `src/circuit.rs`
- `src/ckan.rs`
- `src/dmarc.rs`
- `src/event.rs`
- `src/key_health.rs`
- `src/mediawiki.rs`
- `src/module.rs`
- `src/recon.rs`
- `src/scraper_health.rs`
- `src/service_defs.rs`
- `src/signals.rs`
- `src/spf.rs`
- `src/tlsrpt.rs`
- `src/http.rs` (shared query helper only)
- `src/lib.rs` (module registration only)

No changes were needed in `src/sha256.rs`, `src/redact.rs`, `src/credential_origin.rs`, or `src/source_outcome.rs` for this pass; where broader legacy behaviour would need them to change, that work remains outside my ownership.

## Newly in scope after the policy change

The policy change made the runtime-facing parts of my area newly in scope, provided the pure logic stayed separately testable and the I/O boundary used the shared crate HTTP types. I rebuilt these areas around `crate::http::{Request, Response, Transport}`:

- `util/service_defs/`
- `util/key_health/`
- `util/scraper_health.rs`
- `util/recon.rs`
- pure parts of `core/event/`
- pure metadata/economics parts of `core/module/`

Credential hygiene stayed intact: request planning may carry real keys, but logs, assertions, and report artifacts must not expose secret values.

## File-by-file

| Legacy file | New module | Decision | Why |
| --- | --- | --- | --- |
| `util/dmarc/mod.rs` | `src/dmarc.rs` | REIMPLEMENT | Rebuilt pure DMARC parsing, defaults, issue detection, and aggregate-report target extraction. |
| `util/dmarc/tests.rs` | `src/dmarc.rs` tests | MERGED | Legacy behaviour was restated as unit coverage. |
| `util/spf/mod.rs` | `src/spf.rs` | REIMPLEMENT | Rebuilt pure SPF parsing, mechanism classification, lookup counting, and policy checks. |
| `util/spf/tests.rs` | `src/spf.rs` tests | MERGED | Legacy parser/policy cases were folded into module tests. |
| `util/tlsrpt/mod.rs` | `src/tlsrpt.rs` | REIMPLEMENT | Rebuilt pure TLSRPT parsing and report-destination extraction. |
| `util/tlsrpt/tests.rs` | `src/tlsrpt.rs` tests | MERGED | Rebuilt as unit coverage in the new module. |
| `util/xmp.rs` | — | PENDING | Still needs a fresh in-tree XMP parser; the legacy version depended on helpers/crates not present here. |
| `util/iptc.rs` | — | PENDING | Pure binary parsing is feasible, but not rebuilt in this pass. |
| `util/exif.rs` | — | PENDING | Legacy parsing depended on an external EXIF crate and path/file-oriented entry points not present here. |
| `util/gravatar/mod.rs` | — | PENDING | Still blocked on MD5 support, which this crate does not provide. |
| `util/gravatar/tests.rs` | — | PENDING | Held with the module rebuild. |
| `util/hashcat/mod.rs` | — | PENDING | Still depends on digest coverage and format breadth not present in this crate. |
| `util/hashcat/tests.rs` | — | PENDING | Held with the module rebuild. |
| `util/surnames/mod.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as grouped pure surname helpers. |
| `util/surnames/tests.rs` | `src/signals.rs` tests | MERGED | Folded into grouped tests. |
| `util/sim_anonymity.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as a pure classifier with tags and score helpers. |
| `util/circuit_breaker/mod.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt the host-keyed breaker state machine using only `std` sync primitives. |
| `util/circuit_breaker/tests.rs` | `src/circuit.rs` tests | MERGED | Breaker transition coverage moved into the grouped module tests. |
| `util/backoff.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt exponential backoff policy and deterministic jitter. |
| `util/scraper_health.rs` | `src/scraper_health.rs`, `src/event.rs` | REIMPLEMENT | Newly in scope. Rebuilt source drift aggregation, zero-yield drift, and quarantine TTL over pure event slices. |
| `util/response_cache/mod.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt as a bounded generic cache with `OnceLock` + `Mutex`. |
| `util/response_cache/tests.rs` | `src/circuit.rs` tests | MERGED | Capacity and eviction coverage moved into grouped tests. |
| `util/breach_sector/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt the pure sector classifier and token parsing. |
| `util/breach_sector/tests.rs` | `src/breach.rs` tests | MERGED | Legacy examples were preserved as unit tests. |
| `core/breach_consensus.rs` | — | NOT APPLICABLE | Still depends on monolith-only graph/entity orchestration, not just transport availability. |
| `core/breach_platforms.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt shared breach social-platform helpers/constants. |
| `core/breach_sweep.rs` | — | NOT APPLICABLE | Still depends on the monolith planner/runtime graph, not a missing HTTP layer. |
| `core/stealer_row/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt serialisable row shape and password/combo classification. |
| `core/stealer_row/tests.rs` | `src/breach.rs` tests | MERGED | Rebuilt as unit coverage. |
| `core/data_broker/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt pure host/domain to broker-name mapping. |
| `core/crypto/mod.rs` | `src/breach.rs` | PARTIAL | Rebuilt classification helpers only; the broader digest surface is still outside current crate support. |
| `util/key_fingerprint.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as fingerprint-only rendering helpers. |
| `util/key_health/mod.rs` | `src/key_health.rs`, `src/service_defs.rs` | REIMPLEMENT | Newly in scope. Rebuilt auth-failure diagnosis over observed source health using the shared service registry. |
| `util/key_health/tests.rs` | `src/key_health.rs` tests | MERGED | Legacy auth-failure and truncation cases were restated as unit tests. |
| `util/target_match/mod.rs` | — | PENDING | Still needs a fresh extraction/matching rebuild over the current crate types. |
| `util/target_match/tests.rs` | — | PENDING | Held with the module rebuild. |
| `util/extract/mod.rs` | — | PENDING | Legacy extraction was regex-heavy; no equivalent rebuild was completed here. |
| `util/extract/tests.rs` | — | PENDING | Held with the module rebuild. |
| `util/entity_extractor/mod.rs` | — | PENDING | Depends on monolith classifier/entity wiring and regex-heavy extraction logic. |
| `util/entity_extractor/classifier.rs` | — | PENDING | Depends on monolith classifier/entity wiring. |
| `util/entity_extractor/extractor.rs` | — | PENDING | Depends on tracing and monolith entity orchestration. |
| `util/entity_extractor/patterns.rs` | — | PENDING | Depends on regex-heavy pattern extraction. |
| `util/atproto.rs` | `src/atproto.rs` | REIMPLEMENT | Rebuilt pure handle/DID/platform helpers directly. |
| `util/mediawiki/mod.rs` | `src/mediawiki.rs` | REIMPLEMENT | Rebuilt the MediaWiki HTTP-200 error-envelope checker against this crate's error model. |
| `util/mediawiki/tests.rs` | `src/mediawiki.rs` tests | MERGED | Legacy envelope cases were restated as module tests. |
| `util/ckan/mod.rs` | `src/ckan.rs` | REIMPLEMENT | Rebuilt CKAN envelope helpers and now reuses the shared HTTP query-encoding helper. |
| `util/ckan/tests.rs` | `src/ckan.rs` tests | MERGED | Legacy success/error envelope cases were preserved as tests. |
| `util/service_defs/mod.rs` | `src/service_defs.rs` | REIMPLEMENT | Newly in scope. Rebuilt keyed-provider registry, probe request builder, response classifier, and small evidence extractors on top of `crate::http::{Request, Response, Transport}`. |
| `util/service_defs/tests.rs` | `src/service_defs.rs` tests | MERGED | Important registry/probe-shape cases were restated as unit tests. |
| `util/threat.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as pure threat-tag filtering. |
| `util/freq/mod.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as deterministic top-N frequency summarisation. |
| `util/freq/tests.rs` | `src/signals.rs` tests | MERGED | Folded into grouped helper tests. |
| `util/recon.rs` | `src/recon.rs` | REIMPLEMENT | Newly in scope. Rebuilt host-key normalisation, deterministic ranking, and transport-ready lookup request builders using the shared HTTP types. |
| `util/probe_confidence.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as a shared `(confidence, verified)` helper. |
| `core/query_pack/mod.rs` | — | PENDING | Depends on the monolith scan target model and provider registry not yet exposed here. |
| `core/query_pack/tests.rs` | — | PENDING | Held with the generator rebuild. |
| `core/event/mod.rs` | `src/event.rs`, `src/scraper_health.rs` | PARTIAL | Newly in scope. Rebuilt the pure event data model, skip semantics, rendering, and outcome aggregation; the async broadcast bus remains out of scope for this crate. |
| `core/event/tests.rs` | `src/event.rs` / `src/scraper_health.rs` tests | PARTIAL | Pure/logging and health-aggregation coverage was rebuilt; async runtime bus tests were not ported. |
| `core/module/mod.rs` | `src/module.rs` | PARTIAL | Newly in scope. Rebuilt pure metadata, provider economics descriptors, environment-cost parsing, and conservative unknown-cost gating; async processing traits remain out of scope. |
| `core/module/provider.rs` | `src/module.rs` | PARTIAL | Merged into the pure metadata/economics rebuild. |
| `core/module/provider_tests.rs` | `src/module.rs` tests | MERGED | Pure pricing/descriptor cases were restated as unit tests. |
| `core/module/tests.rs` | `src/module.rs` tests | PARTIAL | Pure metadata tests were rebuilt; runtime/context tests that require async/runtime crates were not ported. |

## Notes

- `src/http.rs` gained the shared query-parameter helper so CKAN/recon/service request builders could reuse a single owner instead of duplicating URL-encoding logic.
- `src/service_defs.rs` uses the shared request/response/transport boundary directly; no duplicate mini-HTTP layer remains.
- Credential handling remains hygiene-safe: requests may carry real keys, but debug output, tests, and this report never record raw secret values.
