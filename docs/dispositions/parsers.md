# Parsers disposition

Permanent legacy references: the two repo-root zip archives are pinned and were not touched. They remain the source reference for future rebuilds.

## Rebuilt in this area

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

Also touched for shared-owner cleanup only:
- `src/http.rs` query helper reuse
- `src/lib.rs` module registration

## Newly in scope after policy change

Rebuilt behind shared crate boundaries (`crate::http::{Request, Response, Transport}` and `fetch`) while keeping pure logic unit-testable:

- `util/service_defs/`
- `util/key_health/`
- `util/scraper_health.rs`
- `util/recon.rs`
- pure parts of `core/event/`
- pure metadata/economics parts of `core/module/`

Credentials are allowed, but artifacts/logs still keep fingerprint-only hygiene.

## File-by-file

| Legacy file | New module | Decision | Why |
| --- | --- | --- | --- |
| `util/dmarc/mod.rs` | `src/dmarc.rs` | REIMPLEMENT | Rebuilt pure DMARC parsing, defaults, issue detection, and report-target extraction. |
| `util/dmarc/tests.rs` | `src/dmarc.rs` tests | MERGED | Legacy behaviour restated as unit tests. |
| `util/spf/mod.rs` | `src/spf.rs` | REIMPLEMENT | Rebuilt pure SPF parsing, mechanism classification, lookup counting, CIDR matching, and policy checks. |
| `util/spf/tests.rs` | `src/spf.rs` tests | MERGED | Legacy parser/policy cases preserved in unit tests. |
| `util/tlsrpt/mod.rs` | `src/tlsrpt.rs` | REIMPLEMENT | Rebuilt pure TLSRPT parsing and report-destination extraction. |
| `util/tlsrpt/tests.rs` | `src/tlsrpt.rs` tests | MERGED | Rebuilt as unit coverage. |
| `util/xmp.rs` | — | PENDING | Still needs a fresh in-tree XMP parser. |
| `util/iptc.rs` | — | PENDING | Pure binary parsing is feasible, but not rebuilt in this pass. |
| `util/exif.rs` | — | PENDING | Legacy parsing depended on external EXIF support and file-oriented entry points not yet rebuilt here. |
| `util/gravatar/mod.rs` | — | PENDING | Still blocked on MD5 support in this crate. |
| `util/gravatar/tests.rs` | — | PENDING | Held with module rebuild. |
| `util/hashcat/mod.rs` | — | PENDING | Still depends on digest/format breadth not present here. |
| `util/hashcat/tests.rs` | — | PENDING | Held with module rebuild. |
| `util/surnames/mod.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as grouped pure surname helpers. |
| `util/surnames/tests.rs` | `src/signals.rs` tests | MERGED | Folded into grouped tests. |
| `util/sim_anonymity.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as pure classifier with tags/scores. |
| `util/circuit_breaker/mod.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt host-keyed breaker state machine. |
| `util/circuit_breaker/tests.rs` | `src/circuit.rs` tests | MERGED | Transition coverage moved into grouped tests. |
| `util/backoff.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt exponential backoff and jitter. |
| `util/scraper_health.rs` | `src/scraper_health.rs`, `src/event.rs` | REIMPLEMENT | Rebuilt drift aggregation, zero-yield drift, and quarantine TTL over pure event slices. |
| `util/response_cache/mod.rs` | `src/circuit.rs` | REIMPLEMENT | Rebuilt bounded generic cache. |
| `util/response_cache/tests.rs` | `src/circuit.rs` tests | MERGED | Cache behaviour folded into grouped tests. |
| `util/breach_sector/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt pure sector classifier and token parsing. |
| `util/breach_sector/tests.rs` | `src/breach.rs` tests | MERGED | Legacy examples preserved as tests. |
| `core/breach_consensus.rs` | — | NOT APPLICABLE | Still depends on monolith-only graph/entity orchestration. |
| `core/breach_platforms.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt shared breach platform helpers/constants. |
| `core/breach_sweep.rs` | — | NOT APPLICABLE | Still depends on monolith planner/runtime graph. |
| `core/stealer_row/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt row shape and password/combo classification. |
| `core/stealer_row/tests.rs` | `src/breach.rs` tests | MERGED | Rebuilt as unit coverage. |
| `core/data_broker/mod.rs` | `src/breach.rs` | REIMPLEMENT | Rebuilt host/domain to broker-name mapping. |
| `core/crypto/mod.rs` | `src/breach.rs` | PARTIAL | Rebuilt classification helpers only; broader digest surface remains out of scope here. |
| `util/key_fingerprint.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt fingerprint-only rendering helpers. |
| `util/key_health/mod.rs` | `src/key_health.rs`, `src/service_defs.rs` | REIMPLEMENT | Rebuilt auth-failure diagnosis over observed source health via shared service registry. |
| `util/key_health/tests.rs` | `src/key_health.rs` tests | MERGED | Legacy auth-failure/truncation cases restated. |
| `util/target_match/mod.rs` | — | PENDING | Still needs a fresh rebuild over current crate types. |
| `util/target_match/tests.rs` | — | PENDING | Held with module rebuild. |
| `util/extract/mod.rs` | — | PENDING | Legacy extraction was regex-heavy; no rebuild completed here. |
| `util/extract/tests.rs` | — | PENDING | Held with module rebuild. |
| `util/entity_extractor/mod.rs` | — | PENDING | Depends on monolith classifier/entity wiring and regex-heavy extraction. |
| `util/entity_extractor/classifier.rs` | — | PENDING | Depends on monolith classifier/entity wiring. |
| `util/entity_extractor/extractor.rs` | — | PENDING | Depends on tracing and monolith entity orchestration. |
| `util/entity_extractor/patterns.rs` | — | PENDING | Depends on regex-heavy pattern extraction. |
| `util/atproto.rs` | `src/atproto.rs` | REIMPLEMENT | Rebuilt pure handle/DID/platform helpers. |
| `util/mediawiki/mod.rs` | `src/mediawiki.rs` | REIMPLEMENT | Rebuilt MediaWiki 200-with-error envelope checker. |
| `util/mediawiki/tests.rs` | `src/mediawiki.rs` tests | MERGED | Legacy envelope cases restated as tests. |
| `util/ckan/mod.rs` | `src/ckan.rs` | REIMPLEMENT | Rebuilt CKAN envelope helpers and shared query encoding reuse. |
| `util/ckan/tests.rs` | `src/ckan.rs` tests | MERGED | Legacy success/error cases preserved as tests. |
| `util/service_defs/mod.rs` | `src/service_defs.rs` | REIMPLEMENT | Rebuilt keyed-provider registry, probe builder, response classifier, and evidence extractors on shared HTTP/fetch boundary. |
| `util/service_defs/tests.rs` | `src/service_defs.rs` tests | MERGED | Registry/probe-shape cases restated as unit tests. |
| `util/threat.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt as pure threat-tag filtering. |
| `util/freq/mod.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt deterministic top-N summarisation. |
| `util/freq/tests.rs` | `src/signals.rs` tests | MERGED | Folded into grouped helper tests. |
| `util/recon.rs` | `src/recon.rs` | REIMPLEMENT | Rebuilt host-key normalisation, deterministic ranking, and transport-ready lookup request builders. |
| `util/probe_confidence.rs` | `src/signals.rs` | REIMPLEMENT | Rebuilt shared `(confidence, verified)` helper. |
| `core/query_pack/mod.rs` | — | PENDING | Depends on monolith scan-target model/provider registry not yet exposed here. |
| `core/query_pack/tests.rs` | — | PENDING | Held with generator rebuild. |
| `core/event/mod.rs` | `src/event.rs`, `src/scraper_health.rs` | PARTIAL | Rebuilt pure event model, skip semantics, rendering, and outcome aggregation; async bus remains out of scope. |
| `core/event/tests.rs` | `src/event.rs` / `src/scraper_health.rs` tests | PARTIAL | Pure/logging and health aggregation rebuilt; async runtime bus tests not ported. |
| `core/module/mod.rs` | `src/module.rs` | PARTIAL | Rebuilt pure metadata, provider economics descriptors, environment-cost parsing, and conservative unknown-cost gating; async processing traits remain out of scope. |
| `core/module/provider.rs` | `src/module.rs` | PARTIAL | Merged into pure metadata/economics rebuild. |
| `core/module/provider_tests.rs` | `src/module.rs` tests | MERGED | Pure pricing/descriptor cases restated as unit tests. |
| `core/module/tests.rs` | `src/module.rs` tests | PARTIAL | Pure metadata tests rebuilt; runtime/context tests requiring async/runtime crates were not ported. |

## Notes

- `circuit::BreakerState` and `assurance::ControlState` are not duplicates: one is runtime request throttling state, the other is governance/control evidence state.
- Shared parsing cleanup moved duplicate record-tag parsing for DMARC/SPF into `src/signals.rs`.
- `key_health` now reuses the crate’s key hygiene path instead of inventing a separate fingerprint scheme.
