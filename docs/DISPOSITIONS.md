# Legacy dispositions

Every legacy file is accounted for per area (rebuilt, merged, or pending). Evidence source: `legacy/`. Do not delete the archives or `legacy/`.

<!-- attack.md -->
# attack disposition

| Legacy path | Lines | Decision | New module | Defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/core/attack/mod.rs` | 4833 | REBUILT | `src/attack.rs`, `src/attack_catalog.rs`, `src/navigator.rs` | ATT&CK catalog and recon mappings were rebuilt for the current crate; the large catalog was mechanically extracted from legacy and pinned with uniqueness, id-shape, sort-order, tactic-reference, and TA0043 slice tests so no binding is inferred from vocabulary alone. |
| `src/core/attack/tests.rs` | 702 | MERGED | `src/attack.rs`, `src/navigator.rs` tests | Legacy ATT&CK and Navigator expectations were folded into current unit tests instead of kept as a parallel test module. |
| `src/core/diamond.rs` | 259 | REBUILT | `src/diamond.rs` | Pure Diamond Model classification/grouping fit the crate contract and was rebuilt against current `recon` entities and relations. |
| `src/core/dependency/mod.rs` | 442 | REBUILT | `src/dependency.rs` | Module graph, producer/consumer indexing, summaries, and human-seed wiring checks were rebuilt as pure graph logic. |
| `src/core/dependency/reachability.rs` | 227 | REBUILT | `src/dependency.rs` | Reachability and dead-module analysis were merged into the rebuilt dependency graph instead of kept as a split submodule. |
| `src/core/dependency/tests.rs` | 600 | MERGED | `src/dependency.rs` tests | Legacy dependency expectations were ported as in-module tests for the rebuilt graph and reachability helpers. |
| `src/core/assurance/catalog.rs` | 375 | REBUILT | `src/assurance.rs` | Assurance catalog/profile data is pure and was consolidated into one assurance module. |
| `src/core/assurance/continuity.rs` | 512 | REBUILT | `src/assurance.rs` | Continuity objectives, state derivation, summary logic, and the newly in-scope source-tree scan were rebuilt; recovery-test verification is now split into pure missing-test detection plus a `SourceTree`/`FsSourceTree` I/O boundary that scans current `src/` and `tests/`. |
| `src/core/assurance/derive.rs` | 129 | REBUILT | `src/assurance.rs` | Assurance level/state derivation was rebuilt and exercised with differential ladder tests. |
| `src/core/assurance/gap.rs` | 160 | REBUILT | `src/assurance.rs` | Assurance gap severity and warnings were folded into the rebuilt assurance model. |
| `src/core/assurance/mod.rs` | 272 | REBUILT | `src/assurance.rs` | Public assurance API was reconstructed as one crate-local module. |
| `src/core/assurance/model.rs` | 423 | REBUILT | `src/assurance.rs` | Assurance enums, evidence model, applicability, verification, and summaries were rebuilt for the current crate. |
| `src/core/assurance/tests.rs` | 531 | MERGED | `src/assurance.rs` tests | Legacy assurance examples were carried over as current unit tests and continuity checks. |
| `src/core/benchmark/mod.rs` | 228 | REBUILT | `src/benchmark.rs` | Benchmark reporting was rebuilt over current metrics, coverage, graph, and scan-record primitives. |
| `src/core/benchmark/tests.rs` | 203 | MERGED | `src/benchmark.rs` tests | Legacy benchmark expectations were ported into in-module tests. |
| `src/core/roi/mod.rs` | 146 | REBUILT | `src/roi.rs` | Saturation, cutoff, and adaptive termination logic were rebuilt as pure scoring helpers. |
| `src/core/roi/tests.rs` | 103 | MERGED | `src/roi.rs` tests | Legacy ROI examples were folded into current unit tests. |
| `src/core/roi/utility.rs` | 406 | REBUILT | `src/roi.rs` | Dispatch-utility scoring and rationale emission were rebuilt in one module. |
| `src/core/roi/utility_tests.rs` | 327 | MERGED | `src/roi.rs` tests | Utility expectations were ported as current tests instead of kept as a parallel file. |
| `src/core/gap/mod.rs` | 233 | REBUILT | `src/gap.rs` | Gap/orphan/null-state analysis was rebuilt over current entity/relation graph types. |
| `src/core/gap/tests.rs` | 126 | MERGED | `src/gap.rs` tests | Legacy gap cases were merged into in-module tests. |
| `src/core/coverage.rs` | 571 | REBUILT | `src/coverage.rs`, `src/benchmark.rs` | Provider coverage/event rollups were rebuilt and benchmark comparability caveats now derive from current event coverage verdicts. |
| `src/core/metrics/mod.rs` | 476 | REBUILT | `src/metrics.rs` | Scan metrics, density, degeneracy/core size, corroboration, and seed reach were rebuilt for current graph/entity types. |
| `src/core/metrics/tests.rs` | 349 | MERGED | `src/metrics.rs` tests | Legacy metrics expectations were ported and extended with order-independence checks. |
| `src/core/trust/mod.rs` | 276 | REBUILT | `src/trust.rs` | Damped trust propagation was rebuilt as deterministic graph logic. |
| `src/core/trust/tests.rs` | 271 | MERGED | `src/trust.rs` tests | Legacy trust cases were folded into current unit tests. |

## Notes

- `src/ledger.rs` was not edited. If the parent wants new ATT&CK bindings later, they must still be added explicitly there; nothing in the rebuilt catalog infers evidence.
- `src/stix.rs` and `src/eval/*` were reviewed for overlap. No code change was required in this pass.
- `src/attack_catalog.rs` was generated mechanically from legacy `src/core/attack/mod.rs` in this working copy, then validated by tests. It was not hand-retyped.
- Policy-change review: no assigned legacy file in this area had been marked NOT APPLICABLE solely because of network or credentials. The one omitted I/O-bound legacy behavior was `assurance/continuity.rs` source-tree scanning; it is now rebuilt behind `SourceTree`/`FsSourceTree`, with unit tests using a fake tree and no live network added in this area.

<!-- entity.md -->
Implemented the entity/evidence-core slice directly in the repo build and refactored it onto shared owners instead of adding parallel helpers.

What changed:
- Expanded `src/intelligence.rs` into a claim/evidence/inference/provider ledger while keeping the aggregate report API.
- Replaced the minimal `src/cross_scan.rs` history summary with a bridge-analysis model using the shared repo types and an injected `CrossScanStore` boundary.
- Kept provenance mandatory on evidence through the entity model and preserved secret hygiene by storing provider credential fingerprints only.
- Used the shared HTTP boundary already present in the repo (`crate::http::{Request, Response, Transport}`) and did not introduce duplicate request/response types.
- Removed or folded small redundancies while making the full crate pass `cargo clippy --all-targets --locked -- -D warnings` and `cargo test`.
- Added a consolidated `src/relation/` module on top of the entity model with legacy relation taxonomy, structural/resolution/registration/name-lineage/handle/coreference/shared-selector/profile-link builders, affiliation helpers, duplicate collapse, and relation-graph utilities.
- Added a consolidated pure `src/correlator.rs` with one rule trait + registry, cached rule context, severity/ranking, candidate quarantine, and rebuilt high-value rule families/oracles (`AU-001/002/003/019/021/060/062/063/070/071/109/110`).
- Ported representative legacy differential-oracle tests for relation builders/graph and correlator helpers/rules into the current crate test suite.

Files intentionally not edited:
- `src/classify.rs`
- `src/session.rs`
- `src/stage.rs`
- `src/http.rs`
- `src/fetch.rs`
- `src/keys.rs`
- `src/egress.rs`
- `src/main.rs`

Validation:
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test`

Cleanup:
- No scratch `wt-*` tree remains in the repository.

Legacy files still not fully rebuilt feature-for-feature (line counts from the monolith snapshot):
- `core/relation/affiliation.rs` — 771 lines
- `core/relation/affiliation/tests.rs` — 831 lines
- `core/relation/builders.rs` — 1741 lines
- `core/relation/graph.rs` — 1962 lines
- `core/relation/social_extract.rs` — 400 lines
- `core/relation/tests.rs` — 1929 lines
- `core/correlator/mod.rs` — 864 lines
- `core/correlator/perf.rs` — 155 lines
- `core/correlator/rules/assoc.rs` — 608 lines
- `core/correlator/rules/breach.rs` — 1385 lines
- `core/correlator/rules/breach_pii.rs` — 1744 lines
- `core/correlator/rules/broker.rs` — 204 lines
- `core/correlator/rules/creator_exposure.rs` — 204 lines
- `core/correlator/rules/crypto.rs` — 175 lines
- `core/correlator/rules/dating_exposure.rs` — 201 lines
- `core/correlator/rules/device_constellation.rs` — 186 lines
- `core/correlator/rules/device_track.rs` — 191 lines
- `core/correlator/rules/gap.rs` — 647 lines
- `core/correlator/rules/geo/chain.rs` — 470 lines
- `core/correlator/rules/geo/cluster.rs` — 307 lines
- `core/correlator/rules/geo/jurisdiction.rs` — 418 lines
- `core/correlator/rules/geo/mod.rs` — 664 lines
- `core/correlator/rules/geo/profile.rs` — 516 lines
- `core/correlator/rules/handle_variant.rs` — 380 lines
- `core/correlator/rules/identity/account/broker.rs` — 353 lines
- `core/correlator/rules/identity/account/handle.rs` — 505 lines
- `core/correlator/rules/identity/account/key.rs` — 190 lines
- `core/correlator/rules/identity/account/mod.rs` — 53 lines
- `core/correlator/rules/identity/account/platform.rs` — 637 lines
- `core/correlator/rules/identity/account/tracking.rs` — 222 lines
- `core/correlator/rules/identity/cluster.rs` — 416 lines
- `core/correlator/rules/identity/mod.rs` — 22 lines
- `core/correlator/rules/infra.rs` — 882 lines
- `core/correlator/rules/infra_closure.rs` — 306 lines
- `core/correlator/rules/integrity.rs` — 183 lines
- `core/correlator/rules/locale.rs` — 123 lines
- `core/correlator/rules/location/mod.rs` — 1494 lines
- `core/correlator/rules/location/tests.rs` — 562 lines
- `core/correlator/rules/lookalike.rs` — 274 lines
- `core/correlator/rules/mod.rs` — 672 lines
- `core/correlator/rules/multipath.rs` — 484 lines
- `core/correlator/rules/org.rs` — 1157 lines
- `core/correlator/rules/payid.rs` — 93 lines
- `core/correlator/rules/resolved.rs` — 213 lines
- `core/correlator/rules/reuse_closure.rs` — 472 lines
- `core/correlator/rules/robust.rs` — 175 lines
- `core/correlator/rules/sim.rs` — 101 lines
- `core/correlator/rules/template.rs` — 247 lines
- `core/correlator/rules/tests.rs` — 502 lines
- `core/correlator/rules/transitive.rs` — 348 lines
- `core/correlator/tests.rs` — 816 lines
- `core/correlator/tests/part02.rs` — 809 lines
- `core/correlator/tests/part03.rs` — 796 lines
- `core/correlator/tests/part04.rs` — 812 lines
- `core/correlator/tests/part05.rs` — 788 lines
- `core/correlator/tests/part06.rs` — 835 lines
- `core/correlator/tests/part07.rs` — 803 lines
- `core/correlator/tests/part08.rs` — 795 lines
- `core/correlator/tests/part09.rs` — 825 lines
- `core/correlator/tests/part10.rs` — 812 lines
- `core/correlator/tests/part11.rs` — 790 lines
- `core/correlator/tests/part12.rs` — 810 lines
- `core/correlator/tests/part13.rs` — 786 lines
- `core/correlator/tests/part14.rs` — 761 lines
- `core/correlator/tests/part15.rs` — 59 lines

<!-- geo.md -->
| legacy path | lines | decision | new module | defect found/evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/util/geo/mod.rs` | 650 | MERGED | `src/geoint.rs`, `src/geo.rs` | Rebuilt pure parsing/validation, AU-state partition, locality/postcode lookups, confidence ladder, and family-distance helpers. Legacy mixed in monolith `Entity` birth/tag helpers; those are left out here. |
| `src/util/geo/tests.rs` | 271 | MERGED | `src/geoint.rs`, `src/geo.rs` | Ported the pure-oracle cases that fit this crate: coordinate parsing, AU box/state, locality lookup, postcode fallback, provider plausibility, namesake distance. |
| `src/util/geometry/circle.rs` | 135 | REBUILT | `src/geometry.rs` | Minimum enclosing circle rebuilt with equirectangular lon scaling and great-circle output radius. |
| `src/util/geometry/coherence.rs` | 162 | REBUILT | `src/geometry.rs` | Single-linkage coherence clustering rebuilt without monolith `union_find` dependency. |
| `src/util/geometry/fix.rs` | 107 | REBUILT | `src/geometry.rs` | Consolidated `LocationFix` rebuilt; deterministic bundle of centroid/median/circle outputs. |
| `src/util/geometry/footprint.rs` | 182 | REBUILT | `src/geometry.rs` | Convex hull + polygon-area centroid rebuilt; preserved the legacy defect fix away from naive vertex means. |
| `src/util/geometry/median.rs` | 192 | REBUILT | `src/geometry.rs` | Geometric median, weighted median, weighted centroid, and robust radius rebuilt. |
| `src/util/geometry/mod.rs` | 37 | MERGED | `src/geometry.rs` | Legacy split modules intentionally collapsed into one pure offline module for this crate. |
| `src/util/geometry/tests.rs` | 649 | MERGED | `src/geometry.rs` | Ported representative differential/property tests for hull, centroid, median, enclosing circle, coherence, and summary text. |
| `src/util/geohash/address.rs` | 117 | MERGED | `src/geohash.rs`, `src/place.rs` | Address parsing merged into the existing geohash module surface. |
| `src/util/geohash/country.rs` | 250 | MERGED | `src/geohash.rs`, `src/place.rs` | Reverse country boxes and ISO/name helpers merged into `src/geohash.rs`; HK/TW/SG ordering preserved. |
| `src/util/geohash/distance.rs` | 33 | MERGED | `src/geohash.rs` | Great-circle distance merged; kept the numerically-stable `atan2` form. |
| `src/util/geohash/encode.rs` | 94 | MERGED | `src/geohash.rs` | Existing geohash encoder extended with legacy-compatible wrapper and coordinate parser. |
| `src/util/geohash/mod.rs` | 36 | MERGED | `src/geohash.rs`, `src/place.rs` | Pure helpers consolidated into the existing geohash module rather than duplicated. |
| `src/util/geohash/tests.rs` | 298 | MERGED | `src/geohash.rs`, `src/place.rs` | Ported reference-vector, parser, metric, timezone, country-box, and address tests. |
| `src/util/geohash/timezone.rs` | 85 | MERGED | `src/geohash.rs`, `src/place.rs` | Coarse timezone inference merged into the existing geohash surface. |
| `src/util/city_coords/mod.rs` | 726 | REBUILT (subset) | `src/geo.rs` | Rebuilt whole-token/longest-match/foreign-gate/postcode fallback logic. Retained only a minimal verified row set used by tests; bulk gazetteer remains `PENDING-PROVENANCE`. |
| `src/util/city_coords/tests.rs` | 389 | MERGED | `src/geo.rs` | Ported the logic-oracle cases (postcode fallback, foreign-address rejection, AU-vs-foreign homonym gating) against the verified subset. |
| `src/util/place_grain.rs` | 276 | MERGED | `src/geohash.rs`, `src/place.rs` | `is_bare_country` merged into geohash/place helpers. |
| `src/util/cell.rs` | 112 | REBUILT | `src/rf.rs` | Canonical tower id, MCC/MNC normalisation, and LAC/TAC fallback rebuilt. |
| `src/util/wifi/mod.rs` | 121 | REBUILT | `src/rf.rs` | SSID generic/default classifier and Wi-Fi band boundaries rebuilt. |
| `src/util/wifi/tests.rs` | 91 | MERGED | `src/rf.rs` | Ported the whole-token vs substring regressions and band-boundary cases. |
| `src/util/oui/mod.rs` | 371 | REBUILT | `src/oui.rs` | Curated MAC/OUI classifier rebuilt; preserved randomized-address and multicast-bit handling. |
| `src/util/oui/ieee.rs` | 144 | REBUILT | `src/oui_ieee.rs`, `src/oui_ieee.bin` | Packed IEEE MA-L registry loader rebuilt and pointed at a copied blob. |
| `src/util/oui/ieee_tests.rs` | 135 | MERGED | `src/oui_ieee.rs` | Ported blob/lookup spot checks into the new IEEE helper. |
| `src/util/oui/tests.rs` | 252 | MERGED | `src/oui.rs` | Ported curated, registry-tier, randomized/private, and table-shape tests. |
| `src/core/geo_family/mod.rs` | 290 | MERGED (subset) | `src/geo.rs` | Rebuilt the pure postcode/distance/namesake subset (`extract_au_postcode`, coarse centroids, distance bands). The monolith `Entity` graph integration remains outside this slice. |
| `src/core/geo_family/tests.rs` | 400 | MERGED (subset) | `src/geo.rs` | Ported postcode extraction, foreign-address rejection, and near/far family-distance cases that fit the pure subset. |
| `src/core/rf.rs` | 383 | REBUILT | `src/rf.rs` | RF sighting model rebuilt with canonical network ids, OUI classification, position/timestamp guards, and WiGLE type parsing. |
| `src/core/rf_tests.rs` | 241 | MERGED | `src/rf.rs` | Ported RF sighting, timestamp, address-bit, and enum-roundtrip tests. |
| `src/core/radar_live.rs` | 434 | REBUILT | `src/radar.rs` | Live Bluetooth presence reducer rebuilt with not-read handling, randomized/bonded aggregates, and capacity eviction reporting. |
| `src/core/radar_live/tests.rs` | 377 | MERGED | `src/radar.rs` | Ported the reducer state-machine regressions (`new/present/missing/departed`, not-read, eviction, metadata). |
| `src/core/radar_track.rs` | 278 | REBUILT | `src/radar.rs` | Cross-sweep recurring-device review rebuilt and ranked deterministically. |
| `src/util/postcode_au/mod.rs` | 265 | REBUILT (subset) | `src/postcode_au.rs`, `src/geo.rs` | Rebuilt JSON parsing, offline centroid fallback, and the newly in-scope online postcode-locality lookup behind the shared `crate::http::{Request, Response, Transport}` boundary. Bulk gazetteer breadth still remains `PENDING-PROVENANCE`. |
| `src/util/postcode_au/tests.rs` | 147 | MERGED (subset) | `src/postcode_au.rs`, `src/geo.rs` | Ported postcode shape/range/fallback cases and added fake-transport tests implementing the shared `Transport` trait for the restored online lookup boundary. |

<!-- parsers.md -->
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

<!-- validation.md -->
| legacy path | lines | decision | new module | defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| core/validation/confusable.rs | 263 | MERGED | src/validation.rs | Rebuilt invisible-strip, skeleton, mixed-script, and gibberish checks; merged the pairwise lookalike primitives from util/confusable here so the duplicate confusable logic cannot drift again. |
| core/validation/domain.rs | 40 | MERGED | src/validation.rs | Rebuilt `is_onion_url` on the shared host parser instead of a standalone string split. |
| core/validation/email.rs | 112 | MERGED | src/validation.rs, src/identity.rs, src/domains.rs | Role-mailbox detection now delegates to the shared local-part authority; canonical email/domain handling is merged into `identity.rs`. |
| core/validation/ip.rs | 209 | MERGED | src/validation.rs | Rebuilt reserved/documentation/bogon and CDN-edge gates, including IPv4-mapped IPv6 parity. |
| core/validation/mod.rs | 56 | REBUILT | src/validation.rs | Reassembled the offline validation surface without the monolith's `EntityKind` dependency by using a local `ValueKind`. |
| core/validation/phone.rs | 195 | MERGED | src/validation.rs, src/address_au.rs, src/identity.rs | Rebuilt strict E.164 validation plus AU canonicalisation delegation; keeps foreign E.164 intact and merges canonical phone handling into `identity.rs`. |
| core/validation/placeholder.rs | 387 | MERGED | src/validation.rs | Rebuilt placeholder/privacy/fragment/residence gates as one offline authority. |
| core/validation/report.rs | 29 | MERGED | src/validation.rs | `ValidationReport` rebuilt unchanged in spirit. |
| core/validation/tests.rs | 605 | MERGED | src/* module tests | Ported representative regression and differential assertions into the rebuilt modules' unit tests instead of copying the monolith's entity-path test file verbatim. |
| util/confusable.rs | 136 | MERGED | src/validation.rs | Rebuilt homoglyph skeleton, Levenshtein distance, and lookalike detection. |
| util/phone/mod.rs | 58 | MERGED | src/validation.rs | Rebuilt `scan_phones` as the shared E.164 scanner. |
| util/domains/mod.rs | 694 | REBUILT | src/domains.rs | Kept the curated multi-label suffix table (explicit PSL decision) and rebuilt the pure domain/freemail/role/platform/VN/DNS helpers. |
| util/domains/tests.rs | 454 | MERGED | src/domains.rs tests | Ported representative invariants and regression cases. |
| util/url_util/mod.rs | 117 | MERGED | src/domains.rs | Rebuilt absolute-HTTP, host extraction, and tracking-parameter gates in the shared domain helper module. |
| util/url_util/tests.rs | 118 | MERGED | src/domains.rs tests | Ported representative host/query/IPv6/tracking assertions. |
| util/str_util/mod.rs | 654 | REBUILT | src/textnorm.rs | Rebuilt the pure text/UTF-8/ASCII folding helpers without extra dependencies; substituted loop-based invariant tests for the monolith's memchr/proptest setup. |
| util/str_util/tests.rs | 446 | MERGED | src/textnorm.rs tests | Ported representative unit and invariant checks. |
| util/bsb/mod.rs | 137 | MERGED | src/au_id.rs | Existing rebuilt BSB logic retained; longest-prefix institution table already matched the monolith's pure capability. |
| util/abn/mod.rs | 296 | MERGED | src/au_id.rs | Added the missing company-form and owner-splitting helpers to the existing ABN/ACN/BSB module. |
| util/abn/tests.rs | 224 | MERGED | src/au_id.rs tests | Ported representative company and identifier assertions. |
| util/address_au/mod.rs | 971 | REBUILT | src/address_au.rs | Rebuilt the pure AU address/state/postcode/phone/domain/network helpers without regex/AC automata dependencies; preserved the documented postcode, line-type, and domain-state fixes. |
| util/address_au/tests.rs | 650 | MERGED | src/address_au.rs tests | Ported representative address, postcode, phone, domain, and operator regressions. |
| util/postcode_au/mod.rs | 266 | REBUILT | src/postcode_au.rs | Rebuilt the pure JSON parser, offline gazetteer centroid lookup, and shape gate, then migrated the newly in-scope postcode fetch path onto the shared `crate::http::{Request, Response, Transport}` boundary. |
| util/postcode_au/tests.rs | 148 | MERGED | src/postcode_au.rs tests | Ported representative parse/offline-centroid/shape assertions. |
| util/uid/mod.rs | 23 | REBUILT | src/uid.rs | The current crate has no `core::entity::scan_id`; rebuilt a unique 64-hex SHA-256-based scan-id helper with time+counter mixing. |
| util/uid/tests.rs | 24 | MERGED | src/uid.rs tests | Ported the legacy shape/uniqueness assertions. |
| util/domain_vn/mod.rs | 101 | MERGED | src/domains.rs | Rebuilt the VN registrant classifier with the shared AU category vocabulary. |
| util/domain_vn/tests.rs | 100 | MERGED | src/domains.rs tests | Ported representative VN suffix cases. |
| util/dns.rs | 224 | REBUILT | src/dns.rs | Kept the pure label/RNAME helpers and moved the runtime resolver path onto the shared `crate::http::Transport` boundary with ordered DoH failover across Cloudflare/Quad9/Google so the newly in-scope path stays separately unit-testable. |
| core/xml.rs | 53 | REBUILT | src/xml.rs | Rebuilt the one-pass XML escaper that drops XML-illegal controls instead of double-escaping or preserving them. |

Policy-change note (network/credentials now allowed):
- Newly in scope and rebuilt behind injectable boundaries:
  - `util/postcode_au` online postcode lookup path via `src/postcode_au.rs::localities_with` on `crate::http::Transport`
  - `util/dns` resolver-pool/failover path via `src/dns.rs::{resolver_config, resolve_with_pool}` on `crate::http::Transport`
- Pure parsing, scoring, and policy remain separately unit-testable; tests use fakes and do not perform live network calls.
- No credential values are logged or embedded in tests/artifacts; these boundaries carry plain request/response data only.
- Redundancies removed during the shared-HTTP refactor: identity/email/phone canonicalisation now delegates to the shared canonical/validation owners; postcode shape/range checks now live in `src/postcode_au.rs`; DNS label/RNAME helpers now live only in `src/dns.rs`.
