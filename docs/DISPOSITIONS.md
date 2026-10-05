# Legacy dispositions

Per-file accounting of the HSE monolith (`legacy/hse-monolith-v1.41.0/`) against the current crate, grouped by area. Decisions: REBUILT / REIMPLEMENT (new code, legacy kept as oracle), MERGED (folded into an existing owner or its tests), PARTIAL, PENDING / NOT YET REBUILT, NOT APPLICABLE. Refactor-overlay items are dispositioned in `RECONSTRUCTION_2026-10-02.md` (third pass).

Evidence source: the canonical extracted trees under `legacy/`. Original archive SHA-256/Git identities and a recoverable commit are recorded in `ARCHIVE_PROVENANCE.md`. Do not mutate legacy oracle content without updating provenance and differential evidence.

## Contents

1. [ATT&CK, assurance and analytics](#attck-assurance-and-analytics)
2. [Entity, relation and correlator core](#entity-relation-and-correlator-core)
3. [Geo, geometry and RF](#geo-geometry-and-rf)
4. [Parsers and signals](#parsers-and-signals)
5. [Validation, domains and text](#validation-domains-and-text)
6. [AU people registers](#au-people-registers)
7. [Providers restored from 764ce8e](#providers-restored-from-764ce8e)
8. [Not yet dispositioned](#not-yet-dispositioned)

## ATT&CK, assurance and analytics

| Legacy path | Lines | Decision | New module | Defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/core/attack/mod.rs` | 4833 | REBUILT | `src/attack.rs`, `src/attack_catalog.rs`, `src/navigator.rs` | ATT&CK catalog and recon mappings were rebuilt for the current crate; the large catalog was mechanically extracted from legacy and pinned with uniqueness, id-shape, sort-order, tactic-reference, and TA0043 slice tests so no binding is inferred from vocabulary alone. |
| `src/core/attack/tests.rs` | 702 | MERGED | `src/attack.rs`, `src/navigator.rs` tests | Legacy ATT&CK and Navigator expectations were folded into current unit tests instead of kept as a parallel test module. |
| `src/core/diamond.rs` | 259 | REBUILT | `src/diamond.rs` | Pure Diamond Model classification/grouping fit the crate contract and was rebuilt against current `entity` kinds. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/dependency/mod.rs` | 442 | REBUILT | `src/dependency.rs` | Module graph, producer/consumer indexing, summaries, and human-seed wiring checks were rebuilt as pure graph logic. |
| `src/core/dependency/reachability.rs` | 227 | REBUILT | `src/dependency.rs` | Reachability and dead-module analysis were merged into the rebuilt dependency graph instead of kept as a split submodule. |
| `src/core/dependency/tests.rs` | 600 | MERGED | `src/dependency.rs` tests | Legacy dependency expectations were ported as in-module tests for the rebuilt graph and reachability helpers. |
| `src/core/assurance/catalog.rs` | 375 | REBUILT | `src/assurance.rs` | Assurance catalog/profile data is pure and was consolidated into one assurance module. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/continuity.rs` | 512 | REBUILT | `src/assurance.rs` | Continuity objectives, state derivation, summary logic, and the newly in-scope source-tree scan were rebuilt; recovery-test verification is now split into pure missing-test detection plus a `SourceTree`/`FsSourceTree` I/O boundary that scans current `src/` and `tests/`. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/derive.rs` | 129 | REBUILT | `src/assurance.rs` | Assurance level/state derivation was rebuilt and exercised with differential ladder tests. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/gap.rs` | 160 | REBUILT | `src/assurance.rs` | Assurance gap severity and warnings were folded into the rebuilt assurance model. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/mod.rs` | 272 | REBUILT | `src/assurance.rs` | Public assurance API was reconstructed as one crate-local module. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/model.rs` | 423 | REBUILT | `src/assurance.rs` | Assurance enums, evidence model, applicability, verification, and summaries were rebuilt for the current crate. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/assurance/tests.rs` | 531 | MERGED | `src/assurance.rs` tests | Legacy assurance examples were carried over as current unit tests and continuity checks. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/benchmark/mod.rs` | 228 | REBUILT | `src/benchmark.rs` | Benchmark reporting was rebuilt over current metrics, coverage, graph, and scan-record primitives. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/benchmark/tests.rs` | 203 | MERGED | `src/benchmark.rs` tests | Legacy benchmark expectations were ported into in-module tests. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/roi/mod.rs` | 146 | REBUILT | `src/roi.rs` | Saturation, cutoff, and adaptive termination logic were rebuilt as pure scoring helpers. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/roi/tests.rs` | 103 | MERGED | `src/roi.rs` tests | Legacy ROI examples were folded into current unit tests. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/roi/utility.rs` | 406 | REBUILT | `src/roi.rs` | Dispatch-utility scoring and rationale emission were rebuilt in one module. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/roi/utility_tests.rs` | 327 | MERGED | `src/roi.rs` tests | Utility expectations were ported as current tests instead of kept as a parallel file. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/gap/mod.rs` | 233 | REBUILT | `src/gap.rs` | Gap/orphan/null-state analysis was rebuilt over current entity/relation graph types. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/gap/tests.rs` | 126 | MERGED | `src/gap.rs` tests | Legacy gap cases were merged into in-module tests. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/coverage.rs` | 571 | REBUILT | `src/coverage.rs`, `src/benchmark.rs` | Provider coverage/event rollups were rebuilt and benchmark comparability caveats now derive from current event coverage verdicts. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/metrics/mod.rs` | 476 | REBUILT | `src/metrics.rs` | Scan metrics, density, degeneracy/core size, corroboration, and seed reach were rebuilt for current graph/entity types. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/metrics/tests.rs` | 349 | MERGED | `src/metrics.rs` tests | Legacy metrics expectations were ported and extended with order-independence checks. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/trust/mod.rs` | 276 | REBUILT | `src/trust.rs` | Damped trust propagation was rebuilt as deterministic graph logic. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |
| `src/core/trust/tests.rs` | 271 | MERGED | `src/trust.rs` tests | Legacy trust cases were folded into current unit tests. Compiled and unit-tested (G8); not yet wired to a CLI caller (G1). |

### Notes

- ATT&CK bindings live only in `src/ledger.rs` (`BINDINGS`) and must be added there explicitly; nothing in the rebuilt catalog infers evidence.
- `src/stix.rs` and `src/eval/*` were reviewed for overlap. No code change was required in this pass.
- Until G8, `src/{assurance,benchmark,coverage,diamond,gap,metrics,roi,trust}.rs` had no `mod` line in `src/lib.rs`, so they were never compiled and their 45 unit tests never ran, although the rows above already said REBUILT/MERGED. They are now declared in `src/lib.rs` and their tests run in `cargo test`. No CLI command or recon path calls them yet; wiring is G1. `tests/dispositions.rs` now fails if a REBUILT, REIMPLEMENT, MERGED or PARTIAL row names a `src/` file that is not in the module tree reached from `src/lib.rs`/`src/main.rs`, or if any `src/**/*.rs` is outside that tree. A `mod` gated by a `cfg` other than `cfg(test)`, or relocated with `path` (including through `cfg_attr`), fails the check rather than counting as compiled.
- `src/attack_catalog.rs` was generated mechanically from legacy `src/core/attack/mod.rs` and validated by tests. It was not hand-retyped.
- Policy-change review: no legacy file in this area had been marked NOT APPLICABLE solely because of network or credentials. The one omitted I/O-bound legacy behavior was `assurance/continuity.rs` source-tree scanning; it is now rebuilt behind `SourceTree`/`FsSourceTree`, with unit tests using a fake tree and no live network added in this area.

## Entity, relation and correlator core

| Legacy path | Decision | Current owner / status | Notes |
| --- | --- | --- | --- |
| `hse-core/src/lib.rs` | REBUILT | `src/entity.rs`, `src/confidence.rs`, `src/lib.rs` | Entity/evidence/confidence surface rebuilt onto the current crate exports. |
| `hse-core/src/tags.rs` | REBUILT | `src/tags.rs` | Canonical tag vocabulary rebuilt as the current shared owner. |
| `hse-core/src/tests.rs` | MERGED | `src/entity.rs`, `src/confidence.rs`, `src/tags.rs` tests | Legacy behaviour restated in current unit tests instead of a parallel legacy test file. |
| `util/union_find.rs` | REBUILT | `src/union_find.rs` | Deterministic grouping/union logic rebuilt directly. |
| `util/canonical.rs` | REBUILT | `src/canonical.rs` | Canonical forms consolidated into the crate's shared owner. |
| `util/json.rs` | REBUILT | `src/json.rs` | Stable JSON canonicalisation/sorting rebuilt as pure logic. |
| `util/timefmt.rs` | REBUILT | `src/timefmt.rs` | Timestamp parsing/formatting rebuilt as pure helpers. |
| `core/graph/mod.rs` | REBUILT | `src/graph.rs` | Current structural graph rebuilt on top of the entity model. |
| `core/graph/tests.rs` | MERGED | `src/graph.rs` tests | Legacy graph invariants folded into current tests. |
| `core/gexf/mod.rs` | REBUILT | `src/gexf.rs` | GEXF export rebuilt for the current graph model. |
| `core/gexf/tests.rs` | MERGED | `src/gexf.rs` tests | Legacy output invariants carried into current tests. |
| `core/path/mod.rs` | REBUILT | `src/path.rs` | Path-finding rebuilt over the current graph surface. |
| `core/path/tests.rs` | MERGED | `src/path.rs` tests | Legacy path oracle cases merged into unit tests. |
| `core/pivot/mod.rs` | REBUILT | `src/pivot.rs` | Pivot scoring/reach logic rebuilt as pure graph analytics. |
| `core/pivot/tests.rs` | MERGED | `src/pivot.rs` tests | Representative pivot invariants ported. |
| `core/community/mod.rs` | REBUILT | `src/community.rs` | Community partition helpers rebuilt as pure graph logic. |
| `core/community/tests.rs` | MERGED | `src/community.rs` tests | Legacy community expectations merged into current tests. |
| `core/coref/mod.rs` | REBUILT | `src/coref.rs`, `src/identity_resolution.rs` | Deterministic coref clustering rebuilt and separated from ancestry-aware merge policy. |
| `core/coref/tests.rs` | MERGED | `src/coref.rs`, `src/identity_resolution.rs` tests | Legacy coref behaviours carried into unit tests. |
| `core/diff/mod.rs` | REBUILT | `src/diff.rs` | Entity/relation diff logic rebuilt as pure comparison helpers. |
| `core/diff/tests.rs` | MERGED | `src/diff.rs` tests | Legacy diff invariants merged into tests. |
| `core/timeline/mod.rs` | REBUILT | `src/timeline.rs` | Timeline reconstruction rebuilt on the entity/evidence model. |
| `core/timeline/tests.rs` | MERGED | `src/timeline.rs` tests | Legacy timeline behaviours carried into unit tests. |
| `core/snake_graph.rs` | REBUILT | `src/snake_graph.rs` | Deterministic graph rendering rebuilt. |
| `core/resolve/mod.rs` | REBUILT | `src/resolve.rs`, `src/identity_resolution.rs`, `src/evidence_ancestry.rs` | Exact-key resolution, ancestry-aware support counting, and reversible merge policy now split across the current owners. |
| `core/resolve/tests.rs` | MERGED | `src/resolve.rs`, `src/identity_resolution.rs`, `src/evidence_ancestry.rs` tests | Legacy resolution oracles folded into current tests. |
| `core/profiles/mod.rs` | REBUILT | `src/profiles.rs` | Profile aggregation rebuilt over current timeline/exposure primitives. |
| `core/profiles/tests.rs` | MERGED | `src/profiles.rs` tests | Legacy profile expectations merged into unit tests. |
| `core/leads/mod.rs` | REBUILT | `src/leads.rs` | Lead ranking/selection rebuilt over current entities. |
| `core/leads/tests.rs` | MERGED | `src/leads.rs` tests | Legacy lead-ordering invariants merged into tests. |
| `core/intelligence.rs` | REBUILT | `src/intelligence.rs` | Rebuilt as a richer pure ledger/report surface. |
| `core/exposure/mod.rs` | REBUILT | `src/exposure.rs` | Exposure scoring rebuilt on current entities/tags. |
| `core/exposure/tests.rs` | MERGED | `src/exposure.rs` tests | Legacy exposure expectations merged into tests. |
| `core/cross_scan.rs` | REBUILT | `src/cross_scan.rs` | Cross-scan bridge analysis rebuilt with an injected store boundary. |
| `core/classifier.rs` | REBUILT | `src/classifier.rs` | Structural entity classification rebuilt as pure logic. |
| `core/classify_module.rs` | REBUILT | `src/classify_module.rs` | Module-level classification/actionability rebuilt. |
| `src/confidence.rs` (current owner) | MERGED OWNER | `src/confidence.rs` | Extended with legacy confidence/verification vocabulary and kept as the single owner. |
| `src/evidence_ancestry.rs` (current owner) | MERGED OWNER | `src/evidence_ancestry.rs` | Kept as the single owner for independent-root support counting. |
| `src/identity_resolution.rs` (current owner) | MERGED OWNER | `src/identity_resolution.rs` | Kept as the single owner for reversible, ancestry-aware merge decisions. `hold_reasons` is the one merge rule: it requires a present, in-range probability (a036d76e) and states every reason a candidate is held. |
| `src/lineage.rs` (current owner) | MERGED OWNER | `src/lineage.rs` | Single owner for lineage read from response data (never the collector name) and for `resolve_with_lineage`, the observation → merge-outcome contract that `check` gate 5 runs (alongside a hand-built `EvidenceAncestryGraph` checked through `allows_automatic_merge`). The registry gate recomputes the collector family from `provenance.source` (ASCII only) and never trusts the stored `source_family`. |

### Relation rebuild accounting

These legacy files are now represented by `src/relation/`, but not yet fully rebuilt feature-for-feature. They remain explicitly accounted for here.

| Legacy path | Lines | Decision | Current owner / status |
| --- | ---: | --- | --- |
| `core/relation/mod.rs` | 84 | PARTIAL | `src/relation/mod.rs` exports the rebuilt surface, but the full legacy scope is not complete yet. |
| `core/relation/types.rs` | 296 | PARTIAL | `src/relation/types.rs` rebuilds the taxonomy/idempotent relation ids and identity-binding semantics. |
| `core/relation/builders.rs` | 1741 | PARTIAL | `src/relation/builders.rs` rebuilds structural/resolution/registration/name-lineage/handle/coref/shared-selector/residency/association subsets; remaining families still need parity. |
| `core/relation/graph.rs` | 1962 | PARTIAL | `src/relation/graph.rs` rebuilds provenance chains, strongest paths, cluster resolution, brokers, and templates; remaining graph behaviours still need parity. |
| `core/relation/affiliation.rs` | 771 | PARTIAL | `src/relation/affiliation.rs` rebuilds officer/employment/membership/control/operator/org-identity subsets; full legacy coverage is incomplete. |
| `core/relation/social_extract.rs` | 400 | PARTIAL | `src/relation/social_extract.rs` rebuilds supported profile-link extraction shapes, not the full legacy extractor surface. |
| `core/relation/tests.rs` | 1929 | PARTIAL ORACLE | Representative builder/graph/profile differential cases were ported into current unit tests; the full oracle set is not yet ported. |
| `core/relation/affiliation/tests.rs` | 831 | PARTIAL ORACLE | Affiliation-specific legacy oracles are only partially covered by the rebuilt tests so far. |

### Correlator rebuild accounting

These legacy files are now represented primarily by `src/correlator.rs`, but many rule families remain only partially rebuilt. Every file remains explicitly accounted for.

| Legacy path | Lines | Decision | Current owner / status |
| --- | ---: | --- | --- |
| `core/correlator/mod.rs` | 864 | PARTIAL | `src/correlator.rs` rebuilds rule context, severity/ranking, candidate quarantine, registry, and a high-value subset of rules. |
| `core/correlator/perf.rs` | 155 | NOT YET REBUILT | No dedicated perf harness has been recreated yet. |
| `core/correlator/rules/mod.rs` | 672 | PARTIAL | Consolidated into one trait + registry in `src/correlator.rs`; full legacy rule inventory still outstanding. |
| `core/correlator/rules/tests.rs` | 502 | PARTIAL ORACLE | Representative helper/rule oracles were ported into `src/correlator.rs` tests; the full legacy oracle set is not yet ported. |
| `core/correlator/rules/assoc.rs` | 608 | NOT YET REBUILT | Accounted for; full association rule family still outstanding. |
| `core/correlator/rules/breach.rs` | 1385 | PARTIAL | `AU-001`, `AU-019`, and `AU-021` style breach/exposure subsets are rebuilt; the rest of the family remains outstanding. |
| `core/correlator/rules/breach_pii.rs` | 1744 | PARTIAL | `breach_corpus_key` field precedence (`dbname`, `breach`, `source_db`) is rebuilt as `src/lineage.rs` `LINEAGE_FIELDS`, without the fallback to the collector name; checked against the 7dca720 oracle by `tests/lineage_legacy.rs`. The rest of the breach-PII rule family is still outstanding. |
| `core/correlator/rules/broker.rs` | 204 | PARTIAL | Connection-broker logic subset rebuilt as `AU-070`; full parity still outstanding. |
| `core/correlator/rules/creator_exposure.rs` | 204 | NOT YET REBUILT | Accounted for; rule family still outstanding. |
| `core/correlator/rules/crypto.rs` | 175 | NOT YET REBUILT | Accounted for; rule family still outstanding. |
| `core/correlator/rules/dating_exposure.rs` | 201 | NOT YET REBUILT | Accounted for; rule family still outstanding. |
| `core/correlator/rules/device_constellation.rs` | 186 | NOT YET REBUILT | Accounted for; rule family still outstanding. |
| `core/correlator/rules/device_track.rs` | 191 | NOT YET REBUILT | Accounted for; rule family still outstanding. |
| `core/correlator/rules/gap.rs` | 647 | PARTIAL | Single-path corroboration-gap subset rebuilt as `AU-063`; remaining gap logic still outstanding. |
| `core/correlator/rules/geo/mod.rs` | 664 | NOT YET REBUILT | Accounted for; geo rule family still outstanding. |
| `core/correlator/rules/geo/chain.rs` | 470 | NOT YET REBUILT | Accounted for; geo-chain rule family still outstanding. |
| `core/correlator/rules/geo/cluster.rs` | 307 | NOT YET REBUILT | Accounted for; geo-cluster rule family still outstanding. |
| `core/correlator/rules/geo/jurisdiction.rs` | 418 | NOT YET REBUILT | Accounted for; jurisdiction rule family still outstanding. |
| `core/correlator/rules/geo/profile.rs` | 516 | NOT YET REBUILT | Accounted for; geo-profile rule family still outstanding. |
| `core/correlator/rules/handle_variant.rs` | 380 | NOT YET REBUILT | Accounted for; numeric/variant handle rule family still outstanding. |
| `core/correlator/rules/identity/mod.rs` | 22 | PARTIAL | Consolidated into `src/correlator.rs`; only a subset of identity rules is rebuilt. |
| `core/correlator/rules/identity/cluster.rs` | 416 | PARTIAL | Identity-cluster subset rebuilt as `AU-002`, `AU-060`, and `AU-071`; full parity still outstanding. |
| `core/correlator/rules/identity/account/mod.rs` | 53 | PARTIAL | Consolidated into `src/correlator.rs`; account-level rule surface is incomplete. |
| `core/correlator/rules/identity/account/broker.rs` | 353 | NOT YET REBUILT | Accounted for; account-broker rule family still outstanding. |
| `core/correlator/rules/identity/account/handle.rs` | 505 | NOT YET REBUILT | Accounted for; account-handle rule family still outstanding. |
| `core/correlator/rules/identity/account/key.rs` | 190 | NOT YET REBUILT | Accounted for; account-key rule family still outstanding. |
| `core/correlator/rules/identity/account/platform.rs` | 637 | NOT YET REBUILT | Accounted for; account-platform rule family still outstanding. |
| `core/correlator/rules/identity/account/tracking.rs` | 222 | NOT YET REBUILT | Accounted for; account-tracking rule family still outstanding. |
| `core/correlator/rules/infra.rs` | 882 | PARTIAL | Shared-hosting-IP subset rebuilt as `AU-110`; remaining infra rules still outstanding. |
| `core/correlator/rules/infra_closure.rs` | 306 | NOT YET REBUILT | Accounted for; infra-closure rule family still outstanding. |
| `core/correlator/rules/integrity.rs` | 183 | NOT YET REBUILT | Accounted for; integrity rule family still outstanding. |
| `core/correlator/rules/locale.rs` | 123 | NOT YET REBUILT | Accounted for; locale rule family still outstanding. |
| `core/correlator/rules/lookalike.rs` | 274 | NOT YET REBUILT | Accounted for; lookalike rule family still outstanding. |
| `core/correlator/rules/multipath.rs` | 484 | PARTIAL | Multi-path corroboration subset rebuilt as `AU-062`; full parity still outstanding. |
| `core/correlator/rules/org.rs` | 1157 | PARTIAL | Shared-registrant/operator subset rebuilt as `AU-109`; the rest of the org rule family remains outstanding. |
| `core/correlator/rules/payid.rs` | 93 | NOT YET REBUILT | Accounted for; PAYID rule family still outstanding. |
| `core/correlator/rules/resolved.rs` | 213 | NOT YET REBUILT | Accounted for; resolved-identity rule family still outstanding. |
| `core/correlator/rules/reuse_closure.rs` | 472 | NOT YET REBUILT | Accounted for; reuse-closure rule family still outstanding. |
| `core/correlator/rules/robust.rs` | 175 | PARTIAL | Robust identity-cluster subset rebuilt as `AU-071`; remaining logic still outstanding. |
| `core/correlator/rules/sim.rs` | 101 | NOT YET REBUILT | Accounted for; SIM rule family still outstanding. |
| `core/correlator/rules/template.rs` | 247 | NOT YET REBUILT | Accounted for; generalized pathway-template rule family still outstanding. |
| `core/correlator/rules/transitive.rs` | 348 | PARTIAL | Transitive identity-closure subset rebuilt as `AU-060`; remaining logic still outstanding. |
| `core/correlator/tests.rs` | 816 | PARTIAL ORACLE | Representative engine-wide invariants were ported into `src/correlator.rs` tests; the full oracle is not yet ported. |
| `core/correlator/rules/location/mod.rs` | 1494 | NOT YET REBUILT | Accounted for; location rule family still outstanding. |
| `core/correlator/rules/location/tests.rs` | 562 | NOT YET REBUILT | Accounted for with the unported geo/location rule family. |
| `core/correlator/tests/part02.rs` | 809 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part03.rs` | 796 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part04.rs` | 812 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part05.rs` | 788 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part06.rs` | 835 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part07.rs` | 803 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part08.rs` | 795 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part09.rs` | 825 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part10.rs` | 812 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part11.rs` | 790 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part12.rs` | 810 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part13.rs` | 786 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part14.rs` | 761 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |
| `core/correlator/tests/part15.rs` | 59 | NOT YET PORTED | Accounted for; full split test suite still outstanding. |

### Notes

- `src/intelligence.rs` is a claim/evidence/inference/provider ledger; `src/cross_scan.rs` is bridge analysis behind an injected `CrossScanStore`.
- Evidence keeps mandatory provenance; provider credentials are stored as fingerprints only.
- Network-facing code uses the shared `crate::http::{Request, Response, Transport}` boundary; no parallel request/response types.
- `src/correlator.rs` has one rule trait and registry, cached rule context, severity/ranking and candidate quarantine; rebuilt rules: `AU-001/002/003/019/021/060/062/063/070/071/109/110`.

## Geo, geometry and RF

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

## Parsers and signals

### Rebuilt in this area

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

### Newly in scope after policy change

Rebuilt behind shared crate boundaries (`crate::http::{Request, Response, Transport}` and `fetch`) while keeping pure logic unit-testable:

- `util/service_defs/`
- `util/key_health/`
- `util/scraper_health.rs`
- `util/recon.rs`
- pure parts of `core/event/`
- pure metadata/economics parts of `core/module/`

Credentials are allowed, but artifacts/logs still keep fingerprint-only hygiene.

### File-by-file

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
| `core/breach_consensus.rs` | `src/lineage.rs`, `src/identity_resolution.rs` | PARTIAL | Distinct-corpus counting (`breach_sources_of`, `is_corroborated`) is rebuilt as lineage families from response fields; the two-corpus threshold and the 0.90 two-corpus `supported_ceiling` are the `AutoMergePolicy` default. Legacy outcomes on 9 fixtures are recorded in `tests/fixtures/legacy_7dca720_breach_consensus.json`, and intentional differences are listed in `docs/LINEAGE.md`. Audit flags, the consensus evidence record and the sweep tag are not rebuilt. |
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

### Notes

- `circuit::BreakerState` and `assurance::ControlState` are not duplicates: one is runtime request throttling state, the other is governance/control evidence state.
- Shared parsing cleanup moved duplicate record-tag parsing for DMARC/SPF into `src/signals.rs`.
- `key_health` now reuses the crate’s key hygiene path instead of inventing a separate fingerprint scheme.

## Validation, domains and text

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
| util/dns.rs | 224 | REBUILT | src/dns.rs | Kept the pure label/RNAME helpers and moved the runtime resolver path onto guarded `fetch` over an injected `crate::http::Transport`, with ordered DoH failover across Cloudflare/Quad9/Google. A challenge page is `BotWaf`, not JSON. `recon dns TARGET` is the CLI. Tests use fakes and do not perform live network calls. |
| core/xml.rs | 53 | REBUILT | src/xml.rs | Rebuilt the one-pass XML escaper that drops XML-illegal controls instead of double-escaping or preserving them. |

### Notes

Policy change (network and credentials now allowed):
- Newly in scope and rebuilt behind injectable boundaries:
  - `util/postcode_au` online postcode lookup path via `src/postcode_au.rs::localities_with` on `crate::http::Transport`
  - `util/dns` resolver-pool/failover path via `src/dns.rs::{resolver_config, resolve_with_pool}` through `fetch` on `crate::http::Transport`
- Pure parsing, scoring, and policy remain separately unit-testable; tests use fakes and do not perform live network calls.
- No credential values are logged or embedded in tests/artifacts; these boundaries carry plain request/response data only.
- Redundancies removed during the shared-HTTP refactor: identity/email/phone canonicalisation now delegates to the shared canonical/validation owners; postcode shape/range checks now live in `src/postcode_au.rs`; DNS label/RNAME helpers now live only in `src/dns.rs`.

## AU people registers

| Legacy path | Lines | Decision | New module | Defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/modules/asic_persons/mod.rs` | 629 | REBUILT | `src/asic_persons.rs`, `src/people_cli.rs`, `src/people_save.rs` | Keyless data.gov.au CKAN collector for banned/disqualified persons, financial advisers and credit representatives. Blocking `fetch` over an injected transport; emit oracles ported from legacy fixtures. Coordinates use `postcode_au::offline_centroid` (L3), not `geo` (L6). `people NAME [--save FILE]` is the collection front-end (`people_cli`) over this collector plus `asic_director`, `au_people` and `au_electoral`, and runs evidence through `lineage::resolve_with_lineage`; one source failure does not abort the others; `people_save` writes an unverified ledger `verify` reloads. Tests never hit the live portal. |
| `src/modules/asic_persons/tests.rs` | 424 | MERGED | `src/asic_persons.rs` tests | Legacy emit, name-match, controller and checksum fixtures plus scripted-transport lookup, envelope-failure and challenge-page cases. |
| `src/modules/asic_director/mod.rs` | 397 | REBUILT | `src/asic_director.rs` | Keyless ASIC Connect Online HTML scrape of director appointments. Blocking `fetch` over an injected transport. Challenge pages, truncated bodies and non-success HTTP are never evidence. ACN emission requires checksum validation. Coordinates use `postcode_au::offline_centroid` (L3), not `geo`/`city_coords` (L6). Called from `people`; a WAF is `Error::Invalid` so it cannot be read as "no director records", and `people_cli` records that without aborting other sources (live Connect is WAF-blocked). Tests never hit the live portal. ATT&CK self-labels are not copied. |
| `src/modules/asic_director/tests.rs` | 275 | MERGED | `src/asic_director.rs` tests | Legacy emit, whole-word match, checksum-invalid ACN, request_failed, HTML entity decode and scripted-transport lookup/challenge cases. The ignored wall-clock linearity test is not rebuilt. |
| `src/modules/au_people/mod.rs` | 495 | REBUILT | `src/au_people.rs` | Keyless True People Search AU HTML scrape. Blocking `fetch` over an injected transport. Challenge pages, truncated bodies and non-success HTTP (other than 404) are never evidence; 404 is ValidZero. Addresses and emails are candidate leads (unattributed line scan). Relatives keep same-surname family only, never tagged `tps-au`. Coordinates use `postcode_au::offline_centroid` (L3), not `geo`. White Pages AU is not queried (retired 404). Called from `people`; a challenged page is `Error::Invalid` and does not abort other sources. ATT&CK self-labels are not copied. |
| `src/modules/au_people/tests.rs` | 307 | MERGED | `src/au_people.rs` tests | Legacy relatives, TPS address/email chrome, candidate-lead, split_name, state-tag and dedup oracles plus scripted-transport lookup/challenge/404 cases. The proptest panic-totality tests are replaced by a small adversarial-byte unit test (no `regex`/`proptest` crate). |
| `src/modules/au_electoral/mod.rs` | 244 | REBUILT | `src/au_electoral.rs` | Keyless NSW/VIC/QLD electoral-commission HTML scrape. Blocking `fetch` over an injected transport. First hit wins. Challenge pages, truncated bodies and non-success HTTP are Unreachable, not "not enrolled". All-unreachable fails closed. No AEC national leg (NameSearch retired). Division centroids are an offline table, not `geo`. Called from `people`; all-unreachable is `Error::Invalid` and does not abort other sources. ATT&CK self-labels are not copied. |
| `src/modules/au_electoral/parse.rs` | 357 | MERGED | `src/au_electoral.rs` | Division/enrolment markers, nearby-negation window, apostrophe names, suburb hints on standalone postcodes. |
| `src/modules/au_electoral/entity.rs` | 90 | MERGED | `src/au_electoral.rs` | Address 0.72 with suburb / 0.58 division-only; coordinates only when the offline centroid table has the division. |
| `src/modules/au_electoral/division_map.rs` | 140 | MERGED | `src/au_electoral.rs` | 67-division centroid table plus Darwin→NT state inference. |
| `src/modules/au_electoral/tests.rs` | 308 | MERGED | `src/au_electoral.rs` tests | Legacy parse/emit/outage oracles plus scripted-transport first-hit, challenge and all-unreachable cases. The proptest panic-totality tests are replaced by a small adversarial-byte unit test. |

### Notes

- Live CKAN (`asic_persons_live_finds_a_banned_person`) is not rebuilt: capability row 4 still requires D and L.
- Live ASIC Connect (`asic_director`) is WAF-blocked (403); `people` still calls it and records the failure without aborting other sources. Tested on a fake transport only.
- `au_people` is called from `people` and tested on a fake transport only; live TPS is not run in CI.
- `au_electoral` is called from `people` and tested on a fake transport only; live commissions are not run in CI.

## Providers restored from 764ce8e

The v1.41.0 source rows below are accounted against the newer stolen.tax v2 and
crt.sh implementations ported onto the guarded fetch layer. The differential
fixtures record legacy outputs; the blank-name/host guard intentionally omits
placeholder markers and unknown stand-in facts.

| Legacy path | Lines | Decision | New module | Defect found / evidence or reason |
| --- | ---: | --- | --- | --- |
| `src/modules/crtsh/mod.rs` | 382 | REIMPLEMENT | `src/crtsh.rs` | 30-second timeout; retries only HTTP 502/503/429, at most three attempts two seconds apart. Challenge, truncated and malformed responses fail closed. Differential fixtures match records, confidence, tags and evidence attributes without a result cap. |
| `src/modules/crtsh/tests.rs` | 345 | MERGED | `src/crtsh/tests.rs`, `src/crtsh/differential.rs` | Legacy cases use fake transports; query shape, entity kinds, retry bounds, challenge pages, truncation and redirects are covered. |
| `src/modules/stolen_tax/mod.rs` | 485 | REIMPLEMENT | `src/stolen_tax.rs` | v2 POST cascade with origin-scoped credentials, bounded same-site redirects, one 120-second lookup deadline and same-key 429 retries. Differential tests cover the legacy cascade; persistent key-pool rotation remains deferred. Password and hash fields are never declared. |
| `src/modules/see_know/mod.rs` | 1006 | PARTIAL | `src/seeknow.rs`, `src/seeknow_collector.rs`, `src/seeknow_cli.rs` | First reconstructed SeekNow slice uses the documented REST API through guarded `fetch` + injected `Transport`. Fast/deep duplicates and federated provider rows cannot manufacture corroboration. Raw password/token/cookie material is excluded. Query-optimizer and geo extract remain deferred. |
| `src/modules/see_know/endpoints/mod.rs` | 377 | PARTIAL | `src/seeknow.rs` | Status/credits/search endpoints rebuilt as typed L4 requests; entitlement and quota failures are distinct from auth and rate-limit. |
| `src/modules/see_know/endpoints/tests.rs` | 280 | MERGED | `tests/seeknow_client.rs`, `tests/seeknow_cli.rs` | Fake-transport coverage for request shape, outcome mapping and CLI rendering. |
| `src/modules/see_know/tests.rs` | 2083 | MERGED | `tests/seeknow_collector.rs`, `tests/seeknow_diagnostics.rs`, `tests/seeknow_outcomes.rs` | Collector lineage, diagnostics and causal-outcome contract tests. |
| `src/modules/wayback/mod.rs` | 586 | REIMPLEMENT | `src/wayback.rs`, `src/archive.rs` | CDX lookup through `fetch`; original URLs are observations and are never fetched. |
| `src/modules/wayback/tests.rs` | 323 | MERGED | `tests/wayback_client.rs`, `tests/archive_model.rs` | Fake-transport CDX parsing plus archive identity/aggregation tests. |

## Not yet dispositioned

Legacy `src/` files of the monolith that no section above lists yet (875 of 1146). They are neither rebuilt nor rejected; most need network providers, credentials, a runtime, or a UI that the crate does not have.

| Legacy area | Files not listed | Of |
| --- | ---: | ---: |
| `src/modules/` (providers) | 522 | 542 |
| `src/util/` | 116 | 213 |
| `src/core/` | 49 | 203 |
| `src/app/` | 45 | 45 |
| `src/web/` | 44 | 44 |
| `src/cli/` | 40 | 40 |
| `src/api/` | 24 | 24 |
| `src/bin/` | 14 | 14 |
| `src/storage/` | 9 | 9 |
| `src/audit/` | 5 | 5 |
| `src/selftest/` | 3 | 3 |
| crate root (`lib.rs`, `main.rs`, `lib_tests.rs`, `main_tests.rs`) | 4 | 4 |
