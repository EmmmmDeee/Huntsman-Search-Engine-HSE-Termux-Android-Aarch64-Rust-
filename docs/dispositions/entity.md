# entity disposition

Permanent legacy references for this slice:
- `Huntsman-HSE-EndToEnd-Refactor-Overlay-feef60a.zip`
- `Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust--main (10).zip`
- extracted trees under `legacy/`

These references were not edited, moved, or deleted.

## Current verification

- `cargo check`
- `cargo clippy --all-targets --locked -- -D warnings`
- `cargo test`

The repo build is currently green; I did not find a remaining unclosed-delimiter failure in this area when rechecked.

## File-by-file accounting

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
| `src/identity_resolution.rs` (current owner) | MERGED OWNER | `src/identity_resolution.rs` | Kept as the single owner for reversible, ancestry-aware merge decisions. |
| `src/classify.rs` (report-only constraint) | NOT EDITED | unchanged | Per assignment, not modified here. |
| `src/session.rs` (report-only constraint) | NOT EDITED | unchanged | Per assignment, not modified here. |
| `src/stage.rs` (report-only constraint) | NOT EDITED | unchanged | Per assignment, not modified here. |

## Relation rebuild accounting

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

## Correlator rebuild accounting

These legacy files are now represented primarily by `src/correlator.rs`, but many rule families remain only partially rebuilt. Every file remains explicitly accounted for.

| Legacy path | Lines | Decision | Current owner / status |
| --- | ---: | --- | --- |
| `core/correlator/mod.rs` | 864 | PARTIAL | `src/correlator.rs` rebuilds rule context, severity/ranking, candidate quarantine, registry, and a high-value subset of rules. |
| `core/correlator/perf.rs` | 155 | NOT YET REBUILT | No dedicated perf harness has been recreated yet. |
| `core/correlator/rules/mod.rs` | 672 | PARTIAL | Consolidated into one trait + registry in `src/correlator.rs`; full legacy rule inventory still outstanding. |
| `core/correlator/rules/tests.rs` | 502 | PARTIAL ORACLE | Representative helper/rule oracles were ported into `src/correlator.rs` tests; the full legacy oracle set is not yet ported. |
| `core/correlator/rules/assoc.rs` | 608 | NOT YET REBUILT | Accounted for; full association rule family still outstanding. |
| `core/correlator/rules/breach.rs` | 1385 | PARTIAL | `AU-001`, `AU-019`, and `AU-021` style breach/exposure subsets are rebuilt; the rest of the family remains outstanding. |
| `core/correlator/rules/breach_pii.rs` | 1744 | NOT YET REBUILT | Accounted for; full breach-PII rule family still outstanding. |
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

## Notes

- `src/classify.rs`, `src/session.rs`, and `src/stage.rs` remain unedited in this slice; any future requested changes there should be reported separately.
- “Remove redundancy” in this area was applied only to the rebuilt `src/` owners; no legacy reference material was removed from accounting.
