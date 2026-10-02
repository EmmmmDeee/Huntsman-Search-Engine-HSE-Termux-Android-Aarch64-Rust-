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
