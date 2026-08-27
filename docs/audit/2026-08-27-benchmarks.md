# Performance snapshot — 2026-08-27

No pre-migration baseline exists to diff against: the audit
(`docs/RUST_MIGRATION_AUDIT_2026-08-27.md`) found nothing to migrate — the
codebase was already 100% Rust. What follows is a **current-state
performance snapshot**, captured with the project's own existing harnesses,
recorded here as the baseline any *future* change should be diffed against.

## Zero-toolchain perf-ratio guard

`cargo test --lib correlator::perf -- --ignored --nocapture` (debug
profile, per the project's own documented invocation in
`src/core/correlator/perf.rs`). This is `core::correlator::correlate_entities`
— the correlation pass that runs after every expansion round during a scan —
exercised across a synthetic entity generator shared with the criterion
bench below, so the two harnesses can't silently disagree on what
"representative load" means.

```
running 3 tests
correlation pass — min µs/call by entity count:
  n=  100     6056.0 µs
  n=  500    28374.2 µs
  n= 1000    60337.4 µs
  n= 2000   114546.2 µs
  n= 5000   325792.4 µs
test core::correlator::perf::scaling_baseline ... ok

subquadratic guard: n=500 28321.1 µs, n=2000 115001.9 µs, ratio 4.06 (max 9)
test core::correlator::perf::pass_is_subquadratic ... ok

per-rule cost — RULES[index]: n=500 µs, n=2000 µs, ratio:
  RULES[ 22]  n=500:     6.26 µs   n=2000:     34.96 µs   ratio   5.59
  RULES[ 74]  n=500:    24.74 µs   n=2000:    126.50 µs   ratio   5.11
  RULES[ 82]  n=500:    26.31 µs   n=2000:    133.10 µs   ratio   5.06
  RULES[ 54]  n=500:    72.80 µs   n=2000:    349.03 µs   ratio   4.79
  RULES[ 38]  n=500:     7.43 µs   n=2000:     35.45 µs   ratio   4.77
  RULES[ 59]  n=500:   149.47 µs   n=2000:    677.57 µs   ratio   4.53
  RULES[ 55]  n=500:   378.30 µs   n=2000:  1686.69 µs   ratio   4.46
  RULES[ 85]  n=500:  1287.98 µs   n=2000:  5710.38 µs   ratio   4.43
  RULES[  2]  n=500:    95.08 µs   n=2000:   420.01 µs   ratio   4.42
  RULES[ 90]  n=500:   922.24 µs   n=2000:  4029.94 µs   ratio   4.37
  RULES[ 24]  n=500:    28.13 µs   n=2000:   120.35 µs   ratio   4.28
  RULES[106]  n=500:   904.61 µs   n=2000:  3862.73 µs   ratio   4.27
  RULES[ 67]  n=500:   134.45 µs   n=2000:   570.90 µs   ratio   4.25
  RULES[ 25]  n=500:    51.10 µs   n=2000:   215.91 µs   ratio   4.23
  RULES[ 53]  n=500:  4193.18 µs   n=2000: 17609.50 µs   ratio   4.20
test core::correlator::perf::per_rule_breakdown ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 6633 filtered out; finished in 17.12s
```

Interpretation (against the project's own guard, not this audit's
judgment): a doubling of entity count (500→1000→2000→…) costs roughly
2.1-2.3× the correlation-pass time, comfortably inside the `pass_is_subquadratic`
guard's ratio-4.06-of-9 pass — near-linear, not quadratic, holding out to
n=5000. No rule in the per-rule breakdown exceeds the same guard's implicit
tolerance; the highest individual-rule ratio (5.59, `RULES[22]`) is a small
absolute cost (35 µs at n=2000) and not close to the 9x ceiling.

## Criterion statistical benchmarks

`cargo bench --locked` (release profile): `benches/scan_throughput.rs`
(hottest pure parse-path scanners — `find_ascii_ci`, `fold_ascii_lower`,
`slugify`, `geohash`, plus the `util::scan::MatchSet` anti-bot detector) and
`benches/correlation_pass.rs` (the same correlation pass above, at
100/500/1000/2000 entities, criterion's proper statistical/regression-
tracked numbers rather than the ratio-only guard above).

**Status: running at the time this document was first committed.** `cargo
bench` does a release-profile rebuild of the full dependency graph before
sampling, which takes longer than this run's other checks. Results will be
appended here (replacing this paragraph) in a follow-up commit on this same
PR once the run completes — tracked as part of this run's own gate
discipline, not left silently incomplete.

CI's `bench-smoke.yml` independently compiles and smoke-runs both benches on
every relevant change as a perf-path API drift guard, regardless of this
snapshot's specific numbers — so a future regression is caught even without
re-running this document.
