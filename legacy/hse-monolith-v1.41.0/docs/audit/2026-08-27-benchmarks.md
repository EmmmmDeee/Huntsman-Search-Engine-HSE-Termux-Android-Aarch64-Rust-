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

Results (release profile, LTO, codegen-units=1 — this project's own
production build settings, so these numbers reflect what actually ships,
not a debug-build approximation):

### `benches/correlation_pass.rs`

| Entities | Mean time | vs. previous doubling |
|---:|---:|---:|
| 100 | 736.96 µs | — |
| 500 | 3.6122 ms | 4.90× for 5× the entities |
| 1000 | 7.7179 ms | 2.14× for 2× the entities |
| 2000 | 14.424 ms | 1.87× for 2× the entities |

Consistent with the zero-toolchain ratio guard above: cost grows sub-linearly
in the *ratio* sense (each entity-count doubling costs well under 2×'s
worth of quadratic growth would demand), confirming the correlation pass's
near-linear scaling under criterion's proper statistical measurement, not
just the coarse ignored-test ratio check.

### `benches/scan_throughput.rs`

| Benchmark | Mean time | Note |
|---|---:|---|
| `entity_extract/dense_all_kinds` | 1.9526 ms (5.57 MiB/s) | worst-case page: every extractable entity kind present |
| `entity_extract/prose_no_matches` | 2.5785 ms (4.99 MiB/s) | worst-case miss: plain prose, no matches to extract |
| `find_ascii_ci_14kb/hit` | 17.389 µs | needle near end of 14 KB multibyte text |
| `find_ascii_ci_14kb/miss` | 33.770 µs | |
| `fold_ascii_lower_unicode` | 13.101 µs | diacritic-folding a repeated Unicode name string |
| `slugify_mixed` | 191.64 ns | |
| `geohash_precision12` | 233.32 ns | |
| `captcha_signature_scan_14kb/match_set` | 2.2121 µs | cached Teddy/SIMD automaton |
| `captcha_signature_scan_14kb/linear_any_contains` | 23.550 µs | the naive N-way `.any(\|p\| hay.contains(p))` it replaced — **10.6× slower** |
| `strip_inline_guard_noblock/old_lowercase_copy` | 2.0699 µs | historical A/B pair kept as a regression guard |
| `strip_inline_guard_noblock/new_find_ascii_ci` | 2.1561 µs | ~4% slower than the old approach on this specific short-input case — a pre-existing, tiny (0.09 µs) characteristic of the current code, not something this run's audit touched; flagged here for transparency rather than smoothed over |
| `au_place_scan_miss/old_per_place_to_lowercase` | 92.023 µs | |
| `au_place_scan_miss/new_find_ascii_ci` | 84.927 µs | ~8% faster |
| `is_captcha_guard_noblock/old_to_lowercase_then_match` | 61.416 µs | |
| `is_captcha_guard_noblock/new_ascii_ci_raw` | 27.679 µs | ~2.2× faster |
| `href_scan/old_std_find` | 10.961 µs | |
| `href_scan/new_memmem_memchr` | 2.2501 µs | ~4.9× faster |
| `target_kind_detect_checks/old_to_ascii_lowercase_then_match` | 86.821 ns | |
| `target_kind_detect_checks/new_direct_byte_compare` | 49.780 ns | ~1.74× faster |

**On "before/after"**: the `old_*`/`new_*` pairs above are *not* this run's
before/after — they are the project's own pre-existing historical
optimization record (each `new_*` variant already replaced its `old_*`
counterpart in production; both are kept in the bench suite specifically as
a regression guard against ever reverting). They are included here because
they are the only genuine "before/after" data this codebase has, and they
demonstrate the same performance discipline this run's audit found
throughout (§4 of the main report) — every non-obvious choice, including
performance-motivated ones, is measured and guarded, not assumed. This
run's own before/after is, honestly, N/A: nothing was ported, so there is
no legacy implementation to diff these numbers against — see
`docs/RUST_MIGRATION_AUDIT_2026-08-27.md` §1.

CI's `bench-smoke.yml` independently compiles and smoke-runs both benches on
every relevant change as a perf-path API drift guard, regardless of this
snapshot's specific numbers — so a future regression is caught even without
re-running this document.
