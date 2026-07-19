//! Correlation-pass performance harness — a committed, zero-dependency baseline.
//!
//! The correlation pass ([`correlate_entities`]) runs after *every* expansion
//! round during a scan, so its cost is multiplied by the round count and must
//! stay (near-)linear in the entity count. A regression here is exactly the
//! class of bug fixed in AU-034 (a per-rule O(U×E) loop that dominated the whole
//! pass and stalled large breach/stealer scans on the low-CPU Termux target).
//!
//! These benchmarks are deliberately **`#[ignore]`d** so they never put
//! wall-clock timing into the default `cargo test` gate (timing assertions in CI
//! are flaky and hurt developer experience). Run them on demand:
//!
//! ```text
//! cargo test -p huntsman-search-engine --lib correlator::perf -- --ignored --nocapture
//! ```
//!
//! [`scaling_baseline`] prints µs/call across entity counts (the numbers to eyeball
//! when doing perf work). [`pass_is_subquadratic`] is an assertive guard: it
//! verifies the pass grows sub-quadratically and fails loudly if an O(n²) rule
//! is reintroduced — opt-in, so it's available to a dedicated CI perf job without
//! burdening the normal test run.
//!
//! Deliberately still no `criterion` dependency *in this file*: it needs no
//! `cargo bench` toolchain step, so it stays the always-available `cargo test
//! -- --ignored` guard. `benches/correlation_pass.rs` now complements it (F.3 /
//! SOL-F3's "widen criterion to the correlation pass" item) with proper
//! criterion-tracked, regression-comparable numbers — `criterion` was not a new
//! dependency to add for that (it already landed for `benches/scan_throughput.rs`
//! on 2026-06-17), only a bench-visible entry point was missing. Both harnesses
//! share one entity generator, [`super::bench_synthetic_entities`], so they can't
//! silently disagree on what "representative load" means.
//!
//! `std::time::Instant` + a min-of-iterations estimator is enough to
//! characterise an O(n) vs O(n²) difference, which is all this file guards.

use std::time::Instant;

use crate::core::entity::Entity;

/// Minimum wall-clock of `iters` runs of the full correlation pass over `ents`,
/// in microseconds. Min (not mean) is the most stable single-machine estimator —
/// it reports the run least perturbed by the scheduler.
fn min_pass_us(ents: &[Entity], iters: u32) -> f64 {
    let mut best = f64::MAX;
    for _ in 0..iters {
        let start = Instant::now();
        let out = super::correlate_entities(ents, "scan");
        // Touch the result so the pass can't be optimised away.
        std::hint::black_box(out.len());
        best = best.min(start.elapsed().as_secs_f64() * 1e6);
    }
    best
}

#[test]
#[ignore = "perf baseline; run with --ignored --nocapture"]
fn scaling_baseline() {
    eprintln!("correlation pass — min µs/call by entity count:");
    for &n in &[100usize, 500, 1000, 2000, 5000] {
        let ents = super::bench_synthetic_entities(n);
        let us = min_pass_us(&ents, 30);
        eprintln!("  n={n:5}  {us:9.1} µs");
    }
}

#[test]
#[ignore = "perf guard; run with --ignored. Catches reintroduction of an O(n^2) rule"]
fn pass_is_subquadratic() {
    // Compare the pass at n and 4n. Linear ⇒ ~4×; quadratic ⇒ ~16×. We assert the
    // ratio stays under 9× — comfortably above linear-plus-noise, far below
    // quadratic — so this fails only on a genuine complexity regression, not on
    // CI jitter.
    const SMALL: usize = 500;
    const LARGE: usize = 2000; // 4× SMALL
    const MAX_RATIO: f64 = 9.0;

    let small = super::bench_synthetic_entities(SMALL);
    let large = super::bench_synthetic_entities(LARGE);
    // Warm up (cache/branch-predictor) so the first timed run isn't penalised.
    let _ = min_pass_us(&small, 5);
    let _ = min_pass_us(&large, 5);

    let t_small = min_pass_us(&small, 50);
    let t_large = min_pass_us(&large, 50);
    let ratio = t_large / t_small;
    eprintln!(
        "subquadratic guard: n={SMALL} {t_small:.1} µs, n={LARGE} {t_large:.1} µs, ratio {ratio:.2} (max {MAX_RATIO})"
    );
    assert!(
        ratio < MAX_RATIO,
        "correlation pass scaled {ratio:.2}× for a 4× entity increase — \
         expected ~4× (linear); a ratio approaching 16× means an O(n^2) rule \
         was reintroduced. Profile per-rule (see git history for AU-034)."
    );
}
