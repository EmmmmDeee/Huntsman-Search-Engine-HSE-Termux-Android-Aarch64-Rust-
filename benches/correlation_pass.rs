//! Criterion bench for the correlation pass — `core::correlator::correlate_entities`,
//! which runs after *every* expansion round during a scan, so its cost is
//! multiplied by the round count and must stay (near-)linear in the entity
//! count (PROBLEM_TREE F.3 / SOLUTION_TREE SOL-F3: "widen criterion to the
//! correlation pass"). Complements, does not replace, the always-available
//! `core::correlator::perf` module's zero-toolchain `#[ignore]`d
//! `cargo test -- --ignored` guard — that one asserts a hard pass/fail ratio
//! bound so it works without `cargo bench` installed; this one gives
//! criterion's proper statistical, regression-tracked numbers for deliberate
//! perf work. Both share the exact same entity generator
//! (`core::correlator::bench_synthetic_entities`) so the two harnesses can
//! never silently disagree on what "representative load" means.
//!
//! Run with `cargo bench`; CI only compiles it (`--no-run`), so it doubles as
//! a perf-path API drift guard like `benches/scan_throughput.rs`.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use huntsman_search_engine::core::correlator::{
    bench_correlate_entities, bench_synthetic_entities,
};

/// The correlation pass across the same entity counts
/// `core::correlator::perf::scaling_baseline` eyeballs — a criterion
/// `BenchmarkId` group makes near-linear-vs-quadratic drift visible in
/// `cargo bench`'s own regression comparison, not just the perf module's
/// hard ratio assertion.
fn bench_correlate_entities_by_scale(c: &mut Criterion) {
    let mut group = c.benchmark_group("correlation_pass");
    for &n in &[100usize, 500, 1000, 2000] {
        let entities = bench_synthetic_entities(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &entities, |b, ents| {
            b.iter(|| {
                let out = bench_correlate_entities(black_box(ents), black_box("scan"));
                black_box(out.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_correlate_entities_by_scale);
criterion_main!(benches);
