//! Throughput micro-benchmarks for the hottest pure scanners on the parse path.
//!
//! These are the functions every scraped page / response flows through, so their
//! MB/s sets the ceiling for on-device (Termux aarch64) scan throughput — the
//! "SpiderFoot in CPython structurally can't match this" claim needs a number,
//! not an assertion (PROBLEM_TREE §3.F F.1/F.3). Run with `cargo bench`; CI only
//! compiles them (`--no-run`), so they double as a perf-path API drift guard.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use huntsman_search_engine::util::geohash::geohash;
use huntsman_search_engine::util::str_util::{find_ascii_ci, fold_ascii_lower, slugify};

/// `find_ascii_ci` is the boundary-safe substring scanner that replaced the
/// `to_lowercase().find()` idiom behind the T0 panic class; it runs on every
/// HTML marker / division / suburb lookup, so its hit/miss throughput matters.
fn bench_find_ascii_ci(c: &mut Criterion) {
    // ~14 KB of realistic scraped text (multibyte content included) with the
    // needle near the end — the worst case for a forward scan.
    let mut body = "Lorem ipsum dolor sit amet, café résumé naïve — élan. ".repeat(300);
    body.push_str("Division of Sydney.");

    let mut group = c.benchmark_group("find_ascii_ci_14kb");
    group.bench_function("hit", |b| {
        b.iter(|| find_ascii_ci(black_box(&body), black_box("division of sydney")));
    });
    group.bench_function("miss", |b| {
        b.iter(|| find_ascii_ci(black_box(&body), black_box("no-such-marker-zzz")));
    });
    group.finish();
}

/// `fold_ascii_lower` normalises every scraped name/handle into its ASCII stem
/// (diacritic folding) before username/email derivation — a per-token hot path.
fn bench_fold_ascii_lower(c: &mut Criterion) {
    let name = "José Müller-Łódź Þorvaldsdóttir Straße Æsir œuvre ".repeat(64);
    c.bench_function("fold_ascii_lower_unicode", |b| {
        b.iter(|| fold_ascii_lower(black_box(&name)));
    });
}

/// `slugify` builds correlation tags from scraped status/source strings.
fn bench_slugify(c: &mut Criterion) {
    let s = "Client Transfer Prohibited — Status: OK / café¹ source";
    c.bench_function("slugify_mixed", |b| {
        b.iter(|| slugify(black_box(s)));
    });
}

/// `geohash` encodes every derived coordinate for the GEOINT correlation keys.
fn bench_geohash(c: &mut Criterion) {
    c.bench_function("geohash_precision12", |b| {
        b.iter(|| geohash(black_box(-27.4766), black_box(153.0166), black_box(12)));
    });
}

/// `util::scan::MatchSet` (SOL-F1) vs the hand-rolled N-way `.any(|p| hay.contains(p))`
/// it replaces — the anti-bot / challenge detector runs on every scraped SERP, so
/// this is the leverage the cached aho-corasick automaton buys: one Teddy/SIMD pass
/// instead of ~16 separate substring scans over the body.
fn bench_match_set_vs_linear(c: &mut Criterion) {
    use huntsman_search_engine::util::scan::MatchSet;
    // Representative of BLOCK_VENDOR_SIGNATURES (all lowercase literals).
    let pats: &[&str] = &[
        "challenges.cloudflare.com",
        "/cdn-cgi/challenge-platform",
        "cf-chl-",
        "/recaptcha/api",
        "g-recaptcha",
        "/sorry/index",
        "hcaptcha.com",
        "captcha-delivery.com",
        "datadome",
        "perimeterx",
        "px-captcha",
        "funcaptcha",
        "arkoselabs",
        "smartcaptcha",
        "anomaly-modal",
        "httpservice/retry",
    ];
    // ~14 KB of realistic page text with NO signature (worst case: full scan).
    let body = "Lorem ipsum dolor sit amet, café résumé. <div class='result'>… </div> "
        .repeat(200)
        .to_lowercase();
    let set = MatchSet::new(pats);

    let mut group = c.benchmark_group("captcha_signature_scan_14kb");
    group.bench_function("match_set", |b| {
        b.iter(|| set.is_match(black_box(&body)));
    });
    group.bench_function("linear_any_contains", |b| {
        b.iter(|| pats.iter().any(|p| black_box(&body).contains(p)));
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_find_ascii_ci,
    bench_fold_ascii_lower,
    bench_slugify,
    bench_geohash,
    bench_match_set_vs_linear
);
criterion_main!(benches);
