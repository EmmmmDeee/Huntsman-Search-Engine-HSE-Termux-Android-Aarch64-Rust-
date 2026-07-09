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

/// `strip_inline_blocks` runs on every SERP title/snippet (three times per result
/// via `strip_tags`). Its guard — "does any inline `<svg>`/`<style>`/`<script>`
/// block exist?" — dominates the common (no-block) case. The old guard allocated
/// a full lowercased copy of the body for three `contains` checks; the new one is
/// three zero-alloc NEON `find_ascii_ci` scans with identical ASCII-CI semantics.
/// This measures the two on a representative no-block snippet (the common path).
fn bench_strip_inline_guard(c: &mut Criterion) {
    let body = "<a href='https://example.org/p'>Jane Doe</a> — engineer at Acme, based in Brisbane. <span>Contact via profile.</span> ".repeat(14);

    let mut group = c.benchmark_group("strip_inline_guard_noblock");
    group.bench_function("old_lowercase_copy", |b| {
        b.iter(|| {
            let l = black_box(&body).to_ascii_lowercase();
            l.contains("<svg") || l.contains("<style") || l.contains("<script")
        });
    });
    group.bench_function("new_find_ascii_ci", |b| {
        b.iter(|| {
            find_ascii_ci(black_box(&body), "<svg").is_some()
                || find_ascii_ci(black_box(&body), "<style").is_some()
                || find_ascii_ci(black_box(&body), "<script").is_some()
        });
    });
    group.finish();
}

/// `extract_addresses_from_text` scans the (already-lowercased) result text once
/// per AU place name. The old code allocated a fresh lowercased `String` for each
/// place on every call (~97 allocs/result); the new code drops that alloc and
/// scans with NEON `find_ascii_ci`. Measured over a representative place set on a
/// miss-heavy body (most places are absent from any given result) — the common case.
fn bench_au_place_scan(c: &mut Criterion) {
    let places: &[&str] = &[
        "Brisbane",
        "Sydney",
        "Melbourne",
        "Perth",
        "Adelaide",
        "Fitzroy",
        "Collingwood",
        "South Yarra",
        "Prahran",
        "Carlton",
        "Brunswick",
        "Newtown",
        "Bondi",
        "Parramatta",
    ];
    let lower = "lorem ipsum dolor sit amet, resume cafe naive elan. ".repeat(300);

    let mut group = c.benchmark_group("au_place_scan_miss");
    group.bench_function("old_per_place_to_lowercase", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for p in places {
                let pl = p.to_lowercase();
                if black_box(&lower).find(&pl).is_some() {
                    hits += 1;
                }
            }
            hits
        });
    });
    group.bench_function("new_find_ascii_ci", |b| {
        b.iter(|| {
            let mut hits = 0usize;
            for p in places {
                if find_ascii_ci(black_box(&lower), p).is_some() {
                    hits += 1;
                }
            }
            hits
        });
    });
    group.finish();
}

/// `is_captcha_page` runs on the body of EVERY fetched response (the hottest
/// path). The old detector allocated a full Unicode-`to_lowercase()` copy of the
/// body just to match its all-ASCII vendor signatures case-insensitively; the new
/// one runs an `ascii_ci` aho-corasick pass over the RAW body — same match, no
/// allocation. Measured on a representative ~14 KB no-block body (the common case).
fn bench_is_captcha_guard(c: &mut Criterion) {
    use huntsman_search_engine::util::scan::MatchSet;
    let sigs: &[&str] = &[
        "challenges.cloudflare.com",
        "/cdn-cgi/challenge-platform",
        "cf-chl-",
        "/recaptcha/api",
        "g-recaptcha",
        "grecaptcha",
        "/sorry/index",
        "hcaptcha.com",
        "datadome",
        "perimeterx",
        "px-captcha",
        "funcaptcha",
        "arkoselabs",
        "smartcaptcha",
        "anomaly-modal",
        "httpservice/retry",
    ];
    // ~14 KB of realistic result HTML with NO block signature (worst case: full scan).
    let body = "Lorem ipsum dolor sit amet, café résumé. <div class='result'>… </div> ".repeat(200);
    let cs = MatchSet::new(sigs);
    let ci = MatchSet::new_ascii_ci(sigs);

    let mut group = c.benchmark_group("is_captcha_guard_noblock");
    group.bench_function("old_to_lowercase_then_match", |b| {
        b.iter(|| {
            let lower = black_box(&body).to_lowercase();
            cs.is_match(&lower)
        });
    });
    group.bench_function("new_ascii_ci_raw", |b| {
        b.iter(|| ci.is_match(black_box(&body)));
    });
    group.finish();
}

/// `HrefIter` enumerates every `href="…"` in a fetched page — driven over the
/// whole raw HTML body of every response by `parse_results`. The old code scanned
/// with std `str::find` (scalar Two-Way, no SIMD prefilter); the new code uses a
/// cached `memmem::Finder` + `memchr` (Teddy/NEON on aarch64). This benches the
/// two scanning strategies over a representative multi-link SERP body.
fn bench_href_scan(c: &mut Criterion) {
    use memchr::{memchr, memmem};
    let body =
        "<div class='result'><a href=\"https://example.org/page/one\">One</a> some snippet text here</div> "
            .repeat(120);

    let mut group = c.benchmark_group("href_scan");
    group.bench_function("old_std_find", |b| {
        b.iter(|| {
            let mut rem: &str = black_box(&body);
            let mut n = 0usize;
            while let Some(idx) = rem.find("href=") {
                rem = &rem[idx + 5..];
                let q = match rem.as_bytes().first() {
                    Some(&c @ (b'"' | b'\'')) => c,
                    _ => continue,
                };
                rem = &rem[1..];
                match rem.find(q as char) {
                    Some(end) => {
                        n += 1;
                        rem = &rem[end + 1..];
                    }
                    None => break,
                }
            }
            n
        });
    });
    group.bench_function("new_memmem_memchr", |b| {
        let finder = memmem::Finder::new(b"href=");
        b.iter(|| {
            let mut rem: &str = black_box(&body);
            let mut n = 0usize;
            while let Some(idx) = finder.find(rem.as_bytes()) {
                rem = &rem[idx + 5..];
                let q = match rem.as_bytes().first() {
                    Some(&c @ (b'"' | b'\'')) => c,
                    _ => continue,
                };
                rem = &rem[1..];
                match memchr(q, rem.as_bytes()) {
                    Some(end) => {
                        n += 1;
                        rem = &rem[end + 1..];
                    }
                    None => break,
                }
            }
            n
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_find_ascii_ci,
    bench_fold_ascii_lower,
    bench_slugify,
    bench_geohash,
    bench_match_set_vs_linear,
    bench_strip_inline_guard,
    bench_au_place_scan,
    bench_is_captcha_guard,
    bench_href_scan
);
criterion_main!(benches);
