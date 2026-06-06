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
//! No `criterion` (or any bench dependency) on purpose: it would pull a heavy
//! transitive tree into a project that is rigorously minimal-dependency for the
//! Termux aarch64 build. `std::time::Instant` + a min-of-iterations estimator is
//! enough to characterise an O(n) vs O(n²) difference, which is all this guards.

use std::time::Instant;

use crate::core::entity::{Entity, EntityKind, Evidence};

/// Build a representative confirmed-entity set of `n` entities that exercises the
/// heavier rules with *real* work (not early-outs):
///
/// * ~¼ `Username` + ~¼ `Email` drawn from a shared, overlapping handle space, so
///   AU-034 (handle reuse) actually matches across the two sets — the path that
///   was quadratic. Username and email of a shared handle carry *different*
///   evidence sources, so the rule's ≥2-distinct-source gate is satisfied and the
///   match work is performed rather than skipped.
/// * the remaining half spread across the other kinds, a fraction tagged
///   `breach`/`stealer-log` with multi-source evidence, to give the breach /
///   identity / corroboration rules realistic input.
///
/// Pure and deterministic (no RNG) so runs are comparable.
fn synthetic_entities(n: usize) -> Vec<Entity> {
    let mut out = Vec::with_capacity(n);
    let quarter = n / 4;
    // Shared handle space: handles repeat every `handle_space` indices so a
    // username and an email can land on the same canonical handle.
    let handle_space = (quarter / 2).max(1);

    for i in 0..n {
        let bucket = i % 4;
        let mut e = match bucket {
            0 => {
                // Username on a shared handle, observed on a platform.
                let mut e = Entity::new(
                    EntityKind::Username,
                    format!("handle{:04}", i % handle_space),
                    0.8,
                    "scan",
                );
                e.add_evidence(Evidence::new("username_search", "observed"));
                e
            }
            1 => {
                // Email whose local-part is the same shared handle, from a
                // *different* source so AU-034's ≥2-source gate passes.
                let mut e = Entity::new(
                    EntityKind::Email,
                    format!("handle{:04}@example{}.com", i % handle_space, i % 7),
                    0.8,
                    "scan",
                );
                e.add_evidence(Evidence::new("hunter_io", "observed"));
                if i % 5 == 0 {
                    e.tag(crate::core::tags::BREACH);
                    e.add_evidence(Evidence::new("oathnet_pro", "breach row"));
                }
                e
            }
            2 => {
                let kind = match (i / 4) % 4 {
                    0 => EntityKind::IpAddress,
                    1 => EntityKind::Domain,
                    2 => EntityKind::Person,
                    _ => EntityKind::Address,
                };
                let mut e = Entity::new(kind, format!("v{i}"), 0.7, "scan");
                e.add_evidence(Evidence::new("name_intel", "derived"));
                if i % 11 == 0 {
                    e.tag(crate::core::tags::STEALER_LOG);
                }
                e
            }
            _ => {
                let kind = match (i / 4) % 3 {
                    0 => EntityKind::Url,
                    1 => EntityKind::CryptoAddress,
                    _ => EntityKind::Organisation,
                };
                let mut e = Entity::new(kind, format!("w{i}"), 0.6, "scan");
                e.add_evidence(Evidence::new("exa_search", "hit"));
                e
            }
        };
        e.tag("src");
        out.push(e);
    }
    out
}

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
        let ents = synthetic_entities(n);
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

    let small = synthetic_entities(SMALL);
    let large = synthetic_entities(LARGE);
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
