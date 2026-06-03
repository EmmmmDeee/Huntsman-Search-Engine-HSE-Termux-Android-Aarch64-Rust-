//! Small, dependency-free statistical estimators shared across the engine.
//!
//! These are deliberately textbook, pure-`f64` functions: no AI/ML, no
//! randomness, no allocation — identical results on every platform (the
//! runtime-independence charter). They exist so decision logic across the
//! codebase scores on *sample-size-aware* statistics rather than raw point
//! estimates, which over-fire on the small samples OSINT modules routinely
//! work with.

/// Most frequent item (statistical mode), ties broken lexicographically so the
/// result is deterministic. `None` for an empty slice.
pub fn mode<'a>(items: &[&'a str]) -> Option<&'a str> {
    if items.is_empty() {
        return None;
    }
    let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for &item in items {
        *counts.entry(item).or_default() += 1;
    }
    counts
        .into_iter()
        .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
        .map(|(val, _)| val)
}

/// [`mode`] with a fallback for the empty case.
pub fn mode_or<'a>(items: &[&'a str], fallback: &'a str) -> &'a str {
    mode(items).unwrap_or(fallback)
}

/// z for a two-sided 95% confidence interval (standard-normal quantile).
pub(crate) const Z_95: f64 = 1.96;

/// Wilson score interval lower bound for a binomial proportion.
///
/// Given `successes` out of `n` trials, returns the lower endpoint of the
/// `z`-sigma Wilson score confidence interval for the true proportion
/// (`z = `[`Z_95`]` ≈ 95%`). Unlike the raw proportion `successes / n`, this
/// bound collapses toward 0 when `n` is small, so a noisy `4/5 = 0.80` sample
/// reports a lower bound of only ≈0.38 — the honest "not enough evidence yet"
/// signal a raw point estimate hides. Returns `0.0` for `n == 0`.
///
/// The Wilson interval is the standard small-sample-safe estimator: unlike the
/// normal (Wald) approximation it does not collapse to a zero-width interval at
/// the `p̂ = 0` / `p̂ = 1` extremes, which is exactly where module-yield and
/// activity-concentration proportions tend to sit.
pub(crate) fn wilson_lower_bound(successes: u64, n: u64, z: f64) -> f64 {
    if n == 0 {
        return 0.0;
    }
    let n = n as f64;
    let phat = successes as f64 / n;
    let z2 = z * z;
    let denom = 1.0 + z2 / n;
    let centre = phat + z2 / (2.0 * n);
    let margin = z * ((phat * (1.0 - phat) + z2 / (4.0 * n)) / n).sqrt();
    ((centre - margin) / denom).clamp(0.0, 1.0)
}

/// Empirical-Bayes shrunk mean: the sample mean `total / scans` pulled toward
/// `global_mean` with prior weight `pseudo` (in pseudo-observations). Low-sample
/// inputs are pulled hardest — a 3-observation fluke is regressed toward the
/// global average — while a high-sample input's own mean dominates. Converges
/// to the raw mean as `scans → ∞`. This is the IMDb / Bayesian-average ranking
/// estimator, made explicit.
pub(crate) fn shrunk_mean(total: u64, scans: u64, global_mean: f64, pseudo: f64) -> f64 {
    (total as f64 + pseudo * global_mean) / (scans as f64 + pseudo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wilson_zero_trials_is_zero() {
        assert_eq!(wilson_lower_bound(0, 0, Z_95), 0.0);
    }

    #[test]
    fn wilson_bound_stays_in_unit_interval_and_below_point_estimate() {
        for (s, n) in [(0, 7), (3, 7), (7, 7), (1, 1), (4, 5), (50, 50)] {
            let lb = wilson_lower_bound(s, n, Z_95);
            assert!((0.0..=1.0).contains(&lb), "{s}/{n} out of range: {lb}");
            let phat = s as f64 / n as f64;
            assert!(lb <= phat + 1e-12, "lb {lb} must not exceed p̂ {phat}");
        }
    }

    #[test]
    fn wilson_bound_tightens_with_more_evidence() {
        // Same 100% sample proportion, more trials ⇒ higher (tighter) bound.
        let n5 = wilson_lower_bound(5, 5, Z_95);
        let n20 = wilson_lower_bound(20, 20, Z_95);
        let n100 = wilson_lower_bound(100, 100, Z_95);
        assert!(n5 < n20 && n20 < n100, "monotone in n: {n5} {n20} {n100}");
        // A noisy 4/5 is nowhere near "confidently high".
        assert!(wilson_lower_bound(4, 5, Z_95) < 0.5);
    }

    #[test]
    fn shrunk_mean_regresses_and_converges() {
        let global = 3.0;
        let lucky = shrunk_mean(27, 3, global, 5.0); // raw 9.0, only 3 scans
        let proven = shrunk_mean(300, 50, global, 5.0); // raw 6.0, 50 scans
        assert!(proven > lucky, "proven must outrank a 3-scan fluke");
        assert!(lucky > global && lucky < 9.0, "fluke pulled toward prior");
        let big = shrunk_mean(6_000_000, 1_000_000, global, 5.0);
        assert!((big - 6.0).abs() < 1e-3, "converges to raw mean: {big}");
    }
}
