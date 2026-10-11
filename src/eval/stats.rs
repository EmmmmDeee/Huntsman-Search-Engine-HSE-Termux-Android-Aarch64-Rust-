/// Fewest values a percentile bootstrap will summarise. Measured coverage of its nominal 95 %
/// interval for the mean (1,500 replications of 1,000 resamples; Monte Carlo error about 1.2
/// points): normal data 0.79 at n = 4, 0.91 at n = 10 and 0.94 at n = 30; exponential data 0.75,
/// 0.87 and 0.93. Thirty is a floor against the worst undercoverage. It is not a 95 % guarantee:
/// a t-based interval covered 0.96 at n = 30 for normal data and 0.94 for exponential data, so it
/// is the better choice for any sample this small.
pub const MIN_BOOTSTRAP_VALUES: usize = 30;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BootstrapInterval {
    pub mean: f64,
    pub low_95: f64,
    pub high_95: f64,
}

/// A xorshift64 generator. A zero state would never leave zero, so a zero seed is replaced by a
/// fixed non-zero constant and every seed produces a sequence.
#[derive(Debug, Clone, Copy)]
struct XorShift64(u64);

impl XorShift64 {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        if x == 0 {
            x = 0x9e37_79b9_7f4a_7c15;
        }
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    /// An index below `len`, which must be at least 1. The remainder is below `len`, so it fits a
    /// `usize` and the cast cannot truncate. Modulo bias is negligible because `len` is far below
    /// 2^64.
    #[allow(clippy::cast_possible_truncation)]
    fn index(&mut self, len: usize) -> usize {
        (self.next() % len as u64) as usize
    }
}

pub(crate) fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().copied().sum::<f64>() / super::count_f64(values.len())
    }
}

/// Deterministic seeded non-parametric bootstrap of the mean: `iterations` resamples of `values`,
/// each as large as `values`, and the 2.5 % and 97.5 % percentiles of their means.
///
/// Returns `None` for fewer than [`MIN_BOOTSTRAP_VALUES`] values, for zero iterations, and for any
/// non-finite value. An interval is never reported for input it cannot summarise.
#[must_use]
pub fn bootstrap_mean_ci(
    values: &[f64],
    seed: u64,
    iterations: usize,
) -> Option<BootstrapInterval> {
    if values.len() < MIN_BOOTSTRAP_VALUES
        || iterations == 0
        || values.iter().any(|value| !value.is_finite())
    {
        return None;
    }

    let mut rng = XorShift64(seed);
    let mut resampled_means = Vec::with_capacity(iterations);
    let mut sample = vec![0.0; values.len()];

    for _ in 0..iterations {
        for slot in &mut sample {
            *slot = values[rng.index(values.len())];
        }
        resampled_means.push(mean(&sample));
    }

    resampled_means.sort_by(f64::total_cmp);
    let count = resampled_means.len();
    Some(BootstrapInterval {
        mean: mean(values),
        low_95: resampled_means[quantile_index(count, 25)],
        high_95: resampled_means[quantile_index(count, 975)],
    })
}

/// Index of the `per_mille`/1000 quantile among `count` sorted values: `floor((count - 1) * p)`,
/// computed exactly in integers. `count` must be at least 1.
fn quantile_index(count: usize, per_mille: usize) -> usize {
    count.saturating_sub(1).saturating_mul(per_mille) / 1_000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The values 1.0 through `len`, as f64.
    fn sample(len: usize) -> Vec<f64> {
        (1..=len)
            .map(|n| f64::from(u32::try_from(n).expect("test samples are small")))
            .collect()
    }

    #[test]
    fn bootstrap_is_deterministic_for_same_seed() {
        let values = sample(MIN_BOOTSTRAP_VALUES);
        assert_eq!(
            bootstrap_mean_ci(&values, 7, 1000),
            bootstrap_mean_ci(&values, 7, 1000)
        );
    }

    #[test]
    fn small_samples_are_refused_not_bootstrapped() {
        // For [1, 2, 3, 4] the percentile interval is [1.5, 3.5]; a t-based 95 % interval is
        // [0.446, 4.554]. Fewer than 30 values must give no interval at all.
        assert!(bootstrap_mean_ci(&[1.0, 2.0, 3.0, 4.0], 7, 1000).is_none());
        assert!(bootstrap_mean_ci(&sample(MIN_BOOTSTRAP_VALUES - 1), 7, 1000).is_none());
        assert!(bootstrap_mean_ci(&sample(MIN_BOOTSTRAP_VALUES), 7, 1000).is_some());
    }

    #[test]
    fn invalid_input_is_not_silently_scored() {
        assert!(bootstrap_mean_ci(&[], 1, 100).is_none());
        assert!(bootstrap_mean_ci(&[f64::NAN], 1, 100).is_none());
        let mut values = sample(MIN_BOOTSTRAP_VALUES);
        values[0] = f64::NAN;
        assert!(bootstrap_mean_ci(&values, 1, 100).is_none());
        assert!(bootstrap_mean_ci(&sample(MIN_BOOTSTRAP_VALUES), 1, 0).is_none());
    }

    #[test]
    fn percentile_indices_match_the_documented_rule() {
        assert_eq!(quantile_index(1000, 25), 24);
        assert_eq!(quantile_index(1000, 975), 974);
        assert_eq!(quantile_index(1, 975), 0);
    }
}
