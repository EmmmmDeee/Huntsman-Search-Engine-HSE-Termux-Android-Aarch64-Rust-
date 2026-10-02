#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BootstrapInterval {
    pub mean: f64,
    pub low_95: f64,
    pub high_95: f64,
}

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

    fn index(&mut self, len: usize) -> usize {
        let len = u64::try_from(len).unwrap_or(u64::MAX);
        usize::try_from(self.next() % len).unwrap_or(0)
    }
}

pub(crate) fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().copied().sum::<f64>() / super::count_f64(values.len())
    }
}

/// Deterministic seeded non-parametric bootstrap of the mean.
#[must_use]
pub fn bootstrap_mean_ci(
    values: &[f64],
    seed: u64,
    iterations: usize,
) -> Option<BootstrapInterval> {
    if values.is_empty() || iterations == 0 || values.iter().any(|value| !value.is_finite()) {
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
    let last = resampled_means.len() - 1;
    let low_index = last.saturating_mul(25) / 1000;
    let high_index = last.saturating_mul(975) / 1000;

    Some(BootstrapInterval {
        mean: mean(values),
        low_95: resampled_means[low_index],
        high_95: resampled_means[high_index],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_is_deterministic_for_same_seed() {
        let values = [1.0, 2.0, 3.0, 4.0];
        assert_eq!(
            bootstrap_mean_ci(&values, 7, 1000),
            bootstrap_mean_ci(&values, 7, 1000)
        );
    }

    #[test]
    fn invalid_input_is_not_silently_scored() {
        assert!(bootstrap_mean_ci(&[], 1, 100).is_none());
        assert!(bootstrap_mean_ci(&[f64::NAN], 1, 100).is_none());
    }
}
