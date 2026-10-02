//! Generic exponential backoff with jitter — a shared retry-pacing primitive
//! for rate-limited paid API clients (SeekNow, OathNet, …).
//!
//! Diagnosed against a real gap: neither `util::see_know` nor `util::oathnet`
//! had any time-based retry pacing at all. A transient rate-limit response
//! (SeekNow's `{"error":"rate_limit"}`, OathNet's HTTP 429) was classified
//! identically to a genuinely exhausted daily quota — both latched the shared
//! per-scan budget flag permanently for the rest of the scan, silently
//! abandoning the provider instead of backing off and retrying. This module
//! is the reusable fix: pure delay computation (fully unit-testable, no
//! sleeping), with the caller responsible for the actual `tokio::time::sleep`
//! on the live path.

use std::time::Duration;

/// How many attempts a retry loop makes, and how the delay between attempts
/// grows. Doubling ("exponential") backoff, capped, with optional jitter so
/// several concurrently-dispatched requests that all get rate-limited at once
/// don't all retry in lockstep (which would just re-trigger the same limit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    /// Total attempts including the first (non-retry) call. A policy with
    /// `max_attempts = 3` allows the initial call plus 2 retries.
    pub max_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub jitter: bool,
}

impl BackoffPolicy {
    #[must_use]
    pub const fn new(
        max_attempts: u32,
        initial_backoff_ms: u64,
        max_backoff_ms: u64,
        jitter: bool,
    ) -> Self {
        Self {
            max_attempts,
            initial_backoff_ms,
            max_backoff_ms,
            jitter,
        }
    }

    /// True while `attempt` (0-indexed — the initial call is attempt 0, so
    /// `should_retry(0)` asks "is there room for a SECOND try") is still
    /// within `max_attempts`.
    #[must_use]
    pub const fn should_retry(&self, attempt: u32) -> bool {
        attempt + 1 < self.max_attempts
    }

    /// The un-jittered delay before retry number `attempt` (0-indexed: the
    /// delay before the first retry, i.e. after attempt 0 has already
    /// failed). Doubles per attempt, capped at `max_backoff_ms`. The shift is
    /// clamped so `1u64 << shift` can never overflow regardless of how large
    /// `attempt` is.
    #[must_use]
    pub const fn base_delay_ms(&self, attempt: u32) -> u64 {
        let shift = if attempt > 31 { 31 } else { attempt };
        let scaled = self.initial_backoff_ms.saturating_mul(1u64 << shift);
        if scaled > self.max_backoff_ms {
            self.max_backoff_ms
        } else {
            scaled
        }
    }

    /// The delay to actually wait before retry number `attempt`:
    /// [`base_delay_ms`](Self::base_delay_ms) with up to ±25% jitter applied
    /// when `self.jitter` is set. Jitter is sourced from a freshly-constructed
    /// [`std::collections::hash_map::RandomState`] — its keys are randomised
    /// per construction, so hashing a fixed input still yields an
    /// unpredictable-per-call spread with zero external `rand` dependency.
    /// Never exceeds `max_backoff_ms + max_backoff_ms/4`.
    #[must_use]
    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.base_delay_ms(attempt);
        if !self.jitter || base == 0 {
            return Duration::from_millis(base);
        }
        let spread = base / 4; // ±25%
        let r = pseudo_random_u64(u64::from(attempt));
        // r % (2*spread + 1) lands in [0, 2*spread]; subtracting spread
        // centres it on [-spread, +spread].
        #[allow(clippy::cast_possible_wrap)]
        let offset = (r % (2 * spread + 1)) as i64 - spread as i64;
        #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
        let ms = (base as i64 + offset).max(0) as u64;
        Duration::from_millis(ms)
    }
}

/// Cheap, dependency-free per-call pseudo-randomness for jitter. Not
/// cryptographically secure and not meant to be — only needed to avoid
/// several concurrent retries synchronising on the exact same delay.
fn pseudo_random_u64(seed: u64) -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut h = std::collections::hash_map::RandomState::new().build_hasher();
    h.write_u64(seed);
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: BackoffPolicy = BackoffPolicy::new(3, 2_000, 8_000, false);

    #[test]
    fn should_retry_allows_exactly_max_attempts_minus_one_retries() {
        // max_attempts = 3: the initial call is attempt 0, so attempts 0 and
        // 1 must permit a retry (2 retries total), attempt 2 must not.
        assert!(POLICY.should_retry(0));
        assert!(POLICY.should_retry(1));
        assert!(!POLICY.should_retry(2));
    }

    #[test]
    fn base_delay_doubles_then_caps() {
        assert_eq!(POLICY.base_delay_ms(0), 2_000);
        assert_eq!(POLICY.base_delay_ms(1), 4_000);
        assert_eq!(POLICY.base_delay_ms(2), 8_000, "capped at max_backoff_ms");
        assert_eq!(
            POLICY.base_delay_ms(10),
            8_000,
            "stays capped for large attempts"
        );
    }

    #[test]
    fn base_delay_never_overflows_for_a_pathological_attempt_count() {
        // A defensive bound: an attempt counter that somehow grew huge (a bug
        // elsewhere looping past max_attempts) must never panic on shift
        // overflow -- it just stays capped.
        assert_eq!(POLICY.base_delay_ms(u32::MAX), POLICY.max_backoff_ms);
    }

    #[test]
    fn no_jitter_delay_matches_base_delay_exactly() {
        for attempt in 0..5 {
            assert_eq!(
                POLICY.delay(attempt).as_millis() as u64,
                POLICY.base_delay_ms(attempt)
            );
        }
    }

    #[test]
    fn jittered_delay_stays_within_the_documented_spread() {
        let jittered = BackoffPolicy::new(3, 2_000, 8_000, true);
        for attempt in 0..4 {
            let base = jittered.base_delay_ms(attempt);
            let spread = base / 4;
            for _ in 0..50 {
                let ms = jittered.delay(attempt).as_millis() as u64;
                assert!(
                    ms <= base + spread,
                    "jittered delay {ms} exceeds base {base} + spread {spread}"
                );
            }
        }
    }

    #[test]
    fn jittered_delay_at_zero_base_is_never_negative_or_panicking() {
        // initial_backoff_ms = 0 -> base_delay_ms(0) = 0 -> spread = 0 ->
        // the modulo-by-(2*spread+1) branch must not divide by zero or panic.
        let zero_base = BackoffPolicy::new(3, 0, 8_000, true);
        assert_eq!(zero_base.delay(0), Duration::from_millis(0));
    }

    #[test]
    fn jitter_actually_varies_the_delay_across_calls() {
        // Not a security property, just confirms the "avoid lockstep retries"
        // goal is real: repeated calls at the same attempt number should not
        // all return the identical delay (statistically overwhelming odds of
        // at least one different value across 100 draws from a real spread).
        let jittered = BackoffPolicy::new(3, 4_000, 8_000, true);
        let first = jittered.delay(0);
        let saw_a_different_value = (0..100).any(|_| jittered.delay(0) != first);
        assert!(
            saw_a_different_value,
            "jitter must vary the delay across calls, not return one fixed value"
        );
    }
}
