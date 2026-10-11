//! One wall-clock budget for a lookup that sends several requests.
//!
//! A provider that sends more than one request (a path cascade, a bounded retry)
//! starts one [`Deadline`] for the whole lookup. Each request is sent with
//! [`crate::http::Request::with_timeout`] set to what is left of the budget, so the
//! transport stops it there; a step that would start after the budget is spent is
//! not sent, and the caller reports it as skipped. The clock is a trait so tests can
//! prove the worst case without waiting for it.

use std::time::{Duration, Instant};

/// Monotonic time and sleeping, injectable for tests.
pub trait Clock {
    fn now(&self) -> Instant;
    fn sleep(&self, duration: Duration);
}

/// The real clock: [`Instant::now`] and [`std::thread::sleep`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// A fixed budget measured from [`Deadline::start`].
pub struct Deadline<'c> {
    clock: &'c dyn Clock,
    started: Instant,
    budget: Duration,
}

impl<'c> Deadline<'c> {
    /// Start `budget` now.
    #[must_use]
    pub fn start(clock: &'c dyn Clock, budget: Duration) -> Self {
        Self {
            clock,
            started: clock.now(),
            budget,
        }
    }

    /// The whole budget this deadline was started with.
    #[must_use]
    pub const fn budget(&self) -> Duration {
        self.budget
    }

    /// Time spent since the start.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.clock.now().saturating_duration_since(self.started)
    }

    /// Time left; zero once the budget is spent.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        self.budget.saturating_sub(self.elapsed())
    }

    /// The budget is spent: nothing more may be sent.
    #[must_use]
    pub fn expired(&self) -> bool {
        self.remaining().is_zero()
    }

    /// Sleep for `pause` if at least that much budget, plus some time to act after
    /// it, remains. Returns `false` (without sleeping) otherwise.
    #[must_use]
    pub fn sleep_within(&self, pause: Duration) -> bool {
        if self.remaining() <= pause {
            return false;
        }
        self.clock.sleep(pause);
        true
    }
}

/// Test clock: time moves only when a test (or a fake transport) advances it.
#[cfg(test)]
pub(crate) struct FakeClock {
    origin: Instant,
    offset: std::cell::Cell<Duration>,
}

#[cfg(test)]
impl FakeClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
            offset: std::cell::Cell::new(Duration::ZERO),
        }
    }

    pub(crate) fn advance(&self, by: Duration) {
        self.offset.set(self.offset.get() + by);
    }

    /// Simulated time since the clock was created.
    pub(crate) fn elapsed(&self) -> Duration {
        self.offset.get()
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn now(&self) -> Instant {
        self.origin + self.offset.get()
    }

    fn sleep(&self, duration: Duration) {
        self.advance(duration);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remaining_counts_down_and_saturates_at_zero() {
        let clock = FakeClock::new();
        let d = Deadline::start(&clock, Duration::from_secs(10));
        assert_eq!(d.budget(), Duration::from_secs(10));
        assert_eq!(d.remaining(), Duration::from_secs(10));
        clock.advance(Duration::from_secs(4));
        assert_eq!(d.elapsed(), Duration::from_secs(4));
        assert_eq!(d.remaining(), Duration::from_secs(6));
        assert!(!d.expired());
        clock.advance(Duration::from_secs(60));
        assert_eq!(d.remaining(), Duration::ZERO);
        assert!(d.expired());
    }

    #[test]
    fn a_pause_is_only_taken_when_budget_is_left_after_it() {
        let clock = FakeClock::new();
        let d = Deadline::start(&clock, Duration::from_secs(5));
        assert!(d.sleep_within(Duration::from_secs(2)));
        assert_eq!(clock.elapsed(), Duration::from_secs(2));
        clock.advance(Duration::from_secs(1));
        // 2 s left: a 2 s pause would leave nothing to send with.
        assert!(!d.sleep_within(Duration::from_secs(2)));
        assert_eq!(clock.elapsed(), Duration::from_secs(3));
    }

    #[test]
    fn the_system_clock_is_monotonic() {
        let c = SystemClock;
        let a = c.now();
        c.sleep(Duration::from_millis(1));
        assert!(c.now() > a);
    }
}
