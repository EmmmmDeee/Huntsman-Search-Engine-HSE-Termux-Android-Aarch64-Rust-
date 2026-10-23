//! Client-side rate limiter for the HIBP API.
//!
//! HIBP rate-limits the breach, paste and stealer-log APIs per key (the plan's
//! requests-per-minute) and answers an overrun with HTTP 429 and a
//! `retry-after` header in seconds (haveibeenpwned.com/API/v3, "Rate
//! limiting"). This limiter keeps a sliding one-minute window so the client
//! stays under the plan's rate before the server has to say so, and
//! [`RateLimiter::block_for`] lets a 429's `retry-after` pause every caller
//! sharing the limiter. The Pwned Passwords API has no rate limit and does not
//! go through here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::Instant;

use crate::environment;

/// Default budget: 10 requests per minute, the lowest HIBP plan's rate.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 10;

/// A sliding-window limiter: at most `limit` acquisitions per `window`.
#[derive(Debug)]
pub struct RateLimiter {
    limit: AtomicU32,
    window: Duration,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    sent: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl RateLimiter {
    /// `per_minute` requests per 60 s. `0` means unlimited.
    #[must_use]
    pub fn per_minute(per_minute: u32) -> Self {
        Self::new(per_minute, Duration::from_secs(60))
    }

    /// `limit` requests per `window`. `0` means unlimited.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit: AtomicU32::new(limit),
            window,
            state: Mutex::new(State::default()),
        }
    }

    /// The configured limit per window.
    pub fn limit(&self) -> u32 {
        self.limit.load(Ordering::Relaxed)
    }

    /// Replace the active request budget. Existing timestamps are retained so
    /// lowering a plan limit cannot erase already-consumed capacity.
    pub fn set_limit(&self, per_minute: u32) {
        self.limit.store(per_minute, Ordering::Relaxed);
    }

    /// The process-wide limiter every HIBP caller shares, sized from
    /// `HIBP_RATE_LIMIT_PER_MINUTE` (default 10).
    pub fn shared() -> Arc<RateLimiter> {
        static SHARED: OnceLock<Arc<RateLimiter>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let rpm = environment::hibp_rate_limit_per_minute()
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .unwrap_or(DEFAULT_REQUESTS_PER_MINUTE);
                Arc::new(RateLimiter::per_minute(rpm))
            })
            .clone()
    }

    /// Wait until a request may be sent, then record it.
    pub fn acquire(&self) {
        let _ = self.acquire_within(Duration::MAX);
    }

    /// Like [`acquire`](Self::acquire), but refuse to sit out a server block
    /// (from [`block_for`](Self::block_for)) with more than `max_wait` left:
    /// return `Err(remaining)` at once, recording no send. The sliding-window
    /// wait is at most one window and is always taken.
    pub fn acquire_within(&self, max_wait: Duration) -> Result<(), Duration> {
        loop {
            let wait = {
                let mut st = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let now = Instant::now();
                match st.blocked_until {
                    Some(until) if until > now => {
                        let remaining = until - now;
                        if remaining > max_wait {
                            return Err(remaining);
                        }
                        Some(remaining)
                    }
                    _ => {
                        st.blocked_until = None;
                        let limit = self.limit();
                        if limit == 0 {
                            None
                        } else {
                            while st
                                .sent
                                .front()
                                .is_some_and(|t| now.duration_since(*t) >= self.window)
                            {
                                st.sent.pop_front();
                            }
                            if st.sent.len() < limit as usize {
                                st.sent.push_back(now);
                                None
                            } else {
                                st.sent.front().map(|oldest| (*oldest + self.window) - now)
                            }
                        }
                    }
                }
            };
            match wait {
                None => return Ok(()),
                Some(d) => std::thread::sleep(d),
            }
        }
    }

    /// Hold every caller for at least `d` (a 429's `retry-after`), capped at
    /// [`fetch::MAX_RETRY_AFTER_SECS`](crate::fetch::MAX_RETRY_AFTER_SECS) like
    /// every other provider pause.
    pub fn block_for(&self, d: Duration) {
        let d = d.min(Duration::from_secs(crate::fetch::MAX_RETRY_AFTER_SECS));
        let now = Instant::now();
        let until = now.checked_add(d).unwrap_or(now);
        let mut st = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.blocked_until.is_none_or(|b| b < until) {
            st.blocked_until = Some(until);
        }
    }
}
