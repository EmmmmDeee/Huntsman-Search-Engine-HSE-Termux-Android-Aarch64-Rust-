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
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::time::Instant;

/// Default budget: 10 requests per minute, the lowest HIBP plan's rate.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 10;

/// Environment variable overriding [`DEFAULT_REQUESTS_PER_MINUTE`] for the
/// process-wide limiter. `0` disables client-side limiting (429 handling stays).
pub const RATE_LIMIT_ENV: &str = "HIBP_RATE_LIMIT_PER_MINUTE";

/// A sliding-window limiter: at most `limit` acquisitions per `window`.
#[derive(Debug)]
pub struct RateLimiter {
    limit: u32,
    window: Duration,
    state: tokio::sync::Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    sent: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

impl RateLimiter {
    /// `per_minute` requests per 60 s. `0` means unlimited.
    pub fn per_minute(per_minute: u32) -> Self {
        Self::new(per_minute, Duration::from_secs(60))
    }

    /// `limit` requests per `window`. `0` means unlimited.
    pub fn new(limit: u32, window: Duration) -> Self {
        Self {
            limit,
            window,
            state: tokio::sync::Mutex::new(State::default()),
        }
    }

    /// The configured limit per window.
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// The process-wide limiter every HIBP caller shares, sized from
    /// `HIBP_RATE_LIMIT_PER_MINUTE` (default 10).
    pub fn shared() -> Arc<RateLimiter> {
        static SHARED: OnceLock<Arc<RateLimiter>> = OnceLock::new();
        SHARED
            .get_or_init(|| {
                let rpm = std::env::var("HIBP_RATE_LIMIT_PER_MINUTE")
                    .ok()
                    .and_then(|v| v.trim().parse::<u32>().ok())
                    .unwrap_or(DEFAULT_REQUESTS_PER_MINUTE);
                Arc::new(RateLimiter::per_minute(rpm))
            })
            .clone()
    }

    /// Wait until a request may be sent, then record it.
    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut st = self.state.lock().await;
                let now = Instant::now();
                match st.blocked_until {
                    Some(until) if until > now => Some(until - now),
                    _ => {
                        st.blocked_until = None;
                        if self.limit == 0 {
                            None
                        } else {
                            while st
                                .sent
                                .front()
                                .is_some_and(|t| now.duration_since(*t) >= self.window)
                            {
                                st.sent.pop_front();
                            }
                            if st.sent.len() < self.limit as usize {
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
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }

    /// Hold every caller for at least `d` (a 429's `retry-after`).
    pub async fn block_for(&self, d: Duration) {
        let mut st = self.state.lock().await;
        let until = Instant::now() + d;
        if st.blocked_until.is_none_or(|b| b < until) {
            st.blocked_until = Some(until);
        }
    }
}
