//! HIBP's request budget, one [`RateLimiter`] for the whole process.
//!
//! HIBP rate-limits the breach, paste and stealer-log APIs per key (the plan's
//! requests-per-minute) and answers an overrun with HTTP 429 and a
//! `retry-after` header in seconds (haveibeenpwned.com/API/v3, "Rate
//! limiting"). This limiter keeps a sliding one-minute window so the client
//! stays under the plan's rate before the server has to say so, and
//! [`RateLimiter::block_for`] lets a 429's `retry-after` pause every caller
//! sharing the limiter. The Pwned Passwords API has no rate limit and does not
//! go through here.

use std::sync::{Arc, OnceLock};

pub use crate::rate_limit::RateLimiter;

use crate::environment;

/// Default budget: 10 requests per minute, the lowest HIBP plan's rate.
pub const DEFAULT_REQUESTS_PER_MINUTE: u32 = 10;

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
