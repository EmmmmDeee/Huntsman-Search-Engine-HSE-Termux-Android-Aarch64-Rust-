//! Per-process module circuit breaker.
//!
//! A debug log from a real alias scan showed the same providers failing the same
//! way on *every* expansion target — `hackertarget` "API count exceeded",
//! `urlscan` HTTP 429, `crtsh` connection errors, `wayback`/`search_engines`
//! timeouts — and being re-dispatched each round regardless. Retrying a
//! quota-exhausted or rate-limited endpoint is guaranteed waste: it burns a
//! dispatch slot and a timeout window that should go to a source that still
//! works, and hammering a 429'd endpoint only extends the ban. Across a deep
//! scan's many targets that waste compounds, starving the productive methods of
//! the very budget that finds more on the subject.
//!
//! The breaker trips a module that reports a *retry-futile* failure so the rest
//! of the scan — and any concurrent scan sharing the same rate-limited endpoint —
//! skips it cleanly until a cooldown elapses:
//!
//!   * **rate-limit / quota / payment** (HTTP 429/402, "rate limit", "quota",
//!     "count exceeded", "credit") → trips immediately. These are deterministic:
//!     the next call cannot succeed until the window resets, so one trip saves
//!     every remaining per-target retry. The cooldown is tuned to the provider's
//!     own reset hint where the message carries one — an explicit `Retry-After` /
//!     `X-RateLimit-Reset`, else a short [`THROTTLE_COOLDOWN`] for a bare 429 and
//!     the long [`RATE_LIMIT_COOLDOWN`] for a billing-cycle quota wall (see
//!     [`cooldown_for`]).
//!   * **hard transport error / timeout** → a single occurrence can be transient
//!     (a flaky DNS hop), so it trips only after [`SOFT_TRIP_THRESHOLD`]
//!     consecutive failures, for the shorter [`SOFT_COOLDOWN`]; one success
//!     resets the streak.
//!
//! Process-global on purpose: a rate limit is a property of the *endpoint*, not
//! of one scan, so a 429 seen by scan A should back scan B off the same provider
//! too. Synthetic/offline modules never fail, so the breaker stays closed and has
//! zero effect on deterministic test scans.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Default cooldown for a rate-limit/quota/payment trip when the provider gives
/// no explicit reset window. Long enough to outlast a typical scan (so the
/// provider isn't re-hit per target) and the daily-quota / credit-exhaustion
/// resets seen in the wild (those windows are hours, but a re-probe after 10 min
/// is cheap insurance). It auto-clears, so a transient spike doesn't disable a
/// provider forever. When the error carries a `Retry-After` / `X-RateLimit-Reset`
/// (or is a plain 429), [`cooldown_for`] tunes the window to the real reset
/// instead of using this blunt constant.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(600);
/// Cooldown for a plain HTTP 429 with no explicit reset header in the message.
/// 429s are short, transient throttles (urlscan resets in ~300 s), so locking a
/// provider out for the full [`RATE_LIMIT_COOLDOWN`] would waste the rest of its
/// usable budget for this scan.
const THROTTLE_COOLDOWN: Duration = Duration::from_secs(300);
/// Floor/ceiling for a cooldown parsed from a provider's reset hint. The floor
/// stops a `Retry-After: 0` (or an already-elapsed epoch) from collapsing the
/// breaker to a no-op; the ceiling stops a malformed or hostile multi-day value
/// from disabling a provider for the whole process.
const MIN_PARSED_COOLDOWN: Duration = Duration::from_secs(5);
const MAX_PARSED_COOLDOWN: Duration = Duration::from_secs(86_400);
/// Consecutive hard-error/timeout failures before a soft trip. One or two can be
/// a flaky network hop; three in a row is a provider that's down for this run.
const SOFT_TRIP_THRESHOLD: u32 = 3;
/// Cooldown for a soft (down/timeout) trip — shorter, since the provider may
/// recover mid-scan; expiry lets it be retried once more.
const SOFT_COOLDOWN: Duration = Duration::from_secs(120);

struct Trip {
    /// `Some(t)` ⇒ the module is tripped and skipped while `Instant::now() < t`.
    /// `None` ⇒ the entry only tracks a soft-failure streak that hasn't yet
    /// reached the trip threshold (so it must NOT be treated as expired/pruned).
    open_until: Option<Instant>,
    /// Consecutive soft failures since the last success (drives the soft trip).
    fail_streak: u32,
}

fn state() -> &'static Mutex<HashMap<&'static str, Trip>> {
    static STATE: OnceLock<Mutex<HashMap<&'static str, Trip>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Classify a module error message as a retry-futile rate-limit/quota signal.
/// Case-insensitive substring match over the vocabulary providers actually use
/// (HTTP status codes plus the prose variants seen across hackertarget/urlscan/
/// shodan/etc.). A false negative just means the slower soft path eventually
/// trips it; a false positive only costs one cooldown.
fn is_rate_limited(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    [
        "429",
        "too many requests",
        "rate limit",
        "rate-limit",
        "ratelimit",
        "quota",
        "count exceeded",
        "credit",
        "payment required",
        "402",
        "exceeded",
    ]
    .iter()
    .any(|needle| m.contains(needle))
}

/// True if `name` is currently tripped (within its cooldown). Consulted by the
/// dispatch gate before a module runs. Expired trips are pruned lazily here so a
/// recovered provider is retried without a background sweeper.
pub(super) fn is_open(name: &str) -> bool {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match g.get(name) {
        // Tripped and still cooling down.
        Some(t) if t.open_until.is_some_and(|u| Instant::now() < u) => true,
        // Tripped but the cooldown elapsed: clear the entry so a recovered
        // provider is retried (a fresh failure starts a new streak).
        Some(t) if t.open_until.is_some() => {
            g.remove(name);
            false
        }
        // Entry exists only to track a soft-failure streak (not yet tripped) —
        // NOT expired; leave it so the streak can still reach the threshold.
        Some(_) | None => false,
    }
}

/// Record that `name` just hit a rate-limit/quota/payment wall → trip now for the
/// default [`RATE_LIMIT_COOLDOWN`]. Use [`record_error`] where the provider's
/// message is available: it tunes the cooldown to the reported reset window via
/// [`cooldown_for`].
pub(super) fn record_rate_limit(name: &'static str) {
    trip(name, RATE_LIMIT_COOLDOWN);
}

/// Record a hard transport error or timeout. Trips only once the failure streak
/// reaches [`SOFT_TRIP_THRESHOLD`], for [`SOFT_COOLDOWN`].
pub(super) fn record_soft_failure(name: &'static str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(name).or_insert(Trip {
        open_until: None,
        fail_streak: 0,
    });
    entry.fail_streak = entry.fail_streak.saturating_add(1);
    if entry.fail_streak >= SOFT_TRIP_THRESHOLD {
        entry.open_until = Some(Instant::now() + SOFT_COOLDOWN);
    }
}

/// Record a successful dispatch → clear any failure state for `name`, so a
/// provider that recovers is immediately trusted again.
pub(super) fn record_success(name: &str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    g.remove(name);
}

/// Classify and record one module outcome's error in a single call from the
/// dispatch finaliser: rate-limit signals trip immediately, everything else is a
/// soft failure. (Timeouts are recorded by the caller via `record_soft_failure`,
/// since they carry no message to classify.)
///
/// A rate-limit trip's cooldown is tuned to the provider's own reset hint via
/// [`cooldown_for`], so a short urlscan 429 (~300 s) isn't locked out for the
/// full default window while a daily-quota provider gets a longer one. When the
/// message yields no tuning signal it falls back to [`record_rate_limit`]'s
/// default window.
pub(super) fn record_error(name: &'static str, msg: &str) {
    if !is_rate_limited(msg) {
        record_soft_failure(name);
        return;
    }
    match cooldown_for(msg) {
        Some(cooldown) => trip(name, cooldown),
        // No reset hint and no short-throttle signal → the blunt default window.
        None => record_rate_limit(name),
    }
}

/// Pick a *tuned* rate-limit cooldown from a provider's error message, or `None`
/// to fall back to the default [`RATE_LIMIT_COOLDOWN`].
///
/// Precedence (first match wins):
///   1. An explicit `Retry-After: <seconds>` or `X-RateLimit-Reset: <value>` — a
///      small value is treated as a delay in seconds; a large value is treated as
///      a Unix-epoch reset timestamp and converted to a delay from now. Either is
///      clamped to [`MIN_PARSED_COOLDOWN`]..=[`MAX_PARSED_COOLDOWN`].
///   2. A daily-quota / credit / payment signal → `None` (the long default — these
///      reset on a billing cycle, not in minutes).
///   3. A plain HTTP 429 throttle with no reset hint → the short
///      [`THROTTLE_COOLDOWN`].
///   4. Anything else still classed as rate-limited → `None` (the default window).
fn cooldown_for(msg: &str) -> Option<Duration> {
    if let Some(d) = parse_reset_hint(msg) {
        return Some(d);
    }
    let m = msg.to_ascii_lowercase();
    // A quota/credit/payment wall is a billing-cycle reset, not a per-minute
    // throttle — keep the long default so the provider isn't re-probed every target.
    if [
        "quota",
        "count exceeded",
        "credit",
        "payment required",
        "402",
    ]
    .iter()
    .any(|needle| m.contains(needle))
    {
        return None;
    }
    // A bare 429 / "too many requests" / "rate limit" is a short throttle.
    if [
        "429",
        "too many requests",
        "rate limit",
        "rate-limit",
        "ratelimit",
    ]
    .iter()
    .any(|needle| m.contains(needle))
    {
        return Some(THROTTLE_COOLDOWN);
    }
    None
}

/// Extract an explicit reset window (in seconds) from a `Retry-After` or
/// `X-RateLimit-Reset` token in `msg`, returning a clamped [`Duration`].
///
/// Recognises the header name (case-insensitively) followed by an optional `:`/
/// `=` and whitespace, then the first run of ASCII digits. A value at or below
/// `now`'s epoch order of magnitude is a relative delay; a larger one is an
/// absolute Unix timestamp converted to a delay from the current wall clock.
/// HTTP-date `Retry-After` values are not parsed (no date lib in this crate);
/// they fall through to the heuristic, which is safe.
fn parse_reset_hint(msg: &str) -> Option<Duration> {
    let lower = msg.to_ascii_lowercase();
    let secs = parse_after_label(&lower, "retry-after")
        .or_else(|| parse_after_label(&lower, "x-ratelimit-reset"))
        .or_else(|| parse_after_label(&lower, "x-rate-limit-reset"))?;
    // Distinguish a relative delay from an absolute epoch: anything beyond ~10
    // years of seconds (3e8) can only be a Unix timestamp, so convert it to a
    // delay from the current wall clock. Smaller values are taken as a delay.
    const EPOCH_THRESHOLD: u64 = 300_000_000;
    let delay = if secs >= EPOCH_THRESHOLD {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        secs.saturating_sub(now)
    } else {
        secs
    };
    Some(Duration::from_secs(delay).clamp(MIN_PARSED_COOLDOWN, MAX_PARSED_COOLDOWN))
}

/// Find `label` in `haystack` (already lowercased) and parse the first run of
/// ASCII digits after it, skipping one optional `:` or `=` and any whitespace.
fn parse_after_label(haystack: &str, label: &str) -> Option<u64> {
    let after = haystack.split_once(label).map(|(_, rest)| rest)?;
    let digits: String = after
        .trim_start_matches([':', '=', ' ', '\t'])
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    // A non-empty digit run that overflows u64 is treated as absent (None), not
    // as a huge cooldown; the heuristic fallback then applies.
    digits.parse::<u64>().ok()
}

fn trip(name: &'static str, cooldown: Duration) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(name).or_insert(Trip {
        open_until: None,
        fail_streak: 0,
    });
    entry.open_until = Some(Instant::now() + cooldown);
    entry.fail_streak = entry.fail_streak.saturating_add(1);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
