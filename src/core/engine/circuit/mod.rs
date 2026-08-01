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
//!   * **rate-limit / quota / payment** (HTTP 429/402 as a standalone token,
//!     "rate limit", "quota", "count exceeded", "out of credit", …) → trips
//!     immediately for [`RATE_LIMIT_COOLDOWN`]. These are deterministic: the
//!     next call cannot succeed until the window resets, so one trip saves
//!     every remaining per-target retry. The vocabulary is deliberately
//!     narrow (see [`is_rate_limited`]) — a bare "exceeded" or "credit" also
//!     matches a transport timeout or an echoed breach record, which would
//!     wrongly bench a healthy provider.
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
use std::time::{Duration, Instant};

/// Cooldown for a rate-limit/quota/payment trip. Long enough to outlast a typical
/// scan (so the provider isn't re-hit per target) and the common reset windows
/// seen in the wild (urlscan resets in ~300 s; daily quotas are longer still).
/// It auto-clears, so a transient spike doesn't disable a provider forever.
const RATE_LIMIT_COOLDOWN: Duration = Duration::from_secs(600);
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
    /// Stable label for logs/telemetry; the operator-facing skip reason is a
    /// separate `&'static str` returned by the dispatch gate.
    reason: &'static str,
}

fn state() -> &'static Mutex<HashMap<&'static str, Trip>> {
    static STATE: OnceLock<Mutex<HashMap<&'static str, Trip>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Rate-limit/quota/payment prose distinctive enough to match as a plain
/// case-insensitive substring — each is a multi-word or compound phrase that
/// doesn't occur inside unrelated text. Deliberately excludes the bare, single
/// words `exceeded` and `credit`: those alone match a transport timeout's
/// "deadline exceeded" and a breach record's "credit card", so a healthy
/// module doing perfectly normal work could trip the long
/// [`RATE_LIMIT_COOLDOWN`] on a coincidental substring in its own error text
/// or in scraped content it happened to echo back.
const QUOTA_PROSE: &[&str] = &[
    "too many requests",
    "rate limit",
    "rate-limit",
    "ratelimit",
    "quota",
    "payment required",
    "count exceeded",
    "limit exceeded",
    "requests exceeded",
    "credit exhausted",
    "out of credit",
    "insufficient credit",
    "credit exceeded",
];

/// Classify a module error message as a retry-futile rate-limit/quota signal.
///
/// Two matchers, both hardened against false positives — a hard match trips
/// the long [`RATE_LIMIT_COOLDOWN`] (600s), which silently drops every
/// subsequent finding a healthy provider would otherwise have produced for the
/// rest of the scan:
/// 1. the distinctive [`QUOTA_PROSE`] compounds (case-insensitive substring);
///    and
/// 2. the HTTP status codes `429`/`402` matched ONLY as a standalone token —
///    split on non-alphanumeric bytes — so a digit run that merely *contains*
///    them (an echoed phone number like `+61429551402`, an ID, a breach
///    record) can't trip the breaker.
///
/// Anything not caught here falls through to the [`SOFT_TRIP_THRESHOLD`]
/// soft path: a genuinely persistent quota wall still trips, just after a
/// couple of retries and with the shorter [`SOFT_COOLDOWN`] — a false
/// negative here costs a retry or two, never a wrongly-benched healthy
/// provider.
fn is_rate_limited(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    if QUOTA_PROSE.iter().any(|needle| m.contains(needle)) {
        return true;
    }
    m.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok == "429" || tok == "402")
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

/// [`Trip::reason`] set by [`record_rate_limit`] — the one hard, deterministic
/// trip cause (as opposed to a soft failure streak's reason strings). Shared
/// as a constant so [`record_success`]'s check can never drift from the
/// literal that actually gets stored.
const RATE_LIMIT_REASON: &str = "rate-limit/quota";

/// Record that `name` just hit a rate-limit/quota/payment wall → trip now for
/// [`RATE_LIMIT_COOLDOWN`].
pub(super) fn record_rate_limit(name: &'static str) {
    trip(name, RATE_LIMIT_COOLDOWN, RATE_LIMIT_REASON);
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
        reason: "repeated failure",
    });
    entry.fail_streak = entry.fail_streak.saturating_add(1);
    if entry.fail_streak >= SOFT_TRIP_THRESHOLD {
        entry.open_until = Some(Instant::now() + SOFT_COOLDOWN);
        entry.reason = "repeated failure/timeout";
    }
}

/// Record a successful dispatch → clear any failure state for `name`, so a
/// provider that recovers is immediately trusted again.
///
/// Does NOT clear an active [`RATE_LIMIT_REASON`] trip still within its
/// cooldown. A rate limit is a property of the endpoint, deterministic until
/// `open_until` elapses (see the module doc) — but `is_open` is consulted only
/// once, before dispatch, so two concurrent scans (`hse serve` allows up to 8,
/// `MAX_CONCURRENT_SCANS`) can both pass the gate before either finishes. If
/// scan A's call then 429s and trips the breaker while scan B's already-in-
/// flight call to the same module succeeds a moment later, an unconditional
/// `remove` here would erase the cooldown A just set — reopening the exact
/// retry-futile window this breaker exists to close, for every scan sharing
/// the endpoint. A soft (non-rate-limit) trip's "one success resets the
/// streak" self-healing behaviour (see [`record_soft_failure`]) is preserved:
/// only a live rate-limit cooldown is protected from a stale concurrent
/// success.
pub(super) fn record_success(name: &str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(t) = g.get(name)
        && t.reason == RATE_LIMIT_REASON
        && t.open_until.is_some_and(|u| Instant::now() < u)
    {
        return;
    }
    g.remove(name);
}

/// Classify and record one module outcome's error in a single call from the
/// dispatch finaliser: rate-limit signals trip immediately, everything else is a
/// soft failure. (Timeouts are recorded by the caller via `record_soft_failure`,
/// since they carry no message to classify.)
pub(super) fn record_error(name: &'static str, msg: &str) {
    if is_rate_limited(msg) {
        record_rate_limit(name);
    } else {
        record_soft_failure(name);
    }
}

fn trip(name: &'static str, cooldown: Duration, reason: &'static str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(name).or_insert(Trip {
        open_until: None,
        fail_streak: 0,
        reason,
    });
    entry.open_until = Some(Instant::now() + cooldown);
    entry.fail_streak = entry.fail_streak.saturating_add(1);
    entry.reason = reason;
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
