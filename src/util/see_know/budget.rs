//! Per-scan and per-session quota budget for SeekNow API calls, plus the
//! key-invalid latch that fast-fails the remaining lookups once a bad key is
//! detected.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::util::budget::QuotaBudget;

// Re-export the shared snapshot type so external consumers
// (`api::handlers::stats`) keep working through the original path.
pub use crate::util::budget::BudgetSnapshot;

use super::enterprise_config::ENTERPRISE;

/// Per-scan + per-session quota budget for SeekNow API calls.
///
/// Hardcoded for enterprise plan: 15,000 daily credits. Dynamically scaled at
/// scan start by probing the `/credits` endpoint via [`scale_scan_cap_from_daily`].
///
/// Scan cap: `clamp(daily_limit / 20, 300, 2500)` = 750 credits per scan for 15k plan.
///   Refreshed at each expansion-round boundary so SeekNow participates in EVERY iteration.
///
/// Session cap: 100,000 (set high; server quota is the backstop).
///   Allows consuming all available quota in one session on the 15k plan.
pub(super) static BUDGET: QuotaBudget = QuotaBudget::new(
    "seeknow",
    ENTERPRISE.scan_budget_floor,
    ENTERPRISE.session_cap,
    "HUNTSMAN_SEEKNOW_SCAN_CAP",
    "HUNTSMAN_SEEKNOW_SESSION_CAP",
);

/// Set once per scan when the `/credits` probe completes. Reset by
/// [`reset_budget`] so every scan gets a fresh probe. Avoids paying one
/// extra HTTP call per target when the module processes multiple seeds.
static QUOTA_PROBED: AtomicBool = AtomicBool::new(false);

/// True if this is the first call since [`reset_budget`] — i.e. the probe
/// has not yet run for this scan. Returns false on all subsequent calls in
/// the same scan (probe already done or no key available). Thread-safe:
/// the first concurrent caller wins; others see false.
pub fn should_probe_quota() -> bool {
    QUOTA_PROBED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
}

/// Scale the per-scan cap to the operator's actual daily allocation.
///
/// Formula: `clamp(daily_limit / 20, 300, 2500)`.
/// - Spends at most 5 % of the daily pool per scan round.
/// - Floor (300): a reasonable full-matrix pass even on small plans.
/// - Ceiling (2500): prevents runaway fan-out on unlimited/very-large plans.
///
/// The operator's env/runtime override is NOT touched — if `HUNTSMAN_SEEKNOW_SCAN_CAP`
/// is set, the probe result is used only when no explicit override was given.
/// The session cap is left unchanged (set high; server quota is the backstop).
pub fn scale_scan_cap_from_daily(daily_limit: u32) {
    // Do not override if the operator already set an explicit cap via env or
    // ScanOptions — their explicit value always takes precedence.
    if std::env::var("HUNTSMAN_SEEKNOW_SCAN_CAP")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|v| v > 0)
    {
        return;
    }
    let cap = (daily_limit / 20).clamp(300, 2500);
    BUDGET.set_scan_cap_override(cap);
    tracing::debug!(
        daily_limit,
        scan_cap = cap,
        "see_know scan cap scaled to plan quota"
    );
}

/// Latched once per process when see-know.eu rejects the configured API key.
///
/// curl exits 0 on an HTTP 401 (it got a response), so the shared curl client
/// reports success and the `{"error":"invalid_api_key"}` body parses to zero
/// items — which previously made SeekNow look like it "found nothing" on every
/// seed instead of "the key is bad". This latch makes the failure explicit and
/// fast-fails the remaining ~160 doomed lookups for the rest of the scan. It is
/// cleared by [`reset_budget`] at the start of each scan so a corrected key
/// (UI Settings / `HUNTSMAN_SEEKNOW_KEY`) recovers without a process restart.
pub(super) static KEY_INVALID: AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Install a runtime per-scan cap. `0` clears the override (falls back
/// to env + static default). The engine calls this once at scan start
/// when the operator set `ScanOptions::seeknow_scan_cap`.
pub fn set_scan_cap_override(cap: u32) {
    BUDGET.set_scan_cap_override(cap);
}

/// True if there's room in both the per-scan and per-session budgets.
/// Public so the module layer can short-circuit endpoint plans before
/// allocating per-endpoint futures.
pub fn budget_remaining() -> bool {
    BUDGET.remaining()
}

/// Remaining queries in the per-scan budget. Used by the module-layer
/// planner to decide how many specialised endpoints to dispatch.
pub fn scan_budget_remaining() -> u32 {
    BUDGET.scan_remaining()
}

/// Snapshot of current per-scan + per-session budget consumption.
/// Surfaced for diagnostics (`hse doctor`) and `/api/v1/stats`.
pub fn budget_snapshot() -> BudgetSnapshot {
    BUDGET.snapshot()
}

// Test-only now: production reserves atomically via `budget_try_increment`.
#[cfg(test)]
pub(super) fn budget_increment() {
    BUDGET.increment();
}

/// Atomically reserve one query against the SeekNow budget (see
/// [`crate::util::budget::QuotaBudget::try_increment`]). Replaces the racy
/// `budget_remaining()`-then-`budget_increment()` gate so the concurrent
/// endpoint fan-out can't overspend the per-scan/per-round cap.
pub(super) fn budget_try_increment() -> bool {
    BUDGET.try_increment()
}

/// True once the SeekNow daily quota has been tripped, so callers skip remaining
/// billable lookups for the rest of the session rather than retry into a known-
/// exhausted cap. Mirrors `oathnet::is_quota_exhausted`.
#[must_use]
pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

/// Reset SeekNow's per-scan budget at the start of every scan (long-lived
/// `hse serve` / `hse live` would otherwise accumulate across scans), and clear
/// the latched key-invalid / quota-probed flags so a scan re-tests a key the
/// operator may have fixed and re-probes the quota — see the inline notes.
pub fn reset_budget() {
    BUDGET.reset_scan();
    // Re-test the key each scan: if the operator fixed it (UI Settings /
    // HUNTSMAN_SEEKNOW_KEY) since the last scan, SeekNow recovers immediately;
    // if it's still bad, the first call this scan re-latches (one warning, then
    // the remaining lookups fast-fail).
    KEY_INVALID.store(false, Ordering::Relaxed);
    // Allow the quota probe to fire again on the next scan.
    QUOTA_PROBED.store(false, Ordering::Relaxed);
    // Clear the cross-module response cache: it dedups identical endpoint
    // queries WITHIN one scan (see `client::RESPONSE_CACHE`'s own doc
    // comment), but with no scan-boundary reset a long-lived `hse serve` /
    // `hse live` process would silently keep returning the first scan's
    // cached SeekNow records for every later re-scan of the same
    // email/username/phone, indefinitely, with no live re-check.
    super::client::RESPONSE_CACHE.clear();
}

/// Refresh SeekNow's per-round budget at each expansion-round boundary so it is
/// utilised in EVERY iteration of a scan, not just until a wide first round
/// drains the budget. Resets only the per-round counter — the per-session
/// ceiling still bounds total volume across all rounds, the operator's cap
/// override survives, and a latched-invalid key stays latched (we do not
/// re-attempt a dead key every round, unlike the per-scan [`reset_budget`]).
pub fn refresh_round_budget() {
    BUDGET.reset_round();
}

pub(super) fn mark_quota_exhausted() {
    BUDGET.mark_exhausted();
    tracing::warn!("SeekNow daily quota exhausted — skipping remaining queries");
}

/// True once see-know.eu has rejected the key. The diagnostic accessor for
/// `hse doctor` / the selftest to report it as an actionable problem.
pub fn is_key_invalid() -> bool {
    KEY_INVALID.load(Ordering::Relaxed)
}

pub(super) fn mark_key_invalid(body: &str) {
    // Emit the actionable guidance exactly once (the false→true transition),
    // naming the actual cause so the operator knows whether to swap the key or
    // upgrade the plan.
    if !KEY_INVALID.swap(true, Ordering::Relaxed) {
        let reason = if body.contains("plan_required") {
            "the account has no paid plan (plan_required) — upgrade at https://see-know.eu/pricing"
        } else {
            "the API key was rejected (invalid_api_key)"
        };
        tracing::warn!(
            "SeekNow (see-know.eu) lookups disabled: {reason}. Set a valid, \
             plan-enabled key via HUNTSMAN_SEEKNOW_KEY or the UI Settings panel."
        );
    }
}
