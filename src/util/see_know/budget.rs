//! Per-scan and per-session quota budget for SeekNow API calls, plus the
//! key-invalid latch that fast-fails the remaining lookups once a bad key is
//! detected.

use crate::util::budget::QuotaBudget;

// Re-export the shared snapshot type so external consumers
// (`api::handlers::stats`) keep working through the original path.
pub use crate::util::budget::BudgetSnapshot;

/// Per-scan + per-session quota budget for SeekNow API calls.
///
/// SeekNow's premiumhq plan grants 5,000 daily lookups — compared with
/// OathNet's much smaller pool, this is effectively unlimited for a single
/// Termux-Android operator. The standing directive is to use see-know.eu
/// MAXIMALLY: fire every useful endpoint on every viable seed, recurse
/// pivots at full depth, and spend quota generously to maximise
/// cross-correlation, confidence, and graph coverage. Budget caps are a
/// safety net against bugs and misconfiguration, not a rationing policy.
///
/// Scan cap (default 300, env `HUNTSMAN_SEEKNOW_SCAN_CAP`,
/// runtime `ScanOptions::seeknow_scan_cap`):
///   A Username seed plans the full 18-endpoint matrix (breach+stealer+
///   external via `/search`, social aggregate, all platform profiles,
///   username history, discord/steam pivots). With 10 recursively-discovered
///   pivots and the full matrix, that is ~180 calls per round. The cap at 300
///   comfortably covers one full round plus one depth pass, while a single
///   scan still consumes only 6 % of the daily 5,000 pool. The cap is
///   refreshed at each expansion-round boundary ([`refresh_round_budget`])
///   so SeekNow participates in EVERY iteration.
///
/// Session cap (default 4,500, env `HUNTSMAN_SEEKNOW_SESSION_CAP`):
///   Bounds total dispatch across all scans in one `hse serve` / `hse live`
///   process lifetime — 90 % of the daily pool, leaving 500 for other
///   incidental usage. At the per-scan cap this allows ~15 full scans per
///   session before the server's own quota-exhaustion response takes over.
pub(super) static BUDGET: QuotaBudget = QuotaBudget::new(
    "seeknow",
    300,
    4500,
    "HUNTSMAN_SEEKNOW_SCAN_CAP",
    "HUNTSMAN_SEEKNOW_SESSION_CAP",
);

/// Latched once per process when see-know.eu rejects the configured API key.
///
/// curl exits 0 on an HTTP 401 (it got a response), so the shared curl client
/// reports success and the `{"error":"invalid_api_key"}` body parses to zero
/// items — which previously made SeekNow look like it "found nothing" on every
/// seed instead of "the key is bad". This latch makes the failure explicit and
/// fast-fails the remaining ~160 doomed lookups for the rest of the scan. It is
/// cleared by [`reset_budget`] at the start of each scan so a corrected key
/// (UI Settings / `HUNTSMAN_SEEKNOW_KEY`) recovers without a process restart.
pub(super) static KEY_INVALID: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

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

pub fn is_quota_exhausted() -> bool {
    BUDGET.is_exhausted()
}

pub fn reset_budget() {
    BUDGET.reset_scan();
    // Re-test the key each scan: if the operator fixed it (UI Settings /
    // HUNTSMAN_SEEKNOW_KEY) since the last scan, SeekNow recovers immediately;
    // if it's still bad, the first call this scan re-latches (one warning, then
    // the remaining ~160 lookups fast-fail).
    KEY_INVALID.store(false, std::sync::atomic::Ordering::Relaxed);
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
    KEY_INVALID.load(std::sync::atomic::Ordering::Relaxed)
}

pub(super) fn mark_key_invalid(body: &str) {
    // Emit the actionable guidance exactly once (the false→true transition),
    // naming the actual cause so the operator knows whether to swap the key or
    // upgrade the plan.
    if !KEY_INVALID.swap(true, std::sync::atomic::Ordering::Relaxed) {
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
