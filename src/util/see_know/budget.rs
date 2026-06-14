//! Per-scan and per-session quota budget for SeekNow API calls, plus the
//! key-invalid latch that fast-fails the remaining lookups once a bad key is
//! detected.

use crate::util::budget::QuotaBudget;

// Re-export the shared snapshot type so external consumers
// (`api::handlers::stats`) keep working through the original path.
pub use crate::util::budget::BudgetSnapshot;

/// Per-scan + per-session quota budget for SeekNow API calls.
///
/// SeekNow's premiumhq plan grants 5,000 daily lookups. The operator's
/// standing directive is to use see-know.eu *maximally* — extensively, within
/// reason, on every remotely promising seed — to maximise cross-correlation
/// and the confidence of recursive searching. So each scan gets a 160-query
/// envelope (env-tunable via `HUNTSMAN_SEEKNOW_SCAN_CAP`, runtime-overridable
/// via `ScanOptions::seeknow_scan_cap`). A single Username seed alone plans up
/// to 11 specialised endpoints (social aggregate, github, twitter, reddit,
/// tiktok, history, roblox, xbox, minecraft, + discord/steam pivots)
/// on top of the universal `/search`; with depth expansion every discovered
/// username/email/phone/domain consumes its own matrix, so a cap of 160 lets
/// the full 18-endpoint pool fire across ~10 recursively-discovered pivots in
/// one scan — corroborating far more of the graph — while still allowing many
/// full scans before the daily 5,000 ceiling. The cap is refreshed at each
/// expansion-round boundary ([`refresh_round_budget`]) so SeekNow participates
/// in EVERY iteration; the 500-query session ceiling (env-tunable via
/// `HUNTSMAN_SEEKNOW_SESSION_CAP`, hard-clamped to 500 by the engine) bounds the
/// total across all rounds of a deep scan — the "bound everything" invariant for
/// a 4 GB device — while leaving room for ~3 full rounds at the per-round cap.
pub(super) static BUDGET: QuotaBudget = QuotaBudget::new(
    "seeknow",
    160,
    500,
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
