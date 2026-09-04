//! Per-scan and per-session quota budget for SeekNow API calls, plus the
//! key-invalid latch that fast-fails the remaining lookups once a bad key is
//! detected.

use crate::util::budget::QuotaBudget;

/// Serialises every test — in this file's own `tests` module AND in
/// `modules::see_know::tests`, a SEPARATE file that also calls
/// [`reset_budget`] directly — that touches [`BUDGET`]'s shared per-scan
/// state (scan-cap override, counters, latches).
///
/// `cargo test` runs the whole crate's unit tests in one process, and the
/// task-local scan id that [`crate::util::budget::with_scan`] would set is
/// left unset (falls back to `""`) by every ordinary `#[test]`/`#[tokio::test]`
/// that doesn't explicitly scope one — which is every test in both files —
/// so they all share ONE `""` bucket in [`BUDGET`]'s per-scan map. Without a
/// SINGLE shared lock, two tests running concurrently interleave
/// `reset_budget()` / `set_scan_cap_override()` and clobber each other: this
/// exact race was fixed once already for the tests within this file (see the
/// history at this static's original call sites), but that fix only
/// serialised call sites that already knew about it — `modules::see_know`'s
/// own test file calls [`reset_budget`] too and, being a different file, was
/// not serialised by a lock private to this one. `pub(crate)` (rather than
/// keeping it file-private) is what lets that other file take the SAME lock
/// instead of a different one that would leave the two files still racing
/// each other. `parking_lot::Mutex` never poisons if a test panics while
/// holding it.
#[cfg(test)]
pub(crate) static BUDGET_TEST_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

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

/// True if this is the first call since [`reset_budget`] — i.e. the probe
/// has not yet run for this scan. Returns false on all subsequent calls in
/// the same scan (probe already done or no key available). Thread-safe:
/// the first concurrent caller wins; others see false.
///
/// Scan-scoped, through [`crate::util::budget::QuotaBudget::claim_probe`].
/// Held as a process-wide atomic — which it was — the first of `hse serve`'s
/// concurrent scans to claim the probe left every sibling unable to fire one,
/// so a sibling ran its whole life pinned to the un-scaled default cap
/// (≈60% under-provisioned on a large plan, the same harm
/// [`release_quota_probe`] exists to avoid), while each new scan cleared a
/// still-active sibling's claim out from under it.
pub fn should_probe_quota() -> bool {
    BUDGET.claim_probe()
}

/// Release the one-shot quota-probe latch [`should_probe_quota`] claimed, so a
/// later seed re-probes. Call this ONLY when the probe the claim guarded
/// actually FAILED (a transient DNS/timeout blip, or a not-yet-valid key):
/// otherwise a single failed first probe pins the scan to the un-scaled default
/// cap (≈60% under-provisioned on a large plan) for its entire life with no
/// recovery short of a new scan. `/credits` is non-billable, so re-probing costs
/// no quota. Left untouched on success, preserving "first caller wins".
pub fn release_quota_probe() {
    BUDGET.release_probe();
}

/// Scale the per-scan cap to the operator's actual daily allocation.
///
/// Formula: `clamp(daily_limit / 20, 300, 2500)`.
/// - Spends at most 5 % of the daily pool per scan round.
/// - Floor (300): a reasonable full-matrix pass even on small plans.
/// - Ceiling (2500): prevents runaway fan-out on unlimited/very-large plans.
///
/// The operator's env/runtime override is NOT touched — if either
/// `HUNTSMAN_SEEKNOW_SCAN_CAP` or the runtime override the engine installs from
/// `ScanOptions::seeknow_scan_cap` (the `--seeknow-scan-cap` flag) is in force,
/// the probe result is discarded and their number stands.
/// The session cap is left unchanged (set high; server quota is the backstop).
pub fn scale_scan_cap_from_daily(daily_limit: u32) {
    // Do not override if the operator already set an explicit cap via env or
    // ScanOptions — their explicit value always takes precedence.
    //
    // This asks `QuotaBudget` rather than re-reading the env var here: the
    // runtime override installed from `ScanOptions` is invisible to an env-only
    // check, so an env-only guard silently RAISED an operator's explicit
    // `--seeknow-scan-cap 50` to the probed plan cap (750 on a 15k plan) —
    // spending 15x the quota they had just withheld. Delegating also keeps the
    // env-var name in exactly one place (the `BUDGET` constructor above), so a
    // rename cannot leave this guard silently reading a variable nobody sets.
    if BUDGET.operator_pinned_scan_cap() {
        return;
    }
    let cap = (daily_limit / 20).clamp(ENTERPRISE.scan_budget_floor, ENTERPRISE.scan_budget_ceil);
    BUDGET.set_scan_cap_override(cap);
    tracing::debug!(
        daily_limit,
        scan_cap = cap,
        "see_know scan cap scaled to plan quota"
    );
}

/// Why SeekNow refuses to answer with the configured key — the two terminal
/// causes [`mark_key_invalid`] latches for the rest of the scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyRejection {
    /// `{"error":"invalid_api_key"}` / "Invalid API key": the key itself is
    /// wrong (or the header was missing).
    InvalidKey = 1,
    /// `{"error":"plan_required"}`: the key is recognised but its account has
    /// no paid plan, so no data endpoint will answer until it does.
    PlanRequired = 2,
}

impl KeyRejection {
    fn from_body(body: &str) -> Self {
        if body.contains("plan_required") {
            Self::PlanRequired
        } else {
            Self::InvalidKey
        }
    }

    /// The cause and its remedy, worded for the operator. The ONE text behind
    /// both the once-per-scan warning and the per-seed module error, so the
    /// two can never disagree about what to fix.
    pub fn guidance(self) -> &'static str {
        match self {
            Self::InvalidKey => {
                "the API key was rejected (invalid_api_key): set a valid, plan-enabled key via HUNTSMAN_SEEKNOW_KEY or the UI Settings panel"
            }
            Self::PlanRequired => {
                "the account has no paid plan (plan_required): upgrade at https://see-know.ru/pricing, or set a plan-enabled key via HUNTSMAN_SEEKNOW_KEY or the UI Settings panel"
            }
        }
    }
}

// The key-rejection latch: set once per scan when SeekNow rejects the
// configured API key; `0` = not rejected, otherwise the `KeyRejection`
// discriminant. Lives in the scan-scoped budget state (`terminal_latch`),
// reached through `key_rejection` / `mark_key_invalid` below.
//
// curl exits 0 on an HTTP 401 (it got a response), so the shared curl client
// reports success and the `{"error":"invalid_api_key"}` body parses to zero
// items — which made SeekNow look like it "found nothing" on every seed
// instead of "the key is bad". This latch makes the failure explicit,
// fast-fails the remaining ~160 doomed lookups for the rest of the scan, and
// (through `key_rejection`) lets the module report each seed as failed
// rather than as a clean negative. It is cleared by `reset_budget` at the
// start of each scan so a corrected key (UI Settings / `HUNTSMAN_SEEKNOW_KEY`)
// recovers without a process restart.
//
// Scan-scoped rather than a process-wide atomic, which is what it was: held
// process-wide, one of `hse serve`'s concurrent scans latching a
// rejection made every sibling report a key failure it never observed and
// fast-fail lookups that would have succeeded, and each new scan cleared a
// live sibling's latch.

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
// `pub(crate)` so `modules::see_know::tests` can drain the budget (re-exported
// under `#[cfg(test)]` from the parent module).
#[cfg(test)]
pub(crate) fn budget_increment() {
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
    // The key-rejection and quota-probe latches live in the scan state
    // `reset_scan()` just cleared, so both are already reset for this scan —
    // and, unlike the process-wide atomics they replaced, resetting THIS scan
    // no longer clears a concurrently-running sibling scan's latches. A
    // corrected key (UI Settings / HUNTSMAN_SEEKNOW_KEY) still recovers on the
    // next scan without a process restart, which is what those stores were for.
    // Clear the cross-module response cache: it dedups identical endpoint
    // queries WITHIN one scan (see `client::RESPONSE_CACHE`'s own doc
    // comment), but with no scan-boundary reset a long-lived `hse serve` /
    // `hse live` process would silently keep returning the first scan's
    // cached SeekNow records for every later re-scan of the same
    // email/username/phone, indefinitely, with no live re-check.
    super::client::RESPONSE_CACHE.clear();
}

/// Remove `scan_id`'s tracked budget state entirely. Called by the engine at
/// scan finalisation so a long-lived `hse serve` / `hse live` process
/// doesn't grow [`BUDGET`]'s per-scan map without bound as scans come and
/// go — mirrors [`crate::util::found_keys::drain`]'s per-scan cleanup.
pub fn cleanup_scan(scan_id: &str) {
    BUDGET.cleanup_scan(scan_id);
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

/// The latched rejection, if SeekNow has rejected the key this scan. The
/// module reads it after its seed's calls to turn the endpoint layer's empty
/// answers into an explicit error; `hse doctor`'s "SeekNow account" section
/// reads [`is_key_invalid`] after probing `/credits` — that probe
/// (`endpoints::query_credits`) is the one call site that can classify+latch
/// this from a FRESH process (before any data-bearing `search`/`get_path`
/// call has had the chance to).
pub fn key_rejection() -> Option<KeyRejection> {
    match BUDGET.terminal_latch() {
        1 => Some(KeyRejection::InvalidKey),
        2 => Some(KeyRejection::PlanRequired),
        _ => None,
    }
}

/// True once SeekNow has rejected the key — [`key_rejection`] as a flag.
pub fn is_key_invalid() -> bool {
    key_rejection().is_some()
}

/// Latch the rejection `body` describes and return it, so the caller that
/// saw the body (the `/credits` probe behind `hse doctor`) can report the
/// same cause and remedy the latch warns with. `pub(crate)` only so
/// `modules::see_know::tests` can latch one directly (re-exported under
/// `#[cfg(test)]` from the parent module); production callers are this
/// module's own client and endpoints.
pub(crate) fn mark_key_invalid(body: &str) -> KeyRejection {
    let rejection = KeyRejection::from_body(body);
    // Emit the actionable guidance exactly once (the clear→latched
    // transition), naming the actual cause so the operator knows whether to
    // swap the key or upgrade the plan.
    let previous = BUDGET.terminal_latch();
    BUDGET.set_terminal_latch(rejection as u8);
    if previous == 0 {
        tracing::warn!(
            "SeekNow lookups disabled for this scan: {}.",
            rejection.guidance()
        );
    }
    rejection
}
