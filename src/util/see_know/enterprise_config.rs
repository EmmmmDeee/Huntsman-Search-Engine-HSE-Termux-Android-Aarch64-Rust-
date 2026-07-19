//! Tunable constants for the SeekNow integration — every field here is read
//! by exactly one real call site (see each field's doc comment); nothing is
//! illustrative-only. The speculative workflow/monitoring/SLA/key-pattern
//! tables that once lived here were unwired scaffolding and were removed
//! (see the dead-code sweep, `PROBLEM_TREE` T2.58/T2.62).
//!
//! `daily_limit`/`per_scan_cap` fields that previously lived here (claiming
//! "15,000 credits/day... the operator's actual plan parameters") were
//! removed entirely, not just left unwired: the REAL daily limit only ever
//! comes from the live `/credits` probe (a hardcoded 15,000 is simply wrong
//! for any operator on a different plan tier, from Beginner's 100/day up),
//! and the real per-scan cap is always DERIVED from that live value via
//! [`super::budget::scale_scan_cap_from_daily`] — so those two fields were
//! not just dead, they actively misdescribed the system to a reader as
//! "the operator's actual plan" when no code path ever consulted them for
//! anything runtime-relevant.

/// Tunable SeekNow integration parameters — each field's doc comment names
/// its one real call site.
pub struct EnterprisePlan {
    /// Pre-probe fallback default AND the floor of
    /// [`super::budget::scale_scan_cap_from_daily`]'s clamp — read at
    /// `super::budget::BUDGET`'s construction (`budget.rs`) and at
    /// `scale_scan_cap_from_daily`'s `.clamp(floor, ceil)` call.
    pub scan_budget_floor: u32,
    /// Ceiling of `scale_scan_cap_from_daily`'s clamp — prevents runaway
    /// fan-out on an unlimited/very-large plan even though the live daily
    /// limit could be far higher.
    pub scan_budget_ceil: u32,
    /// Per-session ceiling — set high; the server's own daily quota is the
    /// real backstop. Read at `BUDGET`'s construction.
    pub session_cap: u32,
    /// In-process response-cache capacity. Read by
    /// `super::client::RESPONSE_CACHE`'s construction.
    pub cache_size: usize,
    /// Transient-error retry count (used for both the 429 backoff policy
    /// and the plain-transport-error retry loop). Read by
    /// `super::endpoints::RATE_LIMIT_BACKOFF`'s construction.
    pub max_retries: u32,
    /// curl subprocess timeout, seconds. Read by `super::client::CLIENT`'s
    /// construction.
    pub curl_timeout_secs: u64,
    /// Outer tokio timeout wrapping the curl call, milliseconds — SHOULD
    /// exceed `curl_timeout_secs * 1000` so curl's own timeout (exit 28)
    /// fires before tokio aborts the process mid-flight. Read by
    /// `super::client::CLIENT`'s construction.
    pub tokio_timeout_millis: u64,
}

/// The live SeekNow integration configuration — every field consumed by a
/// real call site, see [`EnterprisePlan`]'s per-field doc comments.
pub const ENTERPRISE: EnterprisePlan = EnterprisePlan {
    scan_budget_floor: 300,
    scan_budget_ceil: 2_500,
    session_cap: 100_000,
    cache_size: 1_024,
    max_retries: 3,
    curl_timeout_secs: 75,        // above /search's documented ~55s worst case
    tokio_timeout_millis: 78_000, // curl_timeout_secs * 1000 + headroom
};
