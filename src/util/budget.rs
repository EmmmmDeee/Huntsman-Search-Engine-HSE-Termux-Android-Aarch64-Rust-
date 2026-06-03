//! Shared quota budget primitive for API-quota-spending modules.
//!
//! Multiple modules (`util::see_know`, `util::oathnet`, future
//! key-gated providers) all share the same lifecycle:
//!
//!   * per-scan counter (resets at scan start)
//!   * per-session counter (resets at process start)
//!   * a sticky "quota exhausted" flag tripped by 429 / quota errors
//!   * an env-tunable default scan cap, with optional runtime override
//!     installed by the engine when the operator sets a per-scan
//!     `ScanOptions::*_cap` field
//!
//! [`QuotaBudget`] encapsulates that lifecycle so each owner module
//! reduces to a single `static BUDGET: QuotaBudget = QuotaBudget::new(...)`
//! declaration plus thin wrappers for back-compat.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Snapshot of a [`QuotaBudget`] at a point in time. Used by the
/// `/api/v1/stats` handler and the `hse doctor` diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetSnapshot {
    pub scan_used: u32,
    pub scan_cap: u32,
    pub session_used: u32,
    pub session_cap: u32,
    pub quota_exhausted: bool,
}

/// Shared quota lifecycle.
///
/// Construct as a static via the `const fn new()` constructor. Every
/// method takes `&self` so it's safe to share across threads via the
/// static, no `Mutex` needed.
pub struct QuotaBudget {
    /// Human-readable identifier (`"seeknow"`, `"oathnet"`, …) used by
    /// logging / diagnostic surfaces. Not exposed through the public
    /// API beyond `label()`.
    label: &'static str,

    /// Per-scan counter — incremented on every billable call.
    /// Reset to zero by `reset_scan()` at scan start.
    scan_count: AtomicU32,

    /// Per-session counter — never reset within a process lifetime.
    /// Caps the total volume an `hse serve` / `hse live` session
    /// can dispatch in a day.
    session_count: AtomicU32,

    /// Sticky flag — once set to `true` by `mark_exhausted()`,
    /// `remaining()` returns false until `reset_scan()` clears it.
    quota_exhausted: AtomicBool,

    /// Per-scan cap override installed at scan start. `0` means
    /// "no override; use env / default". Cleared by `reset_scan()`.
    cap_override: AtomicU32,

    /// Compile-time default for the per-scan cap. Used when neither
    /// the env var nor the runtime override is set.
    default_scan_cap: u32,

    /// Compile-time default for the per-session ceiling.
    default_session_cap: u32,

    /// Env-var name the operator can set to override the default
    /// per-scan cap (e.g. `"HUNTSMAN_SEEKNOW_SCAN_CAP"`).
    env_scan_cap_var: &'static str,

    /// Env-var name for the per-session ceiling. May be empty,
    /// in which case `default_session_cap` is always used.
    env_session_cap_var: &'static str,
}

impl QuotaBudget {
    /// Construct a budget. `const fn` so callers can declare a
    /// `static BUDGET: QuotaBudget = QuotaBudget::new(...)` and
    /// avoid `LazyLock` indirection.
    ///
    /// Pass an empty string for `env_session_cap_var` to disable
    /// session-cap env-tuning (the default ceiling is then always
    /// authoritative).
    pub const fn new(
        label: &'static str,
        default_scan_cap: u32,
        default_session_cap: u32,
        env_scan_cap_var: &'static str,
        env_session_cap_var: &'static str,
    ) -> Self {
        Self {
            label,
            scan_count: AtomicU32::new(0),
            session_count: AtomicU32::new(0),
            quota_exhausted: AtomicBool::new(false),
            cap_override: AtomicU32::new(0),
            default_scan_cap,
            default_session_cap,
            env_scan_cap_var,
            env_session_cap_var,
        }
    }

    /// Human-readable identifier for diagnostic surfaces.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Effective per-scan cap — `cap_override` if set, else the env
    /// var if set + > 0, else `default_scan_cap`.
    pub fn scan_cap(&self) -> u32 {
        let override_value = self.cap_override.load(Ordering::Acquire);
        if override_value > 0 {
            return override_value;
        }
        std::env::var(self.env_scan_cap_var)
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v > 0)
            .unwrap_or(self.default_scan_cap)
    }

    /// Effective per-session cap — env var if set + > 0, else
    /// `default_session_cap`. No runtime override (the session
    /// ceiling represents the operator's daily-quota contract).
    pub fn session_cap(&self) -> u32 {
        if self.env_session_cap_var.is_empty() {
            return self.default_session_cap;
        }
        std::env::var(self.env_session_cap_var)
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&v: &u32| v > 0)
            .unwrap_or(self.default_session_cap)
    }

    /// Install a per-scan cap override. `0` clears the override
    /// (falls back to env / default). Cleared by `reset_scan()`.
    pub fn set_scan_cap_override(&self, cap: u32) {
        self.cap_override.store(cap, Ordering::Release);
    }

    /// True if there is room in both per-scan and per-session budgets
    /// AND the quota-exhausted flag has not been tripped.
    pub fn remaining(&self) -> bool {
        !self.is_exhausted()
            && self.scan_count.load(Ordering::Acquire) < self.scan_cap()
            && self.session_count.load(Ordering::Acquire) < self.session_cap()
    }

    /// How many more per-scan queries this budget can absorb. Used by
    /// callers that need to trim a fan-out plan to fit the budget.
    pub fn scan_remaining(&self) -> u32 {
        self.scan_cap()
            .saturating_sub(self.scan_count.load(Ordering::Acquire))
    }

    /// Charge one query against both per-scan and per-session counters.
    /// Callers MUST gate on `remaining()` before incrementing.
    ///
    /// Prefer [`try_increment`] for new code: `remaining()`-then-`increment()`
    /// is a non-atomic check-then-act, so concurrent callers can all observe
    /// room and then all increment past the cap.
    pub fn increment(&self) {
        self.scan_count.fetch_add(1, Ordering::Relaxed);
        self.session_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically reserve one query against BOTH the per-scan and per-session
    /// caps. Returns `true` if a slot was reserved (the caller may proceed) or
    /// `false` if a cap is reached or the quota is exhausted.
    ///
    /// This replaces the racy `remaining()`-then-`increment()` pattern: the
    /// see_know endpoint fan-out (`join_all`) and wigle's `tokio::join!` poll
    /// several budget gates before any increment lands, so all could pass the
    /// check and then all charge — overspending the operator's configured cap.
    /// A CAS reservation makes check-and-charge a single atomic step per
    /// counter, so the cap is never exceeded. If the per-session ceiling is hit
    /// after a per-scan slot was taken, the per-scan reservation is rolled back
    /// (saturating) so the two counters stay consistent.
    pub fn try_increment(&self) -> bool {
        if self.is_exhausted() {
            return false;
        }
        let scan_cap = self.scan_cap();
        if self
            .scan_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < scan_cap).then_some(n + 1)
            })
            .is_err()
        {
            return false;
        }
        let session_cap = self.session_cap();
        if self
            .session_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < session_cap).then_some(n + 1)
            })
            .is_err()
        {
            // Session ceiling hit — undo the per-scan reservation. Saturating so
            // a (race-free, but defensive) double-rollback can't underflow.
            let _ = self
                .scan_count
                .fetch_update(Ordering::AcqRel, Ordering::Relaxed, |n| {
                    Some(n.saturating_sub(1))
                });
            return false;
        }
        true
    }

    /// Reset scan-level state at scan start: counter, exhausted flag,
    /// and any installed cap override. Session counter is NOT touched
    /// — that's the long-running ceiling the operator wants preserved.
    pub fn reset_scan(&self) {
        self.scan_count.store(0, Ordering::Release);
        self.quota_exhausted.store(false, Ordering::Release);
        self.cap_override.store(0, Ordering::Release);
    }

    /// Reset ONLY the per-round counter, at each expansion-round boundary, so a
    /// module gets a fresh per-round allowance and participates in *every*
    /// iteration instead of being starved once a wide first round drains the
    /// budget. Deliberately preserves the installed cap override, the sticky
    /// daily-`quota_exhausted` flag (a real upstream signal — don't un-exhaust
    /// it mid-scan), and the per-session ceiling (which still bounds total
    /// volume across all rounds).
    pub fn reset_round(&self) {
        self.scan_count.store(0, Ordering::Release);
    }

    /// Trip the sticky exhausted flag. Subsequent `remaining()` calls
    /// return `false` until `reset_scan()` clears it.
    pub fn mark_exhausted(&self) {
        self.quota_exhausted.store(true, Ordering::Release);
    }

    /// True if `mark_exhausted()` has been called since the last
    /// `reset_scan()`.
    pub fn is_exhausted(&self) -> bool {
        self.quota_exhausted.load(Ordering::Acquire)
    }

    /// Build a [`BudgetSnapshot`] for `/api/v1/stats` / diagnostics.
    pub fn snapshot(&self) -> BudgetSnapshot {
        BudgetSnapshot {
            scan_used: self.scan_count.load(Ordering::Acquire),
            scan_cap: self.scan_cap(),
            session_used: self.session_count.load(Ordering::Acquire),
            session_cap: self.session_cap(),
            quota_exhausted: self.is_exhausted(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> QuotaBudget {
        QuotaBudget::new(
            "test_budget",
            24,
            200,
            "HUNTSMAN_TEST_BUDGET_NONEXISTENT",
            "HUNTSMAN_TEST_BUDGET_NONEXISTENT_SESSION",
        )
    }

    #[test]
    fn defaults_apply_when_no_override_or_env() {
        let b = fresh();
        assert_eq!(b.scan_cap(), 24);
        assert_eq!(b.session_cap(), 200);
        assert!(b.remaining());
        assert!(!b.is_exhausted());
    }

    #[test]
    fn label_is_round_tripped() {
        let b = fresh();
        assert_eq!(b.label(), "test_budget");
    }

    #[test]
    fn reset_round_clears_only_the_per_round_counter() {
        let b = fresh();
        b.set_scan_cap_override(50);
        b.increment();
        b.increment();
        b.mark_exhausted();

        b.reset_round();

        let snap = b.snapshot();
        // Per-round counter is cleared so the next round starts fresh...
        assert_eq!(snap.scan_used, 0);
        // ...but the session counter (the cross-round ceiling), the operator's
        // cap override, and the sticky daily-exhausted flag all survive — a
        // round refresh must not blow the session ceiling, drop the override,
        // or un-exhaust a real daily-quota signal.
        assert_eq!(snap.session_used, 2);
        assert_eq!(b.scan_cap(), 50);
        assert!(b.is_exhausted());
    }

    #[test]
    fn try_increment_never_exceeds_the_scan_cap() {
        let b = QuotaBudget::new("t", 3, 100, "HSE_TRYINC_NONE_A", "HSE_TRYINC_NONE_AS");
        assert!(b.try_increment());
        assert!(b.try_increment());
        assert!(b.try_increment());
        assert!(
            !b.try_increment(),
            "must refuse once the per-scan cap is reached"
        );
        assert!(!b.try_increment());
        assert_eq!(
            b.snapshot().scan_used,
            3,
            "count is never charged past the cap"
        );
    }

    #[test]
    fn try_increment_rolls_back_scan_when_session_cap_hit() {
        // session_cap (2) < scan_cap (10): the 3rd reserve fails on the session
        // ceiling and must NOT leave the per-scan counter incremented.
        let b = QuotaBudget::new("t", 10, 2, "HSE_TRYINC_NONE_B", "HSE_TRYINC_NONE_BS");
        assert!(b.try_increment());
        assert!(b.try_increment());
        assert!(!b.try_increment(), "session ceiling reached");
        let s = b.snapshot();
        assert_eq!(s.session_used, 2);
        assert_eq!(
            s.scan_used, 2,
            "per-scan reservation rolled back on session-cap failure"
        );
    }

    #[test]
    fn try_increment_refuses_when_exhausted() {
        let b = QuotaBudget::new("t", 10, 10, "HSE_TRYINC_NONE_C", "HSE_TRYINC_NONE_CS");
        b.mark_exhausted();
        assert!(!b.try_increment());
        assert_eq!(b.snapshot().scan_used, 0);
    }

    #[test]
    fn override_replaces_default_until_reset() {
        let b = fresh();
        b.set_scan_cap_override(80);
        assert_eq!(b.scan_cap(), 80);
        b.reset_scan();
        assert_eq!(b.scan_cap(), 24);
    }

    #[test]
    fn override_of_zero_falls_back_to_default() {
        let b = fresh();
        b.set_scan_cap_override(0);
        assert_eq!(b.scan_cap(), 24);
    }

    #[test]
    fn increment_consumes_from_both_counters() {
        let b = fresh();
        let scan0 = b.scan_remaining();
        let snap0 = b.snapshot();
        b.increment();
        assert_eq!(b.scan_remaining(), scan0 - 1);
        let snap1 = b.snapshot();
        assert_eq!(snap1.scan_used, snap0.scan_used + 1);
        assert_eq!(snap1.session_used, snap0.session_used + 1);
    }

    #[test]
    fn remaining_false_once_scan_cap_reached() {
        let b = QuotaBudget::new("tiny", 2, 200, "HUNTSMAN_TEST_TINY_NONEXISTENT", "");
        assert!(b.remaining());
        b.increment();
        b.increment();
        assert!(!b.remaining());
        b.reset_scan();
        assert!(b.remaining());
    }

    #[test]
    fn mark_exhausted_disables_remaining_until_reset() {
        let b = fresh();
        assert!(b.remaining());
        b.mark_exhausted();
        assert!(!b.remaining());
        assert!(b.is_exhausted());
        b.reset_scan();
        assert!(b.remaining());
        assert!(!b.is_exhausted());
    }

    #[test]
    fn reset_scan_clears_override_too() {
        let b = fresh();
        b.set_scan_cap_override(99);
        assert_eq!(b.scan_cap(), 99);
        b.reset_scan();
        assert_eq!(b.scan_cap(), 24, "reset_scan must clear cap_override");
    }

    #[test]
    fn snapshot_reflects_live_state() {
        let b = fresh();
        b.set_scan_cap_override(50);
        b.increment();
        let snap = b.snapshot();
        assert_eq!(snap.scan_cap, 50);
        assert_eq!(snap.scan_used, 1);
        assert_eq!(snap.session_cap, 200);
        assert!(snap.session_used >= 1);
        assert!(!snap.quota_exhausted);
    }

    #[test]
    fn session_counter_survives_scan_reset() {
        let b = fresh();
        b.increment();
        b.increment();
        let used_before = b.snapshot().session_used;
        b.reset_scan();
        let used_after = b.snapshot().session_used;
        assert_eq!(
            used_after, used_before,
            "session_count must persist across reset_scan()"
        );
    }

    #[test]
    fn scan_remaining_clamps_at_zero() {
        let b = QuotaBudget::new("tiny2", 1, 200, "HUNTSMAN_TEST_TINY2_NONEXISTENT", "");
        assert_eq!(b.scan_remaining(), 1);
        b.increment();
        assert_eq!(b.scan_remaining(), 0);
        b.increment(); // overshoot
        assert_eq!(b.scan_remaining(), 0);
    }

    #[test]
    fn unset_env_var_falls_back_to_default() {
        // The env-var-override path can't be exercised under
        // `#![forbid(unsafe_code)]` (`std::env::set_var` is `unsafe`
        // on Edition 2024), so this test only proves the fallback
        // path. The override-takes-priority path is exercised by
        // `override_replaces_default_until_reset`.
        let b = QuotaBudget::new(
            "no_env",
            42,
            200,
            "HUNTSMAN_DEFINITELY_NOT_SET_NONEXISTENT",
            "",
        );
        assert_eq!(b.scan_cap(), 42);
    }

    #[test]
    fn empty_session_env_var_uses_default() {
        let b = QuotaBudget::new("nosess", 10, 200, "", "");
        assert_eq!(b.session_cap(), 200);
    }
}
