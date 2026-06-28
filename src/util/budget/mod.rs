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

use std::sync::OnceLock;
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

    /// Memoised env-resolved per-scan cap (env var if set + > 0, else
    /// `default_scan_cap`). Process-environment caps cannot change after start,
    /// so we read the env var at most once instead of on every billable call's
    /// `remaining()` / `try_increment()`. The runtime `cap_override` is checked
    /// *before* this in `scan_cap()`, so memoising the env fallback does not
    /// freeze an operator's per-scan override.
    scan_cap_cache: OnceLock<u32>,

    /// Memoised env-resolved per-session cap (env var if set + > 0, else
    /// `default_session_cap`). Same rationale as `scan_cap_cache`; the session
    /// ceiling has no runtime override, so this is the sole source after first
    /// resolution.
    session_cap_cache: OnceLock<u32>,
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
            scan_cap_cache: OnceLock::new(),
            session_cap_cache: OnceLock::new(),
        }
    }

    /// Human-readable identifier for diagnostic surfaces.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Effective per-scan cap — `cap_override` if set, else the env
    /// var if set + > 0, else `default_scan_cap`.
    ///
    /// The env-derived fallback is resolved once and memoised (see
    /// `scan_cap_cache`): on the `join_all` fan-out hot path this avoids a
    /// `std::env::var` syscall (+ allocation, + a global libc lock on some
    /// platforms) per billable call. The runtime override is still read live on
    /// every call, so an operator's mid-scan cap change takes effect immediately.
    pub fn scan_cap(&self) -> u32 {
        let override_value = self.cap_override.load(Ordering::Acquire);
        if override_value > 0 {
            return override_value;
        }
        *self.scan_cap_cache.get_or_init(|| {
            std::env::var(self.env_scan_cap_var)
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v: &u32| v > 0)
                .unwrap_or(self.default_scan_cap)
        })
    }

    /// Effective per-session cap — env var if set + > 0, else
    /// `default_session_cap`. No runtime override (the session
    /// ceiling represents the operator's daily-quota contract).
    ///
    /// Resolved once and memoised (see `session_cap_cache`) so the env var is
    /// read at most once per process rather than on every `remaining()` /
    /// `try_increment()` / `snapshot()`.
    pub fn session_cap(&self) -> u32 {
        *self.session_cap_cache.get_or_init(|| {
            if self.env_session_cap_var.is_empty() {
                return self.default_session_cap;
            }
            std::env::var(self.env_session_cap_var)
                .ok()
                .and_then(|v| v.parse().ok())
                .filter(|&v: &u32| v > 0)
                .unwrap_or(self.default_session_cap)
        })
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

    /// Charge one query against both per-scan and per-session counters,
    /// *without* a cap check. **Test-only.**
    ///
    /// Production has fully migrated to [`Self::try_increment`], which reserves
    /// against both caps in a single atomic step. The bare `increment()` is the
    /// racy non-atomic check-then-act half of the old `remaining()`-then-
    /// `increment()` gate: concurrent callers could all observe room and then all
    /// charge past the cap. It is gated behind `#[cfg(test)]` so that dangerous
    /// path cannot exist in a release build; the unit tests still use it as a
    /// convenient unconditional counter bump for asserting reset/snapshot
    /// behaviour, where the lack of a cap check is exactly what's wanted.
    #[cfg(test)]
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
    ///
    /// The cap is never *over*spent, but the per-scan-then-session ordering is
    /// not perfectly race-free: between the successful scan reservation and a
    /// session-cap failure, a concurrent caller can briefly observe the
    /// inflated scan counter and be denied a slot it would otherwise have got.
    /// That window is conservative (it errs toward *under*-spending, never over)
    /// and benign, since the scan counter resets every round.
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
            // Session ceiling hit — undo the per-scan reservation. This path runs
            // exactly once per failed call, so the rollback is not itself a double
            // decrement; `saturating_sub` is a purely defensive guard so that even
            // an unexpected extra decrement (e.g. a future refactor) can never
            // underflow the counter past zero.
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
    include!("tests.rs");
}
