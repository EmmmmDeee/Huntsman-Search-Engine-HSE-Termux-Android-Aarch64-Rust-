//! Shared quota budget primitive for API-quota-spending modules.
//!
//! Multiple modules (`util::see_know`, `util::oathnet`, `modules::wigle`,
//! future key-gated providers) all share the same lifecycle:
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
//!
//! ## Scan isolation
//!
//! `hse serve` runs up to [`crate::api::MAX_CONCURRENT_SCANS`] scans at once.
//! Every scan-scoped counter (`scan_count`, the cap override, the sticky
//! exhausted flag) is therefore kept in a [`Mutex`]-guarded map keyed by
//! `scan_id`, not a single process-wide atomic — otherwise one scan starting
//! (or hitting a round boundary) would silently reset a sibling scan's
//! accumulated usage, cap override, and exhausted latch, letting concurrent
//! scans collectively blow past what was meant to be a per-scan-bounded
//! spend. Which scan a call belongs to is read from a task-local ambient
//! ([`with_scan`]) the engine sets around each scan and re-sets inside each
//! spawned per-module dispatch task — the exact same pattern
//! [`crate::util::found_keys::with_scan`] and
//! [`crate::util::regional::with_regional`] already use for this identical
//! class of problem, so every scan-scoped method on [`QuotaBudget`] keeps
//! its original zero-argument signature: no call site in any owner module
//! needs to change.
//!
//! The per-session counter is deliberately NOT part of this per-scan map —
//! it is the cross-scan, cross-round ceiling representing the operator's
//! real daily quota with the upstream provider, and stays a single
//! process-wide atomic exactly as before.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{LazyLock, Mutex};

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

tokio::task_local! {
    /// The `scan_id` of the scan whose modules are executing on this task.
    /// Mirrors [`crate::util::found_keys`]'s identical ambient exactly —
    /// same rationale (PROBLEM_TREE T2.11): per-scan quota state must not
    /// leak across `hse serve`'s concurrently-running scans, and threading
    /// `scan_id` through every [`QuotaBudget`] call site across three owner
    /// modules would be far more invasive than one ambient the engine sets
    /// in two places. Unset outside a scan (e.g. unit tests) ⇒ the default
    /// `""` bucket, same as every existing test already assumes.
    static SCAN: String;
}

/// Run `f` with the current-scan ambient set to `scan_id`, so every
/// [`QuotaBudget`] scan-scoped method called inside `f` reads/writes THAT
/// scan's bucket. The engine wraps each scan and each spawned per-module
/// dispatch task in this, alongside the identical
/// [`crate::util::found_keys::with_scan`] /
/// [`crate::util::regional::with_regional`] wraps — task-locals do not
/// propagate across `tokio::spawn`, so the per-module dispatch spawn must
/// re-apply it or budget calls from a concurrently-dispatched module would
/// silently fall back to the unscoped `""` bucket.
pub async fn with_scan<F: std::future::Future>(scan_id: String, f: F) -> F::Output {
    SCAN.scope(scan_id, f).await
}

/// The scan currently executing on this task, or `""` when unscoped.
fn current_scan() -> String {
    SCAN.try_with(String::clone).unwrap_or_default()
}

/// Test-only synchronous scope: run `f` with the scan ambient set (mirrors
/// [`with_scan`] for sync test bodies). The production path uses the async
/// [`with_scan`].
#[cfg(test)]
fn with_scan_sync<R>(scan_id: &str, f: impl FnOnce() -> R) -> R {
    SCAN.sync_scope(scan_id.to_string(), f)
}

/// Per-scan mutable state — everything that used to live in process-wide
/// atomics but must instead be isolated per `scan_id`.
#[derive(Debug, Default, Clone, Copy)]
struct ScanState {
    /// Billable calls charged against this scan so far.
    count: u32,
    /// Per-scan cap override installed at scan start. `0` means "no
    /// override; use env / default".
    cap_override: u32,
    /// Sticky flag — once `true`, `remaining()` returns `false` for this
    /// scan until `reset_scan()` clears it.
    exhausted: bool,
}

/// Shared quota lifecycle.
///
/// Construct as a static via the `const fn new()` constructor. Every
/// method takes `&self` so it's safe to share across threads via the
/// static, no external synchronisation needed by callers.
pub struct QuotaBudget {
    /// Human-readable identifier (`"seeknow"`, `"oathnet"`, …) used by
    /// logging / diagnostic surfaces. Not exposed through the public
    /// API beyond `label()`.
    label: &'static str,

    /// Scan-scoped state, keyed by `scan_id` — see the module doc for why
    /// this replaced the old per-field atomics. `HashMap::new()` isn't a
    /// `const fn`, so the map is built lazily on first access, same as
    /// `found_keys::SINK`.
    per_scan: LazyLock<Mutex<HashMap<String, ScanState>>>,

    /// Per-session counter — never reset within a process lifetime.
    /// Caps the total volume an `hse serve` / `hse live` session
    /// can dispatch in a day. Deliberately process-wide, not per-scan:
    /// it represents the operator's real daily quota with the upstream
    /// provider, shared by every scan.
    session_count: AtomicU32,

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
            per_scan: LazyLock::new(|| Mutex::new(HashMap::new())),
            session_count: AtomicU32::new(0),
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

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, ScanState>> {
        self.per_scan
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Effective per-scan cap — the current scan's override if set, else the
    /// env var if set + > 0, else `default_scan_cap`.
    pub fn scan_cap(&self) -> u32 {
        let scan = current_scan();
        let override_value = self.lock().get(&scan).map_or(0, |s| s.cap_override);
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

    /// Install a per-scan cap override for the current scan. `0` clears the
    /// override (falls back to env / default). Cleared by `reset_scan()`.
    pub fn set_scan_cap_override(&self, cap: u32) {
        let scan = current_scan();
        self.lock().entry(scan).or_default().cap_override = cap;
    }

    /// True if the operator explicitly pinned the per-scan cap — either through
    /// the runtime override ([`set_scan_cap_override`](Self::set_scan_cap_override),
    /// which the engine installs from `ScanOptions` at scan start) or through
    /// this budget's env var.
    ///
    /// Any caller that *derives* a cap rather than being told one — scaling to a
    /// probed plan allocation, say — must consult this and yield. An operator who
    /// named a number meant it, and the usual reason for naming a small one is to
    /// stop a large plan from being spent; silently raising it spends quota they
    /// explicitly withheld. Reading both sources here (rather than at each call
    /// site) keeps the precedence rule and the env-var name in the single type
    /// that owns them, so a caller cannot implement half of it.
    ///
    /// Mirrors [`scan_cap`](Self::scan_cap)'s own precedence exactly: an override
    /// or env value of `0` means "unset", not "cap at zero".
    pub fn operator_pinned_scan_cap(&self) -> bool {
        // Same source and precedence as `scan_cap()`: the override moved from a
        // single struct-level atomic to a per-scan `ScanState.cap_override`
        // (keyed by `current_scan()`) when scan-scoped state replaced the old
        // per-field atomics, and this check must read the same place `scan_cap`
        // does or the two could disagree about whether a cap is operator-pinned.
        let scan = current_scan();
        let override_value = self.lock().get(&scan).map_or(0, |s| s.cap_override);
        if override_value > 0 {
            return true;
        }
        std::env::var(self.env_scan_cap_var)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .is_some_and(|v| v > 0)
    }

    /// True if there is room in both per-scan and per-session budgets
    /// AND the quota-exhausted flag has not been tripped, for the
    /// current scan.
    pub fn remaining(&self) -> bool {
        let scan = current_scan();
        let scan_cap = self.scan_cap();
        let session_cap = self.session_cap();
        let state = self.lock().get(&scan).copied().unwrap_or_default();
        !state.exhausted
            && state.count < scan_cap
            && self.session_count.load(Ordering::Acquire) < session_cap
    }

    /// How many more per-scan queries this budget can absorb for the
    /// current scan. Used by callers that need to trim a fan-out plan to
    /// fit the budget.
    pub fn scan_remaining(&self) -> u32 {
        let scan = current_scan();
        let used = self.lock().get(&scan).map_or(0, |s| s.count);
        self.scan_cap().saturating_sub(used)
    }

    /// Charge one query against both per-scan (current scan) and
    /// per-session counters.
    ///
    /// Prefer [`Self::try_increment`] for new code: `remaining()`-then-`increment()`
    /// is a non-atomic check-then-act, so concurrent callers can all observe
    /// room and then all increment past the cap.
    pub fn increment(&self) {
        let scan = current_scan();
        self.lock().entry(scan).or_default().count += 1;
        self.session_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Atomically reserve one query against BOTH the current scan's cap and
    /// the per-session cap. Returns `true` if a slot was reserved (the
    /// caller may proceed) or `false` if a cap is reached or the quota is
    /// exhausted.
    ///
    /// This replaces the racy `remaining()`-then-`increment()` pattern: the
    /// see_know endpoint fan-out (`join_all`) and wigle's `tokio::join!` poll
    /// several budget gates before any increment lands, so all could pass the
    /// check and then all charge — overspending the operator's configured cap.
    /// The per-scan check-and-charge happens under one mutex acquisition (a
    /// real critical section, not a CAS retry loop), so two concurrent
    /// reservations against the SAME scan can never both pass the cap check.
    /// If the per-session ceiling is hit after a per-scan slot was taken, the
    /// per-scan reservation is rolled back so the two counters stay
    /// consistent.
    pub fn try_increment(&self) -> bool {
        let scan = current_scan();
        let scan_cap = self.scan_cap();
        {
            let mut g = self.lock();
            let state = g.entry(scan.clone()).or_default();
            if state.exhausted || state.count >= scan_cap {
                return false;
            }
            state.count += 1;
        }
        let session_cap = self.session_cap();
        if self
            .session_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < session_cap).then_some(n + 1)
            })
            .is_err()
        {
            // Session ceiling hit — undo the per-scan reservation.
            if let Some(state) = self.lock().get_mut(&scan) {
                state.count = state.count.saturating_sub(1);
            }
            return false;
        }
        true
    }

    /// Reset the CURRENT scan's state at scan start: its counter, exhausted
    /// flag, and any installed cap override. The per-session counter is NOT
    /// touched — that's the long-running ceiling the operator wants
    /// preserved — and no OTHER scan's state is touched either, unlike the
    /// pre-fix single-static design.
    pub fn reset_scan(&self) {
        let scan = current_scan();
        self.lock().insert(scan, ScanState::default());
    }

    /// Reset ONLY the current scan's per-round counter, at each expansion-
    /// round boundary, so a module gets a fresh per-round allowance and
    /// participates in *every* iteration instead of being starved once a
    /// wide first round drains the budget. Deliberately preserves the
    /// installed cap override, the sticky daily-`exhausted` flag (a real
    /// upstream signal — don't un-exhaust it mid-scan), and the per-session
    /// ceiling (which still bounds total volume across all rounds).
    pub fn reset_round(&self) {
        let scan = current_scan();
        self.lock().entry(scan).or_default().count = 0;
    }

    /// Trip the sticky exhausted flag for the current scan. Subsequent
    /// `remaining()` calls for THIS scan return `false` until
    /// `reset_scan()` clears it.
    pub fn mark_exhausted(&self) {
        let scan = current_scan();
        self.lock().entry(scan).or_default().exhausted = true;
    }

    /// True if `mark_exhausted()` has been called for the current scan
    /// since its last `reset_scan()`.
    pub fn is_exhausted(&self) -> bool {
        let scan = current_scan();
        self.lock().get(&scan).is_some_and(|s| s.exhausted)
    }

    /// Build a [`BudgetSnapshot`] for `/api/v1/stats` / diagnostics, for the
    /// current scan.
    pub fn snapshot(&self) -> BudgetSnapshot {
        let scan = current_scan();
        let state = self.lock().get(&scan).copied().unwrap_or_default();
        BudgetSnapshot {
            scan_used: state.count,
            scan_cap: self.scan_cap(),
            session_used: self.session_count.load(Ordering::Acquire),
            session_cap: self.session_cap(),
            quota_exhausted: state.exhausted,
        }
    }

    /// Remove `scan_id`'s tracked state entirely, so a long-lived
    /// `hse serve` / `hse live` process doesn't grow this map without bound
    /// as scans come and go. Called by the engine at scan finalisation —
    /// mirrors [`crate::util::found_keys::drain`]'s per-scan cleanup.
    /// Takes an explicit `scan_id` (not the ambient) since finalisation is
    /// an engine-driven, one-shot cleanup call, not per-request budget
    /// tracking.
    pub fn cleanup_scan(&self, scan_id: &str) {
        self.lock().remove(scan_id);
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
