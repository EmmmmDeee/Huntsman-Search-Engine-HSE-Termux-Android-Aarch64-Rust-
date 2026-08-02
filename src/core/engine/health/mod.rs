//! Per-process, per-module health tracking (`PROBLEM_TREE` T2.7 /
//! `SOLUTION_TREE` SOL-HEALTH-SIGNAL): `last_success_at` + `consecutive_failures`
//! per source, driven by the real dispatch outcomes `dispatch::finalise_module_result`
//! already classifies.
//!
//! Distinct from [`super::circuit`] (this same directory): `circuit` is a
//! retry-avoidance breaker that *clears all history on success* and times its
//! cooldowns with monotonic [`std::time::Instant`] — exactly wrong for a
//! durable health signal, since the whole point here is remembering *when* a
//! source last worked, not just whether it's safe to retry right now. This
//! module answers a different, durable question — "when did this source last
//! actually succeed, and how many times in a row has it failed since" — using
//! wall-clock epoch seconds so `hse doctor` can report it meaningfully across
//! the whole process's uptime.
//!
//! Process-global, mirroring `circuit`: a scraper's health is a property of
//! the source, not of any one scan.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, Default)]
struct Health {
    last_success_at: Option<u64>,
    consecutive_failures: u32,
}

fn state() -> &'static Mutex<HashMap<&'static str, Health>> {
    static STATE: OnceLock<Mutex<HashMap<&'static str, Health>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Record a successful dispatch: stamps `last_success_at` to now and clears
/// the failure streak — a recovered source's health is trusted immediately,
/// mirroring `circuit::record_success`'s recovery philosophy.
pub(super) fn record_success(name: &'static str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(name).or_default();
    entry.last_success_at = Some(crate::core::entity::unix_now());
    entry.consecutive_failures = 0;
}

/// Record a failed dispatch (hard error or timeout — NOT a clean `MissingKey`
/// skip, which is an unconfigured provider opting out, not a failure of the
/// source itself): increments the consecutive-failure streak.
/// `last_success_at` is left untouched — it answers "when did it last work",
/// not "did it just fail".
pub(super) fn record_failure(name: &'static str) {
    let mut g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = g.entry(name).or_default();
    entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
}

/// One module's tracked health, snapshotted for a report (`hse doctor`).
/// Re-exported as [`super::ModuleHealth`] — `pub(crate)`, not `pub(super)`:
/// instances escape `core::engine` entirely via [`super::module_health_report`],
/// so `app::doctor` (a sibling module tree) needs crate-wide field access, not
/// just visibility to `health`'s immediate parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ModuleHealth {
    /// The dispatched module's name.
    pub(crate) name: &'static str,
    /// Consecutive failed dispatches since the last recorded success.
    pub(crate) consecutive_failures: u32,
    /// Epoch seconds of the last recorded success, or `None` if this module
    /// has never succeeded during this process's uptime.
    pub(crate) last_success_at: Option<u64>,
}

/// Every module currently showing a failure streak, worst-first (ties broken
/// by name for deterministic output — the underlying map is a `HashMap`).
/// Empty on a freshly-started or fully healthy process — the common case,
/// so `hse doctor` prints nothing extra when there's nothing to report.
pub(super) fn unhealthy_modules() -> Vec<ModuleHealth> {
    let g = state()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut v: Vec<ModuleHealth> = g
        .iter()
        .filter(|(_, h)| h.consecutive_failures > 0)
        .map(|(name, h)| ModuleHealth {
            name,
            consecutive_failures: h.consecutive_failures,
            last_success_at: h.last_success_at,
        })
        .collect();
    v.sort_by(|a, b| {
        b.consecutive_failures
            .cmp(&a.consecutive_failures)
            .then_with(|| a.name.cmp(b.name))
    });
    v
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
