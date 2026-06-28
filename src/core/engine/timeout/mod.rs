//! Per-module timeout policy: resolve the effective timeout for a module from
//! the user override / module budget, and clamp pathological modules on Termux.
//! Pure functions over `ScanOptions` + `Module`, split out of the engine so the
//! dispatch loops just call `resolve_timeout` without inlining the policy.
//!
//! # Why the cap is per-module, plus a per-target straggler bound
//!
//! [`TERMUX_MODULE_TIMEOUT_CAP_MS`] bounds one module's `process()` call, not a
//! target's whole dispatch. That is deliberate: each module is an independent
//! upstream (a SERP scrape, a paid API, a DNS walk) with its own latency
//! distribution, and the cap exists to reclaim the dead tail of a *single* hung
//! mobile request without penalising a module that is legitimately still working.
//! A per-target HARD wall is the wrong tool here — it would abort a productive
//! module mid-response just because an unrelated sibling on the same target was
//! slow, and the operator already has [`ScanOptions::max_wall_time_secs`] for a
//! true scan-wide ceiling.
//!
//! But a per-module cap alone leaves a tail: in the concurrent path
//! (`dispatch_target_concurrent`), `max_concurrent` modules run against one
//! target and the JoinSet drain blocks on the *slowest* straggler — up to a full
//! capped timeout (45 s on Termux) — even after the productive majority has long
//! since joined with results. On a flaky mobile link that straggler is usually a
//! request that will time out empty anyway, so the wait is pure dead latency per
//! target, multiplied across every expansion candidate.
//!
//! [`target_soft_deadline_ms`] closes that gap WITHOUT a hard wall: it derives a
//! *soft* per-target deadline from the longest module timeout in the dispatched
//! set. The drain arms that deadline only once a productive majority has joined
//! ([`SOFT_DEADLINE_MAJORITY_NUM`]/[`SOFT_DEADLINE_MAJORITY_DEN`] of the tasks);
//! when it then elapses, the drain `abort_all()`s the remaining stragglers
//! instead of waiting out their individual caps. The deadline is a *fraction*
//! ([`SOFT_DEADLINE_FRACTION_NUM`]/[`SOFT_DEADLINE_FRACTION_DEN`]) of the slowest
//! module's own timeout, so a module that is merely on the slow side of its
//! normal range still completes, while a true hang is cut once its productive
//! peers have all reported. An operator-pinned `module_timeout_ms` opts out (the
//! operator asked for exactly that budget on every module — honour it verbatim,
//! the same contract the per-module cap follows).

use crate::core::module::Module;
use crate::core::scan::ScanOptions;

/// Upper bound (ms) on any single module's timeout when running on Termux and
/// the operator hasn't pinned `--module-timeout`. On a low-power, metered,
/// often-flaky mobile connection a 90–120 s module (search_engines, api_key_probe)
/// can stall the whole scan; capping the worst offenders keeps a phone scan
/// responsive. Desktop and any explicit user timeout are unaffected.
///
/// Lowered from 60 s after live device transcripts showed `search_engines`
/// burning the full minute for zero results on a phone: 45 s still clears every
/// legitimately-long module's happy path (social_probe ~36 s, oathnet/overpass
/// <30 s) while reclaiming the dead tail of hung mobile requests. Per-module
/// `termux_timeout_ms()` can trim further below this; a module whose happy path
/// genuinely exceeds it (see_know's ~55 s `/search` server cap) opts out via
/// [`Module::termux_timeout_cap_exempt`] rather than being killed every run.
pub(super) const TERMUX_MODULE_TIMEOUT_CAP_MS: u64 = 45_000;

pub(super) fn resolve_timeout(opts: &ScanOptions, module: &dyn Module) -> u64 {
    let user_set = opts.module_timeout_ms;
    let is_termux = crate::is_termux();
    // On Termux, consult the module's Termux-specific budget (defaults to
    // max_timeout_ms, so most modules are unaffected) so phone-pathological
    // modules self-trim; off Termux, the full desktop budget. A user-pinned
    // --module-timeout replaces both and is honoured verbatim by the cap.
    let base = match user_set {
        Some(ms) => ms,
        None if is_termux => module.termux_timeout_ms(),
        None => module.max_timeout_ms(),
    };
    apply_termux_cap(
        base,
        user_set.is_some(),
        is_termux,
        module.termux_timeout_cap_exempt(),
    )
}

/// Pure timeout-capping policy (split out so it's unit-testable without env):
/// on Termux with no user override, clamp to [`TERMUX_MODULE_TIMEOUT_CAP_MS`];
/// otherwise pass the resolved value through unchanged. A `cap_exempt` module
/// (its happy path legitimately exceeds the cap on a phone, e.g. see_know) is
/// passed through so the engine waits for its real response instead of killing
/// it — it stays bounded by its own `termux_timeout_ms`.
fn apply_termux_cap(base_ms: u64, user_set: bool, is_termux: bool, cap_exempt: bool) -> u64 {
    if is_termux && !user_set && !cap_exempt {
        base_ms.min(TERMUX_MODULE_TIMEOUT_CAP_MS)
    } else {
        base_ms
    }
}

/// Fraction of the slowest dispatched module's resolved timeout used as the
/// per-target straggler soft deadline (numerator / denominator = 3/4). Once the
/// productive majority of a target's concurrent modules has joined, the drain
/// waits at most this fraction of the slowest module's *own* timeout before
/// aborting whatever is still in flight. Three-quarters leaves a slow-but-honest
/// module room to finish its normal range while cutting the dead tail of a true
/// hang: on Termux's 45 s cap that is a ~34 s bound, vs. the full 45 s the JoinSet
/// would otherwise block on for a single straggler that will time out empty.
const SOFT_DEADLINE_FRACTION_NUM: u64 = 3;
/// Denominator paired with [`SOFT_DEADLINE_FRACTION_NUM`].
const SOFT_DEADLINE_FRACTION_DEN: u64 = 4;

/// Numerator of the "productive majority" join fraction that ARMS the per-target
/// soft deadline (numerator / denominator = 2/3). The deadline timer is not armed
/// until at least this fraction of the target's spawned modules has joined, so a
/// target where most modules are simply slow (not hung) is never cut early — the
/// bound only ever sacrifices the trailing minority once the bulk of the yield is
/// already collected.
const SOFT_DEADLINE_MAJORITY_NUM: usize = 2;
/// Denominator paired with [`SOFT_DEADLINE_MAJORITY_NUM`].
const SOFT_DEADLINE_MAJORITY_DEN: usize = 3;

/// Per-target straggler soft deadline (ms) for the concurrent dispatch path, or
/// `None` when no bound should apply.
///
/// `max_module_timeout_ms` is the largest [`resolve_timeout`] value among the
/// modules actually spawned for this target (the slowest legitimate finisher
/// governs the target's latency). The returned deadline is
/// [`SOFT_DEADLINE_FRACTION_NUM`]/[`SOFT_DEADLINE_FRACTION_DEN`] of it — the wall
/// budget the drain allows AFTER a productive majority has joined before it
/// `abort_all()`s the remaining tasks, bounding straggler tail latency on flaky
/// mobile links.
///
/// Returns `None` (no soft bound — preserve exact legacy behaviour) when:
/// - the operator pinned [`ScanOptions::module_timeout_ms`] (they asked for that
///   budget on every module verbatim, the same opt-out the per-module cap honours), or
/// - `max_module_timeout_ms` is `0` (nothing spawned, or a degenerate zero
///   budget — there is no tail to bound).
///
/// Pure and env-free (the caller passes the already-resolved max), so the policy
/// is unit-testable in isolation like [`apply_termux_cap`]; the actual arming
/// (waiting for the majority, then the timer) lives in the dispatcher.
pub(super) fn target_soft_deadline_ms(
    opts: &ScanOptions,
    max_module_timeout_ms: u64,
) -> Option<u64> {
    if opts.module_timeout_ms.is_some() || max_module_timeout_ms == 0 {
        return None;
    }
    // Saturating throughout: timeouts are operator-supplied / module-declared and
    // could in principle be near `u64::MAX`; the product can never overflow.
    Some(
        max_module_timeout_ms.saturating_mul(SOFT_DEADLINE_FRACTION_NUM)
            / SOFT_DEADLINE_FRACTION_DEN,
    )
}

/// True once `joined` of `spawned` per-target concurrent tasks have completed,
/// i.e. the productive majority ([`SOFT_DEADLINE_MAJORITY_NUM`]/
/// [`SOFT_DEADLINE_MAJORITY_DEN`]) has joined and the per-target soft deadline
/// from [`target_soft_deadline_ms`] should be armed. `spawned == 0` is never a
/// majority (nothing to bound). Pure integer comparison (no float), so the
/// threshold is exact and unit-testable without timing.
pub(super) fn soft_deadline_majority_reached(joined: usize, spawned: usize) -> bool {
    spawned > 0
        && joined.saturating_mul(SOFT_DEADLINE_MAJORITY_DEN)
            >= spawned.saturating_mul(SOFT_DEADLINE_MAJORITY_NUM)
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
