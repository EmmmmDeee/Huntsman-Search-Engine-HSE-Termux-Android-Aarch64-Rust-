//! Per-module timeout policy: resolve the effective timeout for a module from
//! the user override / module budget, and clamp pathological modules on Termux.
//! Pure functions over `ScanOptions` + `Module`, split out of the engine so the
//! dispatch loops just call `resolve_timeout` without inlining the policy.

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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
