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
/// `termux_timeout_ms()` can trim further below this.
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
    apply_termux_cap(base, user_set.is_some(), is_termux)
}

/// Pure timeout-capping policy (split out so it's unit-testable without env):
/// on Termux with no user override, clamp to [`TERMUX_MODULE_TIMEOUT_CAP_MS`];
/// otherwise pass the resolved value through unchanged.
fn apply_termux_cap(base_ms: u64, user_set: bool, is_termux: bool) -> u64 {
    if is_termux && !user_set {
        base_ms.min(TERMUX_MODULE_TIMEOUT_CAP_MS)
    } else {
        base_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::module::{Module, ModuleContext};
    use crate::core::scan::Target;

    #[test]
    fn termux_cap_bounds_long_modules_only_on_termux_without_override() {
        // Desktop (not Termux): full timeout preserved, even 120 s.
        assert_eq!(apply_termux_cap(120_000, false, false), 120_000);
        // Termux, no user override: the worst offenders are clamped to 45 s...
        assert_eq!(
            apply_termux_cap(120_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(
            apply_termux_cap(90_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        // ...the old 60 s ceiling is now itself clamped down to the 45 s cap...
        assert_eq!(
            apply_termux_cap(60_000, false, true),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(TERMUX_MODULE_TIMEOUT_CAP_MS, 45_000);
        // ...while the common short timeouts pass through unchanged.
        assert_eq!(apply_termux_cap(8_000, false, true), 8_000);
        assert_eq!(apply_termux_cap(20_000, false, true), 20_000);
        // An explicit --module-timeout is honoured verbatim, even on Termux,
        // even above the cap (the operator asked for it).
        assert_eq!(apply_termux_cap(120_000, true, true), 120_000);
    }

    #[test]
    fn resolve_timeout_uses_termux_budget_then_cap() {
        // A module whose Termux budget is below the cap is honoured as-is on a
        // phone, while its larger desktop budget is what's used off-Termux.
        // (apply_termux_cap carries the is_termux branch; here we assert the
        // base-selection + clamp composition for both a default and an
        // override module, independent of the runtime environment.)
        struct DefaultMod; // termux_timeout_ms defaults to max_timeout_ms
        #[async_trait::async_trait]
        impl Module for DefaultMod {
            fn name(&self) -> &'static str {
                "d"
            }
            fn priority(&self) -> u8 {
                1
            }
            fn accepts(&self, _t: &Target) -> bool {
                false
            }
            async fn process(
                &self,
                _t: &Target,
                _c: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                Ok(crate::core::module::ModuleResult::new())
            }
            fn max_timeout_ms(&self) -> u64 {
                120_000
            }
        }
        struct TrimmedMod; // overrides termux budget down
        #[async_trait::async_trait]
        impl Module for TrimmedMod {
            fn name(&self) -> &'static str {
                "t"
            }
            fn priority(&self) -> u8 {
                1
            }
            fn accepts(&self, _t: &Target) -> bool {
                false
            }
            async fn process(
                &self,
                _t: &Target,
                _c: &ModuleContext,
            ) -> crate::core::error::Result<crate::core::module::ModuleResult> {
                Ok(crate::core::module::ModuleResult::new())
            }
            fn max_timeout_ms(&self) -> u64 {
                120_000
            }
            fn termux_timeout_ms(&self) -> u64 {
                30_000
            }
        }
        // Default module: desktop budget is the full 120 s; the Termux budget
        // defaults to the same value but is clamped by the cap to 45 s.
        assert_eq!(DefaultMod.termux_timeout_ms(), 120_000);
        assert_eq!(
            apply_termux_cap(DefaultMod.termux_timeout_ms(), false, true),
            45_000
        );
        // Trimmed module: its 30 s Termux budget is under the cap, so it is
        // used verbatim on a phone and is strictly tighter than the default.
        assert_eq!(TrimmedMod.termux_timeout_ms(), 30_000);
        assert_eq!(
            apply_termux_cap(TrimmedMod.termux_timeout_ms(), false, true),
            30_000
        );
        assert!(TrimmedMod.termux_timeout_ms() < DefaultMod.termux_timeout_ms());
    }
}
