use super::*;
    use crate::core::module::{Module, ModuleContext};
    use crate::core::scan::Target;

    #[test]
    fn termux_cap_bounds_long_modules_only_on_termux_without_override() {
        // Desktop (not Termux): full timeout preserved, even 120 s.
        assert_eq!(apply_termux_cap(120_000, false, false, false), 120_000);
        // Termux, no user override, not exempt: the worst offenders clamp to 45 s...
        assert_eq!(
            apply_termux_cap(120_000, false, true, false),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(
            apply_termux_cap(90_000, false, true, false),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        // ...the old 60 s ceiling is now itself clamped down to the 45 s cap...
        assert_eq!(
            apply_termux_cap(60_000, false, true, false),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(TERMUX_MODULE_TIMEOUT_CAP_MS, 45_000);
        // ...while the common short timeouts pass through unchanged.
        assert_eq!(apply_termux_cap(8_000, false, true, false), 8_000);
        assert_eq!(apply_termux_cap(20_000, false, true, false), 20_000);
        // An explicit --module-timeout is honoured verbatim, even on Termux,
        // even above the cap (the operator asked for it).
        assert_eq!(apply_termux_cap(120_000, true, true, false), 120_000);
    }

    #[test]
    fn cap_exempt_module_keeps_its_full_termux_budget() {
        // A cap-exempt module (e.g. see_know, whose ~55 s server cap exceeds the
        // 45 s clamp) keeps its full budget on Termux — clamping it would
        // guarantee a zero-data timeout on every phone scan. Exemption only
        // matters on Termux without a user override (the cap's domain); elsewhere
        // the value already passes through.
        assert_eq!(apply_termux_cap(80_000, false, true, true), 80_000);
        // Non-exempt peer with the same budget is still clamped — the exemption
        // is per-module, not a blanket cap raise.
        assert_eq!(
            apply_termux_cap(80_000, false, true, false),
            TERMUX_MODULE_TIMEOUT_CAP_MS
        );
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
        assert!(!DefaultMod.termux_timeout_cap_exempt());
        assert_eq!(
            apply_termux_cap(
                DefaultMod.termux_timeout_ms(),
                false,
                true,
                DefaultMod.termux_timeout_cap_exempt()
            ),
            45_000
        );
        // Trimmed module: its 30 s Termux budget is under the cap, so it is
        // used verbatim on a phone and is strictly tighter than the default.
        assert_eq!(TrimmedMod.termux_timeout_ms(), 30_000);
        assert_eq!(
            apply_termux_cap(
                TrimmedMod.termux_timeout_ms(),
                false,
                true,
                TrimmedMod.termux_timeout_cap_exempt()
            ),
            30_000
        );
        assert!(TrimmedMod.termux_timeout_ms() < DefaultMod.termux_timeout_ms());
    }

    #[test]
    fn soft_deadline_is_three_quarters_of_slowest_module() {
        let opts = ScanOptions::default(); // no module_timeout_ms override
        // The Termux per-module cap (45 s) ⇒ a ~33.75 s straggler bound, well
        // under the full 45 s the JoinSet would otherwise block on for a single
        // hung module after its productive peers have joined.
        assert_eq!(target_soft_deadline_ms(&opts, 45_000), Some(33_750));
        assert_eq!(target_soft_deadline_ms(&opts, 8_000), Some(6_000));
        // Nothing spawned (or a degenerate zero budget) ⇒ no bound to apply.
        assert_eq!(target_soft_deadline_ms(&opts, 0), None);
    }

    #[test]
    fn soft_deadline_disabled_under_operator_pinned_timeout() {
        // An operator who pinned --module-timeout asked for exactly that budget on
        // every module; honour it verbatim (the same opt-out the per-module cap
        // follows) — no straggler abort.
        let opts = ScanOptions {
            module_timeout_ms: Some(20_000),
            ..ScanOptions::default()
        };
        assert_eq!(target_soft_deadline_ms(&opts, 45_000), None);
    }

    #[test]
    fn majority_arms_the_deadline_only_past_two_thirds() {
        // Empty set is never a majority — nothing to bound.
        assert!(!soft_deadline_majority_reached(0, 0));
        assert!(!soft_deadline_majority_reached(0, 3));
        // 2/3 is the threshold: with 3 spawned it arms at 2, not at 1.
        assert!(!soft_deadline_majority_reached(1, 3));
        assert!(soft_deadline_majority_reached(2, 3));
        assert!(soft_deadline_majority_reached(3, 3));
        // With 8 spawned the productive majority is 6 (ceil of 16/3).
        assert!(!soft_deadline_majority_reached(5, 8));
        assert!(soft_deadline_majority_reached(6, 8));
        // A single-module target arms as soon as it joins (1*3 >= 1*2).
        assert!(soft_deadline_majority_reached(1, 1));
    }
