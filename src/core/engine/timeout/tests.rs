use super::*;
    use crate::core::module::{Module, ModuleContext};
    use crate::core::scan::Target;

    #[test]
    fn constrained_cap_bounds_long_modules_only_when_constrained_without_override() {
        // Desktop (not constrained): full timeout preserved, even 120 s.
        assert_eq!(apply_constrained_cap(120_000, false, false, false), 120_000);
        // Constrained, no user override, not exempt: the worst offenders clamp to 45 s...
        assert_eq!(
            apply_constrained_cap(120_000, false, true, false),
            CONSTRAINED_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(
            apply_constrained_cap(90_000, false, true, false),
            CONSTRAINED_MODULE_TIMEOUT_CAP_MS
        );
        // ...the old 60 s ceiling is now itself clamped down to the 45 s cap...
        assert_eq!(
            apply_constrained_cap(60_000, false, true, false),
            CONSTRAINED_MODULE_TIMEOUT_CAP_MS
        );
        assert_eq!(CONSTRAINED_MODULE_TIMEOUT_CAP_MS, 45_000);
        // ...while the common short timeouts pass through unchanged.
        assert_eq!(apply_constrained_cap(8_000, false, true, false), 8_000);
        assert_eq!(apply_constrained_cap(20_000, false, true, false), 20_000);
        // An explicit --module-timeout is honoured verbatim, even when
        // constrained, even above the cap (the operator asked for it).
        assert_eq!(apply_constrained_cap(120_000, true, true, false), 120_000);
    }

    #[test]
    fn cap_exempt_module_keeps_its_full_constrained_budget() {
        // A cap-exempt module (e.g. see_know, whose ~55 s server cap exceeds the
        // 45 s clamp) keeps its full budget on a constrained device — clamping
        // it would guarantee a zero-data timeout on every phone scan. Exemption
        // only matters when constrained without a user override (the cap's
        // domain); elsewhere the value already passes through.
        assert_eq!(apply_constrained_cap(80_000, false, true, true), 80_000);
        // Non-exempt peer with the same budget is still clamped — the exemption
        // is per-module, not a blanket cap raise.
        assert_eq!(
            apply_constrained_cap(80_000, false, true, false),
            CONSTRAINED_MODULE_TIMEOUT_CAP_MS
        );
    }

    #[test]
    fn resolve_timeout_uses_constrained_budget_then_cap() {
        // A module whose constrained-device budget is below the cap is honoured
        // as-is on a phone, while its larger desktop budget is what's used when
        // unconstrained. (apply_constrained_cap carries the `constrained`
        // branch; here we assert the base-selection + clamp composition for
        // both a default and an override module, independent of the runtime
        // environment.)
        struct DefaultMod; // constrained_timeout_ms defaults to max_timeout_ms
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
        struct TrimmedMod; // overrides the constrained-device budget down
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
            fn constrained_timeout_ms(&self) -> u64 {
                30_000
            }
        }
        // Default module: desktop budget is the full 120 s; the constrained-
        // device budget defaults to the same value but is clamped by the cap
        // to 45 s.
        assert_eq!(DefaultMod.constrained_timeout_ms(), 120_000);
        assert!(!DefaultMod.constrained_timeout_cap_exempt());
        assert_eq!(
            apply_constrained_cap(
                DefaultMod.constrained_timeout_ms(),
                false,
                true,
                DefaultMod.constrained_timeout_cap_exempt()
            ),
            45_000
        );
        // Trimmed module: its 30 s constrained-device budget is under the cap,
        // so it is used verbatim on a phone and is strictly tighter than the
        // default.
        assert_eq!(TrimmedMod.constrained_timeout_ms(), 30_000);
        assert_eq!(
            apply_constrained_cap(
                TrimmedMod.constrained_timeout_ms(),
                false,
                true,
                TrimmedMod.constrained_timeout_cap_exempt()
            ),
            30_000
        );
        assert!(TrimmedMod.constrained_timeout_ms() < DefaultMod.constrained_timeout_ms());
    }
