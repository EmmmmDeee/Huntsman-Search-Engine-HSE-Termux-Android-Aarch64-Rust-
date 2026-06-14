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
