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

    // ── Scan isolation (metamorphic properties) ───────────────────────────
    //
    // These pin the actual invariant the per-scan-id map exists to guarantee:
    // one scan's lifecycle operations (reset, cap override, exhaustion,
    // cleanup) must be observationally invisible to every OTHER scan sharing
    // the same `QuotaBudget`, for ANY pair of distinct scan ids and ANY
    // sequence of interleaved operations — not just the hand-picked examples
    // above. Each property is a metamorphic relation: run operation X against
    // scan A, run a DIFFERENT operation against scan B, then assert scan A's
    // observable state is exactly what it would have been had scan B's
    // operation never happened at all.

    use proptest::prelude::*;

    /// A single operation one "scan" can perform against a shared budget,
    /// for the interleaving property tests below.
    #[derive(Debug, Clone, Copy)]
    enum Op {
        Increment,
        TryIncrement,
        ResetScan,
        ResetRound,
        MarkExhausted,
        SetCapOverride(u32),
    }

    fn apply_op(b: &QuotaBudget, op: Op) {
        match op {
            Op::Increment => b.increment(),
            Op::TryIncrement => {
                b.try_increment();
            }
            Op::ResetScan => b.reset_scan(),
            Op::ResetRound => b.reset_round(),
            Op::MarkExhausted => b.mark_exhausted(),
            Op::SetCapOverride(cap) => b.set_scan_cap_override(cap),
        }
    }

    fn arb_op() -> impl Strategy<Value = Op> {
        prop_oneof![
            Just(Op::Increment),
            Just(Op::TryIncrement),
            Just(Op::ResetScan),
            Just(Op::ResetRound),
            Just(Op::MarkExhausted),
            (1u32..200).prop_map(Op::SetCapOverride),
        ]
    }

    proptest! {
        /// Metamorphic relation: for any distinct scan ids A and B, and any
        /// sequence of operations against A followed by any sequence of
        /// operations against B, A's snapshot after B's operations must
        /// equal A's snapshot before B's operations. B's activity — including
        /// a reset, an exhaustion latch, or a cap override — must be
        /// completely invisible to A.
        ///
        /// This is the exact property the pre-fix single-static design
        /// violated: `reset_scan()` (B's operation) used to zero a SHARED
        /// counter, silently renewing A's cap and un-latching A's exhausted
        /// flag every time a sibling scan started.
        #[test]
        fn a_different_scans_operations_are_invisible_to_this_scan(
            scan_a in "[a-z]{1,6}",
            scan_b in "[a-z]{1,6}",
            ops_a in prop::collection::vec(arb_op(), 1..15),
            ops_b in prop::collection::vec(arb_op(), 1..15),
        ) {
            prop_assume!(scan_a != scan_b);
            let b = QuotaBudget::new("t", 50, 100_000, "HSE_MT_ISOLATION_A", "HSE_MT_ISOLATION_AS");

            with_scan_sync(&scan_a, || {
                for op in &ops_a {
                    apply_op(&b, *op);
                }
            });
            let before = with_scan_sync(&scan_a, || b.snapshot());

            with_scan_sync(&scan_b, || {
                for op in &ops_b {
                    apply_op(&b, *op);
                }
            });
            let after = with_scan_sync(&scan_a, || b.snapshot());

            prop_assert_eq!(before.scan_used, after.scan_used, "scan_used must be invisible to a sibling scan's ops");
            prop_assert_eq!(before.scan_cap, after.scan_cap, "scan_cap (cap override) must be invisible to a sibling scan's ops");
            prop_assert_eq!(before.quota_exhausted, after.quota_exhausted, "quota_exhausted must be invisible to a sibling scan's ops");
        }

        /// Metamorphic relation: the session counter is the sum of every
        /// successful `increment`/`try_increment` across ALL scans,
        /// regardless of how the scan-level operations (reset_scan,
        /// reset_round, mark_exhausted, cap overrides — none of which touch
        /// session_count) are interleaved or which scan_id each ran under.
        /// Reformulated as a relation between two runs: replaying the SAME
        /// increments under a DIFFERENT interleaving of scan-level resets
        /// must yield the SAME session total.
        #[test]
        fn session_total_is_invariant_to_how_scan_level_resets_are_interleaved(
            n_increments in 1u32..25,
            reset_after in prop::collection::vec(any::<bool>(), 1..25),
        ) {
            // Run A: increments only, no resets.
            let a = QuotaBudget::new("t", 100_000, 100_000, "HSE_MT_SESSION_A", "HSE_MT_SESSION_AS");
            with_scan_sync("scan-a", || {
                for _ in 0..n_increments {
                    a.increment();
                }
            });

            // Run B: the SAME number of increments, but with reset_scan()
            // interspersed (on a mix of the same and different scan ids)
            // after some of them, per `reset_after`.
            let b = QuotaBudget::new("t", 100_000, 100_000, "HSE_MT_SESSION_B", "HSE_MT_SESSION_BS");
            let scans = ["scan-x", "scan-y", "scan-z"];
            for i in 0..n_increments {
                let scan = scans[(i as usize) % scans.len()];
                with_scan_sync(scan, || b.increment());
                if reset_after.get(i as usize).copied().unwrap_or(false) {
                    with_scan_sync(scan, || b.reset_scan());
                }
            }

            prop_assert_eq!(
                a.snapshot().session_used,
                n_increments,
                "session total must equal the increment count with no resets"
            );
            prop_assert_eq!(
                b.snapshot().session_used,
                n_increments,
                "session total must equal the SAME increment count even with scan_reset()s interleaved across multiple scan ids — reset_scan() must never touch session_count"
            );
        }

        /// Metamorphic relation: `try_increment`'s per-scan cap is
        /// enforced for THIS scan no matter how many times a SIBLING scan
        /// resets itself in between — the pre-fix bug let any scan's start
        /// silently "renew" every other concurrently-tracked scan's cap by
        /// zeroing the shared counter they all raced on.
        #[test]
        fn try_increment_cap_holds_for_one_scan_despite_sibling_resets(
            cap in 1u32..20,
            attempts in 1u32..60,
            sibling_resets in 0u32..30,
        ) {
            let b = QuotaBudget::new("t", cap, 1_000_000, "HSE_MT_CAP_A", "HSE_MT_CAP_AS");
            let mut successes = 0u32;
            for i in 0..attempts {
                with_scan_sync("scan-under-test", || {
                    if b.try_increment() {
                        successes += 1;
                    }
                });
                if i < sibling_resets {
                    // A completely different, concurrently-tracked scan
                    // resetting itself must never renew scan-under-test's cap.
                    with_scan_sync("sibling-scan", || b.reset_scan());
                }
            }
            prop_assert!(
                successes <= cap,
                "scan-under-test admitted {successes} queries against a cap of {cap}, despite {sibling_resets} sibling-scan resets — a sibling's reset must never renew this scan's budget"
            );
        }

        /// Metamorphic relation: `cleanup_scan(id)` removes exactly the
        /// named scan's state (subsequent reads see the same defaults as a
        /// scan that never ran) and leaves every OTHER scan's state exactly
        /// as it was — the same invisibility relation as the first property,
        /// specialised to the engine's scan-finalisation cleanup hook.
        #[test]
        fn cleanup_scan_removes_only_the_named_scan(
            scan_a in "[a-z]{1,6}",
            scan_b in "[a-z]{1,6}",
            ops_a in prop::collection::vec(arb_op(), 1..10),
            ops_b in prop::collection::vec(arb_op(), 1..10),
        ) {
            prop_assume!(scan_a != scan_b);
            let b = QuotaBudget::new("t", 50, 100_000, "HSE_MT_CLEANUP_A", "HSE_MT_CLEANUP_AS");

            with_scan_sync(&scan_a, || { for op in &ops_a { apply_op(&b, *op); } });
            with_scan_sync(&scan_b, || { for op in &ops_b { apply_op(&b, *op); } });
            let before_b = with_scan_sync(&scan_b, || b.snapshot());

            b.cleanup_scan(&scan_a);

            let after_a = with_scan_sync(&scan_a, || b.snapshot());
            let after_b = with_scan_sync(&scan_b, || b.snapshot());

            prop_assert_eq!(after_a.scan_used, 0, "a cleaned-up scan must read back as never-having-run");
            prop_assert_eq!(after_b.scan_used, before_b.scan_used, "cleanup_scan on A must not change B's scan_used");
            prop_assert_eq!(after_b.scan_cap, before_b.scan_cap, "cleanup_scan on A must not change B's scan_cap");
            prop_assert_eq!(after_b.quota_exhausted, before_b.quota_exhausted, "cleanup_scan on A must not change B's quota_exhausted");
        }
    }

    /// End-to-end proof that the ambient actually survives real `tokio::spawn`
    /// task boundaries — the property tests above use the SYNCHRONOUS
    /// `with_scan_sync` scope, which proves the per-scan-id logic is correct
    /// but not that the ambient propagates the way the engine actually uses
    /// it. This mirrors the engine's real dispatch pattern exactly:
    /// `set.spawn(util::budget::with_scan(sid, async move { ... }))`
    /// (`core::engine::dispatch`'s per-module spawn). Two scans run as
    /// genuinely concurrent tokio tasks against ONE shared budget; one scan
    /// exhausts and increments heavily, the other must be completely
    /// unaffected.
    ///
    /// `multi_thread` (not the `#[tokio::test]` default `current_thread`
    /// flavor): production (`main.rs`) builds a genuine
    /// `new_multi_thread()` runtime, so a `current_thread` test would only
    /// prove correctness under cooperative single-core interleaving, not
    /// the true OS-thread parallelism `hse serve` actually runs under.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_scans_via_real_tokio_spawn_stay_isolated() {
        static B: QuotaBudget = QuotaBudget::new(
            "concurrent-test",
            1_000_000,
            1_000_000,
            "HSE_MT_SPAWN_NONEXISTENT",
            "HSE_MT_SPAWN_NONEXISTENT_S",
        );

        let handle_a = tokio::spawn(with_scan("concurrent-scan-a".to_string(), async {
            for _ in 0..5 {
                B.increment();
            }
            B.mark_exhausted();
        }));
        let handle_b = tokio::spawn(with_scan("concurrent-scan-b".to_string(), async {
            for _ in 0..3 {
                B.increment();
            }
        }));

        let (a, b) = tokio::join!(handle_a, handle_b);
        a.expect("scan A task must not panic");
        b.expect("scan B task must not panic");

        let snap_a = with_scan("concurrent-scan-a".to_string(), async { B.snapshot() }).await;
        let snap_b = with_scan("concurrent-scan-b".to_string(), async { B.snapshot() }).await;

        assert_eq!(snap_a.scan_used, 5);
        assert!(
            snap_a.quota_exhausted,
            "scan A latched its own exhaustion"
        );
        assert_eq!(
            snap_b.scan_used, 3,
            "scan B's count must be exactly its own increments, not mixed with A's"
        );
        assert!(
            !snap_b.quota_exhausted,
            "scan B must NOT be exhausted just because a concurrently-spawned scan A latched its own exhaustion — this is exactly the isolation the pre-fix single-static design broke"
        );
        assert_eq!(
            B.snapshot().session_used,
            8,
            "the shared session counter must still see both scans' increments (8 total) — only the per-scan state is isolated"
        );
    }

    /// Adversarial stress test: [`crate::api::MAX_CONCURRENT_SCANS`] (8)
    /// scans, each a genuinely parallel OS thread (`multi_thread`,
    /// `worker_threads = 8`), each hammering `try_increment` in a tight
    /// loop against ONE shared budget — the exact production shape
    /// (`hse serve`'s scan_semaphore bounds concurrency at this same
    /// number) and the exact access pattern (many rapid `try_increment`
    /// calls racing on the shared `Mutex<HashMap>`) the original bug
    /// report was about. Every scan's admitted-count must land EXACTLY on
    /// its own cap — not less (a lost reservation) and never more (a cap
    /// bypass) — despite genuine cross-core contention on the shared lock.
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn eight_concurrent_scans_under_true_parallel_contention_each_land_exactly_on_their_own_cap()
     {
        static B: QuotaBudget = QuotaBudget::new(
            "stress-test",
            1_000_000_000,
            1_000_000_000,
            "HSE_MT_STRESS_NONEXISTENT",
            "HSE_MT_STRESS_NONEXISTENT_S",
        );

        const N_SCANS: u32 = 8;
        const CAP: u32 = 37; // deliberately not a round number
        const ATTEMPTS_PER_SCAN: u32 = CAP * 5; // heavy oversubscription

        let mut handles = Vec::new();
        for i in 0..N_SCANS {
            let scan_id = format!("stress-scan-{i}");
            handles.push(tokio::spawn(with_scan(scan_id.clone(), async move {
                // set_scan_cap_override before any try_increment, same as the
                // engine installing ScanOptions::seeknow_scan_cap at scan start.
                B.set_scan_cap_override(CAP);
                let mut successes = 0u32;
                for _ in 0..ATTEMPTS_PER_SCAN {
                    if B.try_increment() {
                        successes += 1;
                    }
                    // Yield so the tokio scheduler can genuinely interleave
                    // this task with its siblings on other worker threads,
                    // maximising the window for any cross-scan contention.
                    tokio::task::yield_now().await;
                }
                (scan_id, successes)
            })));
        }

        let mut total_successes = 0u32;
        for h in handles {
            let (scan_id, successes) = h.await.expect("stress task must not panic");
            assert_eq!(
                successes, CAP,
                "{scan_id} admitted {successes}/{CAP} — under genuine multi-thread contention every scan must land EXACTLY on its own cap, neither short-changed nor over-admitted"
            );
            total_successes += successes;
        }

        assert_eq!(
            B.snapshot().session_used,
            total_successes,
            "the session counter must equal the sum of every scan's actual admissions, with no double-count or lost increment from the concurrent contention"
        );
    }
