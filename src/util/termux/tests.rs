use super::*;

    /// A binary that cannot spawn is absent, and absence is a property of the
    /// binary — so it suppresses every invocation of it, whatever the argv.
    #[tokio::test]
    async fn spawn_failure_marks_the_binary_absent_for_every_argv() {
        let bogus = "termux-selftest-nonexistent-tool-xyz";
        clear_unavailable_for_test(bogus);

        // First call spawns, fails (ENOENT) → None, and is cached absent.
        assert!(termux_cmd(bogus, &["-p", "gps"], 500).await.is_none());
        assert!(
            state()
                .absent
                .get(bogus)
                .is_some_and(|&until| until > Instant::now()),
            "a tool that would not spawn must be cached absent"
        );

        // A DIFFERENT argv of the same binary is short-circuited too: the
        // package isn't installed, so no invocation of it can work.
        assert_eq!(
            check_skip(bogus, &["-r", "last"], Instant::now()),
            Some("tool absent (would not spawn)")
        );
    }

    /// The regression that blinded a running radar: a timeout is a property of
    /// one invocation at one moment, not of the binary. It must not suppress a
    /// sibling invocation — that is what collapsed signal_radar's GNSS ladder,
    /// whose whole purpose is to fall back to the cheap last-known-fix read
    /// when the expensive fresh lock is the thing that timed out.
    #[test]
    fn timeout_backs_off_only_the_invocation_that_timed_out() {
        let cmd = "termux-selftest-ladder";
        let now = Instant::now();
        record_timeout(cmd, &["-p", "gps", "-r", "once"], now);

        assert_eq!(
            check_skip(cmd, &["-p", "gps", "-r", "once"], now),
            Some("backing off after timeout"),
            "the invocation that timed out must be backed off"
        );
        assert_eq!(
            check_skip(cmd, &["-p", "network", "-r", "last"], now),
            None,
            "a sibling invocation must stay live — the fallback exists for exactly this case"
        );
    }

    /// A timeout must not write a sensor off the way a missing binary is: the
    /// first backoff is short enough to recover within a sweep or two, and only
    /// a run of consecutive timeouts escalates to the absent-tool ceiling.
    #[test]
    fn timeout_backoff_escalates_from_short_and_caps() {
        let cmd = "termux-selftest-escalate";
        let now = Instant::now();
        let ladder: Vec<u64> = (0..6)
            .map(|_| record_timeout(cmd, &[], now).as_secs())
            .collect();
        assert_eq!(
            ladder,
            vec![30, 60, 120, 240, 300, 300],
            "backoff must start short, double per consecutive timeout, and cap"
        );
    }

    /// The backoff is a delay, not a latch: once it elapses the invocation is
    /// retried. Six sweeps of a live radar were lost to a skip that never expired
    /// within the session.
    #[test]
    fn backoff_expires_and_the_invocation_is_retried() {
        let cmd = "termux-selftest-expiry";
        let now = Instant::now();
        record_timeout(cmd, &[], now);

        assert!(check_skip(cmd, &[], now).is_some(), "skipped while backing off");
        assert_eq!(
            check_skip(cmd, &[], now + Duration::from_secs(31)),
            None,
            "the first backoff must elapse in well under the absent-tool TTL"
        );
    }

    /// A tool that answers promptly is live: that clears this invocation's
    /// backoff (so its ladder restarts from the bottom) and proves the binary
    /// exists (so any absence mark goes too) — but says nothing about a slower
    /// sibling invocation, whose backoff must survive.
    #[test]
    fn a_responsive_run_clears_its_own_marks_only() {
        let cmd = "termux-selftest-responsive";
        let now = Instant::now();
        record_absent(cmd, now);
        record_timeout(cmd, &["-r", "last"], now);
        record_timeout(cmd, &["-r", "once"], now);

        record_responsive(cmd, &["-r", "last"], true);

        assert_eq!(
            check_skip(cmd, &["-r", "last"], now),
            None,
            "the invocation that answered must be live again"
        );
        assert_eq!(
            check_skip(cmd, &["-r", "once"], now),
            Some("backing off after timeout"),
            "a sibling's backoff must survive — a fast cache read proves nothing about a slow lock"
        );

        // And its ladder restarted from the bottom rather than resuming.
        assert_eq!(record_timeout(cmd, &["-r", "last"], now).as_secs(), 30);
    }

    /// The argv key must not let two different invocations collide.
    #[test]
    fn invocation_key_separates_argv_and_degrades_to_the_bare_name() {
        assert_eq!(invocation_key("termux-location", &[]), "termux-location");
        assert_ne!(
            invocation_key("termux-location", &["-p", "gps"]),
            invocation_key("termux-location", &["-p", "network"])
        );
    }

    /// The distinction the radar reports on: an empty sweep because the radios
    /// were read and were quiet, versus an empty sweep because they were never
    /// read. Pure arithmetic over locally-built snapshots, so it does not race
    /// the process-global counters other tests move.
    #[test]
    fn activity_separates_a_quiet_sweep_from_a_blind_one() {
        let base = Activity {
            reads: 7,
            skipped: 3,
            failed: 1,
        };

        let quiet = Activity {
            reads: 9,
            ..base
        }
        .since(base);
        assert!(!quiet.took_no_readings(), "a sweep that read is not blind");
        assert!(!quiet.is_idle());

        let blind = Activity {
            skipped: 9,
            ..base
        }
        .since(base);
        assert!(
            blind.took_no_readings(),
            "skips with no reads means nothing was observed"
        );

        let failed_only = Activity {
            failed: 4,
            ..base
        }
        .since(base);
        assert!(
            failed_only.took_no_readings(),
            "a tool that ran and returned nothing usable is also no observation"
        );

        assert!(base.since(base).is_idle(), "no calls at all is idle");
        assert!(
            !base.since(base).took_no_readings(),
            "idle is not the same as blind — nothing was even asked for"
        );
    }

    /// Counter arithmetic must never panic on out-of-order operands.
    #[test]
    fn activity_delta_saturates_rather_than_underflowing() {
        let earlier = Activity {
            reads: 1,
            skipped: 1,
            failed: 1,
        };
        assert_eq!(Activity::default().since(earlier), Activity::default());
    }

    /// The masking bug the per-tool tally exists to fix: one radio succeeding
    /// must not make a DIFFERENT radio look like it was read.
    ///
    /// Uses the real process-global counters via `record_responsive`, so this
    /// pins the actual accounting rather than a re-implementation. Both tools
    /// are fictitious names, so no other test's tallies are disturbed.
    #[test]
    fn a_sibling_tools_success_does_not_mask_this_tools_failure() {
        const OK_TOOL: &str = "termux-test-radio-that-works";
        const DEAD_TOOL: &str = "termux-test-radio-that-does-not";

        let agg_before = activity();
        let ok_before = activity_for(OK_TOOL);
        let dead_before = activity_for(DEAD_TOOL);

        // One tool reads successfully; the other runs and returns nothing usable
        // — exactly the mixed sweep that defeated the aggregate.
        record_responsive(OK_TOOL, &[], true);
        record_responsive(DEAD_TOOL, &[], false);

        // The AGGREGATE cannot tell them apart: a read happened, so it reports
        // readings were taken. Trusting this for the dead radio is the bug.
        let agg = activity().since(agg_before);
        assert_eq!(agg.reads, 1);
        assert!(
            !agg.took_no_readings(),
            "the aggregate sees the sibling's read and reports the sweep as read"
        );

        // The PER-TOOL tallies are unambiguous.
        let ok = activity_for(OK_TOOL).since(ok_before);
        assert_eq!(ok.reads, 1);
        assert!(!ok.took_no_readings(), "this tool genuinely read");

        let dead = activity_for(DEAD_TOOL).since(dead_before);
        assert_eq!(dead.reads, 0);
        assert_eq!(dead.failed, 1);
        assert!(
            dead.took_no_readings(),
            "this tool took no reading, regardless of what its sibling did"
        );
    }

    /// A tool never called reports an all-zero (idle) tally rather than panicking
    /// or inventing counts — so a caller can snapshot before a sweep that may
    /// never invoke it.
    #[test]
    fn activity_for_an_uncalled_tool_is_idle() {
        let a = activity_for("termux-test-never-invoked");
        assert_eq!(a, Activity::default());
        assert!(a.is_idle());
        assert!(
            !a.took_no_readings(),
            "never asked for is idle, not blind — the two are different claims"
        );
    }
