use super::*;

    // The breaker is process-global, so these tests share one map and run in
    // parallel. Each uses a UNIQUE module name (the test's own name) so they are
    // mutually independent — no shared global reset that could race a sibling.

    #[test]
    fn rate_limit_trips_immediately_and_blocks() {
        let m = "t_rate_limit_trips";
        assert!(!is_open(m));
        record_error(m, "HTTP 429 Too Many Requests: rate limit exceeded");
        assert!(is_open(m), "a 429 must trip the breaker at once");
        record_success(m); // provider recovered / window reset
        assert!(!is_open(m));
    }

    #[test]
    fn quota_prose_variants_are_recognised() {
        for (i, msg) in [
            "API count exceeded - Increase Quota with Membership",
            "402 Payment Required",
            "monthly credit exhausted",
            "Rate-Limit reached",
        ]
        .iter()
        .enumerate()
        {
            // A distinct module per message — leaked global state from a sibling
            // can never mask a miss.
            let m: &'static str = Box::leak(format!("t_quota_{i}").into_boxed_str());
            record_error(m, msg);
            assert!(is_open(m), "should trip on: {msg}");
        }
    }

    #[test]
    fn soft_failures_trip_only_after_threshold() {
        let m = "t_soft_threshold";
        record_soft_failure(m);
        record_soft_failure(m);
        assert!(!is_open(m), "two transient failures must not trip");
        record_soft_failure(m);
        assert!(is_open(m), "the third consecutive failure trips");
    }

    #[test]
    fn success_resets_the_soft_streak() {
        let m = "t_success_resets";
        record_soft_failure(m);
        record_soft_failure(m);
        record_success(m); // recovered → streak cleared
        record_soft_failure(m);
        assert!(
            !is_open(m),
            "a success between failures must reset the streak"
        );
    }

    #[test]
    fn unrelated_modules_are_independent() {
        record_error("t_indep_a", "API count exceeded");
        assert!(is_open("t_indep_a"));
        assert!(
            !is_open("t_indep_b"),
            "one provider's trip must not block others"
        );
    }

    #[test]
    fn non_rate_limit_error_is_treated_as_soft() {
        let m = "t_nonrl_soft";
        // A bare connection error is soft: one occurrence must not trip.
        record_error(m, "error sending request for url (https://crt.sh/...)");
        assert!(!is_open(m));
    }

    #[test]
    fn record_error_with_an_echoed_identifier_does_not_hard_trip_the_breaker() {
        // Full end-to-end regression through the SAME public API the real
        // dispatch finaliser calls (`record_error`), not just the pure
        // classifier: a module whose own error text happens to echo a real AU
        // phone number (a shape this project's own scans routinely surface)
        // must NOT be hard-tripped for 600s on that coincidence -- it's a
        // single soft failure like any other transient error, so it takes two
        // more before the module is benched.
        let m = "t_echoed_identifier_soft";
        record_error(m, "module reported: subject phone +61429551402");
        assert!(
            !is_open(m),
            "one error containing an echoed 429/402 digit run must not hard-trip"
        );
        // Confirm it really did fall through to the soft path (not silently
        // ignored): two more of the SAME shape complete the 3-strike soft trip.
        record_error(m, "module reported: subject phone +61429551402");
        record_error(m, "module reported: subject phone +61429551402");
        assert!(
            is_open(m),
            "three consecutive soft failures must still trip, just via the \
             soft path and its shorter cooldown"
        );
    }

    // ── is_rate_limited ───────────────────────────────────────────────────────

    #[test]
    fn is_rate_limited_matches_status_codes_and_prose_case_insensitively() {
        for msg in [
            "HTTP 429 Too Many Requests",
            "rate limit exceeded",
            "Rate-Limit hit",
            "ratelimit",
            "monthly QUOTA reached",
            "API count exceeded",
            "out of credit",
            "402 Payment Required",
        ] {
            assert!(is_rate_limited(msg), "should be rate-limit: {msg}");
        }
    }

    #[test]
    fn is_rate_limited_false_for_benign_errors() {
        assert!(!is_rate_limited("connection reset by peer"));
        assert!(!is_rate_limited("404 not found"));
        assert!(!is_rate_limited(""));
    }

    #[test]
    fn is_rate_limited_does_not_misfire_on_timeouts_or_echoed_identifiers() {
        // Regression: the old vocabulary included the BARE tokens "429"/"402"/
        // "exceeded"/"credit". A tokio transport timeout's own message ("deadline
        // exceeded"), a breach/stealer record echoing a phone number that merely
        // *contains* the digits 429 or 402, or scraped text mentioning "credit
        // card" each one-shot the hard 600s RATE_LIMIT_COOLDOWN via record_error
        // -- silently dropping every subsequent finding a healthy module would
        // have produced for the rest of the scan, on a coincidental substring
        // that has nothing to do with an actual rate limit.
        assert!(
            !is_rate_limited("deadline exceeded while connecting"),
            "a transport timeout must not be read as a rate limit"
        );
        assert!(
            !is_rate_limited("subject phone: +61429551402"),
            "a phone number that merely contains 429/402 must not trip the breaker"
        );
        assert!(
            !is_rate_limited("record note: paid by credit card ending 4021"),
            "'credit card' in scraped content must not be read as a quota signal"
        );
        assert!(
            !is_rate_limited("order id 4029991402 not found"),
            "a bare digit run containing 429/402 must not match as the HTTP status"
        );
    }

    // ── cooldown expiry against an injected clock ─────────────────────────────
    //
    // These drive time by PASSING a later `now`, never by sleeping, so they are
    // deterministic and cost no wall-clock time. A device suspend is, from this
    // module's side, indistinguishable from the clock jumping forward while none
    // of our code ran — which is exactly what these hand it.
    //
    // They assert that expiry tracks the wall clock it is GIVEN. That
    // `SystemTime` keeps advancing across an Android doze is a property of the
    // OS, not of this code, and is deliberately not asserted here.

    /// A fixed wall-clock origin, so these tests don't depend on when they run.
    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
    }

    #[test]
    fn hard_trip_expiry_tracks_the_injected_wall_clock() {
        let m = "t_clock_hard_expiry";
        record_error_at(m, "HTTP 429 Too Many Requests", t0());
        assert!(is_open_at(m, t0() + Duration::from_secs(1)));
        assert!(
            is_open_at(m, t0() + RATE_LIMIT_COOLDOWN - Duration::from_secs(1)),
            "still benched one second before the cooldown elapses"
        );
        assert!(
            !is_open_at(m, t0() + RATE_LIMIT_COOLDOWN + Duration::from_secs(1)),
            "must reopen once the wall clock passes the deadline"
        );
    }

    #[test]
    fn a_suspend_outlasting_the_cooldown_reopens_the_breaker_on_wake() {
        // The defect this module's clock note describes: with a monotonic
        // deadline the elapsed suspend does not count, so the provider stays
        // benched long past its 600 s cooldown and its findings are silently
        // dropped. Against a wall clock, two hours of suspend is two hours.
        let m = "t_clock_long_suspend";
        record_error_at(m, "API count exceeded", t0());
        assert!(is_open_at(m, t0() + Duration::from_secs(30)));
        assert!(
            !is_open_at(m, t0() + Duration::from_secs(7_200)),
            "a suspend longer than the cooldown must leave the provider retryable"
        );
    }

    #[test]
    fn a_suspend_shorter_than_the_cooldown_leaves_the_trip_intact() {
        // The converse guard: the fix must not reopen a breaker early.
        let m = "t_clock_short_suspend";
        record_error_at(m, "429", t0());
        assert!(
            is_open_at(m, t0() + Duration::from_secs(300)),
            "half the cooldown has passed — the provider is still rate-limited"
        );
    }

    #[test]
    fn soft_trip_expiry_tracks_the_injected_wall_clock() {
        let m = "t_clock_soft_expiry";
        record_soft_failure_at(m, t0());
        record_soft_failure_at(m, t0());
        record_soft_failure_at(m, t0()); // third consecutive → soft trip
        assert!(is_open_at(m, t0() + SOFT_COOLDOWN - Duration::from_secs(1)));
        assert!(
            !is_open_at(m, t0() + SOFT_COOLDOWN + Duration::from_secs(1)),
            "the shorter soft cooldown expires on the same wall clock"
        );
    }

    #[test]
    fn an_untripped_soft_streak_is_never_expired_by_the_clock() {
        // A sub-threshold streak carries NO deadline, so no amount of elapsed
        // time may clear it — otherwise a doze would silently reset the streak
        // and a persistently-failing provider would never reach its trip.
        let m = "t_clock_streak_survives";
        record_soft_failure_at(m, t0());
        record_soft_failure_at(m, t0()); // streak = 2, threshold is 3
        let a_day_later = t0() + Duration::from_secs(86_400);
        assert!(!is_open_at(m, a_day_later), "two failures must not be open");
        record_soft_failure_at(m, a_day_later);
        assert!(
            is_open_at(m, a_day_later + Duration::from_secs(1)),
            "the streak survived the gap, so the third failure still trips"
        );
    }

    #[test]
    fn a_backwards_clock_step_lengthens_the_cooldown_without_panicking() {
        // The documented exposure of using a wall clock: an NTP correction
        // steps time backwards mid-cooldown. The trip must stay open (longer
        // than intended, the safe direction) and nothing may panic.
        let m = "t_clock_backwards_step";
        record_error_at(m, "429", t0());
        assert!(
            is_open_at(m, t0() - Duration::from_secs(3_600)),
            "a backwards step lengthens the bench rather than corrupting it"
        );
    }

    #[test]
    fn is_rate_limited_still_matches_429_402_as_a_standalone_token() {
        // The token-anchoring in the fix above must not overcorrect: an actual
        // HTTP 429/402 status code, appearing as its own token (delimited by
        // whitespace/punctuation), must still trip the breaker.
        assert!(is_rate_limited("HTTP 429"));
        assert!(is_rate_limited("status=429"));
        assert!(is_rate_limited("error: 402"));
        assert!(is_rate_limited("(402)"));
    }
