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
    }

    #[test]
    fn success_does_not_clear_an_active_rate_limit_trip() {
        // Regression: `record_success` used to unconditionally `remove()` the
        // whole Trip entry on ANY success, so a rate-limit cooldown set by one
        // call could be wiped moments later by an unrelated concurrent
        // success to the SAME module (e.g. a second scan's already-in-flight
        // call to the same provider completing after the first scan's 429
        // tripped it — `hse serve` allows several concurrent scans, and the
        // breaker gate is only consulted once, before dispatch, so both calls
        // can pass it before either finishes). That reopened the exact
        // retry-futile window this breaker exists to close, for every scan
        // sharing the endpoint. A rate limit is a deterministic, timed
        // property of the endpoint (see the module doc) — a success that
        // didn't actually observe the cooldown elapsing must not clear it.
        let m = "t_rate_limit_survives_success";
        record_error(m, "HTTP 429 Too Many Requests: rate limit exceeded");
        assert!(is_open(m), "a 429 must trip the breaker at once");
        record_success(m);
        assert!(
            is_open(m),
            "a concurrent success must not clear an active rate-limit cooldown"
        );
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
