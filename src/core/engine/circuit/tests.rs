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
        // FALSE-POSITIVE REGRESSION: the old bare-substring vocabulary matched
        // "exceeded" and "429"/"402" anywhere, so each of these hard-tripped the
        // 600s cooldown and silently blackholed a HEALTHY provider for the rest of
        // the scan. They must now fall through to the soft path.
        assert!(
            !is_rate_limited("operation timed out: deadline exceeded"),
            "a transport timeout is not a rate limit"
        );
        assert!(
            !is_rate_limited("no results for +61429551402"),
            "an echoed phone number containing 429/402 is not a rate limit"
        );
        assert!(
            !is_rate_limited("record: 4029 4000 0000 0002 credit card"),
            "breach text mentioning 'credit card' is not a rate limit"
        );
        assert!(
            !is_rate_limited("upstream deadline exceeded for id 1402934"),
            "a digit run containing 402/429 is not a standalone status token"
        );
        // Genuine quota/limit signals still classify (co-located with a status word).
        assert!(is_rate_limited("HTTP 429 Too Many Requests"));
        assert!(is_rate_limited("monthly credit exhausted"));
        assert!(is_rate_limited("API count exceeded"));
    }

    #[test]
    fn timeout_and_echoed_identifier_take_the_soft_path_not_the_hard_cooldown() {
        // End-to-end through record_error: ONE such error must not open the breaker
        // (the 3-strike soft path owns transient failures), where the old code
        // hard-tripped on the first occurrence.
        let m = "t_timeout_is_soft";
        record_error(m, "operation timed out: deadline exceeded");
        assert!(!is_open(m), "a single timeout must not trip the breaker");

        let p = "t_echoed_id_is_soft";
        record_error(p, "no results for +61429551402");
        assert!(!is_open(p), "an echoed identifier must not trip the breaker");
    }
