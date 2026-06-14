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
