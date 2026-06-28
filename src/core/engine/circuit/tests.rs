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

    // ── cooldown_for / parse_reset_hint ───────────────────────────────────────

    #[test]
    fn bare_429_uses_short_throttle_cooldown() {
        // A plain throttle with no reset header → the short window, not the blunt
        // 600 s default that would waste the rest of the provider's scan budget.
        assert_eq!(
            cooldown_for("HTTP 429 Too Many Requests"),
            Some(THROTTLE_COOLDOWN)
        );
        assert_eq!(cooldown_for("rate limit exceeded"), Some(THROTTLE_COOLDOWN));
    }

    #[test]
    fn quota_wall_falls_back_to_long_default_cooldown() {
        // A billing-cycle reset (daily quota / exhausted credit) yields no tuning
        // signal → None, so `record_error` uses the long default window: re-probing
        // every target before the cycle rolls over is waste.
        assert_eq!(cooldown_for("API count exceeded - Increase Quota"), None);
        assert_eq!(cooldown_for("monthly credit exhausted"), None);
        assert_eq!(cooldown_for("402 Payment Required"), None);
    }

    #[test]
    fn explicit_retry_after_seconds_is_honoured() {
        // urlscan's ~300 s reset, reported as a Retry-After delay, tunes exactly.
        assert_eq!(
            cooldown_for("HTTP 429: rate limited, Retry-After: 300"),
            Some(Duration::from_secs(300))
        );
        // The header wins even over a quota signal in the same message.
        assert_eq!(
            cooldown_for("quota exceeded; retry-after = 45"),
            Some(Duration::from_secs(45))
        );
    }

    #[test]
    fn x_ratelimit_reset_relative_seconds_is_honoured() {
        assert_eq!(
            cooldown_for("429 too many requests; X-RateLimit-Reset: 90"),
            Some(Duration::from_secs(90))
        );
    }

    #[test]
    fn reset_hint_is_clamped_to_sane_bounds() {
        // Retry-After: 0 must not collapse the breaker to a no-op.
        assert_eq!(parse_reset_hint("Retry-After: 0"), Some(MIN_PARSED_COOLDOWN));
        // A hostile multi-day value must not disable a provider for the process.
        assert_eq!(
            parse_reset_hint("Retry-After: 9999999"),
            Some(MAX_PARSED_COOLDOWN)
        );
    }

    #[test]
    fn epoch_reset_is_converted_to_a_delay() {
        // A future Unix-epoch reset (now + 120 s) converts to ~120 s of cooldown,
        // not a 50-year cooldown from misreading the absolute timestamp.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_secs();
        let reset = now + 120;
        let d = parse_reset_hint(&format!("429; X-RateLimit-Reset: {reset}"))
            .expect("epoch reset must parse");
        // Allow a couple of seconds of slop for the clock read inside the parser.
        assert!(
            d >= Duration::from_secs(115) && d <= Duration::from_secs(120),
            "expected ~120 s, got {d:?}"
        );
    }

    #[test]
    fn no_reset_hint_means_none() {
        assert_eq!(parse_reset_hint("plain 429 with no header"), None);
        assert_eq!(parse_reset_hint("quota exceeded"), None);
        // An HTTP-date Retry-After is not parsed (no date lib) → None, so the
        // heuristic fallback applies rather than a wrong cooldown.
        assert_eq!(
            parse_reset_hint("Retry-After: Wed, 21 Oct 2026 07:28:00 GMT"),
            None
        );
    }
