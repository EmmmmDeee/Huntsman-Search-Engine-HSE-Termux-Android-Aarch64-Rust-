use super::*;

    #[tokio::test]
    async fn failed_tool_is_cached_unavailable_then_skipped() {
        let bogus = "termux-selftest-nonexistent-tool-xyz";
        mark_available(bogus); // clean slate

        // First call spawns, fails (ENOENT) → None, and is cached unavailable.
        assert!(termux_cmd(bogus, &[], 500).await.is_none());
        assert!(
            skip_until(bogus).is_some_and(|t| t > Instant::now()),
            "a failed tool must be cached as unavailable"
        );

        // Second call short-circuits via the cache (no spawn, instant None).
        assert!(termux_cmd(bogus, &[], 500).await.is_none());

        // A success/responsive run clears the mark so it can be used again.
        mark_available(bogus);
        assert!(skip_until(bogus).is_none());
    }

    #[test]
    fn unavailable_ttl_defaults_then_honours_override() {
        // Parsing/fallback is tested directly via `unavailable_ttl_from` so we
        // never mutate process env (the crate is `#![forbid(unsafe_code)]` and
        // `std::env::set_var` is unsafe). The live `unavailable_ttl()` is a thin
        // wrapper that just feeds it the env var.

        // Unset → the compile-time default.
        assert_eq!(unavailable_ttl_from(None), DEFAULT_UNAVAILABLE_TTL);

        // A numeric override (seconds) is honoured for a faster re-probe.
        assert_eq!(unavailable_ttl_from(Some("5")), Duration::from_secs(5));

        // Zero re-probes on the very next call.
        assert_eq!(unavailable_ttl_from(Some("0")), Duration::ZERO);

        // Surrounding whitespace is tolerated.
        assert_eq!(unavailable_ttl_from(Some("  30 ")), Duration::from_secs(30));

        // Garbage / empty falls back to the default rather than panicking.
        assert_eq!(
            unavailable_ttl_from(Some("not-a-number")),
            DEFAULT_UNAVAILABLE_TTL
        );
        assert_eq!(unavailable_ttl_from(Some("")), DEFAULT_UNAVAILABLE_TTL);
        assert_eq!(unavailable_ttl_from(Some("-5")), DEFAULT_UNAVAILABLE_TTL);
    }

    #[test]
    fn adaptive_timeout_floors_at_requested_then_raises_with_latency() {
        let tool = "termux-selftest-latency-probe-xyz";
        // Clean slate: drop any recorded history for this name.
        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);

        // No history → exactly the caller's requested budget (no behaviour change).
        assert_eq!(adaptive_timeout_ms(tool, 3000), 3000);

        // A recorded slow success raises the floor to peak × headroom.
        record_latency(tool, 2500);
        assert_eq!(
            adaptive_timeout_ms(tool, 3000),
            2500 * u64::from(LATENCY_HEADROOM),
            "a tool that succeeds slowly should raise its own timeout floor"
        );

        // The window keeps the peak of recent samples; a faster later sample
        // still leaves the floor at the recent peak.
        record_latency(tool, 1000);
        assert_eq!(
            adaptive_timeout_ms(tool, 3000),
            2500 * u64::from(LATENCY_HEADROOM)
        );

        // Below the requested budget, the requested budget still wins.
        assert_eq!(adaptive_timeout_ms(tool, 9000), 9000);

        // Cleanup.
        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);
    }

    #[test]
    fn adaptive_timeout_is_capped_but_never_below_request() {
        let tool = "termux-selftest-latency-cap-xyz";
        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);

        // A pathological latency sample is clamped to the adaptive ceiling.
        record_latency(tool, 1_000_000);
        assert_eq!(adaptive_timeout_ms(tool, 3000), MAX_ADAPTIVE_TIMEOUT_MS);

        // A request larger than the cap is itself honoured (the cap never
        // shortens a caller's explicit budget).
        let big = MAX_ADAPTIVE_TIMEOUT_MS + 5000;
        assert_eq!(adaptive_timeout_ms(tool, big), big);

        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);
    }

    #[test]
    fn latency_window_is_bounded() {
        let tool = "termux-selftest-latency-window-xyz";
        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);

        for i in 0..(LATENCY_WINDOW as u64 + 4) {
            record_latency(tool, i);
        }
        let len = LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(tool)
            .map_or(0, VecDeque::len);
        assert_eq!(len, LATENCY_WINDOW, "latency window must stay bounded");

        LATENCY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(tool);
    }
