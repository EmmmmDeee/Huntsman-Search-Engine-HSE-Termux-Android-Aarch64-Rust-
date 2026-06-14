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
