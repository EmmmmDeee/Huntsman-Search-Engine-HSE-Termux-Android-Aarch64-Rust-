use super::*;

    #[test]
    fn classify_maps_every_outcome() {
        assert_eq!(classify(&FetchOutcome::Unreachable, 0), EngineStatus::Down);
        assert_eq!(classify(&FetchOutcome::Blocked, 0), EngineStatus::Blocked);
        assert_eq!(
            classify(&FetchOutcome::Body("x".into()), 5),
            EngineStatus::Up
        );
        // Reachable but empty → blocked, not up.
        assert_eq!(
            classify(&FetchOutcome::Body("x".into()), 0),
            EngineStatus::Blocked
        );
    }

    #[test]
    fn diagnose_distinguishes_parser_failure_from_block() {
        // Reachable page linking many EXTERNAL hosts but 0 parsed → parser defect.
        let body = FetchOutcome::Body("x".into());
        let d = diagnose(&body, 0, 25);
        assert!(d.contains("PARSER"), "got: {d}");
        // Reachable but few external links → soft-block/throttle, NOT parser blame.
        let d = diagnose(&body, 0, 2);
        assert!(
            d.contains("soft-block") || d.contains("throttling"),
            "got: {d}"
        );
        assert!(!d.contains("PARSER"), "got: {d}");
        // Up case names the count.
        assert!(diagnose(&body, 7, 30).contains('7'));
        // Network + anti-bot cases name their layer.
        assert!(diagnose(&FetchOutcome::Unreachable, 0, 0).contains("network"));
        assert!(diagnose(&FetchOutcome::Blocked, 0, 0).contains("anti-bot"));
    }

    #[test]
    fn external_link_count_ignores_engine_chrome() {
        // A brave-style nav/soft-block page: links are all the engine's own
        // chrome → 0 external hosts (so NOT falsely flagged a parser defect).
        let nav = r#"<a href="https://search.brave.com/help">h</a>
                     <a href="https://brave.com/download">d</a>
                     <a href="/settings">s</a>"#;
        assert_eq!(external_link_count(nav, "brave"), 0);
        // A real results page links distinct external hosts → counted (deduped).
        let results = r#"<a href="https://example.com/a">1</a>
                         <a href="https://example.com/b">dup-host</a>
                         <a href="https://wikipedia.org/x">2</a>
                         <a href="https://github.com/y">3</a>"#;
        assert_eq!(external_link_count(results, "brave"), 3);
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(EngineStatus::Up.as_str(), "up");
        assert_eq!(EngineStatus::Blocked.as_str(), "blocked");
        assert_eq!(EngineStatus::Down.as_str(), "down");
    }

    #[test]
    fn classify_reachable_empty_body_is_blocked() {
        // A body with content but zero parsed results is a soft-block.
        let body = FetchOutcome::Body("some page content here".into());
        assert_eq!(classify(&body, 0), EngineStatus::Blocked);
        assert_ne!(classify(&body, 0), EngineStatus::Up);
    }

    #[test]
    fn external_link_count_handles_empty_body() {
        assert_eq!(external_link_count("", "bing"), 0);
    }

/// A timeout must be diagnosed as a timeout, naming the budget it overran —
/// never as a network failure.
///
/// Measured on a real Termux device over a mobile link: an `hse engines` sweep
/// reported 14 of 17 engines "down", and NINE of them had latencies clustered at
/// 8.2-8.6 s against the (then hard-coded) 8 s budget. They were timing out, not
/// dead, and the operator was told "network/TLS failure" and reasonably
/// concluded the engines were unusable. "This engine is dead" and "we did not
/// wait long enough" need different actions, so they must read differently.
#[test]
fn a_timeout_is_diagnosed_as_a_timeout_not_a_network_failure() {
    let timed_out = FetchOutcome::TimedOut { budget_ms: 8_000 };
    let d = diagnose(&timed_out, 0, 0);

    assert!(d.contains("timed out"), "must name the timeout: {d}");
    assert!(d.contains("8000"), "must name the budget it overran: {d}");
    assert!(
        d.contains("HUNTSMAN_SEARCH_TIMEOUT_MS"),
        "must name the lever that fixes it: {d}"
    );
    assert!(
        !d.contains("network/TLS"),
        "a timeout must NOT be reported as a network failure: {d}"
    );

    // The genuinely-unreachable diagnosis stays distinct, and no longer claims
    // "timeout" as one of its possible causes — that case has its own arm now.
    let unreachable = diagnose(&FetchOutcome::Unreachable, 0, 0);
    assert!(unreachable.contains("network/TLS"), "{unreachable}");
    assert!(
        !unreachable.contains("timed out"),
        "the two causes must not read the same: {unreachable}"
    );
    assert_ne!(d, unreachable);
}

/// The per-request budget is configurable, clamped, and defaults sanely — the
/// lever the timeout diagnosis tells the operator to reach for has to exist.
#[test]
fn the_fetch_budget_is_bounded_whatever_the_env_says() {
    // Whatever this host's env holds, the value is always in the sane band —
    // a typo can neither disable the bound nor make every request fail instantly.
    let ms = crate::modules::search_engines::fetch::max_fetch_ms();
    assert!(
        (1_000..=120_000).contains(&ms),
        "budget must stay in the clamped band, got {ms}"
    );
}
