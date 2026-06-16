
use super::{date_diff_days, source_family, text_mentions_ip};

    #[test]
    fn text_mentions_ip_is_whole_address_for_v4() {
        assert!(text_mentions_ip("seen at 1.2.3.4: Brisbane", "1.2.3.4"));
        assert!(text_mentions_ip("origin 1.2.3.4:8080", "1.2.3.4"));
        // Substring of a longer address must not match.
        assert!(!text_mentions_ip("host 11.2.3.45 responded", "1.2.3.4"));
        assert!(!text_mentions_ip("host 1.2.3.45 responded", "1.2.3.4"));
    }

    #[test]
    fn text_mentions_ip_is_whole_address_for_v6() {
        assert!(text_mentions_ip(
            "AAAA 2001:db8::1 for example.com",
            "2001:db8::1"
        ));
        // Bracketed-with-port spelling: ']' is a legitimate boundary.
        assert!(text_mentions_ip("via [2001:db8::1]:443", "2001:db8::1"));
        // Hex letters and ':' EXTEND a v6 address — these are different
        // addresses, and the v4-only boundary set falsely chained them.
        assert!(!text_mentions_ip("AAAA 2001:db8::1a for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::12 for x", "2001:db8::1"));
        assert!(!text_mentions_ip("AAAA 2001:db8::1:2 for x", "2001:db8::1"));
        // Entity values are normalised lowercase; summaries may be uppercase.
        assert!(text_mentions_ip("AAAA 2001:DB8::1 for x", "2001:db8::1"));
    }

    #[test]
    fn source_family_covers_every_registered_coarse_geo_provider() {
        // The sibling providers of the already-listed ipinfo/ipquery/wigle —
        // these fell through to "other" and were excluded from cross-family
        // diversity counts, contrary to the classifier's stated intent.
        assert_eq!(source_family("ipapi"), "infra");
        assert_eq!(source_family("ip2location"), "infra");
        assert_eq!(source_family("mylnikov"), "infra");
    }

    #[test]
    fn source_family_classifies_all_major_families() {
        assert_eq!(source_family("hibp"), "breach");
        assert_eq!(source_family("dehashed"), "breach");
        assert_eq!(source_family("github_user"), "code");
        assert_eq!(source_family("npm_author"), "code");
        assert_eq!(source_family("reddit_user"), "forum");
        assert_eq!(source_family("hacker_news"), "forum");
        assert_eq!(source_family("social_probe"), "social");
        assert_eq!(source_family("gravatar"), "social");
        assert_eq!(source_family("username_search"), "presence");
        assert_eq!(source_family("epieos"), "presence");
        assert_eq!(source_family("search_engines"), "search");
        assert_eq!(source_family("google"), "search");
        assert_eq!(source_family("smtp_vrfy"), "email_intel");
        assert_eq!(source_family("emailrep"), "email_intel");
        assert_eq!(source_family("proxycurl"), "identity_registry");
        assert_eq!(source_family("name_intel"), "identity_registry");
        assert_eq!(source_family("shodan"), "infra");
        assert_eq!(source_family("dns_intel"), "infra");
        assert_eq!(source_family("some_unknown_module"), "other");
    }

    #[test]
    fn date_diff_days_approximates_same_day_as_zero() {
        assert_eq!(date_diff_days("2024-06-15", "2024-06-15"), 0);
    }

    #[test]
    fn date_diff_days_approximates_day_gaps() {
        // 5 days apart within same month: exact
        assert_eq!(date_diff_days("2024-06-10", "2024-06-15"), 5);
        // Crossing a year boundary (~365 days)
        let gap = date_diff_days("2023-06-15", "2024-06-15");
        assert!((360..=370).contains(&gap), "year gap should be ~365, got {gap}");
    }

    #[test]
    fn date_diff_days_returns_max_for_malformed() {
        assert_eq!(date_diff_days("not-a-date", "2024-06-15"), u64::MAX);
        assert_eq!(date_diff_days("2024-06-15", ""), u64::MAX);
        assert_eq!(date_diff_days("2024-06", "2024-06-15"), u64::MAX);
    }
