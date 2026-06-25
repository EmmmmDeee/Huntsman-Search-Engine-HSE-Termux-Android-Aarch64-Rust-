
use super::{
    Entity, EntityKind, canonical_handle, date_diff_days, is_generic_handle, source_family,
    tagged_matching_sources, text_mentions_ip,
};
use crate::core::entity::Evidence;

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
        assert_eq!(source_family("ip_whois_geo"), "infra");
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
    fn source_family_covers_registry_scanners_and_registries() {
        // Real registry module names that used to fall to `other` (their forms
        // contain no earlier needle) and so silently under-counted family
        // diversity. Each is now classified to its genuine family.
        for m in [
            "abuseipdb",
            "bgpview",
            "criminal_ip",
            "ipqs",
            "netblock",
            "netlas",
            "onyphe",
            "portscan",
            "ripestat",
            "securitytrails",
            "zoomeye",
            "domainsdb",
        ] {
            assert_eq!(source_family(m), "infra", "{m} is network infrastructure");
        }
        for m in [
            "fullcontact",
            "contact_enrich",
            "gleif_lei",
            "asic_director",
            "au_electoral",
            "au_people",
            "ahpra",
            "acnc_charities",
        ] {
            assert_eq!(
                source_family(m),
                "identity_registry",
                "{m} is an identity/business registry"
            );
        }
        assert_eq!(source_family("hudsonrock"), "breach");
        assert_eq!(source_family("crates_io"), "code");
        assert_eq!(source_family("exa_search"), "search");

        // Deliberately left `other`: genuinely ambiguous or non-family sources —
        // crediting them as a distinct family would be over-credit, not coverage.
        for m in [
            "chain_intel",     // blockchain — no crypto family exists
            "virustotal",      // threat intel, not infra resolution
            "threatfox",       // threat-IOC feed
            "device_sensors",  // local on-device sensor
            "username_variants", // a derivation pass, not an observation
        ] {
            assert_eq!(source_family(m), "other", "{m} must stay unclassified");
        }
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

    // ── canonical_handle ──────────────────────────────────────────────────────

    #[test]
    fn canonical_handle_collapses_separators_and_case() {
        // Same handle written with different punctuation collapses to one token.
        assert_eq!(canonical_handle("Jordan.Meyers"), "jordanmeyers");
        assert_eq!(canonical_handle("jordan_meyers"), "jordanmeyers");
        assert_eq!(canonical_handle("jordan-meyers"), "jordanmeyers");
    }

    // ── is_generic_handle ─────────────────────────────────────────────────────

    #[test]
    fn is_generic_handle_flags_role_mailboxes_not_personal_handles() {
        assert!(is_generic_handle("info"));
        assert!(is_generic_handle("support"));
        assert!(!is_generic_handle("jordanmeyers"));
    }

    // ── tagged_matching_sources ───────────────────────────────────────────────

    #[test]
    fn tagged_matching_sources_intersects_evidence_with_allowlist() {
        let mut e = Entity::new(EntityKind::Username, "jdoe", 0.6, "s");
        e.add_evidence(Evidence::new("github_user", "found"));
        e.add_evidence(Evidence::new("keybase", "found"));
        e.add_evidence(Evidence::new("name_intel", "derived"));
        let allowed = ["github_user", "keybase"];
        let got = tagged_matching_sources(&e, &allowed);
        assert_eq!(got.len(), 2);
        assert!(got.contains("github_user") && got.contains("keybase"));
        assert!(!got.contains("name_intel"), "outside the allowlist");
    }


    // ── rule_au_083_locale_multi_email_corroboration ──────────────────────────

    #[test]
    fn locale_multi_email_corroboration_fires_on_two_locale_evidence_entries() {
        use super::locale::rule_au_083_locale_multi_email_corroboration;
        use crate::core::entity::Evidence;
        let mut a = Entity::new(EntityKind::Address, "Scandinavia (Sweden/Iceland)", 0.35, "scan-au083-arch");
        a.tags.push("locale-inferred".into());
        a.add_evidence(
            Evidence::new("email_locale", "locale match sv")
                .with_attr("locale", "sv")
                .with_attr("pattern", "surname_suffix"),
        );
        a.add_evidence(
            Evidence::new("email_locale", "locale match sv")
                .with_attr("locale", "sv")
                .with_attr("pattern", "surname_suffix"),
        );
        let results = rule_au_083_locale_multi_email_corroboration(&[a], "scan-au083-arch", 0);
        assert_eq!(results.len(), 1, "locale rule must fire when >=2 email_locale evidence entries share a locale");
    }
