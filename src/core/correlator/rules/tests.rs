
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

    #[test]
    fn au114_transitive_credential_reuse_blast_radius_fires() {
        // Secret A ties alice+bob; a DIFFERENT secret B ties bob+carol. No single
        // secret spans all three, so only the transitive-closure rule (AU-114)
        // surfaces the full three-account blast radius — the AU-047 blind spot.
        let mut a = Entity::new(
            EntityKind::Password,
            "$2b$12$abcdefghijklmnopqrstuv0123456789ABCDEFGHIJKLMNOPqrst",
            0.9,
            "scan-au114",
        );
        a.add_evidence(Evidence::new("breach", "record").with_attr("username", "alice"));
        a.add_evidence(Evidence::new("breach", "record").with_attr("username", "bob"));
        let mut b = Entity::new(
            EntityKind::Password,
            "$2b$12$ZYXWVUTSRQPONMLKJIHGFE9876543210zyxwvutsrqponmlkAAAA",
            0.9,
            "scan-au114",
        );
        b.add_evidence(Evidence::new("breach", "record").with_attr("username", "bob"));
        b.add_evidence(Evidence::new("breach", "record").with_attr("username", "carol"));
        let results = super::rule_au_114_credential_reuse_blast_radius(&[a, b], "scan-au114", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-114 must fire once on a transitive reuse chain no single secret spans"
        );
        assert_eq!(results[0].rule_id, "AU-114");
    }

    #[test]
    fn au115_trackable_rf_device_fires_on_a_hardware_mac_in_a_sweep() {
        // A universally-administered device (0x3C, U/L bit clear) alongside a
        // randomized privacy address (0x36, U/L bit set) — both radar-tagged.
        let mut hw = Entity::new(EntityKind::MacAddress, "3C:5A:B4:11:22:33", 0.8, "scan-au115");
        hw.tag("bluetooth");
        let mut rnd = Entity::new(EntityKind::MacAddress, "36:32:62:36:31:33", 0.8, "scan-au115");
        rnd.tag("bluetooth");
        let results = super::rule_au_115_trackable_rf_device(&[hw, rnd], "scan-au115", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-115 must fire when a trackable hardware MAC is present in an RF sweep"
        );
        assert_eq!(results[0].rule_id, "AU-115");
    }

    #[test]
    fn au116_transitive_infrastructure_closure_fires() {
        use crate::core::relation::{Relation, RelationKind};
        // a.com → IP1 ← b.com → IP2 ← c.com: three owners chained across two IPs,
        // a footprint no single-shared-host rule can see.
        let a = Entity::new(EntityKind::Domain, "a.com", 0.8, "scan-au116");
        let b = Entity::new(EntityKind::Domain, "b.com", 0.8, "scan-au116");
        let c = Entity::new(EntityKind::Domain, "c.com", 0.8, "scan-au116");
        let ip1 = Entity::new(EntityKind::IpAddress, "203.0.113.1", 0.8, "scan-au116");
        let ip2 = Entity::new(EntityKind::IpAddress, "203.0.113.2", 0.8, "scan-au116");
        let mk = |f: &Entity, t: &Entity| {
            Relation::new(f.uid.clone(), t.uid.clone(), RelationKind::ResolvesTo, 0.8, "scan-au116")
        };
        let rels = [mk(&a, &ip1), mk(&b, &ip1), mk(&b, &ip2), mk(&c, &ip2)];
        let ents = [a, b, c, ip1, ip2];
        let results = super::rule_au_116_infrastructure_pivot_closure(&ents, &rels, "scan-au116", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-116 must fire on a multi-server infrastructure chain"
        );
        assert_eq!(results[0].rule_id, "AU-116");
    }

    #[test]
    fn au117_personal_device_constellation_fires_on_a_bonded_kit() {
        // Two paired (bond:bonded) Bluetooth devices; one broadcasts a persistent
        // universally-administered MAC (0x3C) — a self-carried hardware fingerprint.
        let mut car = Entity::new(EntityKind::MacAddress, "3C:5A:B4:11:22:33", 0.8, "scan-au117");
        car.tag("bluetooth");
        car.tag("bond:bonded");
        let mut buds = Entity::new(EntityKind::MacAddress, "36:32:62:36:31:33", 0.8, "scan-au117");
        buds.tag("bluetooth");
        buds.tag("bond:bonded");
        let results = super::rule_au_117_personal_device_constellation(&[car, buds], "scan-au117", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-117 must fire on a bonded kit with a trackable member"
        );
        assert_eq!(results[0].rule_id, "AU-117");
    }

    #[test]
    fn au118_lookalike_domain_impersonation_fires() {
        // paypal.com vs paypa1.com — a homoglyph phishing look-alike discovered
        // in the same scan.
        let real = Entity::new(EntityKind::Domain, "paypal.com", 0.8, "scan-au118");
        let fake = Entity::new(EntityKind::Domain, "paypa1.com", 0.8, "scan-au118");
        let results = super::rule_au_118_lookalike_domain_impersonation(&[real, fake], "scan-au118", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-118 must fire on a homoglyph domain look-alike pair"
        );
        assert_eq!(results[0].rule_id, "AU-118");
    }
