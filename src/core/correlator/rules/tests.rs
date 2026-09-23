
use super::{
    Entity, EntityKind, RuleContext, canonical_handle, date_diff_days, is_generic_handle,
    source_family, tagged_matching_sources, text_mentions_ip,
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
    fn text_mentions_ip_does_not_panic_on_a_non_ascii_needle() {
        // Regression: a non-ASCII `ip` whose match failed the boundary check
        // advanced the byte cursor by +1 into the middle of a multi-byte char,
        // and the next `text[from..]` slice panicked. `"aé1"` / `"é"` is the
        // minimal reproduction — `é` (2 bytes) is found at offset 1, the
        // following digit `1` fails the after-boundary test, `from` becomes 2
        // (the é continuation byte), and slicing there is not on a char
        // boundary. A non-ASCII string is never a valid address, so the answer
        // is simply `false` — and, crucially, no panic.
        assert!(!text_mentions_ip("aé1", "é"));
        assert!(!text_mentions_ip("café at 1.2.3.4", "café"));
        assert!(!text_mentions_ip("2001:db8::café", "café"));
        // ASCII matching is unchanged by the guard.
        assert!(text_mentions_ip("café near 1.2.3.4 today", "1.2.3.4"));
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
    fn source_family_covers_every_breach_category_module() {
        // Walks the LIVE registry, so a newly added breach corpus is caught the
        // moment it is registered. The previous version of this test was a
        // hand-maintained literal list of module names, which could not detect
        // an omission by construction — the list was both the input and the
        // expectation. It passed while `stolen_tax` (a paid credential corpus)
        // sat unclassified, and the engine's runtime warning it delegated to
        // was firing on every scan with nobody reading it.
        //
        // A miss is not cosmetic: `"other"` is excluded from cross-family
        // diversity, so an unclassified corpus silently stops counting toward
        // corroboration, stops being a family the gap analysis can find
        // missing, and is dropped from the breach sweep's dispatch allow-list.
        let breach_modules: Vec<&'static str> = crate::modules::registry()
            .iter()
            .filter(|m| m.category() == crate::core::ModuleCategory::Breach)
            .map(|m| m.name())
            .collect();
        assert!(
            !breach_modules.is_empty(),
            "registry walk found no breach-category modules at all — the walk itself is broken"
        );

        let unclassified: Vec<&&str> = breach_modules
            .iter()
            .filter(|n| !super::breach_pii::is_breach_source(n))
            .filter(|n| !super::breach_pii::NON_CORPUS_BREACH_MODULES.contains(n))
            .collect();
        assert!(
            unclassified.is_empty(),
            "breach-category modules classified by neither `is_breach_source` nor \
             `NON_CORPUS_BREACH_MODULES`: {unclassified:?} — add the corpus to \
             `source_family`'s breach needles, or record it as a deliberate non-corpus \
             with its reason"
        );

        // The exclusion set cannot rot either: every name in it must still be a
        // registered breach-category module, and must not have quietly become a
        // graded corpus (which would make the entry a contradiction rather than
        // a decision).
        for excluded in super::breach_pii::NON_CORPUS_BREACH_MODULES {
            assert!(
                breach_modules.contains(excluded),
                "`{excluded}` is listed in NON_CORPUS_BREACH_MODULES but is not a registered \
                 breach-category module — stale entry"
            );
            assert!(
                !super::breach_pii::is_breach_source(excluded),
                "`{excluded}` is listed as a deliberate NON-corpus yet `is_breach_source` \
                 accepts it — the two classifications contradict each other"
            );
        }

        // `stolen_tax` is the corpus the registry walk caught: a paid,
        // key-gated breach API emitting Email/Username/Credential whose name
        // carries no generic breach token.
        assert_eq!(source_family("stolen_tax"), "breach");
        // `see_know` is a breach-category module whose name has no breach token
        // and whose family is deliberately NOT "breach" (it is a people-search
        // aggregator). `is_breach_source` special-cases it instead, so the
        // consensus pass still counts it as an attesting corpus.
        assert_ne!(source_family("see_know"), "breach");
        assert!(super::breach_pii::is_breach_source("see_know"));
        // `ahmia` is the opposite case: breach-category, but a full-text Tor
        // index rather than a record corpus, so it must NOT attest anything.
        assert!(!super::breach_pii::is_breach_source("ahmia"));
    }

    #[test]
    fn no_self_enrichment_pass_is_ever_a_leaked_record_source() {
        // The CONVERSE of the test above, and the direction it does not cover.
        // `source_family`'s breach needles are SUBSTRING-matched, so a source
        // whose name merely contains `breach`/`stealer`/`pwned`/… is classed
        // `"breach"` on its name alone. `breach_timezone` is exactly that: a
        // deterministic self-enrichment pass (it is the first entry in
        // `ENRICHMENT_ONLY_SOURCES`) that makes no network call and DERIVES
        // Address/Coordinates by clustering timestamps to guess a UTC offset.
        //
        // A derivation is never a leaked record. `breach_consensus`'s
        // `breach_sources_of` already knew that and spells the pairing out —
        // `is_breach_source(..) && !is_non_corroborating_source(..)` — but
        // `breach_pii`'s ~15 record gates call `is_breach_source` bare, so the
        // guard protected the corpus COUNT while the PII-assembly gates, whose
        // whole purpose is to keep derived localities out of an assembled
        // person, were left open to any name that happens to collide.
        //
        // Asserted over the whole enrichment list rather than the one colliding
        // name, so adding (say) `stealer_normalize` to `ENRICHMENT_ONLY_SOURCES`
        // fails here instead of silently re-opening the hole.
        for src in crate::core::entity::ENRICHMENT_ONLY_SOURCES {
            assert!(
                !super::breach_pii::is_breach_source(src),
                "`{src}` is a deterministic self-enrichment pass — a derivation, never a leaked \
                 record — yet `is_breach_source` accepts it, so `breach_pii` would assemble its \
                 derived attributes into a person as breach-record PII"
            );
        }
        // The specific collision this test was written for, named so a failure
        // is self-explaining.
        assert_eq!(source_family("breach_timezone"), "breach");
        assert!(!super::breach_pii::is_breach_source("breach_timezone"));
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
        // Real geo *modules* are infrastructure geo — unchanged.
        assert_eq!(source_family("ip_geo"), "infra");
        assert_eq!(source_family("geocode"), "infra");
        // Regression: the engine-derived corroboration PASS `geo_corroboration`
        // must be the unscored `"other"` family, NOT `"infra"` — its `"geo"`
        // substring once hijacked it there, manufacturing a phantom orthogonal
        // family that inflated AU-062 multipath. Its promotion-source siblings
        // classify the same way.
        assert_eq!(source_family("geo_corroboration"), "other");
        assert_eq!(source_family("multipath_corroboration"), "other");
        assert_eq!(source_family("cross_scan_corroboration"), "other");
        assert_eq!(source_family("some_unknown_module"), "other");
    }

    #[test]
    fn source_family_covers_registry_scanners_and_registries() {
        // Real registry module names that used to fall to `other` (their forms
        // contain no earlier needle) and so silently under-counted family
        // diversity. Each is now classified to its genuine family.
        for m in [
            "abuseipdb",
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
        let results = rule_au_083_locale_multi_email_corroboration(&RuleContext::new(&[a]), "scan-au083-arch", 0);
        assert_eq!(results.len(), 1, "locale rule must fire when >=2 email_locale evidence entries share a locale");
    }

    #[test]
    fn au121_transitive_credential_reuse_blast_radius_fires() {
        // Secret A ties alice+bobby; a DIFFERENT secret B ties bobby+carol. No
        // single secret spans all three, so only the transitive-closure rule
        // (AU-121) surfaces the full three-account blast radius — the AU-047
        // blind spot.
        let mut a = Entity::new(
            EntityKind::Password,
            "$2b$12$abcdefghijklmnopqrstuv0123456789ABCDEFGHIJKLMNOPqrst",
            0.9,
            "scan-au121",
        );
        a.add_evidence(Evidence::new("breach", "record").with_attr("username", "alice"));
        a.add_evidence(Evidence::new("breach", "record").with_attr("username", "bobby"));
        let mut b = Entity::new(
            EntityKind::Password,
            "$2b$12$ZYXWVUTSRQPONMLKJIHGFE9876543210zyxwvutsrqponmlkAAAA",
            0.9,
            "scan-au121",
        );
        b.add_evidence(Evidence::new("breach", "record").with_attr("username", "bobby"));
        b.add_evidence(Evidence::new("breach", "record").with_attr("username", "carol"));
        let results = super::rule_au_121_credential_reuse_blast_radius(&RuleContext::new(&[a, b]), "scan-au121", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-121 must fire once on a transitive reuse chain no single secret spans"
        );
        assert_eq!(results[0].rule_id, "AU-121");
    }

    #[test]
    fn au122_trackable_rf_device_fires_on_a_hardware_mac_in_a_sweep() {
        // A universally-administered device (0x3C, U/L bit clear) alongside a
        // randomized privacy address (0x36, U/L bit set) — both radar-tagged.
        let mut hw = Entity::new(EntityKind::MacAddress, "3C:5A:B4:11:22:33", 0.8, "scan-au122");
        hw.tag("bluetooth");
        let mut rnd = Entity::new(EntityKind::MacAddress, "36:32:62:36:31:33", 0.8, "scan-au122");
        rnd.tag("bluetooth");
        let results = super::rule_au_122_trackable_rf_device(&RuleContext::new(&[hw, rnd]), "scan-au122", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-122 must fire when a trackable hardware MAC is present in an RF sweep"
        );
        assert_eq!(results[0].rule_id, "AU-122");
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
        let results = super::rule_au_116_infrastructure_pivot_closure(&RuleContext::new(&ents), &rels, "scan-au116", 0);
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
        let results = super::rule_au_117_personal_device_constellation(&RuleContext::new(&[car, buds]), "scan-au117", 0);
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
        let results = super::rule_au_118_lookalike_domain_impersonation(&RuleContext::new(&[real, fake]), "scan-au118", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-118 must fire on a homoglyph domain look-alike pair"
        );
        assert_eq!(results[0].rule_id, "AU-118");
    }

    #[test]
    fn au118_sees_an_impersonation_under_a_vietnamese_second_level() {
        // REQ-PSL-001: FAILS on the 39-entry suffix table. With no `com.vn`
        // in it, both domains folded to the "registrable domain" `com.vn` —
        // one key, so no pair, so no Vietnamese impersonation could ever fire.
        let real = Entity::new(EntityKind::Domain, "techcombank.com.vn", 0.8, "scan-au118-vn");
        let fake = Entity::new(EntityKind::Domain, "techc0mbank.com.vn", 0.8, "scan-au118-vn");
        let results = super::rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[real, fake]),
            "scan-au118-vn",
            0,
        );
        assert_eq!(results.len(), 1, "AU-118 must fire on the .com.vn pair");
        assert!(results[0].description.contains("techc0mbank.com.vn"));
    }

    #[test]
    fn au118_never_pairs_a_public_suffix_label_with_an_unrelated_brand() {
        // A control, not a regression lock: the brand label is the first label
        // of the REGISTRABLE domain, so it must never be a suffix label. This
        // passed on the 39-entry table too (falsification P0 in REQ-PSL-001:
        // the suspected `com`/`corn` pairing does not occur), and it pins that
        // the PSL change did not introduce one either.
        let vn = Entity::new(EntityKind::Domain, "anphat.com.vn", 0.8, "scan-au118-sfx");
        let other = Entity::new(EntityKind::Domain, "corn.com", 0.8, "scan-au118-sfx");
        let results = super::rule_au_118_lookalike_domain_impersonation(
            &RuleContext::new(&[vn, other]),
            "scan-au118-sfx",
            0,
        );
        assert!(
            results.is_empty(),
            "a suffix label is not a brand: {:?}",
            results.iter().map(|c| &c.description).collect::<Vec<_>>()
        );
    }

    #[test]
    fn au119_dating_platform_exposure_fires_on_confirmed_profiles() {
        // Two body-marker-confirmed dating profiles → a personal-exposure finding.
        let mk = |url: &str, platform: &str| {
            let mut e = Entity::new(EntityKind::Url, url, 0.8, "scan-au119");
            e.tag("cat:dating");
            e.tag(format!("platform:{platform}"));
            e.tag("verified-detection");
            e
        };
        let ents = [
            mk("https://tinder.com/@rhino", "Tinder"),
            mk("https://badoo.com/@rhino", "Badoo"),
        ];
        let results = super::rule_au_119_dating_platform_exposure(&RuleContext::new(&ents), "scan-au119", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-119 must fire on confirmed dating-platform profiles"
        );
        assert_eq!(results[0].rule_id, "AU-119");
    }

    #[test]
    fn au120_monetized_creator_exposure_fires_on_confirmed_profiles() {
        // A body-marker-confirmed subscription-creator profile → identity-linked
        // exposure finding.
        let mut e = Entity::new(EntityKind::Url, "https://onlyfans.com/rhino", 0.9, "scan-au120");
        e.tag("cat:fans");
        e.tag("platform:OnlyFans");
        e.tag("verified-detection");
        let results = super::rule_au_120_monetized_creator_exposure(&RuleContext::new(&[e]), "scan-au120", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-120 must fire on a confirmed creator profile"
        );
        assert_eq!(results[0].rule_id, "AU-120");
    }

    #[test]
    fn au123_numeric_variant_handle_persona_fires_across_sources() {
        // A base handle plus a birth-year suffix, observed by two distinct
        // source modules — the digit-suffix reuse pattern the exact-match
        // handle rules (canonical_handle keeps digits) never join.
        let mut a = Entity::new(EntityKind::Username, "jdiegmann", 0.7, "scan-au123");
        a.add_evidence(Evidence::new("github_user", "found"));
        let mut b = Entity::new(EntityKind::Username, "jdiegmann92", 0.7, "scan-au123");
        b.add_evidence(Evidence::new("keybase", "found"));
        let results = super::rule_au_123_numeric_variant_handle_persona(&RuleContext::new(&[a, b]), "scan-au123", 0);
        assert_eq!(
            results.len(),
            1,
            "AU-123 must fire on a numeric-variant handle pair from distinct sources"
        );
        assert_eq!(results[0].rule_id, "AU-123");
    }

    #[test]
    fn au124_ransomware_victim_exposure_fires_and_names_the_group() {
        // An Organisation + its Domain tagged `ransomware-victim` (as
        // ransomware_live/ransomlook emit), plus a `reference` leak-site URL that
        // must NOT inflate the flagged-subject count. The claiming group rides as
        // a `group:` tag and must appear in the finding.
        let mut org = Entity::new(EntityKind::Organisation, "Acme Corp", 0.8, "scan-au124");
        org.tag("ransomware-victim");
        org.tag("group:lockbit");
        let mut dom = Entity::new(EntityKind::Domain, "acme.example", 0.8, "scan-au124");
        dom.tag("ransomware-victim");
        dom.tag("group:lockbit");
        let mut url = Entity::new(EntityKind::Url, "https://www.ransomlook.io/leaks/x", 0.7, "scan-au124");
        url.tag("ransomware-victim");
        url.tag("reference");
        let results = super::rule_au_124_ransomware_victim_exposure(
            &RuleContext::new(&[org, dom, url]),
            "scan-au124",
            0,
        );
        assert_eq!(results.len(), 1, "AU-124 must fire when a ransomware-victim tag is present");
        assert_eq!(results[0].rule_id, "AU-124");
        assert!(
            results[0].description.contains("lockbit"),
            "the claiming group must be named: {}",
            results[0].description
        );
        // Two subject entities (org + domain); the `reference` URL is excluded.
        assert!(
            results[0].description.starts_with("2 "),
            "reference URL must not inflate the flagged count: {}",
            results[0].description
        );
    }

    #[test]
    fn au124_ransomware_victim_exposure_silent_without_the_tag() {
        // No `ransomware-victim` tag anywhere → the rule yields nothing.
        let e = Entity::new(EntityKind::Organisation, "Innocent Ltd", 0.8, "scan-au124b");
        let results = super::rule_au_124_ransomware_victim_exposure(
            &RuleContext::new(&[e]),
            "scan-au124b",
            0,
        );
        assert!(results.is_empty(), "AU-124 must stay silent with no victim tag");
    }

#[test]
fn au_108_counts_every_platform_breach_rich_mints() {
    // github + tiktok are minted by breach_rich as `platform:handle` breach
    // Usernames, but AU-108's own hand-copied platform list stopped at snapchat,
    // so two genuinely distinct breach-listed platforms produced no footprint.
    // Both consumers now read `core::breach_platforms::BREACH_SOCIAL_PLATFORMS`.
    let mut gh = Entity::new(EntityKind::Username, "github:alice123", 0.6, "scan-au108");
    gh.tag("breach");
    let mut tt = Entity::new(EntityKind::Username, "tiktok:alice123", 0.6, "scan-au108");
    tt.tag("breach");
    let results = super::rule_au_108_breach_social_footprint(&RuleContext::new(&[gh, tt]), "scan-au108", 0);
    assert_eq!(results.len(), 1, "two distinct breach-listed platforms fire AU-108");
    assert!(results[0].description.contains("github") && results[0].description.contains("tiktok"));
    // Every platform breach_rich mints is one AU-108 recognises: no drift by construction.
    for plat in crate::core::breach_platforms::BREACH_SOCIAL_PLATFORMS {
        let mut a = Entity::new(EntityKind::Username, format!("{plat}:someone"), 0.6, "s");
        a.tag("breach");
        let mut b = Entity::new(EntityKind::Username, "telegram:someone", 0.6, "s");
        b.tag("breach");
        if *plat == "telegram" {
            continue;
        }
        assert_eq!(
            super::rule_au_108_breach_social_footprint(&RuleContext::new(&[a, b]), "s", 0).len(),
            1,
            "{plat} must count toward the footprint"
        );
    }
}
