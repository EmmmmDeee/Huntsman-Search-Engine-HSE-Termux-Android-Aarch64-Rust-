use super::*;

    #[test]
    fn zero_hits_is_inconclusive_only_when_mostly_blocked() {
        assert!(inconclusive(0, 30, 30), "all blocked → inconclusive");
        assert!(inconclusive(0, 15, 30), "half blocked → inconclusive");
        assert!(
            !inconclusive(0, 5, 30),
            "mostly definitive not-found → genuine absence"
        );
        assert!(!inconclusive(1, 29, 30), "any hit → never inconclusive");
        assert!(!inconclusive(0, 0, 0), "no probes → not inconclusive");
    }

    #[test]
    fn accepts_only_username() {
        let m = StreamingProbe;
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn site_list_nontrivial() {
        assert!(
            SITES.len() >= 20,
            "expected ≥20 sites (comprehensive streaming coverage), got {}",
            SITES.len()
        );
        for site in SITES {
            assert!(site.url.contains("{}"), "{} missing placeholder", site.name);
        }
    }

    #[test]
    fn every_probe_url_is_https() {
        for site in SITES {
            assert!(
                site.url.starts_with("https://"),
                "{} probe URL is not https: {}",
                site.name,
                site.url
            );
        }
    }

    #[test]
    fn every_category_is_canonical() {
        assert!(CATEGORIES.is_sorted(), "CATEGORIES must stay sorted");
        for site in SITES {
            assert!(
                CATEGORIES.contains(&site.cat),
                "{} uses non-canonical category {:?} (add it to sites::CATEGORIES if intended)",
                site.name,
                site.cat
            );
        }
    }

    #[test]
    fn no_duplicate_site_names() {
        let mut seen = std::collections::HashSet::new();
        for site in SITES {
            assert!(seen.insert(site.name), "duplicate site name: {}", site.name);
        }
    }

    #[test]
    fn max_timeout_ms_budgeted_for_full_table_sweep() {
        let m = StreamingProbe;
        let budget = m.max_timeout_ms();
        let needed =
            ((SITES.len() as u64).div_ceil(MAX_CONCURRENT_PROBES as u64)) * 4_500;
        assert!(
            budget >= needed,
            "max_timeout_ms ({budget}ms) too tight for full sweep of {} sites \
             at {MAX_CONCURRENT_PROBES} concurrent probes (need ≥ {needed}ms)",
            SITES.len(),
        );
    }

    #[test]
    fn categories_cover_all_three_buckets() {
        let cats: std::collections::BTreeSet<&str> = SITES.iter().map(|s| s.cat).collect();
        for expected in &["cam", "fans", "adult"] {
            assert!(
                cats.contains(expected),
                "missing category: {expected} (have: {cats:?})"
            );
        }
    }

    #[test]
    fn browser_ua_is_chrome_shaped() {
        assert!(BROWSER_UA.contains("Mozilla/5.0"));
        assert!(BROWSER_UA.contains("Chrome/"));
        assert!(!BROWSER_UA.contains("huntsman-search-engine"));
    }

    #[test]
    fn detection_strength_tiers_status_only_below_body_verified() {
        // A body-verified detection (page rendered, no "not found" marker) is a
        // real presence signal; a bare status-200 is a weaker, soft-404-prone lead.
        assert_eq!(
            detection_strength(&Detect::StatusAndNotBody(200, "not found")),
            (0.92, true)
        );
        assert_eq!(detection_strength(&Detect::StatusEq(200)), (0.74, false));
    }

    #[test]
    fn build_entities_tiers_confidence_and_gates_exposure_on_verified() {
        let tally = ProbeTally {
            definitive_absent: 5,
            inconclusive_probes: 2,
            sites_probed: 40,
        };

        // A STATUS-ONLY cam hit: its URL must ride at 0.74 tagged `weak-detection`,
        // and the summary must NOT assert the sensitive `cam-identity-exposed`
        // claim — a soft-404 200 is not proof of a cam identity. (Fail-before: the
        // URL was a flat 0.92 and any cam hit stamped the exposure tag.)
        let weak = vec![Hit {
            site_name: "Stripchat",
            site_cat: "cam",
            url: "https://stripchat.com/alice".to_string(),
            confidence: 0.74,
            verified: false,
        }];
        let out = build_entities("alice", "s", &weak, &tally);
        let url = out
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url)
            .expect("a Url entity");
        assert!(
            (url.confidence - 0.74).abs() < 1e-9,
            "a status-only hit must ride at 0.74, got {}",
            url.confidence
        );
        assert!(url.has_tag("weak-detection"));
        let summary = out
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("a summary entity");
        assert!(
            !summary.has_tag("cam-identity-exposed"),
            "a status-only hit must not assert a high-confidence cam identity"
        );

        // A BODY-VERIFIED cam hit: URL at 0.92 tagged `verified-detection`, and the
        // summary earns the `cam-identity-exposed` claim.
        let verified = vec![Hit {
            site_name: "Chaturbate",
            site_cat: "cam",
            url: "https://chaturbate.com/alice/".to_string(),
            confidence: 0.92,
            verified: true,
        }];
        let out2 = build_entities("alice", "s", &verified, &tally);
        let url2 = out2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url)
            .expect("a Url entity");
        assert!((url2.confidence - 0.92).abs() < 1e-9);
        assert!(url2.has_tag("verified-detection"));
        let summary2 = out2
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("a summary entity");
        assert!(
            summary2.has_tag("cam-identity-exposed"),
            "a body-verified cam hit earns the exposure tag"
        );
    }
