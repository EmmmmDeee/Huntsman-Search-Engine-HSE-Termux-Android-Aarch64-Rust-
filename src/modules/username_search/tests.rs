use super::*;
use crate::core::confidence;

    // The M6 zero-hit disambiguation (`inconclusive`) and the browser-UA shape
    // guard now live with their single-sourced implementations in
    // `util::probe::tests`; this file keeps the username_search-specific coverage.

    #[test]
    fn accepts_only_username() {
        let m = UsernameSearch;
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    }

    #[test]
    fn site_list_nontrivial() {
        // Guard against accidentally truncating SITES in a future edit.
        assert!(
            SITES.len() >= 100,
            "expected ≥100 sites (Maigret-scale), got {}",
            SITES.len()
        );
        // Every URL must contain the substitution placeholder.
        for site in SITES {
            assert!(site.url.contains("{}"), "{} missing placeholder", site.name);
        }
    }

    #[test]
    fn every_probe_url_is_https() {
        // A username probe over plaintext http leaks the searched handle to any
        // on-path observer — unacceptable for an OSINT tool. Guard the invariant
        // (it holds today; this stops a future http:// entry slipping in).
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
    fn categories_cover_maigret_domains() {
        let cats: std::collections::BTreeSet<&str> = SITES.iter().map(|s| s.cat).collect();
        // At minimum: social, dev, gaming, music, video, photo, forum
        for expected in &[
            "social", "dev", "gaming", "music", "video", "photo", "forum",
        ] {
            assert!(
                cats.contains(expected),
                "missing category: {expected} (have: {cats:?})"
            );
        }
    }

    #[test]
    fn every_category_is_canonical() {
        // The reverse of the coverage check: no site may use a category outside
        // the documented CATEGORIES allow-list, so a typo ("socail") or an
        // undocumented bucket fails CI instead of silently mis-classifying.
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
        // Regression guard: with 334 sites and 32 concurrent probes,
        // the module needs ~ceil(334/32) × 4.5s = 47s of probing
        // wall-time. If a future contributor reverts to the default
        // 3_000ms (MODULE_TIMEOUT_MS) the engine will kill the
        // module after ~2 batches and surface only ~10% of real
        // hits. 60s envelope leaves headroom for slow CDN probes.
        let m = UsernameSearch;
        let budget = m.max_timeout_ms();
        let needed = ((SITES.len() as u64).div_ceil(MAX_CONCURRENT_PROBES as u64)) * 4_500;
        assert!(
            budget >= needed,
            "max_timeout_ms ({budget}ms) too tight for full sweep of {} sites \
             at {MAX_CONCURRENT_PROBES} concurrent probes (need ≥ {needed}ms)",
            SITES.len(),
        );
    }

    #[test]
    fn detection_strength_tiers_body_markers_above_status_only() {
        // Body-marker rules actually inspect the page → full confidence + verified.
        let (c_body, v_body) = detection_strength(&Detect::StatusAndBody(200, "x"));
        let (c_notbody, v_notbody) = detection_strength(&Detect::StatusAndNotBody(200, "x"));
        assert_eq!((c_body, v_body), (0.92, true));
        assert_eq!((c_notbody, v_notbody), (0.92, true));

        // Bare status-200 is plausible-but-unverified (SPA shells / soft-404s
        // fake it) → lower confidence, not verified.
        let (c_status, v_status) = detection_strength(&Detect::StatusEq(200));
        assert!(!v_status, "status-only detection must not be marked verified");
        assert!(
            c_status < c_body,
            "status-only confidence {c_status} must rank below body-marker {c_body}"
        );
        // …but still above the engine's confidence::MEDIUM expand floor so it remains pivotable.
        assert!(
            c_status > confidence::MEDIUM,
            "status-only hit {c_status} must stay above the confidence::MEDIUM expand floor"
        );
    }

    #[test]
    fn every_site_gets_a_bounded_confidence() {
        // Whatever detection rule a site uses, the stamped confidence must be a
        // valid probability and the verified flag must agree with the rule kind.
        for site in SITES {
            let (conf, verified) = detection_strength(&site.detect);
            assert!(
                (0.0..=1.0).contains(&conf),
                "{} confidence {conf} out of range",
                site.name
            );
            let is_body = matches!(
                site.detect,
                Detect::StatusAndBody(..) | Detect::StatusAndNotBody(..)
            );
            assert_eq!(
                verified, is_body,
                "{} verified flag must match its detection kind",
                site.name
            );
        }
    }

