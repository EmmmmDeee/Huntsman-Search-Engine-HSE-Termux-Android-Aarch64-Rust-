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
        // Regression guard: with 354 sites and 32 concurrent probes,
        // the module needs ~ceil(354/32) × 4.5s = 54s of probing
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
    fn duplicate_site_table_urls_exist_and_are_the_reason_aggregate_results_dedups() {
        // Documents the real, present-day shape of SITES: a handful of entries
        // across the table resolve to the identical URL for any given username
        // (two upstream list sources describing the same platform). This is not
        // itself asserted as a defect — see `aggregate_results_counts_a_shared_url_once`
        // for the behavior that makes it harmless — but a future cleanup that
        // removes the duplication is fine too; this only pins today's ground
        // truth so aggregate_results's dedup path stays exercised by at least
        // one real pair rather than only by synthetic fixtures below.
        let mut by_template: std::collections::HashMap<&str, usize> =
            std::collections::HashMap::new();
        for site in SITES {
            *by_template.entry(site.url).or_insert(0) += 1;
        }
        assert!(
            by_template.values().any(|&n| n > 1),
            "expected at least one URL template shared by more than one site entry"
        );
    }

    #[test]
    fn aggregate_results_counts_a_shared_url_once() {
        // Two site-table entries that both resolve to the SAME URL (as several
        // real entries do — see the test above) must contribute exactly one
        // Url entity and one count toward found_names/category_counts/
        // verified_hits, not two. Without the dedup this doubles
        // `platforms_count` and can flip summary tags like
        // `strong-social-presence` (>=3 social hits) off a single real account.
        let results: Vec<(&'static str, &'static str, ProbeResult)> = vec![
            (
                "SiteA",
                "social",
                ProbeResult::Found {
                    url: "https://example.com/alice".to_string(),
                    confidence: 0.92,
                    verified: true,
                },
            ),
            (
                "SiteA (alt)",
                "social",
                ProbeResult::Found {
                    url: "https://example.com/alice".to_string(),
                    confidence: 0.74,
                    verified: false,
                },
            ),
        ];
        let r = aggregate_results("alice", &results, "scan").expect("two hits, never inconclusive");
        let urls: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .collect();
        assert_eq!(
            urls.len(),
            1,
            "the shared URL must be emitted once, not once per table entry: {urls:?}"
        );
        let summary = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("summary entity");
        assert_eq!(
            summary.evidence[0].attributes.get("platforms_count").map(String::as_str),
            Some("1"),
            "platforms_count must reflect the one distinct platform, not two table entries"
        );
    }

    #[test]
    fn aggregate_results_prefers_the_verified_hit_regardless_of_table_order() {
        // Regression (Copilot review on PR #557): a first-seen-wins dedup let
        // site-table ORDER decide the outcome — the real `DeviantArt` (status-
        // only, 0.74, table-order first) / `DeviantArt (alt)` (body-marker,
        // 0.92, table-order second) pair both target the identical URL, and
        // "keep whichever was probed first" would keep the WEAK result even
        // though a stronger sibling rule also confirmed the same account. The
        // deduped hit must always be the strongest one seen, independent of
        // which arrived first.
        let results: Vec<(&'static str, &'static str, ProbeResult)> = vec![
            (
                "DeviantArt",
                "photo",
                ProbeResult::Found {
                    url: "https://www.deviantart.com/alice".to_string(),
                    confidence: 0.74,
                    verified: false,
                },
            ),
            (
                "DeviantArt (alt)",
                "photo",
                ProbeResult::Found {
                    url: "https://www.deviantart.com/alice".to_string(),
                    confidence: 0.92,
                    verified: true,
                },
            ),
        ];
        let r = aggregate_results("alice", &results, "scan").expect("two hits, never inconclusive");
        let urls: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .collect();
        assert_eq!(urls.len(), 1, "the shared URL must still be emitted once: {urls:?}");
        assert!(
            urls[0].has_tag("verified-detection"),
            "the STRONGER (verified) sibling must win regardless of which table entry \
             was probed first: {urls:?}"
        );
        assert!((urls[0].confidence - 0.92).abs() < 1e-9);
        let summary = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Username)
            .expect("summary entity");
        assert_eq!(
            summary.evidence[0].attributes.get("hits_verified").map(String::as_str),
            Some("1"),
            "the winning hit must count toward hits_verified, not hits_status_only"
        );
    }

    #[test]
    fn aggregate_results_emits_distinct_hits_on_distinct_urls() {
        // Sanity check for the test above: two DIFFERENT URLs are not folded
        // together by the dedup.
        let results: Vec<(&'static str, &'static str, ProbeResult)> = vec![
            (
                "SiteA",
                "social",
                ProbeResult::Found {
                    url: "https://example.com/alice".to_string(),
                    confidence: 0.92,
                    verified: true,
                },
            ),
            (
                "SiteB",
                "dev",
                ProbeResult::Found {
                    url: "https://example.org/alice".to_string(),
                    confidence: 0.92,
                    verified: true,
                },
            ),
        ];
        let r = aggregate_results("alice", &results, "scan").expect("two hits, never inconclusive");
        let urls: Vec<&Entity> = r
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Url)
            .collect();
        assert_eq!(urls.len(), 2, "two distinct URLs must both be emitted: {urls:?}");
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

