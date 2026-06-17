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
