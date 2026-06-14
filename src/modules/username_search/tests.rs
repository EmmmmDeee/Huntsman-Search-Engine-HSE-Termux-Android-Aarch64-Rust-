use super::*;

    #[test]
    fn zero_hits_is_inconclusive_only_when_mostly_blocked() {
        // M6 policy: a zero-hit run is "inconclusive" (→ surfaced as an error,
        // not a confirmed absence) only when most probes were blocked.
        assert!(inconclusive(0, 334, 334), "all blocked → inconclusive");
        assert!(inconclusive(0, 167, 334), "half blocked → inconclusive");
        assert!(
            !inconclusive(0, 10, 334),
            "mostly definitive not-found → genuine absence"
        );
        assert!(!inconclusive(3, 300, 334), "any hit → never inconclusive");
        assert!(!inconclusive(0, 0, 0), "no probes → not inconclusive");
    }

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
    fn browser_ua_is_chrome_shaped() {
        // Regression guard: if a contributor reverts to the tool UA
        // (`huntsman-search-engine/...`), Cloudflare-fronted sites
        // will 403 ~30% of the table again. Lock in the shape so
        // anyone changing it has to update this test too.
        assert!(BROWSER_UA.contains("Mozilla/5.0"));
        assert!(BROWSER_UA.contains("Chrome/"));
        assert!(!BROWSER_UA.contains("huntsman-search-engine"));
    }
