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
        // …but still above the engine's 0.50 expand floor so it remains pivotable.
        assert!(
            c_status > 0.50,
            "status-only hit {c_status} must stay above the 0.50 expand floor"
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

    // ── account_exists (PROBLEM_TREE T2.7, scraper resilience) ─────────────

    #[test]
    fn account_exists_status_eq_ignores_body() {
        let d = Detect::StatusEq(200);
        assert!(account_exists(&d, 200, None));
        assert!(!account_exists(&d, 404, None));
        // A body present alongside a StatusEq rule must not change the verdict.
        assert!(account_exists(&d, 200, Some("anything at all")));
    }

    #[test]
    fn account_exists_status_and_body_requires_both() {
        let d = Detect::StatusAndBody(200, "profile_exists_marker");
        assert!(account_exists(&d, 200, Some("...profile_exists_marker...")));
        assert!(
            !account_exists(&d, 200, Some("no marker here")),
            "status matches but needle absent"
        );
        assert!(
            !account_exists(&d, 404, Some("...profile_exists_marker...")),
            "needle present but status mismatched"
        );
    }

    #[test]
    fn account_exists_status_and_not_body_requires_needle_absent() {
        let d = Detect::StatusAndNotBody(200, "user not found");
        assert!(
            account_exists(&d, 200, Some("<title>a real profile</title>")),
            "status matches and the not-found marker is absent"
        );
        assert!(
            !account_exists(&d, 200, Some("<title>user not found</title>")),
            "status matches but the not-found marker is present"
        );
    }

    /// A body-dependent rule asked to decide with no body at all (should not
    /// happen — the caller always reads the body once status matches)
    /// conservatively resolves to "not found" rather than assuming a hit.
    #[test]
    fn account_exists_body_dependent_rule_with_no_body_is_not_found() {
        assert!(!account_exists(
            &Detect::StatusAndBody(200, "x"),
            200,
            None
        ));
        assert!(!account_exists(
            &Detect::StatusAndNotBody(200, "x"),
            200,
            None
        ));
    }

    // ── Real golden-fixture regression (T2.7): a live-captured Lobste.rs
    // response, run through the SAME `Detect` rule the live `SITES` table
    // registers for it — not a hand-rolled synthetic — so a future edit to
    // the table's rule (or the parsing logic) that would misclassify this
    // real, previously-observed response fails here, offline, deterministically.

    const LOBSTERS_FOUND_FIXTURE: &str = include_str!("testdata/lobsters_user_found.html");

    fn lobsters_site() -> &'static sites::Site {
        SITES
            .iter()
            .find(|s| s.name == "Lobste.rs")
            .expect("Lobste.rs must remain registered in SITES")
    }

    /// Captured 2026-07-03 from `https://lobste.rs/u/pushcx` (a long-standing
    /// public Lobsters admin handle, not private data) — HTTP 200, no "user
    /// not found" marker anywhere in the body.
    #[test]
    fn lobsters_real_found_page_is_classified_as_found() {
        let site = lobsters_site();
        assert!(
            !LOBSTERS_FOUND_FIXTURE.contains("user not found"),
            "fixture sanity: the captured page must not contain the not-found marker"
        );
        assert!(account_exists(&site.detect, 200, Some(LOBSTERS_FOUND_FIXTURE)));
    }

    /// Captured 2026-07-03: `https://lobste.rs/u/<a fabricated nonexistent
    /// handle>` returns a clean HTTP 404 for an absent account — not the
    /// HTTP 200 + "user not found" body the site's own `Detect` rule was
    /// written to expect. The status mismatch alone must still correctly
    /// resolve to "not found" (the real-world path the live code takes,
    /// short-circuiting before ever reading the body — see the call site
    /// in `process()`).
    #[test]
    fn lobsters_real_not_found_status_is_classified_as_not_found() {
        let site = lobsters_site();
        assert!(!account_exists(&site.detect, 404, None));
    }

    // ── Real golden-fixture regression (T2.7): a live-captured Archive of Our
    // Own response, run through the SAME `Detect` rule the live `SITES` table
    // registers for it — not a hand-rolled synthetic.

    const AO3_FOUND_FIXTURE: &str = include_str!("testdata/ao3_user_found.html");

    fn ao3_site() -> &'static sites::Site {
        SITES
            .iter()
            .find(|s| s.name == "Archive of Our Own")
            .expect("Archive of Our Own must remain registered in SITES")
    }

    /// Captured 2026-07-03 from `https://archiveofourown.org/users/orphan_account`
    /// (AO3's own built-in system account used when authors anonymize/orphan
    /// their works — not any private individual's identity) — HTTP 200, no
    /// "not be found" marker anywhere in the body. Truncated to the `<head>`
    /// plus the profile header block; the real response continues into a
    /// listing of orphaned works, which is dropped here so this fixture
    /// doesn't carry mature-content tags into the repository.
    #[test]
    fn ao3_real_found_page_is_classified_as_found() {
        let site = ao3_site();
        assert!(
            !AO3_FOUND_FIXTURE.contains("not be found"),
            "fixture sanity: the captured page must not contain the not-found marker"
        );
        assert!(account_exists(&site.detect, 200, Some(AO3_FOUND_FIXTURE)));
    }

    /// Captured 2026-07-03: `https://archiveofourown.org/users/<a fabricated
    /// nonexistent handle>` returns a clean HTTP 404 for an absent account —
    /// not the HTTP 200 + "not be found" body the site's own `Detect` rule
    /// was written to expect. The status mismatch alone must still correctly
    /// resolve to "not found", matching the same drift pattern already found
    /// for Lobste.rs.
    #[test]
    fn ao3_real_not_found_status_is_classified_as_not_found() {
        let site = ao3_site();
        assert!(!account_exists(&site.detect, 404, None));
    }
