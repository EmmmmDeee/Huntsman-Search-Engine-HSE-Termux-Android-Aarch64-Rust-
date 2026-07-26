use super::*;

    #[test]
    fn separator_swaps_are_generated_and_deduped() {
        let v = generate_username_variants("jerome.despal");
        assert!(v.contains(&"jeromedespal".to_string())); // separators removed
        assert!(v.contains(&"jerome_despal".to_string())); // → underscore
        assert!(v.contains(&"jerome-despal".to_string())); // → dash
        // The original form is never emitted as its own variant.
        assert!(!v.contains(&"jerome.despal".to_string()));
    }

    #[test]
    fn trailing_digit_and_truncation_variants() {
        let v = generate_username_variants("jdespal");
        assert!(v.contains(&"jdespal1".to_string()));
        assert!(v.contains(&"jdespal2".to_string()));
        assert!(v.contains(&"jdespa".to_string())); // last char dropped
    }

    #[test]
    fn digit_terminated_handles_skip_digit_variants() {
        // Already ends in a digit → no `…1`/`…2` appended.
        let v = generate_username_variants("agent007");
        assert!(!v.iter().any(|s| s.ends_with("0071") || s.ends_with("0072")));
    }

    #[test]
    fn multibyte_handle_truncates_by_char_without_panicking() {
        // Regression: a handle ending in a multi-byte codepoint must not panic
        // on the truncation slice, and must drop a whole char.
        let v = generate_username_variants("andré");
        assert!(v.contains(&"andr".to_string())); // 'é' dropped whole
        assert!(v.iter().all(|s| s != "andré"));

        // Pure non-ASCII handle (every char multi-byte) — also must not panic.
        let _ = generate_username_variants("Ωμέγα");
    }

    #[test]
    fn short_handle_yields_no_variants() {
        // No separators, < 4 chars → nothing (too short to pivot on).
        assert!(generate_username_variants("ab").is_empty());
    }

    #[test]
    fn interleave_runs_regional_dorks_early() {
        let base = vec!["base0".to_string(), "base1".into(), "base2".into()];
        let regional = vec!["au0".to_string(), "au1".into()];
        let q = interleave_regional(base, regional);
        // Strongest base query first, then AU dorks, then the rest.
        assert_eq!(q, ["base0", "au0", "au1", "base1", "base2"]);
        // AU dorks land before the tail base queries (won't be starved).
        let au_pos = q.iter().position(|x| x == "au0").expect("should succeed");
        let tail_pos = q.iter().position(|x| x == "base1").expect("should succeed");
        assert!(au_pos < tail_pos);
        // Degenerate inputs.
        assert_eq!(interleave_regional(vec![], vec!["a".into()]), ["a"]);
        assert_eq!(interleave_regional(vec!["b".into()], vec![]), ["b"]);
    }

    #[test]
    fn detect_region_flags_australian_seeds() {
        use crate::core::scan::Target;
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Email, "person@deakin.edu.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 412 345 678")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(
                TargetKind::Address,
                "10 Queen St, Brisbane QLD"
            )),
            Some(Region::Au)
        );
        // Non-AU seeds → no region.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com")),
            None
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Username, "jdoe")),
            None
        );
    }

    #[test]
    fn detect_region_phone_distinguishes_au_cc_from_us_area_code() {
        use crate::core::scan::Target;
        // Bare AU country code at full international length → AU.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "61 412 345 678")),
            Some(Region::Au)
        );
        // US `610` area code (10 digits) must NOT be read as AU country code.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "610-555-1234")),
            None
        );
        // `+61` stays unambiguous regardless of spacing.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 2 9000 0000")),
            Some(Region::Au)
        );
    }

    // ── build_queries_base ───────────────────────────────────────────────────

    #[test]
    fn build_queries_base_domain_emits_site_and_link_dorks() {
        use crate::core::scan::Target;
        let q = build_queries_base(&Target::new(TargetKind::Domain, "example.com"));
        assert!(!q.is_empty());
        // Bare `site:example.com` removed — 50% block rate / 27% hit rate in live
        // scans; the operator-enriched site: patterns below carry 99-100% hit rate.
        assert!(!q.iter().any(|s| s == "site:example.com"), "bare site: dork must be absent");
        assert!(q.iter().any(|s| s == "link:example.com"));
        // Subdomain-discovery dork (negative site).
        assert!(
            q.iter()
                .any(|s| s.contains("site:example.com -site:www.example.com"))
        );
        // Progressive subdomain-walk: a second dork excludes the common
        // subdomains too, to surface the long tail the first one never reaches.
        assert!(
            q.iter().any(|s| s.contains("-site:mail.example.com")
                && s.contains("-site:blog.example.com")),
            "progressive subdomain-walk dork must be present"
        );
    }

    #[test]
    fn build_queries_base_email_freemail_omits_pivot_custom_domain_includes_it() {
        use crate::core::scan::Target;
        // The social-pivot dork is gated on the domain NOT being a freemail
        // provider (gmail/yahoo/hotmail/outlook).
        let pivot = "site:linkedin.com OR site:github.com OR site:facebook.com";

        // gmail.com (freemail) → the per-`{v}` social-pivot dork is absent.
        let gmail = build_queries_base(&Target::new(TargetKind::Email, "alice@gmail.com"));
        assert!(!gmail.is_empty());
        assert!(
            !gmail
                .iter()
                .any(|s| s == &format!("\"alice@gmail.com\" {pivot}")),
            "freemail email must not emit the social-pivot dork: {gmail:?}"
        );

        // Custom domain → the social-pivot dork IS emitted.
        let custom = build_queries_base(&Target::new(TargetKind::Email, "alice@acme.com"));
        assert!(
            custom
                .iter()
                .any(|s| s == &format!("\"alice@acme.com\" {pivot}")),
            "custom-domain email must emit the social-pivot dork: {custom:?}"
        );
    }

    #[test]
    fn build_queries_base_username_emits_bare_handle_and_intitle() {
        use crate::core::scan::Target;
        // Username is normalised to lowercase.
        let q = build_queries_base(&Target::new(TargetKind::Username, "jdoe"));
        assert!(!q.is_empty());
        // Tier-1 bare handle (no operators) is the very first query.
        assert!(q.iter().any(|s| s == "jdoe"));
        // Tier-3 page-title / URL operator dork.
        assert!(q.iter().any(|s| s == "intitle:\"jdoe\" OR inurl:jdoe"));
    }

    #[test]
    fn build_queries_base_ip_emits_recon_engine_dork() {
        use crate::core::scan::Target;
        let q = build_queries_base(&Target::new(TargetKind::IpAddress, "8.8.8.8"));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s.contains("site:shodan.io OR site:censys.io OR site:zoomeye.org"))
        );
    }

    #[test]
    fn build_queries_base_organisation_emits_registry_dork() {
        use crate::core::scan::Target;
        // Organisation value keeps its original case (trim-only normalisation).
        let q = build_queries_base(&Target::new(TargetKind::Organisation, "Acme Corp"));
        assert!(!q.is_empty());
        assert!(
            q.iter()
                .any(|s| s.contains("site:abr.business.gov.au OR site:asic.gov.au"))
        );
    }

    #[test]
    fn build_queries_base_returns_empty_for_unhandled_kind() {
        use crate::core::scan::Target;
        // Cidr falls through the `_` arm → no base dorks.
        assert!(build_queries_base(&Target::new(TargetKind::Cidr, "10.0.0.0/8")).is_empty());
    }

    #[test]
    fn build_queries_base_crypto_address_emits_exact_explorer_and_abuse_dorks() {
        use crate::core::scan::Target;
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // genesis BTC address
        let q = build_queries_base(&Target::new(TargetKind::CryptoAddress, addr));
        assert!(!q.is_empty(), "a crypto address must yield free-SERP dorks");
        // Exact-match quoted address is the strongest pivot — must be first.
        assert_eq!(q[0], format!("\"{addr}\""));
        // Abuse/scam DBs, block explorers and sanctions are all covered.
        assert!(q.iter().any(|s| s.contains("site:chainabuse.com")));
        assert!(
            q.iter()
                .any(|s| s.contains("site:etherscan.io") && s.contains("site:blockchair.com"))
        );
        assert!(q.iter().any(|s| s.contains("OFAC") && s.contains("sanctions")));
        // Every dork pins the exact address (no over-broad, address-free query).
        assert!(q.iter().all(|s| s.contains(addr)));
    }
