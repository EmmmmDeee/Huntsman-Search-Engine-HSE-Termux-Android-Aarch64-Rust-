use super::*;

    #[test]
    fn accepts_domain_and_url() {
        let m = WebCrawler;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/profile")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn timeout_is_60s() {
        assert_eq!(WebCrawler.max_timeout_ms(), 60_000);
    }

    #[test]
    fn produces_declares_every_kind_the_hydration_path_can_emit() {
        // Regression (PROBLEM_TREE T2.37): produces() must list MacAddress,
        // DeviceId, and Person alongside the other classifier-derived kinds —
        // `hydration_json_can_classify_leaves_as_mac_device_and_person`
        // (hydration_tests.rs) proves all three are genuinely reachable via
        // extract_hydration_entities, not merely theoretical.
        let kinds = WebCrawler.produces();
        for k in [
            crate::core::entity::EntityKind::MacAddress,
            crate::core::entity::EntityKind::DeviceId,
            crate::core::entity::EntityKind::Person,
        ] {
            assert!(kinds.contains(&k), "produces() must declare {k:?}");
        }
    }

    #[test]
    fn link_iter_extracts_hrefs() {
        let html = concat!(
            r#"<a href="https://example.com/page1">Link 1</a>"#,
            r#" <a href='/page2'>Link 2</a>"#,
            r##" <a href="#anchor">Skip</a>"##,
            r#" <a href="javascript:void(0)">Skip</a>"#,
            r#" <a href="mailto:x@y.com">Skip</a>"#,
        );
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert_eq!(links, vec!["https://example.com/page1", "/page2"]);
    }

    #[test]
    fn link_iter_handles_empty_and_malformed() {
        let html = r#"<a href="">empty</a><a href>no quote</a>"#;
        let links: Vec<&str> = LinkIter::new(html).collect();
        assert!(links.is_empty());
    }

    #[test]
    fn email_extraction() {
        let body = "Contact us at support@acme.com or sales@test.org for info";
        let mut emails = HashSet::new();
        extract_emails(body, &mut emails);
        assert!(emails.contains("support@acme.com"));
        assert!(emails.contains("sales@test.org"));
    }

    #[test]
    fn email_extraction_skips_image_extensions() {
        let body = "icon@2x.png and logo@3x.jpg should be skipped";
        let mut emails = HashSet::new();
        extract_emails(body, &mut emails);
        assert!(emails.is_empty());
    }

    #[test]
    fn phone_extraction() {
        let body = "Call us at +1-555-123-4567 or +44 20 7946 0958";
        let mut phones = HashSet::new();
        extract_phones(body, &mut phones);
        assert_eq!(phones.len(), 2);
        assert!(phones.iter().any(|p| p.contains("+1555")));
    }

    #[test]
    fn framework_detection_wordpress() {
        let mut found = HashSet::new();
        detect_frameworks(
            "<link rel='stylesheet' href='/wp-content/themes/foo/style.css'>",
            &mut found,
        );
        assert!(found.contains("WordPress"));
    }

    #[test]
    fn framework_detection_react_and_nextjs() {
        let mut found = HashSet::new();
        detect_frameworks(
            r#"<div id="__next"><script src="/_next/static/chunks/main.js"></script></div>"#,
            &mut found,
        );
        assert!(found.contains("Next.js"));
    }

    #[test]
    fn framework_detection_multiple() {
        let mut found = HashSet::new();
        let body = "<script src='/jquery.min.js'></script><link href='bootstrap.css'><script src='vue.js'></script>";
        detect_frameworks(body, &mut found);
        assert!(found.contains("jQuery"));
        assert!(found.contains("Bootstrap"));
        assert!(found.contains("Vue.js"));
    }

    #[test]
    fn page_type_detection() {
        let mut types = HashSet::new();
        let body =
            r#"<form method="POST"><input type="password" name="pw"><input type="file"></form>"#;
        detect_page_types(body, &mut types);
        assert!(types.contains("has_forms"));
        assert!(types.contains("login_form"));
        assert!(types.contains("file_upload"));
    }

    #[test]
    fn page_type_admin_detection() {
        let mut types = HashSet::new();
        detect_page_types("<a href='/admin/dashboard'>Admin</a>", &mut types);
        assert!(types.contains("admin_panel"));
    }

    #[test]
    fn security_header_audit() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            "max-age=31536000".parse().unwrap(),
        );
        headers.insert("x-frame-options", "DENY".parse().unwrap());

        let mut results = Vec::new();
        audit_security_headers(&headers, &mut results);

        let hsts = results
            .iter()
            .find(|(n, _)| *n == "Strict-Transport-Security");
        assert_eq!(hsts, Some(&("Strict-Transport-Security", true)));

        let csp = results
            .iter()
            .find(|(n, _)| *n == "Content-Security-Policy");
        assert_eq!(csp, Some(&("Content-Security-Policy", false)));
    }

    #[test]
    fn binary_url_filtering() {
        assert!(is_binary_url("https://example.com/image.png"));
        assert!(is_binary_url("https://example.com/doc.pdf?v=2"));
        assert!(is_binary_url("https://example.com/font.woff2"));
        assert!(!is_binary_url("https://example.com/page"));
        assert!(!is_binary_url("https://example.com/about.html"));
    }

    #[test]
    fn robots_disallow_check() {
        let rules = vec!["/admin/".to_string(), "/private".to_string()];
        assert!(is_disallowed("https://example.com/admin/users", &rules));
        assert!(is_disallowed("https://example.com/private", &rules));
        assert!(!is_disallowed("https://example.com/about", &rules));
    }

    #[test]
    fn registrable_domain_extraction() {
        assert_eq!(
            extract_registrable_domain("www.example.com"),
            Some("example.com".into())
        );
        assert_eq!(
            extract_registrable_domain("cdn.assets.example.org"),
            Some("example.org".into())
        );
        assert_eq!(extract_registrable_domain("localhost"), None);
    }

    // ── build_entities determinism ──────────────────────────────────────────

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn build_entities_emits_domains_emails_tracking_ids_and_phones_sorted() {
        // Insertion order deliberately non-alphabetical so a HashSet's randomised
        // iteration order can never coincidentally pass this test.
        let mut state = CrawlState {
            visited: HashSet::new(),
            queue: VecDeque::new(),
            pages_fetched: 3,
            disallow_rules: Vec::new(),
            result: ModuleResult::new(),
            external_domains: set(&["zeta.example", "alpha.example", "mid.example"]),
            subdomains: set(&["zsub.example.com", "asub.example.com"]),
            emails: set(&["zoe@example.com", "amy@example.com", "mike@example.com"]),
            phones: set(&["+61499999999", "+61411111111"]),
            tracking_ids: [("UA-999", "Google Analytics"), ("UA-111", "Google Analytics")]
                .into_iter()
                .map(|(id, provider)| (id.to_string(), provider.to_string()))
                .collect(),
            hydration_findings: Vec::new(),
            frameworks: HashSet::new(),
            page_types: HashSet::new(),
            security_headers: Vec::new(),
            internal_links: 0,
            external_links: 0,
            notable_pages: Vec::new(),
        };

        build_entities(
            "example.com",
            "example.com",
            "scan-1",
            MAX_DEPTH,
            false,
            "https://example.com",
            &mut state,
        );

        let domains: Vec<&str> = state
            .result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Domain && e.value != "example.com")
            .map(|e| e.value.as_str())
            .collect();
        // Subdomains are emitted (sorted) before external domains (sorted).
        assert_eq!(
            domains,
            vec![
                "asub.example.com",
                "zsub.example.com",
                "alpha.example",
                "mid.example",
                "zeta.example",
            ]
        );

        let emails: Vec<&str> = state
            .result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Email)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(
            emails,
            vec!["amy@example.com", "mike@example.com", "zoe@example.com"]
        );

        let phones: Vec<&str> = state
            .result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::Phone)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(phones, vec!["+61411111111", "+61499999999"]);

        let tracking_ids: Vec<&str> = state
            .result
            .entities
            .iter()
            .filter(|e| e.kind == EntityKind::TrackingId)
            .map(|e| e.value.as_str())
            .collect();
        assert_eq!(tracking_ids, vec!["UA-111", "UA-999"]);
    }
