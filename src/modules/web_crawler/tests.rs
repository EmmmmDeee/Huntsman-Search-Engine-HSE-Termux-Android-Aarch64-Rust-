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
            "max-age=31536000".parse().expect("should succeed"),
        );
        headers.insert("x-frame-options", "DENY".parse().expect("should succeed"));

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
            image_urls: Vec::new(),
            image_urls_seen: HashSet::new(),
        };

        build_entities(
            "example.com",
            "example.com",
            "scan-1",
            MAX_DEPTH,
            SeedShape {
                is_url_target: false,
                shared_profile_host: false,
            },
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

    /// A `CrawlState` with everything empty — for exercising one behaviour at a
    /// time without restating every field.
    fn empty_state() -> CrawlState {
        CrawlState {
            visited: HashSet::new(),
            queue: VecDeque::new(),
            pages_fetched: 0,
            disallow_rules: Vec::new(),
            result: ModuleResult::new(),
            external_domains: HashSet::new(),
            subdomains: HashSet::new(),
            emails: HashSet::new(),
            phones: HashSet::new(),
            tracking_ids: HashSet::new(),
            hydration_findings: Vec::new(),
            frameworks: HashSet::new(),
            page_types: HashSet::new(),
            security_headers: Vec::new(),
            internal_links: 0,
            external_links: 0,
            notable_pages: Vec::new(),
            image_urls: Vec::new(),
            image_urls_seen: HashSet::new(),
        }
    }

    /// Populate a state with both site-ownership signal (subdomains, external
    /// links, images, stack) and genuine subject data (email, phone), so a
    /// single fixture can prove which half survives.
    fn profile_crawl_state() -> CrawlState {
        let mut state = empty_state();
        state.pages_fetched = 1;
        state.subdomains = set(&["cdn.instagram.com", "help.instagram.com"]);
        state.external_domains = set(&["facebook.com", "threads.net"]);
        state.image_urls = vec!["https://cdn.instagram.com/p/photo.jpg".to_string()];
        state.image_urls_seen = set(&["https://cdn.instagram.com/p/photo.jpg"]);
        state.frameworks = ["Next.js"].into_iter().collect();
        state.emails = set(&["subject@personal-mail.com"]);
        state.phones = set(&["+61411111111"]);
        state
    }

    #[test]
    fn profile_url_on_a_shared_platform_yields_no_site_ownership_claims() {
        // Crawling instagram.com/<subject> says the ACCOUNT exists. It says
        // nothing about who owns Instagram — yet this used to mint
        // `instagram.com` as a VERY_HIGH_PLUS subject Domain and then attribute
        // the platform's subdomains, CDN images, outbound links and tech stack
        // to the person, so a person scan mapped Instagram's estate.
        let mut state = profile_crawl_state();
        build_entities(
            "instagram.com",
            "instagram.com",
            "scan-1",
            MAX_DEPTH,
            SeedShape {
                is_url_target: true,
                shared_profile_host: true,
            },
            "https://instagram.com/subject",
            &mut state,
        );

        assert!(
            !state
                .result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain),
            "no Domain entity may be minted for a shared platform: {:?}",
            state
                .result
                .entities
                .iter()
                .filter(|e| e.kind == EntityKind::Domain)
                .map(|e| e.value.as_str())
                .collect::<Vec<_>>()
        );

        let url_entity = state
            .result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value == "https://instagram.com/subject")
            .expect("the profile URL itself is the finding and must survive");
        assert!(
            !url_entity.tags.iter().any(|t| t.starts_with("tech:")),
            "the platform's stack must not be attributed to the subject: {:?}",
            url_entity.tags
        );
        assert!(
            !state
                .result
                .entities
                .iter()
                .any(|e| e.has_tag("exif-lead")),
            "platform CDN images are not the subject's photographs"
        );

        // Subject data observed ON the profile page is exactly what the crawl is
        // for, and must still come through.
        assert!(
            state
                .result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Email && e.value == "subject@personal-mail.com"),
            "an email on the profile page is subject data and must be kept"
        );
        assert!(
            state
                .result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Phone),
            "a phone on the profile page is subject data and must be kept"
        );
    }

    #[test]
    fn explicit_domain_scan_still_maps_infrastructure() {
        // The counterpart guard: suppression is scoped to profile URLs. Asking
        // to scan a domain outright is a deliberate infrastructure request and
        // must be unaffected — otherwise the fix above would silently gut
        // legitimate domain reconnaissance.
        let mut state = profile_crawl_state();
        build_entities(
            "instagram.com",
            "instagram.com",
            "scan-1",
            MAX_DEPTH,
            // An explicit Domain scan, so never a shared-profile host.
            SeedShape {
                is_url_target: false,
                shared_profile_host: false,
            },
            "https://instagram.com",
            &mut state,
        );
        assert!(
            state
                .result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "instagram.com"),
            "an explicit domain scan must still mint the domain entity"
        );
        assert!(
            state
                .result
                .entities
                .iter()
                .any(|e| e.kind == EntityKind::Domain && e.value == "cdn.instagram.com"),
            "an explicit domain scan must still emit discovered subdomains"
        );
    }

    #[test]
    fn crawl_evidence_reports_true_image_total_and_flags_the_cap() {
        // The evidence must state how many images were actually found, not the
        // saturated emitted count, so a truncated list is never presented as
        // complete. Here twice the cap was discovered but only the cap emitted.
        let mut state = empty_state();
        state.image_urls_seen = (0..IMAGE_LEADS_CAP * 2)
            .map(|i| format!("https://example.com/img{i}.jpg"))
            .collect();
        state.image_urls = (0..IMAGE_LEADS_CAP)
            .map(|i| format!("https://example.com/img{i}.jpg"))
            .collect();
        build_entities(
            "example.com",
            "example.com",
            "scan-1",
            MAX_DEPTH,
            SeedShape {
                is_url_target: false,
                shared_profile_host: false,
            },
            "https://example.com",
            &mut state,
        );
        let attrs = &state
            .result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "example.com")
            .expect("domain entity")
            .evidence[0]
            .attributes;
        // True discovered total, the (capped) emitted count, and an explicit
        // flag that truncation occurred.
        assert_eq!(
            attrs.get("image_leads_found").map(String::as_str),
            Some((IMAGE_LEADS_CAP * 2).to_string().as_str())
        );
        assert_eq!(
            attrs.get("image_leads_emitted").map(String::as_str),
            Some(IMAGE_LEADS_CAP.to_string().as_str())
        );
        assert_eq!(
            attrs.get("image_leads_capped").map(String::as_str),
            Some(IMAGE_LEADS_CAP.to_string().as_str())
        );
    }

    #[test]
    fn crawl_evidence_omits_the_cap_flag_when_nothing_was_truncated() {
        // When every discovered image fit under the cap, there is no truncation
        // to announce — the `image_leads_capped` flag must be absent.
        let mut state = empty_state();
        state.image_urls_seen = ["https://example.com/a.jpg", "https://example.com/b.jpg"]
            .into_iter()
            .map(ToString::to_string)
            .collect();
        state.image_urls = state.image_urls_seen.iter().cloned().collect();
        build_entities(
            "example.com",
            "example.com",
            "scan-1",
            MAX_DEPTH,
            SeedShape {
                is_url_target: false,
                shared_profile_host: false,
            },
            "https://example.com",
            &mut state,
        );
        let attrs = &state
            .result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Domain && e.value == "example.com")
            .expect("domain entity")
            .evidence[0]
            .attributes;
        assert_eq!(
            attrs.get("image_leads_found").map(String::as_str),
            Some("2")
        );
        assert!(
            !attrs.contains_key("image_leads_capped"),
            "no truncation occurred, so the cap flag must be absent"
        );
    }

    #[test]
    fn image_leads_become_low_confidence_url_entities_for_exif_geo() {
        let mut state = empty_state();
        state.image_urls = vec!["https://example.com/photos/family.jpg".to_string()];
        build_entities(
            "example.com",
            "example.com",
            "scan-1",
            MAX_DEPTH,
            SeedShape {
                is_url_target: false,
                shared_profile_host: false,
            },
            "https://example.com",
            &mut state,
        );

        let lead = state
            .result
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Url && e.value.contains("family.jpg"))
            .expect("image URL emitted as a Url entity");
        assert!(lead.tags.iter().any(|t| t == "exif-lead"));
        assert!(lead.tags.iter().any(|t| t == "image"));
        // Presence on a page is not evidence the photo depicts the subject: the
        // lead sits below MEDIUM so nothing downstream reads it as a link, but
        // above the expansion floor so the EXIF fetch still runs.
        assert!(
            lead.confidence < confidence::MEDIUM,
            "an image's mere presence must not read as an established link"
        );
        // The entity must be the shape `exif_geo` actually accepts, or the lead
        // is a dead node.
        assert!(crate::util::exif::looks_like_image_url(&lead.value));
    }
