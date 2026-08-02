use super::*;

    #[test]
    fn extract_github_location_from_html() {
        let html = r#"<li itemprop="homeLocation"><svg></svg><span class="p-label">Brisbane, Australia</span></li>"#;
        let loc = extract_github_location(html).expect("should succeed");
        assert_eq!(loc, "Brisbane, Australia");
    }

    #[test]
    fn extract_github_location_missing() {
        assert!(extract_github_location("<html><body>no location</body></html>").is_none());
    }

    #[test]
    fn extract_meta_geo_placename() {
        let html = r#"<meta name="geo.placename" content="Sydney, NSW">"#;
        let loc = extract_meta_location(html).expect("should succeed");
        assert_eq!(loc, "Sydney, NSW");
    }

    #[test]
    fn extract_meta_content_before_name_is_found() {
        // The content attribute can precede the name/property; the old
        // forward-only scan from the name attr missed this. Bounding the whole
        // element finds it in either order.
        let html = r#"<meta content="Brisbane, QLD" property="og:region">"#;
        assert_eq!(extract_meta_location(html).expect("should succeed"), "Brisbane, QLD");
    }

    #[test]
    fn extract_meta_tolerates_multibyte_and_unterminated() {
        // A multibyte char (é) inside the extracted value must not panic the
        // slice, and an unterminated content="… must be skipped, not coerced
        // to an empty string.
        let ok = r#"<meta name="og:locality" content="Café Nundah">"#;
        assert_eq!(extract_meta_location(ok).expect("should succeed"), "Café Nundah");
        let unterminated = r#"<meta name="og:locality" content="Nundah"#;
        assert!(extract_meta_location(unterminated).is_none());
    }

    #[test]
    fn extract_meta_missing() {
        assert!(extract_meta_location("<html></html>").is_none());
    }

    #[tokio::test]
    async fn module_accepts_supported_hosts() {
        let m = SocialLocation;
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://github.com/alice")));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://www.ratemyagent.com.au/real-estate-agent/haigen-bamford-as105/"
        )));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://www.homely.com.au/agent/haigenb"
        )));
        assert!(m.accepts(&Target::new(
            TargetKind::Url,
            "https://www.linkedin.com/in/haigen-bamford"
        )));
        assert!(!m.accepts(&Target::new(TargetKind::Url, "https://example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "github.com")));
    }

    #[test]
    fn professional_host_detection() {
        assert!(is_professional_host("ratemyagent.com.au"));
        assert!(is_professional_host("www.homely.com.au"));
        assert!(is_professional_host("linkedin.com"));
        assert!(!is_professional_host("github.com"));
        assert!(!is_professional_host("reddit.com"));
    }
