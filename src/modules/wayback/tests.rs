use super::*;

    #[test]
    fn accepts_domain_and_url() {
        let m = Wayback;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com/p")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn iso_conversion() {
        assert_eq!(iso_from_cdx("20140912153012"), "2014-09-12 15:30:12 UTC");
        assert_eq!(iso_from_cdx("not-a-timestamp"), "not-a-timestamp");
        assert_eq!(iso_from_cdx("12345"), "12345");
    }

    #[test]
    fn extract_domain_strips_scheme_path_port_and_lowercases() {
        assert_eq!(
            extract_domain(TargetKind::Url, "https://Example.COM:8443/a/b?x=1"),
            "example.com"
        );
        assert_eq!(
            extract_domain(TargetKind::Url, "http://sub.host.org/"),
            "sub.host.org"
        );
        // Non-URL kinds are just trimmed + lowercased.
        assert_eq!(
            extract_domain(TargetKind::Domain, "  Example.com "),
            "example.com"
        );
        assert_eq!(extract_domain(TargetKind::Domain, ""), "");
    }

    fn row(cells: &[&str]) -> Row {
        Row(cells.iter().map(std::string::ToString::to_string).collect())
    }

    fn attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn header_only_or_empty_response_yields_no_entity() {
        assert!(build_entity(EntityKind::Domain, "x.com", &[], "s").is_none());
        // Header row only — domain unarchived.
        let header = [row(&["timestamp", "statuscode"])];
        assert!(build_entity(EntityKind::Domain, "x.com", &header, "s").is_none());
    }

    #[test]
    fn counts_snapshots_and_picks_bookend_timestamps() {
        let rows = [
            row(&["timestamp", "statuscode"]), // header
            row(&["20140912153012", "200"]),   // earliest
            row(&["20160101000000", "301"]),
            row(&["20200722120000", "200"]), // most recent
        ];
        let e = build_entity(EntityKind::Domain, "example.com", &rows, "s").unwrap();
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("archived"));
        assert!((e.confidence - 0.80).abs() < 1e-9);
        assert_eq!(attr(&e, "snapshot_count"), Some("3")); // header excluded
        assert_eq!(attr(&e, "first_seen"), Some("20140912153012"));
        assert_eq!(attr(&e, "first_seen_iso"), Some("2014-09-12 15:30:12 UTC"));
        assert_eq!(attr(&e, "last_seen"), Some("20200722120000"));
        assert_eq!(attr(&e, "last_seen_iso"), Some("2020-07-22 12:00:00 UTC"));
        // 200 appears twice, 301 once → ranked by frequency.
        assert_eq!(attr(&e, "status_distribution"), Some("200×2, 301×1"));
    }

    #[test]
    fn build_entity_url_target_yields_url_kind() {
        let rows = [
            row(&["timestamp", "statuscode"]),
            row(&["20230601120000", "200"]),
        ];
        let e = build_entity(
            EntityKind::Url,
            "https://example.com/page",
            &rows,
            "s",
        )
        .unwrap();
        assert_eq!(e.kind, EntityKind::Url);
        assert_eq!(e.value, "https://example.com/page");
        assert!(e.has_tag("archived"));
    }

    #[test]
    fn is_contact_path_matches_keywords() {
        assert!(is_contact_path("https://example.com/contact-us"));
        assert!(is_contact_path("https://example.com/about"));
        assert!(is_contact_path("https://example.com/team/"));
        assert!(is_contact_path("https://example.com/our-staff"));
        assert!(is_contact_path("https://example.com/impressum"));
        assert!(!is_contact_path("https://example.com/blog/post-1"));
        assert!(!is_contact_path("https://example.com/products"));
        assert!(!is_contact_path("https://example.com/"));
    }

    #[test]
    fn archive_url_format() {
        assert_eq!(
            archive_url("20140912153012", "http://example.com/contact"),
            "https://web.archive.org/web/20140912153012id_/http://example.com/contact"
        );
    }

    #[test]
    fn module_metadata() {
        let m = Wayback;
        assert_eq!(m.name(), "wayback");
        assert!(!m.description().is_empty());
        assert_eq!(m.priority(), 38);
        assert_eq!(m.max_timeout_ms(), 30_000);
        assert!(m.produces().contains(&EntityKind::Domain));
        assert!(m.produces().contains(&EntityKind::Url));
        assert!(m.produces().contains(&EntityKind::Email));
        assert!(m.produces().contains(&EntityKind::Phone));
        // MITRE override covers T1596 (web archive) and T1589.002 (email extraction).
        let techniques = m.attack_techniques();
        assert!(techniques.contains(&"T1596"));
        assert!(techniques.contains(&"T1589.002"));
    }
