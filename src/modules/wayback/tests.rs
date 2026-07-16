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
    fn select_contact_snapshots_caps_but_reports_true_total() {
        // 15 archived contact pages + 5 non-contact pages. Only 10 are mined,
        // but the true total (15) must be reported so truncation can be signaled.
        let mut rows = vec![row(&["timestamp", "original"])]; // header
        for i in 0..15 {
            rows.push(row(&[
                "20200101000000",
                &format!("http://example.com/contact/{i}"),
            ]));
        }
        for i in 0..5 {
            rows.push(row(&["20210101000000", &format!("http://example.com/blog/{i}")]));
        }
        let (selected, total) = select_contact_snapshots(&rows);
        assert_eq!(total, 15, "total must count ALL contact snapshots, not the cap");
        assert_eq!(
            selected.len(),
            MAX_CONTACT_SNAPSHOTS,
            "the mined selection is capped at MAX_CONTACT_SNAPSHOTS"
        );
    }

    #[test]
    fn select_contact_snapshots_under_cap_returns_all() {
        let rows = [
            row(&["timestamp", "original"]),
            row(&["20200101000000", "http://example.com/about"]),
            row(&["20200102000000", "http://example.com/team"]),
            row(&["20200103000000", "http://example.com/blog/x"]), // non-contact, ignored
        ];
        let (selected, total) = select_contact_snapshots(&rows);
        assert_eq!(total, 2);
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn mark_contact_truncation_flags_only_when_over_cap() {
        // Regression (T2.141): the archive seed must be tagged `truncated` and
        // carry the true total ONLY when more archived contact pages exist than
        // the mining cap fetched.
        let rows = [
            row(&["timestamp", "statuscode"]),
            row(&["20200101000000", "200"]),
        ];
        let mut seed = build_entity(EntityKind::Domain, "example.com", &rows, "s").unwrap();

        // Exactly at the cap → no truncation.
        mark_contact_truncation(&mut seed, MAX_CONTACT_SNAPSHOTS);
        assert!(!seed.has_tag("truncated"), "must not flag at or under the cap");

        // Over the cap → tag + dedicated evidence line with the true total.
        let total = MAX_CONTACT_SNAPSHOTS + 23;
        mark_contact_truncation(&mut seed, total);
        assert!(seed.has_tag("truncated"), "seed must be tagged 'truncated'");
        let ev = seed.evidence.last().unwrap();
        assert_eq!(
            ev.attributes.get("total_contact_snapshots").map(String::as_str),
            Some(total.to_string().as_str()),
            "total_contact_snapshots must reflect the full archive count"
        );
        assert_eq!(
            ev.attributes.get("contact_snapshots_mined").map(String::as_str),
            Some(MAX_CONTACT_SNAPSHOTS.to_string().as_str())
        );
        assert_eq!(
            ev.attributes.get("contact_snapshots_capped").map(String::as_str),
            Some("true"),
            "contact_snapshots_capped must be set when the cap is hit"
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

    #[test]
    fn mine_keys_from_body_pools_a_leaked_key_with_wayback_provenance() {
        // A 234-char BinaryEdge-shaped (`bp0_`-prefixed, poolable) key embedded
        // in a synthetic archived page body — same fixture shape used to prove
        // the web_crawler/username_search tokenizer merge (T2.80), reused here
        // to prove wayback's NEW key-mining pass actually reaches `pool.add`
        // with the archive-specific provenance (timestamp + original URL), not
        // just a generic "found it" no-op.
        let leaked_key = format!(
            "bp0_{}",
            "oHBvRPOIvGrv5iFlbCBFNOgmBjMtpsiaOclRz3AwzKsbVRJN9wVGFYGW2WmQzCudiH7YFjS1on43XkMtECqOxSF2O3GYRdo1XKXWNqRs7rpEmoKiuPKdYR7osjOrU1xxDO0CzUZREN68k4tUNpfZ46pdJQIPvjiQvlb5lZXOIgfFwD3HJoKyrbmEYYmdhQj38AruHr4iwRxpVHSbKdA9u4uQgwLg6G3oT1ogmM"
        );
        let body = format!(
            "<html><body>Contact us. API_KEY={leaked_key} Thanks.</body></html>"
        );
        let pool = crate::util::key_pool::global_pool();
        let domain = "wayback-keymine-test.example";
        let ts_iso = "2019-03-14 00:00:00 UTC";
        let original_url = "http://wayback-keymine-test.example/contact";

        mine_keys_from_body(&pool, &body, domain, ts_iso, original_url);

        let entry = pool
            .snapshot()
            .services
            .get("binaryedge")
            .into_iter()
            .flatten()
            .find(|e| e.value == leaked_key)
            .cloned();
        let found = entry.is_some();
        if let Some(e) = &entry {
            assert_eq!(
                e.discovered_by.as_deref(),
                Some(format!("wayback:{domain}").as_str()),
                "provenance must name wayback, not a generic/wrong source"
            );
            assert!(
                e.notes.as_deref().is_some_and(|n| n.contains(ts_iso)
                    && n.contains(original_url)),
                "notes must carry the archive timestamp + original URL, got {:?}",
                e.notes
            );
        }
        if found {
            pool.remove("binaryedge", &leaked_key);
        }
        assert!(
            found,
            "a leaked key in an archived page body must reach the key pool"
        );
    }
