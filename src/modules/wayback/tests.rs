use crate::core::confidence;
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
        let e = build_entity(EntityKind::Domain, "example.com", &rows, "s").expect("should succeed");
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("archived"));
        assert!((e.confidence - confidence::HIGH_PLUSPLUS).abs() < 1e-9);
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
        .expect("should succeed");
        assert_eq!(e.kind, EntityKind::Url);
        assert_eq!(e.value, "https://example.com/page");
        assert!(e.has_tag("archived"));
    }

    #[test]
    fn historical_subdomains_recovers_distinct_non_apex_hosts() {
        // A CDX domain-match response (fl=original): header + archived URLs
        // across subdomains, the apex, and duplicates.
        let rows = [
            row(&["original"]), // CDX column header
            row(&["http://dev.example.com/index.html"]),
            row(&["https://dev.example.com/login"]), // dup host, diff path
            row(&["http://staging.example.com/"]),
            row(&["http://api.example.com/"]),
            row(&["https://example.com/"]),         // apex echo — dropped
            row(&["http://unrelated.other.org/x"]), // not a subdomain — dropped
        ];
        let ents = historical_subdomains(&rows, "example.com", "s");
        let hosts: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
        // Distinct, sorted, apex + unrelated dropped, dup collapsed. (A `www.`
        // host is deliberately absent: Entity::new canonicalises `www.x` → `x`,
        // which would merge with the apex — a benign dedup, not a subdomain.)
        assert_eq!(
            hosts,
            [
                "api.example.com",
                "dev.example.com",
                "staging.example.com"
            ]
        );
        assert!(
            ents.iter()
                .all(|e| e.kind == EntityKind::Domain
                    && e.has_tag("archived")
                    && e.has_tag("wayback-historical"))
        );
    }

    #[test]
    fn historical_subdomains_empty_or_header_only_yields_nothing() {
        assert!(historical_subdomains(&[], "example.com", "s").is_empty());
        let header = [row(&["original"])];
        assert!(historical_subdomains(&header, "example.com", "s").is_empty());
        // A blank domain never matches.
        let rows = [row(&["original"]), row(&["http://x.example.com/"])];
        assert!(historical_subdomains(&rows, "", "s").is_empty());
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

    #[test]
    fn mine_url_entity_emits_url_with_wayback_tags_and_evidence() {
        // The archived contact-page URL mined per snapshot must itself be
        // pivotable as a first-class Url entity, not just an attribute
        // tacked onto the co-discovered Email/Phone entities.
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        let original_url = "http://example.com/contact";
        let fetch_url = archive_url("20140912153012", original_url);
        let ts_iso = iso_from_cdx("20140912153012");

        let e = mine_url_entity(&mut seen_urls, original_url, &fetch_url, &ts_iso, "s")
            .expect("first sighting of original_url must yield a Url entity");

        assert_eq!(e.kind, EntityKind::Url);
        assert_eq!(e.value, original_url);
        assert!((e.confidence - confidence::MEDIUM_HIGH).abs() < 1e-9);
        assert!(e.has_tag("wayback-historical"));
        assert!(e.has_tag(crate::core::tags::SEARCH_DISCOVERED));
        assert_eq!(e.evidence[0].source, SRC);
        assert!(e.evidence[0].summary.contains(original_url));
        assert_eq!(attr(&e, "archive_url"), Some(fetch_url.as_str()));
        assert_eq!(attr(&e, "snapshot_timestamp_iso"), Some(ts_iso.as_str()));
    }

    #[test]
    fn mine_url_entity_dedups_repeated_original_url_across_snapshots() {
        // collapse=urlkey makes a repeated original_url across two CDX rows
        // rare but not impossible; seen_urls must prevent a duplicate entity.
        let mut seen_urls: std::collections::HashSet<String> = std::collections::HashSet::new();
        let original_url = "http://example.com/about";

        let fetch_url_1 = archive_url("20140912153012", original_url);
        let first = mine_url_entity(
            &mut seen_urls,
            original_url,
            &fetch_url_1,
            "2014-09-12 15:30:12 UTC",
            "s",
        );
        assert!(first.is_some(), "first sighting must be emitted");

        let fetch_url_2 = archive_url("20200722120000", original_url);
        let second = mine_url_entity(
            &mut seen_urls,
            original_url,
            &fetch_url_2,
            "2020-07-22 12:00:00 UTC",
            "s",
        );
        assert!(
            second.is_none(),
            "repeated original_url must be deduped via seen_urls, not re-emitted"
        );
        assert_eq!(seen_urls.len(), 1);
    }
