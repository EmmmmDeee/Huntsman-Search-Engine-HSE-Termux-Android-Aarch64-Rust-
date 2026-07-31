use crate::core::confidence;
use super::*;

    #[test]
    fn fingerprint_table_is_sorted_and_non_empty() {
        assert!(!TAKEOVER_FINGERPRINTS.is_empty());
        for &(pattern, service, _) in TAKEOVER_FINGERPRINTS {
            assert!(!pattern.is_empty());
            assert!(!service.is_empty());
        }
    }

    #[test]
    fn known_services_present() {
        let services: Vec<&str> = TAKEOVER_FINGERPRINTS.iter().map(|t| t.1).collect();
        assert!(services.contains(&"AWS S3"));
        assert!(services.contains(&"Heroku"));
        assert!(services.contains(&"GitHub Pages"));
        assert!(services.contains(&"Netlify"));
    }

    #[tokio::test]
    async fn module_metadata() {
        let m = SubdomainTakeover;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "sub.example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    // ── matching_fingerprints (pure) ────────────────────────────────────

    #[test]
    fn matching_fingerprints_selects_by_cname_substring() {
        let hits: Vec<&str> = matching_fingerprints("myapp.herokuapp.com")
            .map(|f| f.1)
            .collect();
        assert_eq!(hits, vec!["Heroku"], "only the Heroku pattern is a substring");
    }

    #[test]
    fn matching_fingerprints_none_for_unknown_provider() {
        assert_eq!(matching_fingerprints("host.example.com").count(), 0);
    }

    #[test]
    fn matching_fingerprints_preserves_path_for_check_selection() {
        // S3 carries an HTTP body fingerprint; Azure Cloud (.cloudapp.net) is an
        // NXDOMAIN-only check (path = None) — the builder/check selector relies on
        // this third field surviving the match.
        let s3 = matching_fingerprints("bucket.s3.amazonaws.com")
            .next()
            .expect("should succeed");
        assert_eq!(s3.2, Some("NoSuchBucket"));
        let azure = matching_fingerprints("svc.cloudapp.net").next().expect("should succeed");
        assert_eq!(azure.2, None);
    }

    // ── build_entities (pure) ───────────────────────────────────────────

    #[test]
    fn build_entities_yields_vulnerable_domain_with_tags_and_evidence() {
        let ents = build_entities("app.example.com", "app.herokuapp.com", "Heroku", "s");
        assert_eq!(ents.len(), 1);
        let e = &ents[0];
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "app.example.com");
        assert!((e.confidence - confidence::VERY_HIGH_PLUS).abs() < 1e-9);
        assert!(e.has_tag(crate::core::tags::VULNERABLE) && e.has_tag("subdomain-takeover"));
        assert!(e.has_tag("takeover:Heroku"));

        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("cname_target").map(String::as_str),
            Some("app.herokuapp.com")
        );
        assert_eq!(ev.attributes.get("service").map(String::as_str), Some("Heroku"));
        assert!(ev.summary.contains("Heroku may be claimable"));
    }

    #[test]
    fn build_entities_blank_service_adds_no_takeover_tag_or_attr() {
        let e = build_entities("app.example.com", "x.cloudapp.net", "", "s").remove(0);
        assert!(
            !e.tags.iter().any(|t| t.starts_with("takeover:")),
            "a blank service must not produce a `takeover:` tag"
        );
        assert!(!e.evidence[0].attributes.contains_key("service"));
        // The vulnerable / subdomain-takeover tags and the CNAME attr remain.
        assert!(e.has_tag(crate::core::tags::VULNERABLE) && e.has_tag("subdomain-takeover"));
        assert_eq!(
            e.evidence[0].attributes.get("cname_target").map(String::as_str),
            Some("x.cloudapp.net")
        );
    }

    #[test]
    fn build_entities_blank_cname_skips_cname_attr() {
        let e = build_entities("app.example.com", "", "Heroku", "s").remove(0);
        assert!(!e.evidence[0].attributes.contains_key("cname_target"));
        assert!(e.has_tag("takeover:Heroku"));
    }

    // ---- dangling_verdict: a takeover claim needs an authority's "no" ----

    /// Build the exact `NetError` hickory delivers for a negative answer — no
    /// resolver, no runtime, no network. Mirrors the fixture in
    /// `crate::util::dns`'s tests.
    fn negative(name: &str, code: hickory_resolver::proto::op::ResponseCode) -> hickory_resolver::net::NetError {
        use hickory_resolver::net::NoRecords;
        use hickory_resolver::proto::op::Query;
        use hickory_resolver::proto::rr::{Name, RecordType};
        hickory_resolver::net::NetError::from(NoRecords::new(
            Query::query(Name::from_ascii(name).expect("valid test name"), RecordType::A),
            code,
        ))
    }

    #[test]
    fn a_resolver_malfunction_is_not_a_dangling_cname() {
        // THE regression test. `check_nxdomain` was
        // `lookup_ip(..).await.is_err()`, so a 2s timeout on a flaky link
        // returned the VULNERABLE signal and fabricated a Severity::High
        // finding at confidence::VERY_HIGH_PLUS. A malfunction must now refuse
        // to answer rather than answer wrongly.
        let timeout = hickory_resolver::net::NetError::Timeout;
        assert!(
            dangling_verdict::<()>("x.cloudapp.net", Err(timeout)).is_err(),
            "a timeout must not be reported as a dangling CNAME"
        );
        let no_conns = hickory_resolver::net::NetError::NoConnections;
        assert!(
            dangling_verdict::<()>("x.cloudapp.net", Err(no_conns)).is_err(),
            "an exhausted resolver pool must not be reported as a dangling CNAME"
        );
    }

    #[test]
    fn nxdomain_is_the_only_dangling_signal() {
        use hickory_resolver::proto::op::ResponseCode;
        // The label does not exist -> genuinely claimable.
        assert!(
            dangling_verdict::<()>(
                "x.cloudapp.net",
                Err(negative("x.cloudapp.net.", ResponseCode::NXDomain))
            )
            .expect("NXDOMAIN is a clean answer, not an error"),
            "NXDOMAIN means the label is unregistered and therefore claimable"
        );
        // NODATA: the label exists and publishes some other type, so it is NOT
        // free to claim.
        assert!(
            !dangling_verdict::<()>(
                "x.cloudapp.net",
                Err(negative("x.cloudapp.net.", ResponseCode::NoError))
            )
            .expect("NODATA is a clean answer, not an error"),
            "NODATA means the label exists, so it is not free to claim"
        );
        // It resolves -> someone owns it.
        assert!(
            !dangling_verdict("x.cloudapp.net", Ok(())).expect("Ok resolves cleanly"),
            "a target that resolves belongs to someone"
        );
    }

    #[test]
    fn a_servfail_does_not_become_a_takeover_finding() {
        // SERVFAIL can travel INSIDE hickory's NoRecordsFound, so the obvious
        // `is_no_records_found()` shorthand would call this a clean miss. Here
        // that would mean a broken authority manufacturing a High finding.
        use hickory_resolver::proto::op::ResponseCode;
        assert!(
            dangling_verdict::<()>(
                "x.cloudapp.net",
                Err(negative("x.cloudapp.net.", ResponseCode::ServFail))
            )
            .is_err(),
            "a broken authority must not be reported as a dangling CNAME"
        );
    }
