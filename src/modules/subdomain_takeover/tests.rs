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
            .unwrap();
        assert_eq!(s3.2, Some("NoSuchBucket"));
        let azure = matching_fingerprints("svc.cloudapp.net").next().unwrap();
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
        assert!((e.confidence - 0.90).abs() < 1e-9);
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

    // ── is_genuine_no_cname (pure, T2.151) ──────────────────────────────
    //
    // T2.151 regression: process() previously discarded EVERY NetError kind
    // (Timeout, Io, Busy, NoConnections, Proto, an unrelated ResponseCode)
    // into the same `None` as a genuine "server answered, no CNAME here" —
    // silently zeroing the module's sole evidence-producing path on any
    // resolver hiccup. Only NXDOMAIN/NoRecordsFound is the correct clean
    // miss. Constructed against real hickory_resolver::net types — no live
    // DNS (Rule 3): the trivially-constructible unit-variant failures prove
    // the negative case, and a genuine NoRecordsFound(NXDomain) proves the
    // positive.

    #[test]
    fn is_genuine_no_cname_false_for_real_transport_and_protocol_failures() {
        use hickory_resolver::net::NetError;
        for e in [
            NetError::Timeout,
            NetError::Busy,
            NetError::NoConnections,
            NetError::Message("synthetic proto failure"),
        ] {
            assert!(
                !is_genuine_no_cname(&e),
                "{e:?} is a real resolution failure, not a genuine 'no CNAME' answer"
            );
        }
    }

    #[test]
    fn is_genuine_no_cname_true_for_nxdomain_and_no_records_found() {
        use hickory_resolver::net::{DnsError, NetError, NoRecords};
        use hickory_resolver::proto::op::{Query, ResponseCode};
        use hickory_resolver::proto::rr::{Name, RecordType};

        let query = Query::query(Name::root(), RecordType::CNAME);
        let nxdomain = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            query.clone(),
            ResponseCode::NXDomain,
        )));
        assert!(
            is_genuine_no_cname(&nxdomain),
            "a genuine NXDOMAIN must read as 'no CNAME', not a failure"
        );

        // NoError-with-empty-answer (the domain exists but has no CNAME) is
        // likewise a genuine clean miss, distinct from NXDOMAIN.
        let no_records = NetError::Dns(DnsError::NoRecordsFound(NoRecords::new(
            query,
            ResponseCode::NoError,
        )));
        assert!(
            is_genuine_no_cname(&no_records),
            "a NoError/no-records answer must also read as 'no CNAME'"
        );
    }

    #[test]
    fn is_genuine_no_cname_false_for_an_unrelated_response_code() {
        // A server-side error response code (e.g. SERVFAIL/REFUSED) is a real
        // outage/misconfiguration signal, not a "no CNAME" answer.
        use hickory_resolver::net::{DnsError, NetError};
        use hickory_resolver::proto::op::ResponseCode;

        let servfail = NetError::Dns(DnsError::ResponseCode(ResponseCode::ServFail));
        assert!(
            !is_genuine_no_cname(&servfail),
            "a SERVFAIL response code must not read as 'no CNAME'"
        );
    }
