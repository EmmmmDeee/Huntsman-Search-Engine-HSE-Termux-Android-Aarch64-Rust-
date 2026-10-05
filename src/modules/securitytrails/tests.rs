use crate::core::confidence;
use super::*;
    #[test]
    fn accepts_domain_and_ip() {
        let m = SecurityTrails;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
    #[test]
    fn cost_is_key_gated() {
        assert!(matches!(SecurityTrails.cost(), ModuleCost::KeyGated));
    }

    fn ev_attr<'a>(e: &'a Entity, k: &str) -> Option<&'a str> {
        e.evidence[0].attributes.get(k).map(String::as_str)
    }

    #[test]
    fn subdomain_entity_qualifies_host_and_carries_count() {
        let e = build_subdomain_entity("example.com", "mail", "42", "s").expect("should succeed");
        assert_eq!(e.kind, EntityKind::Domain);
        assert_eq!(e.value, "mail.example.com");
        assert!(e.has_tag("subdomain") && e.has_tag("securitytrails"));
        assert!((e.confidence - confidence::EXPERT).abs() < 1e-9);
        assert_eq!(ev_attr(&e, "parent_domain"), Some("example.com"));
        assert_eq!(ev_attr(&e, "total_subdomains"), Some("42"));
    }

    #[test]
    fn blank_subdomain_label_is_skipped() {
        assert!(build_subdomain_entity("example.com", "  ", "1", "s").is_none());
    }

    #[test]
    fn a_www_sub_label_is_skipped_as_an_apex_echo() {
        // Regression: SecurityTrails' subdomains list routinely includes
        // "www" — a near-certain hit for any real domain, not an edge case.
        // `Entity::new` strips a leading "www." label internally, so
        // "www.example.com" collapses onto the scan's own apex/subject uid.
        // Before this was fixed, EVERY sub-label was unconditionally tagged
        // "subdomain" with no apex check at all, permanently mislabeling the
        // subject's own entity as a subdomain of itself via
        // `Entity::merge`'s tag-union.
        assert!(build_subdomain_entity("example.com", "www", "1", "s").is_none());
        // Case-insensitive, matching `Entity::new`'s own normalisation.
        assert!(build_subdomain_entity("Example.COM", "WWW", "1", "s").is_none());
        // A genuine sub-label is unaffected.
        assert!(build_subdomain_entity("example.com", "mail", "1", "s").is_some());
    }

    #[test]
    fn associated_entity_accepts_real_hostname() {
        let e = build_associated_entity("1.2.3.4", Some("mail.acme.com."), "7", "s").expect("should succeed");
        assert_eq!(e.kind, EntityKind::Domain);
        // Trailing dot stripped before the value reaches the entity.
        assert_eq!(e.value, "mail.acme.com");
        assert!(e.has_tag("reverse-ip") && e.has_tag("securitytrails"));
        assert!((e.confidence - 0.82).abs() < 1e-9);
        assert_eq!(ev_attr(&e, "ip"), Some("1.2.3.4"));
        // The full associated-domain count rides along, never hidden by the cap.
        assert_eq!(ev_attr(&e, "total_associated"), Some("7"));
    }

    #[test]
    fn associated_entity_rejects_non_hostnames() {
        // None / blank.
        assert!(build_associated_entity("1.2.3.4", None, "0", "s").is_none());
        assert!(build_associated_entity("1.2.3.4", Some("  "), "0", "s").is_none());
        // Bare IP literal (PTR pointing back at the IP itself).
        assert!(build_associated_entity("1.2.3.4", Some("1.2.3.4"), "0", "s").is_none());
        assert!(build_associated_entity("::1", Some("2001:db8::1"), "0", "s").is_none());
        // Single label, no dot.
        assert!(build_associated_entity("1.2.3.4", Some("localhost"), "0", "s").is_none());
    }

    #[test]
    fn associated_entities_cap_the_fan_out_but_surface_the_true_total() {
        // A shared host with 40 associated domains returned and a reported total
        // of 5000. The entity fan-out is capped at 30 (co-tenant flood guard),
        // but every emitted entity must carry the TRUE total (5000) — not the
        // returned count, and never a silently-dropped signal. Before the fix the
        // reverse-IP path surfaced no count at all, hiding how shared the host is.
        let records: Vec<AssociatedRecord> = (0..40)
            .map(|i| {
                serde_json::from_str::<AssociatedRecord>(&format!(
                    r#"{{"hostname":"h{i}.example.com"}}"#
                ))
                .expect("should succeed")
            })
            .collect();
        let es = associated_entities(&records, Some(5000), "1.2.3.4", "s");
        assert_eq!(
            es.len(),
            MAX_REVERSE_RECORDS,
            "entity fan-out capped at {MAX_REVERSE_RECORDS} co-tenant pivots"
        );
        assert!(
            es.iter()
                .all(|e| ev_attr(e, "total_associated") == Some("5000")),
            "every emitted entity carries the true associated-domain total, not the returned count"
        );
        // With no reported total, fall back to the number of records returned —
        // never a fabricated number.
        let es2 = associated_entities(&records, None, "1.2.3.4", "s");
        assert!(es2.iter().all(|e| ev_attr(e, "total_associated") == Some("40")));
    }

    fn assoc_body(hosts: &[&str], record_count: Option<u64>) -> AssociatedResp {
        let recs: Vec<String> = hosts
            .iter()
            .map(|h| format!(r#"{{"hostname":"{h}"}}"#))
            .collect();
        let count = record_count.map_or(String::new(), |n| format!(r#","record_count":{n}"#));
        serde_json::from_str(&format!(r#"{{"records":[{}]{count}}}"#, recs.join(",")))
            .expect("should succeed")
    }

    fn hosts(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("h{i}.example.com")).collect()
    }

    #[test]
    fn a_paged_reverse_ip_answer_is_declared_truncated() {
        // 40 records back, SecurityTrails reports 5000: 30 of 5000 must not
        // read as a complete answer to coverage (REQ-SECURITYTRAILS-001).
        let hs = hosts(40);
        let refs: Vec<&str> = hs.iter().map(String::as_str).collect();
        let r = reverse_ip_result(&assoc_body(&refs, Some(5000)), "1.2.3.4", "s");
        assert_eq!(r.entities.len(), MAX_REVERSE_RECORDS, "premise: fan-out capped");
        let t = r.truncation.expect("30 of 5000 must not read as complete");
        assert!(t.contains("30 of 5000"), "{t}");
    }

    #[test]
    fn a_reverse_ip_answer_over_the_cap_without_a_count_is_declared_truncated_with_no_total() {
        let hs = hosts(40);
        let refs: Vec<&str> = hs.iter().map(String::as_str).collect();
        let r = reverse_ip_result(&assoc_body(&refs, None), "1.2.3.4", "s");
        let t = r.truncation.expect("the client-side cap dropped 10 records");
        assert!(t.contains("did not report how many exist"), "{t}");
    }

    #[test]
    fn a_complete_reverse_ip_answer_with_a_rejected_record_stays_complete() {
        // Over-correction guard: the IP-literal PTR was retrieved and rejected,
        // not left unread, so 2 of 2 is complete even though 1 entity results.
        let r = reverse_ip_result(
            &assoc_body(&["a.example.com", "1.2.3.4"], Some(2)),
            "1.2.3.4",
            "s",
        );
        assert_eq!(r.entities.len(), 1, "premise: the IP literal is rejected");
        assert!(r.truncation.is_none(), "{:?}", r.truncation);
        // And a short answer with no count at all stays complete.
        let r = reverse_ip_result(&assoc_body(&["a.example.com"], None), "1.2.3.4", "s");
        assert!(r.truncation.is_none(), "{:?}", r.truncation);
    }

    #[test]
    fn a_reverse_ip_answer_of_exactly_the_cap_with_a_matching_count_stays_complete() {
        let hs = hosts(MAX_REVERSE_RECORDS);
        let refs: Vec<&str> = hs.iter().map(String::as_str).collect();
        let r = reverse_ip_result(&assoc_body(&refs, Some(MAX_REVERSE_RECORDS as u64)), "1.2.3.4", "s");
        assert!(r.truncation.is_none(), "{:?}", r.truncation);
    }

    #[test]
    fn a_subdomain_list_short_of_the_reported_count_is_declared_truncated() {
        let body: SubdomainResp =
            serde_json::from_str(r#"{"subdomains":["mail","www"],"subdomain_count":9}"#)
                .expect("should succeed");
        let r = subdomain_result(&body, "example.com", "s");
        let t = r.truncation.expect("2 of 9 must not read as complete");
        assert!(t.contains("2 of 9"), "{t}");
    }

    #[test]
    fn a_complete_subdomain_list_with_a_www_echo_stays_complete() {
        // Over-correction guard: "www" is dropped as an apex echo, so 1 entity
        // results from 2 labels, yet the list is complete (count 2).
        let body: SubdomainResp =
            serde_json::from_str(r#"{"subdomains":["mail","www"],"subdomain_count":2}"#)
                .expect("should succeed");
        let r = subdomain_result(&body, "example.com", "s");
        assert_eq!(r.entities.len(), 1, "premise: www is an apex echo");
        assert!(r.truncation.is_none(), "{:?}", r.truncation);
    }
