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
        let e = build_subdomain_entity("example.com", "mail", "42", "s").unwrap();
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
    fn associated_entity_accepts_real_hostname() {
        let e = build_associated_entity("1.2.3.4", Some("mail.acme.com."), "7", "s").unwrap();
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
                .unwrap()
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
