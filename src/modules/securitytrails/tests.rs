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
        assert!((e.confidence - 0.88).abs() < 1e-9);
        assert_eq!(ev_attr(&e, "parent_domain"), Some("example.com"));
        assert_eq!(ev_attr(&e, "total_subdomains"), Some("42"));
    }

    #[test]
    fn blank_subdomain_label_is_skipped() {
        assert!(build_subdomain_entity("example.com", "  ", "1", "s").is_none());
    }

    #[test]
    fn associated_entity_accepts_real_hostname() {
        let e = build_associated_entity("1.2.3.4", Some("mail.acme.com."), "s").unwrap();
        assert_eq!(e.kind, EntityKind::Domain);
        // Trailing dot stripped before the value reaches the entity.
        assert_eq!(e.value, "mail.acme.com");
        assert!(e.has_tag("reverse-ip") && e.has_tag("securitytrails"));
        assert!((e.confidence - 0.82).abs() < 1e-9);
        assert_eq!(ev_attr(&e, "ip"), Some("1.2.3.4"));
    }

    #[test]
    fn associated_entity_rejects_non_hostnames() {
        // None / blank.
        assert!(build_associated_entity("1.2.3.4", None, "s").is_none());
        assert!(build_associated_entity("1.2.3.4", Some("  "), "s").is_none());
        // Bare IP literal (PTR pointing back at the IP itself).
        assert!(build_associated_entity("1.2.3.4", Some("1.2.3.4"), "s").is_none());
        assert!(build_associated_entity("::1", Some("2001:db8::1"), "s").is_none());
        // Single label, no dot.
        assert!(build_associated_entity("1.2.3.4", Some("localhost"), "s").is_none());
    }
