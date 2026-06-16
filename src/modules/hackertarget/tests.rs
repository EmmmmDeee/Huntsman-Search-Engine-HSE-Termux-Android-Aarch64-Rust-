use super::*;

    #[test]
    fn accepts_domain_and_ip() {
        let m = HackerTarget;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn cost_is_free() {
        assert!(matches!(
            HackerTarget.cost(),
            crate::core::module::ModuleCost::Free
        ));
    }

    #[test]
    fn description_non_empty() {
        assert!(!HackerTarget.description().is_empty());
    }

    // ── build_hostsearch_entities (pure) ────────────────────────────────

    fn of_kind(ents: &[Entity], kind: EntityKind) -> Vec<&Entity> {
        ents.iter().filter(|e| e.kind == kind).collect()
    }

    #[test]
    fn hostsearch_yields_subdomains_external_hosts_and_ips() {
        // sub of example.com → 0.75 + subdomain tag; an external CNAME target →
        // 0.50, no subdomain tag; each routable IP → one IpAddress entity.
        let body = "mail.example.com,93.184.216.34\n\
                    api.example.com,93.184.216.35\n\
                    cdn.fastly.net,151.101.1.10";
        let ents = build_hostsearch_entities(body, "example.com", "s");

        let domains = of_kind(&ents, EntityKind::Domain);
        assert_eq!(domains.len(), 3);
        let sub = domains.iter().find(|e| e.value == "mail.example.com").unwrap();
        assert!((sub.confidence - 0.75).abs() < 1e-9);
        assert!(sub.has_tag("hackertarget") && sub.has_tag(tags::SUBDOMAIN));
        assert_eq!(
            sub.evidence[0].attributes.get("resolved_ip").map(String::as_str),
            Some("93.184.216.34")
        );
        let ext = domains.iter().find(|e| e.value == "cdn.fastly.net").unwrap();
        assert!((ext.confidence - 0.50).abs() < 1e-9, "external host → 0.50");
        assert!(!ext.has_tag(tags::SUBDOMAIN));

        let ips = of_kind(&ents, EntityKind::IpAddress);
        let ip_vals: Vec<&str> = ips.iter().map(|e| e.value.as_str()).collect();
        assert!(ip_vals.contains(&"93.184.216.34") && ip_vals.contains(&"151.101.1.10"));
        assert!(ips.iter().all(|e| e.has_tag("hackertarget")));
    }

    #[test]
    fn hostsearch_dedups_repeats_and_skips_bad_lines() {
        // Duplicate host + IP, a line with no comma, and a 0.-prefixed IP.
        let body = "a.example.com,10.0.0.1\n\
                    a.example.com,10.0.0.1\n\
                    garbage-no-comma\n\
                    b.example.com,0.0.0.0";
        let ents = build_hostsearch_entities(body, "example.com", "s");
        // a.example.com (once) + 10.0.0.1 (once) + b.example.com. 0.0.0.0 skipped.
        let domains = of_kind(&ents, EntityKind::Domain);
        assert_eq!(domains.len(), 2, "duplicate host folded; bad line ignored");
        let ips = of_kind(&ents, EntityKind::IpAddress);
        assert_eq!(ips.len(), 1, "duplicate IP folded; 0.-prefixed IP skipped");
        assert_eq!(ips[0].value, "10.0.0.1");
    }

    #[test]
    fn hostsearch_blank_ip_adds_no_resolved_ip_attr() {
        let ents = build_hostsearch_entities("host.example.com,", "example.com", "s");
        let d = of_kind(&ents, EntityKind::Domain);
        assert_eq!(d.len(), 1);
        assert!(
            !d[0].evidence[0].attributes.contains_key("resolved_ip"),
            "a blank resolved IP must not become a `resolved_ip` attribute"
        );
        // The empty second field produces no IpAddress entity either.
        assert!(of_kind(&ents, EntityKind::IpAddress).is_empty());
    }

    #[test]
    fn hostsearch_empty_body_yields_nothing() {
        assert!(build_hostsearch_entities("", "example.com", "s").is_empty());
    }

    // ── build_reverse_ip_entities (pure) ────────────────────────────────

    #[test]
    fn reverse_ip_yields_tagged_domains_dedup_and_skips_self() {
        let body = "example.com\n\
                    other.com\n\
                    example.com\n\
                    1.2.3.4\n\
                    no-dot-line";
        let ents = build_reverse_ip_entities(body, "1.2.3.4", "s");
        let vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(vals, vec!["example.com", "other.com"], "dedup + skip self IP + skip dotless");
        assert!(ents.iter().all(|e| {
            e.kind == EntityKind::Domain && e.has_tag("hackertarget") && e.has_tag("reverse-ip")
        }));
    }

    // ── build_reverse_dns_entities (pure) ───────────────────────────────

    #[test]
    fn reverse_dns_strips_trailing_dot_and_tags_ptr() {
        let ents = build_reverse_dns_entities("host.example.com.\n", "1.2.3.4", "s");
        assert_eq!(ents.len(), 1);
        let e = &ents[0];
        assert_eq!(e.value, "host.example.com", "trailing dot stripped");
        assert!((e.confidence - 0.70).abs() < 1e-9);
        assert!(e.has_tag("hackertarget") && e.has_tag(tags::PTR));
        assert!(e.evidence[0].summary.contains("Reverse DNS for 1.2.3.4"));
    }

    #[test]
    fn reverse_dns_skips_blank_and_dotless_lines() {
        let ents = build_reverse_dns_entities("\nlocalhost\nptr.example.com\n", "1.2.3.4", "s");
        let vals: Vec<&str> = ents.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(vals, vec!["ptr.example.com"]);
    }
