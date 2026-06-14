use super::*;

    #[test]
    fn build_asns_emits_prefixed_asn_with_prefix_evidence() {
        let ni = NetworkInfo {
            asns: vec!["15169".into(), "".into(), "notanum".into()],
            prefix: Some("8.8.8.0/24".into()),
        };
        let es = build_asns(&ni, "scan");
        assert_eq!(es.len(), 1, "only the valid numeric ASN");
        assert_eq!(es[0].kind, EntityKind::Asn);
        assert_eq!(es[0].value, "AS15169");
        assert!(es[0].has_tag("ripestat"));
        assert_eq!(
            es[0].evidence[0].attributes.get("prefix").unwrap(),
            "8.8.8.0/24"
        );
    }

    #[test]
    fn build_org_from_holder() {
        let ao = AsOverview {
            holder: Some("GOOGLE - Google LLC".into()),
        };
        let e = build_org(&ao, "scan").unwrap();
        assert_eq!(e.kind, EntityKind::Organisation);
        assert_eq!(e.value, "GOOGLE - Google LLC");
        assert!(e.has_tag("network-holder"));
        // Empty / missing holder yields nothing.
        assert!(build_org(&AsOverview::default(), "scan").is_none());
    }

    #[test]
    fn build_abuse_emits_tagged_emails_and_filters_junk() {
        let es = build_abuse(
            &[
                // Infrastructure provider desks — must be suppressed so they
                // never enter the subject's identity cluster.
                "network-abuse@google.com".into(),
                "abuse@cloudflare.com".into(),
                "not-an-email".into(),
                // A non-provider mailbox on a private netblock survives.
                "  ops@example.org ".into(),
            ],
            "scan",
        );
        assert_eq!(es.len(), 1, "only the non-infrastructure contact survives");
        assert!(
            es.iter()
                .all(|e| e.kind == EntityKind::Email && e.has_tag("abuse-contact"))
        );
        let vals: Vec<&str> = es.iter().map(|e| e.value.as_str()).collect();
        assert!(!vals.iter().any(|v| v.contains("google.com")));
        assert!(!vals.iter().any(|v| v.contains("cloudflare.com")));
        // Trimmed + normalised.
        assert!(vals.iter().any(|v| v.contains("ops@example.org")));
    }

    #[test]
    fn accepts_ip_and_asn_only() {
        assert!(RipeStat.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(RipeStat.accepts(&Target::new(TargetKind::Asn, "AS15169")));
        assert!(!RipeStat.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }
