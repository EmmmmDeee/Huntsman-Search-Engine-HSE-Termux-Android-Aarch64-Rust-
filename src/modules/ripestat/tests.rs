use super::*;

    #[test]
    fn build_asns_emits_prefixed_asn_with_prefix_evidence() {
        let ni = NetworkInfo {
            asns: vec!["15169".into(), "".into(), "notanum".into()],
            prefix: Some("8.8.8.0/24".into()),
        };
        let es = build_asns(&ni, "scan");
        // One ASN entity + one Cidr entity from the covering prefix.
        assert_eq!(es.len(), 2, "valid numeric ASN + covering Cidr");
        let asn_e = es.iter().find(|e| e.kind == EntityKind::Asn).expect("should succeed");
        assert_eq!(asn_e.value, "AS15169");
        assert!(asn_e.has_tag("ripestat"));
        assert_eq!(
            asn_e.evidence[0].attributes.get("prefix").expect("should succeed"),
            "8.8.8.0/24"
        );
        let cidr_e = es.iter().find(|e| e.kind == EntityKind::Cidr).expect("should succeed");
        assert_eq!(cidr_e.value, "8.8.8.0/24");
        assert!(cidr_e.has_tag("network-prefix"));
        // Single announcing ASN ⇒ the covering Cidr carries the origin `asn`
        // as evidence, naming this prefix's origin network (AS15169).
        assert_eq!(
            cidr_e.evidence[0].attributes.get("asn").map(String::as_str),
            Some("15169")
        );
    }

    #[test]
    fn build_asns_leaves_a_multi_origin_prefix_unattributed() {
        // A MOAS (multiple-origin AS) prefix has no single owner to assert, so the
        // covering Cidr must NOT carry an `asn` — the origin is left unattributed
        // rather than naming an arbitrary one of the origins.
        let ni = NetworkInfo {
            asns: vec!["64512".into(), "64513".into()],
            prefix: Some("203.0.113.0/24".into()),
        };
        let es = build_asns(&ni, "scan");
        let cidr_e = es
            .iter()
            .find(|e| e.kind == EntityKind::Cidr)
            .expect("covering Cidr");
        assert!(
            !cidr_e.evidence[0].attributes.contains_key("asn"),
            "a multi-origin prefix must not assert a single owner ASN"
        );
    }

    #[test]
    fn build_org_from_holder() {
        let ao = AsOverview {
            holder: Some("GOOGLE - Google LLC".into()),
        };
        let e = build_org(&ao, "scan").expect("should succeed");
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
    fn build_announced_prefixes_emits_deduped_sorted_cidrs() {
        let ap = AnnouncedPrefixes {
            prefixes: vec![
                AnnouncedPrefix {
                    prefix: Some("8.8.8.0/24".into()),
                },
                AnnouncedPrefix {
                    prefix: Some("  8.8.4.0/24 ".into()),
                },
                // Duplicate of the first (post-trim) — must collapse.
                AnnouncedPrefix {
                    prefix: Some("8.8.8.0/24".into()),
                },
                // Malformed / no mask — dropped, never a junk CIDR.
                AnnouncedPrefix {
                    prefix: Some("not-a-prefix".into()),
                },
                AnnouncedPrefix { prefix: None },
            ],
        };
        let es = build_announced_prefixes(&ap, "scan");
        let vals: Vec<&str> = es.iter().map(|e| e.value.as_str()).collect();
        // Deduped to two, in sorted (deterministic) order — not API order.
        assert_eq!(vals, ["8.8.4.0/24", "8.8.8.0/24"]);
        assert!(
            es.iter()
                .all(|e| e.kind == EntityKind::Cidr
                    && e.has_tag("ripestat")
                    && e.has_tag("network-prefix"))
        );
    }

    #[test]
    fn accepts_ip_and_asn_only() {
        assert!(RipeStat.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
        assert!(RipeStat.accepts(&Target::new(TargetKind::Asn, "AS15169")));
        assert!(!RipeStat.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    }

    #[test]
    fn module_metadata() {
        let m = RipeStat;
        assert_eq!(m.name(), "ripestat");
        assert!(!m.description().is_empty());
        assert_eq!(m.priority(), 107);
        assert_eq!(m.max_timeout_ms(), 14_000);
        assert!(!m.attack_techniques().is_empty());
        assert!(m.produces().contains(&EntityKind::Asn));
    }

    #[test]
    fn build_asns_rejects_non_numeric_and_empty() {
        let ni = NetworkInfo {
            asns: vec!["".into(), "not-a-number".into(), "abc123".into()],
            prefix: None,
        };
        assert!(build_asns(&ni, "scan").is_empty());
    }

    #[test]
    fn build_abuse_emits_multiple_distinct() {
        // Two different non-infrastructure contacts → both emitted.
        let emails = vec!["ops@example.org".to_string(), "sec@example.net".to_string()];
        let es = build_abuse(&emails, "scan");
        assert_eq!(es.len(), 2);
        assert!(es.iter().all(|e| e.kind == crate::core::entity::EntityKind::Email));
    }
