use super::*;

    fn entry(json: &str) -> DomainEntry {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn accepts_domain_org_name() {
        let m = DomainsDb;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme")));
        assert!(m.accepts(&Target::new(TargetKind::FullName, "John Doe")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn cost_is_keygated() {
        // Key-gated since the provider disabled anonymous access (2026). A
        // `Free` classification here silently swallowed every 401 and returned
        // nothing; KeyGated makes the "needs key" state honest and lets
        // `--free-only` skip it cleanly.
        assert!(matches!(
            DomainsDb.cost(),
            crate::core::module::ModuleCost::KeyGated
        ));
    }

    #[tokio::test]
    async fn missing_key_yields_a_clean_needs_key_skip_not_a_silent_empty() {
        // Regression: with anonymous access disabled upstream, an unconfigured
        // domainsdb must surface `Error::MissingKey` (→ dispatch renders a
        // "needs API key" skip with the signup hint), NOT `Ok(empty)` — which
        // is what the pre-fix Free module produced on every scan once its 401s
        // began, hiding the dead source from the operator entirely.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };
        let err = DomainsDb
            .process(&Target::new(TargetKind::Domain, "example.com"), &ctx)
            .await
            .expect_err("an unconfigured key must be a MissingKey skip, not a silent empty result");
        assert!(
            matches!(err, crate::core::error::Error::MissingKey(ref k) if k == KEY_ENV),
            "must name the domainsdb key env so the operator sees the signup hint: {err:?}"
        );
    }

    #[test]
    fn deser() {
        let j = r#"{"domains":[{"domain":"example.com","create_date":"2020-01-01","isDead":"False"}],"total":1}"#;
        let r: DbResp = serde_json::from_str(j).unwrap();
        assert_eq!(r.domains.len(), 1);
        assert_eq!(r.total, Some(1));
    }

    #[test]
    fn live_domain_surfaces_created_and_updated() {
        let e = build_domain_entity(
            &entry(
                r#"{"domain":"acme-corp.com","create_date":"2019-03-01",
                    "update_date":"2024-06-15","country":"US","isDead":"False"}"#,
            ),
            false,
            "s",
        )
        .unwrap();
        assert_eq!(e.kind, EntityKind::Domain);
        assert!(e.has_tag("domainsdb") && !e.has_tag("dead-domain") && !e.has_tag("broad-match"));
        assert!((e.confidence - 0.55).abs() < 1e-9);
        let ev = &e.evidence[0];
        assert_eq!(
            ev.attributes.get("created").map(String::as_str),
            Some("2019-03-01")
        );
        // `updated` — the field the struct-level allow used to bury.
        assert_eq!(
            ev.attributes.get("updated").map(String::as_str),
            Some("2024-06-15")
        );
        assert_eq!(ev.attributes.get("country").map(String::as_str), Some("US"));
    }

    #[test]
    fn dead_domain_is_tagged_and_lower_confidence() {
        let e = build_domain_entity(
            &entry(r#"{"domain":"gone.com","isDead":"True"}"#),
            false,
            "s",
        )
        .unwrap();
        assert!(e.has_tag("dead-domain"));
        assert!((e.confidence - 0.35).abs() < 1e-9);
    }

    #[test]
    fn broad_match_dampens_and_tags() {
        // A generic keyword (high `total`) → broad-match: tagged + 0.7× damped.
        let e = build_domain_entity(&entry(r#"{"domain":"john-smith.com"}"#), true, "s").unwrap();
        assert!(e.has_tag("broad-match"));
        assert!((e.confidence - 0.55 * 0.7).abs() < 1e-9);
        // Dead + broad stacks both penalties.
        let dead = build_domain_entity(&entry(r#"{"domain":"x.com","isDead":"True"}"#), true, "s")
            .unwrap();
        assert!((dead.confidence - 0.35 * 0.7).abs() < 1e-9);
    }

    #[test]
    fn blank_domain_is_skipped() {
        assert!(build_domain_entity(&entry(r#"{"domain":"  "}"#), false, "s").is_none());
    }
