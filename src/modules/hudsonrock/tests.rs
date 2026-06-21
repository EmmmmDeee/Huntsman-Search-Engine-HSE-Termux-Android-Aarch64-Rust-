use super::*;

    #[test]
    fn accepts_only_email_and_domain() {
        let m = HudsonRock;
        assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "b.com")));
        // Usernames are NEVER routed here — search-by-login 400s ("Email is
        // required") on a bare handle (seen live on the `javery88` scan), and
        // the engine surfaces real emails as Email targets. Reject both a bare
        // handle AND an email-shaped one so `accepts()` stays value-independent
        // (the property the two registry-dispatch invariants rely on).
        assert!(!m.accepts(&Target::new(TargetKind::Username, "javery88")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "javery88@gmail.com")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[tokio::test]
    async fn username_target_yields_nothing_without_a_request() {
        // A Username never reaches process() via the engine (accepts() rejects
        // it); a direct call still falls through to empty — no doomed 400.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };
        let r = HudsonRock
            .process(&Target::new(TargetKind::Username, "javery88"), &ctx)
            .await
            .unwrap();
        assert!(
            r.is_empty(),
            "username must not call the email-only endpoint"
        );
    }

    #[tokio::test]
    async fn android_app_package_domain_yields_nothing_without_a_request() {
        // A reverse-DNS app package (`com.facebook.katana`) can reach process()
        // by recall of a Domain minted before the upstream gate. search-by-domain
        // for it would return strangers' stealer records — short-circuit to empty.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };
        let r = HudsonRock
            .process(
                &Target::new(TargetKind::Domain, "com.facebook.katana"),
                &ctx,
            )
            .await
            .unwrap();
        assert!(
            r.is_empty(),
            "an app package must not trigger a search-by-domain call"
        );
    }

    #[test]
    fn fresh_compromise_gets_higher_confidence() {
        let recent = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2026-05-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: Some("Lumma".into()),
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        assert!((compute_confidence(&[recent]) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn old_compromise_gets_base_confidence() {
        let old = Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some("2020-01-01T00:00:00Z".into()),
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        assert!((compute_confidence(&[old]) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn parse_iso_epoch_works() {
        assert!(parse_iso_epoch("2025-06-15T12:00:00Z").is_some());
        assert!(parse_iso_epoch("2025-06-15").is_some());
        assert!(parse_iso_epoch("garbage").is_none());
        assert!(parse_iso_epoch("").is_none());
    }

    #[test]
    fn module_metadata_full() {
        let m = HudsonRock;
        assert_eq!(m.name(), "hudsonrock");
        assert!(!m.description().is_empty());
        assert_eq!(m.priority(), 130);
        assert_eq!(m.max_timeout_ms(), 10_000);
        assert_eq!(m.category(), ModuleCategory::Breach);
        assert!(m.attack_techniques().contains(&"T1589.001"));
        assert!(m.attack_techniques().contains(&"T1590.005"));
        use crate::core::entity::EntityKind;
        assert!(m.produces().contains(&EntityKind::IpAddress));
    }

    #[test]
    fn compute_confidence_mixed_stealers_yields_fresh() {
        // One old + one recent stealer → FRESH_CONFIDENCE (any-recent wins)
        let old = Stealer {
            date_compromised: Some("2020-01-01T00:00:00Z".into()),
            stealer_family: None,
            computer_name: None,
            operating_system: None,
            date_uploaded: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        let recent = Stealer {
            date_compromised: Some("2026-05-01T00:00:00Z".into()),
            stealer_family: None,
            computer_name: None,
            operating_system: None,
            date_uploaded: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        };
        assert!((compute_confidence(&[old, recent]) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn compute_confidence_empty_yields_base() {
        assert!((compute_confidence(&[]) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    // ── URL-encoding / @ preservation ────────────────────────────────────────

    #[test]
    fn at_sign_preserved_in_encoded_url() {
        // urlencode() uses form_urlencoded which encodes '@' as '%40'.
        // HudsonRock's search-by-login validates '@' presence in the raw query
        // string BEFORE URL-decoding, so '%40' triggers "Email is required".
        // The fix reverses the substitution: replace("%40", "@").
        let encoded = crate::util::http::urlencode("dns@cloudflare.com").replace("%40", "@");
        assert!(
            encoded.contains('@'),
            "encoded URL must preserve the literal '@': {encoded}"
        );
        assert!(
            !encoded.contains("%40"),
            "encoded URL must not contain '%40': {encoded}"
        );
    }

    #[tokio::test]
    async fn email_without_at_sign_yields_empty_result() {
        // The defensive guard added to the Email arm exits early for any value
        // that lacks '@', preventing the doomed HTTP 400.
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "t".into(),
            bus,
            http: crate::util::http::build_client(),
            keys: std::collections::HashMap::new(),
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };
        let r = HudsonRock
            .process(&Target::new(TargetKind::Email, "notanemail"), &ctx)
            .await
            .unwrap();
        assert!(
            r.is_empty(),
            "email without '@' must not fire the HTTP request"
        );
    }
