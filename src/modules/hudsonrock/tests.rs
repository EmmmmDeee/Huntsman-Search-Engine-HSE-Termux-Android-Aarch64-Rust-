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

    /// A `Stealer` with only `date_compromised` set — the sole field the
    /// freshness scorer reads.
    fn dated(date_compromised: &str) -> Stealer {
        Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: Some(date_compromised.into()),
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        }
    }

    #[test]
    fn fresh_compromise_gets_higher_confidence() {
        // Time is injected, not read from the wall clock: a compromise 30 days
        // before `now` is inside the 90-day window and scores FRESH. Because
        // `now` is fixed relative to the fixture, this can never rot.
        let recent = dated("2026-05-01T00:00:00Z");
        let now = parse_iso_epoch("2026-05-31T00:00:00Z").unwrap();
        assert!((compute_confidence_at(&[recent], now) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn old_compromise_gets_base_confidence() {
        // 2.5 years before `now` — far outside the window → BASE.
        let old = dated("2020-01-01T00:00:00Z");
        let now = parse_iso_epoch("2022-08-01T00:00:00Z").unwrap();
        assert!((compute_confidence_at(&[old], now) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn freshness_boundary_is_the_90_day_window() {
        // Regression proof for the injected-time boundary: with the compromise
        // fixed, a `now` 89 days later is still inside the 90-day window (FRESH),
        // and 91 days later is outside it (BASE). Deterministic — cannot rot.
        let comp_ts = parse_iso_epoch("2026-05-01T00:00:00Z").unwrap();
        let day = 86_400u64;
        assert!(
            (compute_confidence_at(&[dated("2026-05-01T00:00:00Z")], comp_ts + 89 * day)
                - FRESH_CONFIDENCE)
                .abs()
                < 1e-9
        );
        assert!(
            (compute_confidence_at(&[dated("2026-05-01T00:00:00Z")], comp_ts + 91 * day)
                - BASE_CONFIDENCE)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn parse_iso_epoch_works() {
        assert!(parse_iso_epoch("2025-06-15T12:00:00Z").is_some());
        assert!(parse_iso_epoch("2025-06-15").is_some());
        assert!(parse_iso_epoch("garbage").is_none());
        assert!(parse_iso_epoch("").is_none());
    }
