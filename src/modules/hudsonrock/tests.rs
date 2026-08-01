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

    /// Fixed evaluation instant — 2026-06-15T00:00:00Z — so the *rolling*
    /// `[now - 90d, now]` freshness window is pinned. These assertions
    /// previously read the wall clock while pinning the fixture date, so they
    /// rotted: a record dated 2026-05-01 sat inside the window when written and
    /// aged out of it 92 days later, turning the suite red on unchanged code.
    const TEST_NOW: u64 = 1_781_481_600;

    /// `TEST_NOW - 90 * 86400` — exactly 2026-03-17T00:00:00Z, the oldest
    /// instant the window still admits (`ts >= cutoff` is inclusive).
    const WINDOW_EDGE: &str = "2026-03-17T00:00:00Z";

    fn stealer_dated(date: Option<&str>) -> Stealer {
        Stealer {
            computer_name: None,
            operating_system: None,
            date_compromised: date.map(Into::into),
            date_uploaded: None,
            stealer_family: None,
            ip: None,
            malware_path: None,
            credentials: vec![],
        }
    }

    #[test]
    fn fresh_compromise_gets_higher_confidence() {
        // TEST_NOW - 10 days.
        let recent = stealer_dated(Some("2026-06-05T00:00:00Z"));
        assert!((compute_confidence(&[recent], TEST_NOW) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn old_compromise_gets_base_confidence() {
        let old = stealer_dated(Some("2020-01-01T00:00:00Z"));
        assert!((compute_confidence(&[old], TEST_NOW) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn freshness_window_boundary_is_inclusive() {
        // Exactly on the cutoff → still fresh.
        let edge = stealer_dated(Some(WINDOW_EDGE));
        assert!(
            (compute_confidence(&[edge], TEST_NOW) - FRESH_CONFIDENCE).abs() < 1e-9,
            "a compromise exactly {FRESHNESS_WINDOW_DAYS} days old must stay inside the window"
        );
        // One day past it → base.
        let past_edge = stealer_dated(Some("2026-03-16T00:00:00Z"));
        assert!(
            (compute_confidence(&[past_edge], TEST_NOW) - BASE_CONFIDENCE).abs() < 1e-9,
            "one day older than the window must fall out of it"
        );
    }

    #[test]
    fn undated_compromise_is_never_treated_as_fresh() {
        // No date is an absence of evidence, not evidence of recency —
        // inventing freshness here would inflate confidence on every record
        // the provider returns without a `date_compromised`.
        let undated = stealer_dated(None);
        assert!((compute_confidence(&[undated], TEST_NOW) - BASE_CONFIDENCE).abs() < 1e-9);
        let unparseable = stealer_dated(Some("not-a-date"));
        assert!((compute_confidence(&[unparseable], TEST_NOW) - BASE_CONFIDENCE).abs() < 1e-9);
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
        // One old + one recent stealer → FRESH_CONFIDENCE (any-recent wins).
        let old = stealer_dated(Some("2020-01-01T00:00:00Z"));
        let recent = stealer_dated(Some("2026-06-05T00:00:00Z"));
        assert!((compute_confidence(&[old, recent], TEST_NOW) - FRESH_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn compute_confidence_empty_yields_base() {
        assert!((compute_confidence(&[], TEST_NOW) - BASE_CONFIDENCE).abs() < 1e-9);
    }

    #[test]
    fn victim_ips_only_admit_routable_public_addresses() {
        use crate::core::entity::EntityKind;
        use crate::core::tags;

        fn stealer_with_ip(ip: Option<&str>) -> Stealer {
            Stealer {
                computer_name: None,
                operating_system: None,
                date_compromised: None,
                date_uploaded: None,
                stealer_family: None,
                ip: ip.map(String::from),
                malware_path: None,
                credentials: vec![],
            }
        }

        let stealers = [
            stealer_with_ip(Some("8.8.8.8")),        // public v4 → kept
            stealer_with_ip(Some("10.0.0.5")),       // RFC1918 → dropped
            stealer_with_ip(Some("192.168.1.20")),   // RFC1918 → dropped
            stealer_with_ip(Some("127.0.0.1")),      // loopback → dropped
            stealer_with_ip(Some("100.64.1.1")),     // CGNAT → dropped
            stealer_with_ip(Some("unknown.host")),   // non-IP (has a dot) → dropped
            stealer_with_ip(Some("  1.1.1.1  ")),    // public, whitespace-wrapped → kept, trimmed
            stealer_with_ip(Some("8.8.8.8")),        // duplicate of the first → deduped
            stealer_with_ip(Some("2606:4700:4700::1111")), // public v6 → kept
            stealer_with_ip(Some("fd00::1")),        // ULA (private v6) → dropped
            stealer_with_ip(None),                   // absent → skipped
        ];

        let ips = victim_ip_entities(&stealers, "s");
        let values: Vec<&str> = ips.iter().map(|e| e.value.as_str()).collect();
        assert_eq!(
            values,
            vec!["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"],
            "only routable public IPs survive, trimmed and deduplicated"
        );
        // Every emitted IP is a geolocation lead — precisely why a private/reserved
        // address must never be admitted (it would fabricate a nowhere location).
        assert!(
            ips.iter().all(|e| e.kind == EntityKind::IpAddress
                && e.has_tag(tags::GEOLOCATION_LEAD)
                && e.has_tag(tags::STEALER_LOG)),
            "each victim IP is a stealer-log geolocation lead"
        );
    }

    // ── URL-encoding / @ preservation ────────────────────────────────────────

    #[test]
    fn search_by_login_uses_the_email_query_parameter() {
        // Regression for the upstream API drift live testing caught: Cavalier's
        // search-by-login is keyed by `email=`, not `username=` (a `username=`
        // request 400s with "Email is required", silently breaking every lookup).
        let url = super::search_by_login_url("dns@cloudflare.com");
        assert!(
            url.contains("search-by-login?email="),
            "login lookup must use the `email` query parameter, got: {url}"
        );
        assert!(
            !url.contains("username="),
            "the stale `username` parameter must not reappear: {url}"
        );
        // Standard form-encoding is fine on the `email=` endpoint (`@`→`%40`).
        assert!(url.contains("dns%40cloudflare.com"), "url: {url}");
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
