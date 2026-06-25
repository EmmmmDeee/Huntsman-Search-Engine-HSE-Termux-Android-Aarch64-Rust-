use super::*;

#[test]
fn classifies_known_australian_service() {
        let geo = classify_domain("commbank.com.au").unwrap();
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "known_service");
        assert!((geo.confidence - 0.60).abs() < 1e-9);
    }

    #[test]
    fn classifies_cctld_fallback() {
        let geo = classify_domain("example.com.au").unwrap();
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "cctld");
        assert!((geo.confidence - 0.45).abs() < 1e-9);
    }

    #[test]
    fn strips_www() {
        let geo = classify_by_known_service("www.chase.com").unwrap();
        assert_eq!(geo.country_code, "US");
    }

    #[test]
    fn unknown_domain_returns_none() {
        assert!(classify_domain("example.com").is_none());
    }

    #[test]
    fn german_tld() {
        let geo = classify_domain("sparkasse.de").unwrap();
        assert_eq!(geo.country_code, "DE");
        assert_eq!(geo.method, "known_service");
    }

    #[test]
    fn simple_cctld() {
        let geo = classify_domain("random-site.fr").unwrap();
        assert_eq!(geo.country_code, "FR");
        assert_eq!(geo.method, "cctld");
    }

    #[tokio::test]
    async fn module_accepts_domain_and_url() {
        let m = GeoDomainClassifier;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com.au")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com.au")));
        assert!(!m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
    }

    #[tokio::test]
    async fn module_produces_address_entity() {
        let m = GeoDomainClassifier;
        let target = Target::new(TargetKind::Domain, "seek.com.au");
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::Address);
        assert_eq!(r.entities[0].value, "Australia");
        assert!(r.entities[0].has_tag("domain-inferred"));
    }

    #[test]
    fn tables_are_well_formed_and_iso_consistent() {
        // Both lookups compare against a *lowercased* domain
        // (classify_by_known_service / classify_by_cctld), so any entry carrying
        // an uppercase letter can never match — it would be silently dead data,
        // the same failure mode that hid a mistyped OUI prefix. Guard the shape
        // of every entry, plus the invariant that one ISO code names exactly one
        // country across both tables (so "AU" can't drift to two spellings).
        fn two_upper(cc: &str) -> bool {
            cc.len() == 2 && cc.bytes().all(|b| b.is_ascii_uppercase())
        }
        let mut iso_name: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut check_iso = |cc: &'static str, name: &'static str| {
            assert!(
                two_upper(cc),
                "ISO code {cc:?} must be two uppercase ASCII letters"
            );
            if let Some(prev) = iso_name.insert(cc, name) {
                assert_eq!(
                    prev, name,
                    "ISO {cc} names two countries: {prev:?} vs {name:?}"
                );
            }
        };

        for &(pattern, location, cc) in GEO_SERVICES {
            assert_eq!(
                pattern,
                pattern.to_ascii_lowercase(),
                "GEO_SERVICES pattern {pattern:?} must be lowercase to match a lowercased domain"
            );
            assert!(
                pattern.contains('.') && !pattern.starts_with('.') && !pattern.ends_with('.'),
                "GEO_SERVICES pattern {pattern:?} must be a bare domain (interior dot, no leading/trailing dot)"
            );
            check_iso(cc, location);
        }
        for &(tld, location, cc) in CCTLD_MAP {
            assert_eq!(
                tld,
                tld.to_ascii_lowercase(),
                "CCTLD tld {tld:?} must be lowercase to match a lowercased domain"
            );
            assert!(
                tld.starts_with('.') && tld.len() >= 3,
                "CCTLD tld {tld:?} must start with '.' and be a real suffix"
            );
            check_iso(cc, location);
        }
    }

    #[test]
    fn classifies_au_state_government_domain_to_jurisdiction() {
        // A `*.{state}.gov.au` domain resolves to state grain (not just country).
        let geo = classify_domain("health.nsw.gov.au").unwrap();
        assert_eq!(geo.method, "au_gov_domain");
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.location, "New South Wales, Australia");
        assert_eq!(geo.au_state, Some("NSW"));

        // Case-insensitive, deeper subdomain.
        let vic = classify_domain("schools.education.VIC.gov.au").unwrap();
        assert_eq!(vic.au_state, Some("VIC"));
    }

    #[test]
    fn federal_gov_domain_falls_back_to_country_grain() {
        // `ato.gov.au` has no state label → not jurisdiction-precise; it still
        // classifies as Australia via the ccTLD, with no au_state.
        let geo = classify_domain("ato.gov.au").unwrap();
        assert_eq!(geo.au_state, None);
        assert_eq!(geo.country_code, "AU");
    }

    #[tokio::test]
    async fn gov_domain_emits_state_address_without_a_coordinate() {
        let m = GeoDomainClassifier;
        let target = Target::new(TargetKind::Domain, "transport.nsw.gov.au");
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        let ctx = ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
            proxy_pool: Default::default(),
        };
        let r = m.process(&target, &ctx).await.unwrap();
        // Exactly one Address (state grain), tagged with the jurisdiction; NO
        // Coordinates (a whole state must not pin a point).
        assert!(r.entities.iter().all(|e| e.kind == EntityKind::Address));
        let a = &r.entities[0];
        assert_eq!(a.value, "New South Wales, Australia");
        assert!(a.has_tag("au-state:NSW"));
        assert!(a.has_tag("gov-domain"));
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Coordinates));
    }
