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
    async fn module_accepts_domain_url_and_email() {
        let m = GeoDomainClassifier;
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com.au")));
        assert!(m.accepts(&Target::new(TargetKind::Url, "https://example.com.au")));
        // Email is now accepted — its domain geolocates the person when it is an
        // education / government institution (gated inside `process`).
        assert!(m.accepts(&Target::new(TargetKind::Email, "test@example.com")));
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
        };
        let r = m.process(&target, &ctx).await.unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::Address);
        assert_eq!(r.entities[0].value, "Australia");
        assert!(r.entities[0].has_tag("domain-inferred"));
    }

    #[cfg(test)]
    fn test_ctx() -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(8);
        ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys: Default::default(),
            cancel: Default::default(),
        }
    }

    #[tokio::test]
    async fn university_email_geolocates_person_to_city() {
        // A `@uni.edu.au` address places the person in that university's city —
        // finer than the bare `.edu.au` country/state grain.
        let m = GeoDomainClassifier;
        let r = m
            .process(&Target::new(TargetKind::Email, "j.citizen@uq.edu.au"), &test_ctx())
            .await
            .unwrap();
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("an institutional email yields a location");
        assert_eq!(addr.value, "Brisbane, Australia");
        assert!(addr.has_tag("email-affiliation"), "tagged as an email-derived affiliation");
        assert!(addr.has_tag("geoint"));
    }

    #[tokio::test]
    async fn state_gov_email_geolocates_to_jurisdiction() {
        // A `@*.{state}.gov.au` address pins the public servant's state.
        let m = GeoDomainClassifier;
        let r = m
            .process(
                &Target::new(TargetKind::Email, "officer@health.nsw.gov.au"),
                &test_ctx(),
            )
            .await
            .unwrap();
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("a state-gov email yields a jurisdiction");
        assert_eq!(addr.value, "New South Wales, Australia");
        assert!(addr.has_tag("au-state:NSW"));
        assert!(addr.has_tag("email-affiliation"));
    }

    #[tokio::test]
    async fn freemail_corporate_and_federal_emails_yield_no_geo() {
        // Only an EDUCATION / GOVERNMENT institution domain locates the person.
        // Freemail, generic corporate, a country-grain AU service, and a
        // non-state federal agency all yield nothing rather than a misleading fix.
        let m = GeoDomainClassifier;
        for addr in [
            "person@gmail.com",        // freemail
            "person@randomcorp.com",   // generic corporate
            "person@telstra.com.au",   // AU service, but country-grain only
            "person@ato.gov.au",       // federal (no state) → not pinpointable
        ] {
            let r = m
                .process(&Target::new(TargetKind::Email, addr), &test_ctx())
                .await
                .unwrap();
            assert!(
                r.entities.is_empty(),
                "{addr} must not produce a location"
            );
        }
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
        let mut check_iso = |cc: &'static str, location: &'static str| {
            assert!(
                two_upper(cc),
                "ISO code {cc:?} must be two uppercase ASCII letters"
            );
            // A location is country-grain ("Australia") or city-grain ("Brisbane,
            // Australia"); the invariant is that one ISO code names exactly one
            // COUNTRY (the trailing comma segment), so "AU" can't drift across
            // spellings while still allowing finer city locations.
            let country = location.rsplit(',').next().unwrap_or(location).trim();
            if let Some(prev) = iso_name.insert(cc, country) {
                assert_eq!(
                    prev, country,
                    "ISO {cc} names two countries: {prev:?} vs {country:?}"
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

    #[test]
    fn classifies_au_university_to_its_city() {
        // A university domain resolves to its home CITY (finer than the .edu.au
        // country fallback), via the known-service table — matched as a subdomain.
        let uq = classify_domain("student.uq.edu.au").unwrap();
        assert_eq!(uq.country_code, "AU");
        assert_eq!(uq.location, "Brisbane, Australia");
        assert_eq!(uq.au_state, None); // city grain, not a whole-state jurisdiction

        assert_eq!(classify_domain("unimelb.edu.au").unwrap().location, "Melbourne, Australia");
        assert_eq!(classify_domain("anu.edu.au").unwrap().location, "Canberra, Australia");
        assert_eq!(classify_domain("monash.edu").unwrap().location, "Melbourne, Australia");
    }

    #[test]
    fn classifies_au_state_education_domain_to_jurisdiction() {
        // A state school-system domain resolves to state grain (au_state set).
        let nsw = classify_domain("schools.nsw.edu.au").unwrap();
        assert_eq!(nsw.method, "au_gov_domain");
        assert_eq!(nsw.au_state, Some("NSW"));
        assert_eq!(nsw.location, "New South Wales, Australia");
        // Education Queensland.
        assert_eq!(classify_domain("eq.edu.au").unwrap().au_state, Some("QLD"));
    }

    #[test]
    fn id_au_and_asn_au_now_classify_as_australia() {
        // Previously these AU 2LDs fell through to no classification.
        let id = classify_domain("haigen.id.au").unwrap();
        assert_eq!(id.country_code, "AU");
        assert_eq!(id.location, "Australia");
        let asn = classify_domain("surfclub.asn.au").unwrap();
        assert_eq!(asn.country_code, "AU");
    }

    #[tokio::test]
    async fn individual_id_au_domain_is_tagged_people_centric() {
        // A `.id.au` domain is a natural-person Australian registrant — the
        // emitted location must carry the people-centric registrant tag.
        let m = GeoDomainClassifier;
        let r = m
            .process(&Target::new(TargetKind::Domain, "haigen.id.au"), &test_ctx())
            .await
            .unwrap();
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("a .id.au domain yields an AU location");
        assert!(addr.has_tag("au-registrant:individual"));
        assert!(addr.has_tag("au-relevant"));
        assert!(
            addr.evidence
                .iter()
                .any(|ev| ev.attributes.get("au_registrant").map(String::as_str) == Some("individual"))
        );
    }

    #[tokio::test]
    async fn commercial_com_au_domain_is_tagged_commercial() {
        let m = GeoDomainClassifier;
        let r = m
            .process(&Target::new(TargetKind::Domain, "acme-widgets.com.au"), &test_ctx())
            .await
            .unwrap();
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect(".com.au yields an AU location");
        assert!(addr.has_tag("au-registrant:commercial"));
        assert!(addr.has_tag("au-relevant"));
    }
