use crate::core::confidence;
use super::*;

#[test]
fn classifies_known_australian_service() {
        let geo = classify_domain("commbank.com.au").expect("should succeed");
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "known_service");
        assert!((geo.confidence - confidence::MEDIUM_PLUS).abs() < 1e-9);
    }

    #[test]
    fn classifies_cctld_fallback() {
        let geo = classify_domain("example.com.au").expect("should succeed");
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "cctld");
        assert!((geo.confidence - confidence::LOW_MEDIUM).abs() < 1e-9);
    }

    #[test]
    fn classifies_au_state_gov_domain() {
        // Regression: this classifier's confidence was a bare 0.62 (exact
        // match for confidence::NOTABLE) assigned via a struct-literal field
        // rather than the module's own named constants its two sibling
        // classifiers use — and had no confidence assertion at all until now.
        let geo =
            classify_au_jurisdiction_domain("health.nsw.gov.au").expect("should succeed");
        assert_eq!(geo.location, "New South Wales, Australia");
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.method, "au_gov_domain");
        assert_eq!(geo.au_state, Some("NSW"));
        assert!((geo.confidence - confidence::NOTABLE).abs() < 1e-9);
    }

    #[test]
    fn strips_www() {
        let geo = classify_by_known_service("www.chase.com").expect("should succeed");
        assert_eq!(geo.country_code, "US");
    }

    #[test]
    fn unknown_domain_returns_none() {
        assert!(classify_domain("example.com").is_none());
    }

    #[test]
    fn german_tld() {
        let geo = classify_domain("sparkasse.de").expect("should succeed");
        assert_eq!(geo.country_code, "DE");
        assert_eq!(geo.method, "known_service");
    }

    #[test]
    fn simple_cctld() {
        let geo = classify_domain("random-site.fr").expect("should succeed");
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
        let r = m.process(&target, &ctx).await.expect("should succeed");
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
            .expect("should succeed");
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
            .expect("should succeed");
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
                .expect("should succeed");
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
        let geo = classify_domain("health.nsw.gov.au").expect("should succeed");
        assert_eq!(geo.method, "au_gov_domain");
        assert_eq!(geo.country_code, "AU");
        assert_eq!(geo.location, "New South Wales, Australia");
        assert_eq!(geo.au_state, Some("NSW"));

        // Case-insensitive, deeper subdomain.
        let vic = classify_domain("schools.education.VIC.gov.au").expect("should succeed");
        assert_eq!(vic.au_state, Some("VIC"));
    }

    #[test]
    fn federal_gov_domain_falls_back_to_country_grain() {
        // `ato.gov.au` has no state label → not jurisdiction-precise; it still
        // classifies as Australia via the ccTLD, with no au_state.
        let geo = classify_domain("ato.gov.au").expect("should succeed");
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
        let r = m.process(&target, &ctx).await.expect("should succeed");
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
        let uq = classify_domain("student.uq.edu.au").expect("should succeed");
        assert_eq!(uq.country_code, "AU");
        assert_eq!(uq.location, "Brisbane, Australia");
        assert_eq!(uq.au_state, None); // city grain, not a whole-state jurisdiction

        assert_eq!(classify_domain("unimelb.edu.au").expect("should succeed").location, "Melbourne, Australia");
        assert_eq!(classify_domain("anu.edu.au").expect("should succeed").location, "Canberra, Australia");
        assert_eq!(classify_domain("monash.edu").expect("should succeed").location, "Melbourne, Australia");
    }

    #[test]
    fn classifies_au_state_education_domain_to_jurisdiction() {
        // A state school-system domain resolves to state grain (au_state set).
        let nsw = classify_domain("schools.nsw.edu.au").expect("should succeed");
        assert_eq!(nsw.method, "au_gov_domain");
        assert_eq!(nsw.au_state, Some("NSW"));
        assert_eq!(nsw.location, "New South Wales, Australia");
        // Education Queensland.
        assert_eq!(classify_domain("eq.edu.au").expect("should succeed").au_state, Some("QLD"));
    }

    #[test]
    fn id_au_and_asn_au_now_classify_as_australia() {
        // Previously these AU 2LDs fell through to no classification.
        let id = classify_domain("haigen.id.au").expect("should succeed");
        assert_eq!(id.country_code, "AU");
        assert_eq!(id.location, "Australia");
        let asn = classify_domain("surfclub.asn.au").expect("should succeed");
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
            .expect("should succeed");
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
            .expect("should succeed");
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect(".com.au yields an AU location");
        assert!(addr.has_tag("au-registrant:commercial"));
        assert!(addr.has_tag("au-relevant"));
    }

    #[test]
    fn vietnamese_second_level_domains_now_classify_as_vietnam() {
        // Regression: before the VNNIC namespace was tabulated, only `.com.vn`
        // classified — every other real `.vn` 2LD (`gov`/`edu`/`ac`/`org`/`net`/
        // `biz`/`name`) and a directly-registered `.vn` fell through to NO
        // classification, so a Vietnamese government or university domain produced
        // no jurisdiction signal at all. All now resolve to Vietnam at ccTLD grain.
        for domain in [
            "mps.gov.vn",
            "vnu.edu.vn",
            "vast.ac.vn",
            "redcross.org.vn",
            "isp.net.vn",
            "shop.biz.vn",
            "nguyen-van-a.name.vn",
            "chinhphu.vn",   // directly-registered under the bare ccTLD
            "example.com.vn",
        ] {
            let geo = classify_domain(domain)
                .unwrap_or_else(|| panic!("{domain} must classify as Vietnam"));
            assert_eq!(geo.country_code, "VN", "{domain}");
            assert_eq!(geo.location, "Vietnam", "{domain}");
            assert_eq!(geo.method, "cctld", "{domain}");
            assert_eq!(geo.au_state, None, "{domain} is not an AU jurisdiction");
        }
    }

    #[tokio::test]
    async fn vn_government_domain_emits_tagged_vietnam_address_without_a_coordinate() {
        // A `.gov.vn` domain yields exactly one Vietnam Address carrying the
        // VN-jurisdiction + registrant tags — and NO Coordinates, because the
        // country-grain "Vietnam" is not a geocodable city (no fabricated point).
        let m = GeoDomainClassifier;
        let r = m
            .process(&Target::new(TargetKind::Domain, "mps.gov.vn"), &test_ctx())
            .await
            .expect("should succeed");
        assert!(
            r.entities.iter().all(|e| e.kind == EntityKind::Address),
            "no Coordinates entity for a country-grain location"
        );
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("a .gov.vn domain yields a VN location");
        assert_eq!(addr.value, "Vietnam");
        assert!(addr.has_tag("domain-inferred"));
        assert!(addr.has_tag("vn-registrant:government"));
        assert!(addr.has_tag("vn-relevant"));
        assert!(
            addr.evidence
                .iter()
                .any(|ev| ev.attributes.get("vn_registrant").map(String::as_str)
                    == Some("government")),
            "the registrant category is recorded as evidence"
        );
        assert!(!r.entities.iter().any(|e| e.kind == EntityKind::Coordinates));
    }

    #[tokio::test]
    async fn individual_name_vn_domain_is_tagged_people_centric() {
        // A `.name.vn` domain is a natural-person Vietnamese registrant — the VN
        // analogue of `.id.au` — so the emitted location carries the individual
        // registrant tag.
        let m = GeoDomainClassifier;
        let r = m
            .process(
                &Target::new(TargetKind::Domain, "nguyen-van-a.name.vn"),
                &test_ctx(),
            )
            .await
            .expect("should succeed");
        let addr = r
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Address)
            .expect("a .name.vn domain yields a VN location");
        assert!(addr.has_tag("vn-registrant:individual"));
        assert!(addr.has_tag("vn-relevant"));
    }

// ── REQ-GEODOMAIN-001: the Email affiliation path beyond Australia ──────────

/// A context for the no-network path. This module makes zero network calls, so
/// the client is never used.
fn geo_ctx() -> crate::core::module::ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    crate::core::module::ModuleContext {
        scan_id: "geo-vn".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::new(),
        cancel: crate::core::cancel::CancelHandle::new(),
    }
}

async fn classify_email(value: &str) -> Vec<(EntityKind, String, Vec<String>)> {
    GeoDomainClassifier
        .process(&Target::new(TargetKind::Email, value), &geo_ctx())
        .await
        .expect("this module makes no network calls")
        .entities
        .into_iter()
        .map(|e| (e.kind, e.value, e.tags.clone()))
        .collect()
}

/// CLAUDE.md names `.vn` a first-class jurisdiction *via this module and
/// `util::domain_vn`*. Measured before the fix, every one of these yielded
/// nothing: the Email path ran only the two AU-heavy classifiers, so the
/// `.vn` registrant tagging — which lives inside `if let Some(geo)` — was
/// unreachable because no classification was ever produced to tag.
#[tokio::test]
async fn a_vietnamese_institutional_email_places_its_holder_in_vietnam() {
    for addr in [
        "someone@hcmus.edu.vn",
        "someone@vnu.edu.vn",
        "someone@mof.gov.vn",
    ] {
        let out = classify_email(addr).await;
        let addr_ent = out
            .iter()
            .find(|(k, _, _)| *k == EntityKind::Address)
            .unwrap_or_else(|| panic!("{addr} must place its holder somewhere"));
        assert_eq!(addr_ent.1, "Vietnam", "{addr}");
        assert!(
            addr_ent.2.iter().any(|t| t == "email-affiliation"),
            "{addr} must be marked the affiliation signal it is: {:?}",
            addr_ent.2
        );
        assert!(
            addr_ent.2.iter().any(|t| t.starts_with("vn-registrant:")),
            "{addr} must carry the VNNIC registrant type — the tagging that was \
             unreachable on this path: {:?}",
            addr_ent.2
        );
    }
}

/// The gap was never VN-specific: the Email path had no classifier for ANY
/// institution outside the AU tables.
#[tokio::test]
async fn a_non_australian_academic_email_is_no_longer_silent() {
    let out = classify_email("someone@ox.ac.uk").await;
    assert_eq!(
        out.iter()
            .find(|(k, _, _)| *k == EntityKind::Address)
            .map(|(_, v, _)| v.as_str()),
        Some("United Kingdom"),
    );
}

/// A country is not a point. The ccTLD grain must not mint a Coordinates
/// entity — that would be the precision overstatement this module's own
/// `au_state` guard already refuses for whole-state classifications.
#[tokio::test]
async fn the_country_grain_never_mints_a_coordinate() {
    for addr in ["someone@hcmus.edu.vn", "someone@ox.ac.uk"] {
        let out = classify_email(addr).await;
        assert!(
            !out.iter().any(|(k, _, _)| *k == EntityKind::Coordinates),
            "{addr} resolved only to a country and must not carry a point: {out:?}"
        );
    }
}

/// Control — passes before the fix too. The institutional gate still excludes
/// freemail and generic corporate addresses, which is what makes admitting the
/// ccTLD grain safe here at all.
#[tokio::test]
async fn a_freemail_or_generic_corporate_email_still_yields_nothing() {
    for addr in ["someone@gmail.com", "someone@acme-corp.com.vn"] {
        assert!(
            classify_email(addr).await.is_empty(),
            "{addr} is not an institutional affiliation"
        );
    }
}

/// Control — passes before the fix too. The precise AU paths still win ahead of
/// the ccTLD fallback, and the country-grain "Australia" is still dropped.
#[tokio::test]
async fn the_precise_australian_paths_are_unchanged() {
    let out = classify_email("someone@unimelb.edu.au").await;
    assert_eq!(
        out.iter()
            .find(|(k, _, _)| *k == EntityKind::Address)
            .map(|(_, v, _)| v.as_str()),
        Some("Melbourne, Australia"),
        "the known-service city must still beat the ccTLD country"
    );
    assert!(
        !classify_email("someone@not-a-listed-uni.edu.au")
            .await
            .iter()
            .any(|(_, v, _)| v == "Australia"),
        "an AU scan already assumes Australia; the country grain adds nothing"
    );
}
