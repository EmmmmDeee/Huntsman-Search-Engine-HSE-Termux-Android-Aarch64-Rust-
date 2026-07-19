use super::{
    Seon,
    entity_builders::{build_email_entities, build_phone_entities},
    types::{SeonEmailResp, SeonPhoneResp},
};
use crate::core::{
    entity::EntityKind,
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_email_and_phone() {
    let m = Seon;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+1234")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(Seon.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    assert_eq!(Seon.name(), "seon");
    assert_eq!(Seon.priority(), 95);
    assert_eq!(Seon.max_timeout_ms(), 8_000);
    assert!(!Seon.description().is_empty());
    // The email path's registrant extraction and the phone path's
    // carrier/CNAM pivots genuinely produce these. `Url` is NOT declared:
    // the pre-fix phone path's `profile_url_entity` call (the only site that
    // ever constructed one) is gone now that both paths are rewritten
    // against their real schemas.
    for kind in [
        EntityKind::Person,
        EntityKind::Organisation,
        EntityKind::Address,
        EntityKind::Domain,
    ] {
        assert!(Seon.produces().contains(&kind), "missing {kind:?}");
    }
    assert!(
        !Seon.produces().contains(&EntityKind::Url),
        "no code in this module constructs a Url entity any more"
    );
}

#[test]
fn attack_techniques_drop_social_media_and_identify_roles() {
    use crate::core::attack;
    let t = Seon.attack_techniques();
    // T1593.001 (Social Media) and T1591.004 (Identify Roles) were both
    // never-actually-earned claims — see mod.rs's doc comment — and must
    // not survive the fix.
    assert!(
        !t.contains(&"T1593.001"),
        "no per-platform data exists anymore"
    );
    assert!(!t.contains(&"T1591.004"), "no role/job-title field exists");
    for id in ["T1589", "T1589.002", "T1589.003", "T1591.001", "T1591.002"] {
        assert!(t.contains(&id), "seon must claim {id}, got {t:?}");
        assert!(attack::technique(id).is_some(), "{id} must be catalogued");
    }
}

/// A real `email-api/v3` response shape (field names/nesting verified
/// against SEON's own current API reference, 2026-07) — the schema this
/// module's response types must match. Values are synthetic.
const REAL_EMAIL_RESPONSE: &str = r#"{
    "success": true,
    "data": {
        "risk_scores": {"global_network_score": 11.26},
        "email_details": {
            "deliverable": true,
            "minimum_age_months": 24,
            "earliest_profile_date": "2024-01-01 00:00:00"
        },
        "email_domain_details": {
            "domain": "example.com",
            "registered": true,
            "disposable": false,
            "free": false,
            "custom": true,
            "registrar_name": "NameCheap, Inc.",
            "created": "2015-03-20 12:42:37"
        },
        "account_aggregates": {
            "total_registration": 39,
            "business": {
                "total_registration": 14,
                "technology": {"registered": 11, "checked": 34}
            },
            "personal": {
                "total_registration": 25,
                "social_media": {"registered": 8, "checked": 21},
                "dating": {"registered": 2, "checked": 6},
                "technology": {"registered": 2, "checked": 7}
            }
        },
        "seon_fraud_history": {
            "hits": 9,
            "customer_hits": 4,
            "fraudulent_decline_hits": 2,
            "first_seen": 1584887689,
            "last_seen": 1713949826
        },
        "breach_details": {
            "breaches": [
                {"date": "2018-07-23", "domain": "apollo.io", "name": "Apollo"},
                {"date": "2019-05-24", "domain": "canva.com", "name": "Canva"}
            ],
            "number_of_breaches": 2,
            "haveibeenpwned_listed": true
        },
        "associated_domain_registrations": {
            "domains": [{
                "domain_name": "thisisasampledomain.com",
                "full_name": "Jordan Avery",
                "company_name": "JD Enterprises Ltd",
                "mailing_address": "472, Doejohn Street",
                "city_name": "JD City",
                "state_name": "QLD",
                "zip_code": "4000",
                "country_code": "AU",
                "phone_number": "+61400000000"
            }]
        }
    }
}"#;

#[test]
fn parse_email_response_matches_the_real_v3_schema() {
    // Red/green anchor for the whole fix: this MUST deserialize into real
    // (non-None) values, unlike the pre-fix structs which silently matched
    // nothing in this shape.
    let r: SeonEmailResp = serde_json::from_str(REAL_EMAIL_RESPONSE).unwrap();
    assert_eq!(r.success, Some(true));
    let data = r.data.unwrap();
    assert!((data.risk_scores.unwrap().global_network_score.unwrap() - 11.26).abs() < 0.01);
    assert_eq!(data.email_domain_details.unwrap().disposable, Some(false));
    assert_eq!(
        data.breach_details.unwrap().breaches.len(),
        2,
        "breach_details.breaches must deserialize — it didn't exist in the pre-fix struct at all"
    );
    assert_eq!(
        data.associated_domain_registrations.unwrap().domains.len(),
        1,
        "associated_domain_registrations must deserialize — genuinely new signal this fix recovers"
    );
}

// ── Core: email entity building against the real schema ─────────────
fn email(json: &str) -> Vec<crate::core::entity::Entity> {
    let r: SeonEmailResp = serde_json::from_str(json).unwrap();
    build_email_entities(
        &Target::new(TargetKind::Email, "jane@acme.com"),
        &r.data.unwrap(),
        "s",
    )
}

#[test]
fn email_entity_carries_fraud_domain_and_breach_evidence() {
    let es = email(REAL_EMAIL_RESPONSE);
    let email_e = &es[0];
    assert_eq!(email_e.kind, EntityKind::Email);
    assert!(email_e.has_tag("custom-domain"));
    assert!(email_e.has_tag("fraud-history"));
    assert!(email_e.has_tag("fraudulent-decline-history"));
    assert!(email_e.has_tag(crate::core::tags::BREACH));
    let ev = &email_e.evidence[0];
    assert_eq!(
        ev.attributes.get("fraud_score").map(String::as_str),
        Some("11.3")
    );
    assert_eq!(
        ev.attributes.get("domain_registrar").map(String::as_str),
        Some("NameCheap, Inc.")
    );
    assert_eq!(
        ev.attributes
            .get("platform_registrations")
            .map(String::as_str),
        Some("39")
    );
    assert_eq!(
        ev.attributes
            .get("business_platform_registrations")
            .map(String::as_str),
        Some("14")
    );
    // Deterministic (sorted), and — the real collision case SEON's own
    // example data exhibits — "technology" appears in BOTH business (11/34)
    // and personal (2/7) with DIFFERENT counts, and both must survive
    // distinctly rather than one silently overwriting the other.
    assert_eq!(
        ev.attributes.get("platform_categories").map(String::as_str),
        Some(
            "dating[personal]:2/6, social_media[personal]:8/21, \
             technology[business]:11/34, technology[personal]:2/7"
        )
    );
    assert_eq!(
        ev.attributes.get("breach_count").map(String::as_str),
        Some("2")
    );
    assert_eq!(
        ev.attributes
            .get("haveibeenpwned_listed")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn email_emits_a_domain_per_breach_with_breach_date_stamped() {
    let es = email(REAL_EMAIL_RESPONSE);
    let domains: Vec<&crate::core::entity::Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Domain && e.has_tag(crate::core::tags::BREACH))
        .collect();
    assert_eq!(domains.len(), 2, "one Domain per breach entry");
    let apollo = domains.iter().find(|d| d.value == "apollo.io").unwrap();
    assert!(apollo.has_tag(crate::core::tags::BREACH_DERIVED));
    assert_eq!(
        apollo.evidence[0]
            .attributes
            .get("breach_date")
            .map(String::as_str),
        Some("2018-07-23"),
        "breach_date must be stamped so AU-019 can date-cluster this breach"
    );
}

#[test]
fn email_emits_registrant_pii_for_associated_domains() {
    let es = email(REAL_EMAIL_RESPONSE);

    let domain = es
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "thisisasampledomain.com")
        .expect("registrant domain entity");
    assert!(domain.has_tag(crate::core::tags::REGISTRANT));

    let person = es
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("registrant Person entity");
    assert_eq!(person.value, "Jordan Avery");
    assert!((person.confidence - 0.72).abs() < 1e-9);

    let org = es
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("registrant Organisation entity");
    assert_eq!(org.value, "JD Enterprises Ltd");

    let phone = es
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .expect("registrant Phone entity");
    assert_eq!(phone.value, "+61400000000");

    let addr = es
        .iter()
        .find(|e| e.kind == EntityKind::Address)
        .expect("registrant Address entity");
    assert_eq!(addr.value, "472, Doejohn Street, JD City, QLD, 4000, AU");
}

#[test]
fn email_registrant_pii_skips_redacted_privacy_placeholders() {
    let es = email(
        r#"{"data":{"associated_domain_registrations":{"domains":[{
            "domain_name":"masked.example",
            "full_name":"REDACTED FOR PRIVACY",
            "company_name":"Data Protected",
            "mailing_address":"Redacted",
            "phone_number":"REDACTED"
        }]}}}"#,
    );
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
    assert!(es.iter().all(|e| e.kind != EntityKind::Organisation));
    assert!(es.iter().all(|e| e.kind != EntityKind::Phone));
    assert!(es.iter().all(|e| e.kind != EntityKind::Address));
    // The domain name itself is real (not a redaction placeholder) and
    // still surfaces.
    assert!(
        es.iter()
            .any(|e| e.kind == EntityKind::Domain && e.value == "masked.example")
    );
}

#[test]
fn email_registrant_name_requires_a_real_full_name_not_a_handle() {
    // A single-token "name" (no space) is not admitted as a Person, mirroring
    // whois's own registrant-name guard.
    let es = email(
        r#"{"data":{"associated_domain_registrations":{"domains":[{
            "domain_name":"x.example",
            "full_name":"jdoe"
        }]}}}"#,
    );
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
}

#[test]
fn email_emits_its_own_domain_as_a_pivot() {
    // `email_domain_details.domain` was previously only ever attached as an
    // evidence attribute on the Email entity — this fix mints it as a
    // first-class Domain entity too. The fixture's domain has custom:true,
    // free:false, disposable:false, so it must pass the freemail/disposable
    // guard.
    let es = email(REAL_EMAIL_RESPONSE);
    let domain = es
        .iter()
        .find(|e| e.kind == EntityKind::Domain && e.value == "example.com")
        .expect("email's own domain entity");
    assert!(domain.has_tag("seon"));
    let ev = &domain.evidence[0];
    assert_eq!(
        ev.attributes.get("registrar_name").map(String::as_str),
        Some("NameCheap, Inc.")
    );
    assert_eq!(
        ev.attributes.get("registered").map(String::as_str),
        Some("true")
    );
}

#[test]
fn email_own_domain_pivot_skips_freemail_and_disposable() {
    let es = email(
        r#"{"data":{"email_domain_details":{
            "domain":"gmail.com","free":true,"registered":true
        }}}"#,
    );
    assert!(
        es.iter()
            .all(|e| !(e.kind == EntityKind::Domain && e.value == "gmail.com")),
        "freemail domains must not be minted as a Domain pivot"
    );

    let es = email(
        r#"{"data":{"email_domain_details":{
            "domain":"tempmail.example","disposable":true,"registered":true
        }}}"#,
    );
    assert!(
        es.iter()
            .all(|e| !(e.kind == EntityKind::Domain && e.value == "tempmail.example")),
        "disposable domains must not be minted as a Domain pivot"
    );
}

#[test]
fn email_high_score_is_flagged_high_risk() {
    let es = email(r#"{"data":{"risk_scores":{"global_network_score":92.0}}}"#);
    assert!(es[0].has_tag("high-risk"));
    let low = email(r#"{"data":{"risk_scores":{"global_network_score":10.0}}}"#);
    assert!(!low[0].has_tag("high-risk"));
}

#[test]
fn email_no_signal_yields_only_the_enriched_email() {
    let es = email(r#"{"data":{"email_details":{"deliverable":true}}}"#);
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
}

#[test]
fn email_absent_data_object_yields_no_panic_no_entities() {
    // Old-shaped or malformed bodies (missing every section) must degrade
    // cleanly rather than panic — `#[serde(default)]` throughout guarantees
    // this, but pin it as a regression test.
    let es = email(r#"{"data":{}}"#);
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
    assert!(es[0].evidence[0].attributes.is_empty());
}

// ── Core: phone entity building against the real schema ─────────────

/// A real `phone-api/v2` response shape (field names/nesting verified
/// against SEON's own current API reference, 2026-07) — the schema this
/// module's response types must match. Values are synthetic.
const REAL_PHONE_RESPONSE: &str = r#"{
    "success": true,
    "data": {
        "risk_scores": {"global_network_score": 5.0},
        "account_aggregates": {
            "total_registration": 6,
            "personal": {
                "total_registration": 6,
                "messenger": {"registered": 3, "checked": 8},
                "social_media": {"registered": 3, "checked": 10}
            }
        },
        "seon_fraud_history": {
            "hits": 1,
            "customer_hits": 1,
            "first_seen": 1600000000,
            "last_seen": 1600000000
        },
        "provider_carrier_details": {
            "carrier": "Telstra",
            "country": "Australia",
            "disposable": false,
            "phone_is_valid": true,
            "type": "mobile"
        },
        "hlr_details": {
            "imsi": "505013873220912",
            "original_carrier": "Telstra",
            "ported_carrier": "Optus",
            "roaming_carrier": null,
            "serving_msc": "50501",
            "status": "Connected"
        },
        "cnam_details": {
            "name": "Jordan Avery"
        }
    }
}"#;

#[test]
fn parse_phone_response_matches_the_real_v2_schema() {
    // Red/green anchor for the phone-path leg of this fix: this MUST
    // deserialize into real (non-None) values, unlike the pre-fix structs
    // which silently matched nothing in this shape.
    let r: SeonPhoneResp = serde_json::from_str(REAL_PHONE_RESPONSE).unwrap();
    assert_eq!(r.success, Some(true));
    let data = r.data.unwrap();
    assert!((data.risk_scores.unwrap().global_network_score.unwrap() - 5.0).abs() < 0.01);
    let pcd = data.provider_carrier_details.unwrap();
    assert_eq!(pcd.carrier.as_deref(), Some("Telstra"));
    assert_eq!(pcd.phone_is_valid, Some(true));
    let hlr = data.hlr_details.unwrap();
    assert_eq!(
        hlr.imsi.as_deref(),
        Some("505013873220912"),
        "hlr_details must deserialize — it didn't exist in the pre-fix struct at all"
    );
    assert_eq!(
        data.cnam_details.unwrap().name.as_deref(),
        Some("Jordan Avery"),
        "cnam_details must deserialize — genuinely new signal this fix recovers"
    );
}

fn phone(json: &str) -> Vec<crate::core::entity::Entity> {
    let r: SeonPhoneResp = serde_json::from_str(json).unwrap();
    build_phone_entities(
        &Target::new(TargetKind::Phone, "+61400000000"),
        &r.data.unwrap(),
        "s",
    )
}

#[test]
fn phone_entity_carries_fraud_carrier_and_hlr_evidence() {
    let es = phone(REAL_PHONE_RESPONSE);
    let phone_e = &es[0];
    assert_eq!(phone_e.kind, EntityKind::Phone);
    assert!(phone_e.has_tag("country:Australia"));
    assert!(phone_e.has_tag("line:mobile"));
    assert!(phone_e.has_tag("ported"));
    assert!(phone_e.has_tag("fraud-history"));
    let ev = &phone_e.evidence[0];
    assert_eq!(
        ev.attributes.get("fraud_score").map(String::as_str),
        Some("5.0")
    );
    assert_eq!(
        ev.attributes.get("carrier").map(String::as_str),
        Some("Telstra")
    );
    assert_eq!(ev.attributes.get("valid").map(String::as_str), Some("true"));
    assert_eq!(
        ev.attributes.get("hlr_status").map(String::as_str),
        Some("Connected")
    );
    assert_eq!(
        ev.attributes.get("imsi").map(String::as_str),
        Some("505013873220912")
    );
    assert_eq!(
        ev.attributes.get("ported_carrier").map(String::as_str),
        Some("Optus")
    );
    assert_eq!(
        ev.attributes.get("ported_from_carrier").map(String::as_str),
        Some("Telstra")
    );
    assert_eq!(
        ev.attributes
            .get("personal_platform_registrations")
            .map(String::as_str),
        Some("6")
    );
    assert_eq!(
        ev.attributes.get("platform_categories").map(String::as_str),
        Some("messenger[personal]:3/8, social_media[personal]:3/10")
    );
}

#[test]
fn phone_emits_a_carrier_organisation_pivot() {
    let es = phone(REAL_PHONE_RESPONSE);
    let carrier = es
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("carrier Organisation entity");
    assert_eq!(carrier.value, "Telstra");
    assert!(carrier.has_tag("carrier"));
    assert!((carrier.confidence - 0.62).abs() < 1e-9);
}

#[test]
fn phone_emits_a_ported_carrier_organisation_pivot() {
    // hlr_details.ported_carrier was previously only surfaced as evidence
    // text — this fix routes it through the same carrier_entity() helper
    // used for provider_carrier_details.carrier, so a number ported to a
    // new network mints a second, distinguishable Organisation pivot.
    let es = phone(REAL_PHONE_RESPONSE);
    let orgs: Vec<&crate::core::entity::Entity> = es
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .collect();
    assert_eq!(orgs[0].value, "Telstra", "provider carrier must stay first");
    let ported = orgs
        .iter()
        .find(|e| e.value == "Optus")
        .expect("ported-carrier Organisation entity");
    assert!(ported.has_tag("carrier"));
    assert!(ported.has_tag("ported-carrier"));
    assert!((ported.confidence - 0.62).abs() < 1e-9);
}

#[test]
fn phone_emits_a_cnam_person_pivot() {
    let es = phone(REAL_PHONE_RESPONSE);
    let person = es
        .iter()
        .find(|e| e.kind == EntityKind::Person)
        .expect("CNAM Person entity");
    assert_eq!(person.value, "Jordan Avery");
    assert!(person.has_tag("cnam"));
    assert!(person.has_tag("pstn-subscriber"));
    assert!((person.confidence - 0.55).abs() < 1e-9);
}

#[test]
fn phone_high_score_is_flagged_high_risk() {
    let es = phone(r#"{"data":{"risk_scores":{"global_network_score":92.0}}}"#);
    assert!(es[0].has_tag("high-risk"));
    let low = phone(r#"{"data":{"risk_scores":{"global_network_score":10.0}}}"#);
    assert!(!low[0].has_tag("high-risk"));
}

#[test]
fn phone_no_signal_yields_only_the_enriched_phone() {
    let es = phone(r#"{"data":{"provider_carrier_details":{"phone_is_valid":true}}}"#);
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Phone);
}

#[test]
fn phone_absent_data_object_yields_no_panic_no_entities() {
    // Old-shaped or malformed bodies (missing every section) must degrade
    // cleanly rather than panic — `#[serde(default)]` throughout guarantees
    // this, but pin it as a regression test.
    let es = phone(r#"{"data":{}}"#);
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Phone);
    assert!(es[0].evidence[0].attributes.is_empty());
}

#[test]
fn phone_too_short_carrier_and_cnam_name_skip_the_pivots() {
    let es = phone(
        r#"{"data":{
            "provider_carrier_details":{"carrier":"X"},
            "cnam_details":{"name":"Y"}
        }}"#,
    );
    assert!(es.iter().all(|e| e.kind != EntityKind::Organisation));
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
}
