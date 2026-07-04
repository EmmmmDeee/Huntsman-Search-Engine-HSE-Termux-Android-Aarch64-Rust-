use super::{
    Seon,
    entity_builders::{
        build_email_entities, build_phone_entities, profile_url_entity, registered_accounts,
    },
    types::{AccountPresence, SeonEmailResp, SeonPhoneResp},
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
    // produces() advertises the Url leads it now emits.
    assert!(Seon.produces().contains(&EntityKind::Url));
    assert!(Seon.produces().contains(&EntityKind::Person));
}

#[test]
fn parse_email_response() {
    let raw = r#"{"success":true,"data":{"score":12.5,"deliverable":true,
        "domain_details":{"domain":"example.com","registered":true,"disposable":false,"free":false,"custom":true},
        "account_details":{"facebook":{"registered":true,"name":"John Doe"},"twitter":{"registered":false},"github":{"registered":true}}}}"#;
    let r: SeonEmailResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.success, Some(true));
    let data = r.data.unwrap();
    assert!((data.score.unwrap() - 12.5).abs() < 0.01);
    assert_eq!(data.domain_details.unwrap().disposable, Some(false));
}

// ── Core: email entity building (incl. the recovered profile URLs) ──
fn email(json: &str) -> Vec<crate::core::entity::Entity> {
    let r: SeonEmailResp = serde_json::from_str(json).unwrap();
    build_email_entities(
        &Target::new(TargetKind::Email, "jane@acme.com"),
        &r.data.unwrap(),
        "s",
    )
}

#[test]
fn email_emits_url_entities_for_each_profile_link() {
    let es = email(
        r#"{"data":{
            "domain_details":{"domain":"acme.com","registered":true,"custom":true,"free":false},
            "account_details":{
                "facebook":{"registered":true,"name":"Jane Doe","url":"https://facebook.com/jane"},
                "github":{"registered":true,"url":"https://github.com/jane"},
                "twitter":{"registered":false,"url":"https://twitter.com/ghost"}
            }}}"#,
    );
    // The enriched email entity carries the domain flags + platform CSV.
    let email_e = &es[0];
    let ev = &email_e.evidence[0];
    assert!(email_e.has_tag("custom-domain"));
    assert_eq!(
        ev.attributes.get("domain_registered").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("custom_domain").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("platform_count").map(String::as_str),
        Some("2")
    );

    // Two Url leads (facebook, github) — NOT the unregistered twitter.
    let urls: Vec<&crate::core::entity::Entity> =
        es.iter().filter(|e| e.kind == EntityKind::Url).collect();
    assert_eq!(urls.len(), 2);
    let vals: Vec<&str> = urls.iter().map(|e| e.value.as_str()).collect();
    assert!(vals.contains(&"https://facebook.com/jane"));
    assert!(vals.contains(&"https://github.com/jane"));
    assert!(
        urls.iter()
            .all(|e| e.has_tag("social-profile") && e.has_tag("seon"))
    );
    let fb = urls.iter().find(|e| e.value.contains("facebook")).unwrap();
    assert!(fb.has_tag("platform:facebook"));

    // One Person from the best-named identity platform (facebook).
    let people: Vec<&crate::core::entity::Entity> =
        es.iter().filter(|e| e.kind == EntityKind::Person).collect();
    assert_eq!(people.len(), 1);
    assert_eq!(people[0].value, "Jane Doe");
    assert!(people[0].has_tag("platform:facebook"));
}

#[test]
fn email_emits_a_person_for_each_distinct_reported_name() {
    // Full-fidelity: identity platforms routinely report different name variants;
    // every DISTINCT self-reported name must surface as a Person — the old
    // find_map emitted only the first, silently dropping the rest. The SAME name on
    // two platforms dedups to one Person tagged with both.
    let es = email(
        r#"{"data":{
            "domain_details":{"domain":"acme.com","registered":true,"custom":true,"free":false},
            "account_details":{
                "facebook":{"registered":true,"name":"Jon Smith"},
                "linkedin":{"registered":true,"name":"Jonathan A. Smith"},
                "twitter":{"registered":true,"name":"Jon Smith"},
                "github":{"registered":true,"name":"jsmith"}
            }}}"#,
    );
    let people: Vec<&crate::core::entity::Entity> =
        es.iter().filter(|e| e.kind == EntityKind::Person).collect();
    let names: Vec<&str> = people.iter().map(|e| e.value.as_str()).collect();
    // Both DISTINCT names surface; the space-less github handle "jsmith" does not.
    assert!(names.contains(&"Jon Smith"), "got {names:?}");
    assert!(names.contains(&"Jonathan A. Smith"), "got {names:?}");
    assert_eq!(
        people.len(),
        2,
        "one Person per distinct name (github 'jsmith' has no space): {names:?}"
    );
    // The name reported by two platforms carries both platform tags.
    let jon = people.iter().find(|e| e.value == "Jon Smith").unwrap();
    assert!(jon.has_tag("platform:facebook") && jon.has_tag("platform:twitter"));
}

#[test]
fn email_high_score_is_flagged_high_risk() {
    let es = email(r#"{"data":{"score":92.0}}"#);
    assert!(es[0].has_tag("high-risk"));
    let low = email(r#"{"data":{"score":10.0}}"#);
    assert!(!low[0].has_tag("high-risk"));
}

#[test]
fn email_no_accounts_yields_only_the_enriched_email() {
    let es = email(r#"{"data":{"deliverable":true}}"#);
    assert_eq!(es.len(), 1);
    assert_eq!(es[0].kind, EntityKind::Email);
    assert!(
        es.iter()
            .all(|e| !matches!(e.kind, EntityKind::Url | EntityKind::Person))
    );
}

#[test]
fn email_person_skips_handles_and_partial_names() {
    // A registered platform whose "name" is a handle (no space) is not a Person.
    let es =
        email(r#"{"data":{"account_details":{"github":{"registered":true,"name":"janedoe"}}}}"#);
    assert!(es.iter().all(|e| e.kind != EntityKind::Person));
}

// ── Core: phone entity building ─────────────────────────────────────
#[test]
fn phone_enriches_and_emits_messaging_profile_urls() {
    let r: SeonPhoneResp = serde_json::from_str(
        r#"{"data":{"score":5.0,"valid":true,"carrier":"Telstra","country_code":"au","type":"mobile",
            "account_details":{
                "whatsapp":{"registered":true,"url":"https://wa.me/61400"},
                "telegram":{"registered":true},
                "viber":{"registered":false,"url":"https://viber/x"}
            }}}"#,
    )
    .unwrap();
    let es = build_phone_entities(
        &Target::new(TargetKind::Phone, "+61400000000"),
        &r.data.unwrap(),
        "s",
    );
    let phone_e = &es[0];
    assert_eq!(phone_e.kind, EntityKind::Phone);
    assert!(phone_e.has_tag("country:AU"));
    assert!(phone_e.has_tag("line:mobile"));
    let ev = &phone_e.evidence[0];
    assert_eq!(
        ev.attributes.get("carrier").map(String::as_str),
        Some("Telstra")
    );
    assert_eq!(
        ev.attributes.get("messaging_platforms").map(String::as_str),
        Some("whatsapp,telegram")
    );

    // Only whatsapp had a URL (telegram had none; viber unregistered).
    let urls: Vec<&crate::core::entity::Entity> =
        es.iter().filter(|e| e.kind == EntityKind::Url).collect();
    assert_eq!(urls.len(), 1);
    assert_eq!(urls[0].value, "https://wa.me/61400");
    assert!(urls[0].has_tag("platform:whatsapp"));
}

// ── Pure entity-builder helpers (direct unit tests) ──────────────────
fn presence(registered: Option<bool>, name: Option<&str>, url: Option<&str>) -> AccountPresence {
    AccountPresence {
        registered,
        name: name.map(String::from),
        url: url.map(String::from),
    }
}

#[test]
fn registered_accounts_keeps_only_registered_in_declared_order() {
    // Build a few presences; only those with `registered == Some(true)` survive,
    // and the result preserves the order the pairs were declared in.
    let fb = Some(presence(
        Some(true),
        Some("Jordan Avery"),
        Some("https://fb/ja"),
    ));
    let tw = Some(presence(Some(false), None, None)); // not registered → dropped
    let li = Some(presence(Some(true), None, None));
    let gh: Option<AccountPresence> = None; // absent → dropped
    let got = registered_accounts(&[
        ("facebook", &fb),
        ("twitter", &tw),
        ("linkedin", &li),
        ("github", &gh),
    ]);
    let names: Vec<&str> = got.iter().map(|(n, _)| *n).collect();
    assert_eq!(names, ["facebook", "linkedin"]);
    // The borrowed AccountPresence is the same data we passed in.
    assert_eq!(got[0].1.name.as_deref(), Some("Jordan Avery"));
}

#[test]
fn registered_accounts_empty_when_none_registered() {
    let a = Some(presence(Some(false), None, None));
    let b = Some(presence(None, Some("x"), None)); // registered is None, not true
    let got = registered_accounts(&[("facebook", &a), ("twitter", &b)]);
    assert!(got.is_empty());
}

#[test]
fn profile_url_entity_shape() {
    let e = profile_url_entity("whatsapp", "https://wa.me/61400", "+61400", "scan-1");
    assert_eq!(e.kind, EntityKind::Url);
    assert_eq!(e.value, "https://wa.me/61400");
    assert!((e.confidence - 0.70).abs() < 1e-9);
    assert!(e.has_tag("seon"));
    assert!(e.has_tag("social-profile"));
    assert!(e.has_tag("platform:whatsapp"));
    assert_eq!(e.evidence.len(), 1);
    assert_eq!(e.evidence[0].source, "seon");
    assert_eq!(
        e.evidence[0].summary,
        "whatsapp profile via SEON for +61400"
    );
}
