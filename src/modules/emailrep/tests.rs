use super::*;

fn email_target() -> Target {
    Target::new(TargetKind::Email, "test@example.com")
}

// ── Module surface ──────────────────────────────────────────────────
#[test]
fn accepts_email_only() {
    let m = EmailRep;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "x")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+1")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(EmailRep.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    assert_eq!(EmailRep.name(), "emailrep");
    assert_eq!(EmailRep.priority(), 90);
    assert_eq!(EmailRep.max_timeout_ms(), 5_000);
}

#[test]
fn parse_response() {
    let raw = r#"{
        "email": "test@example.com",
        "reputation": "high",
        "suspicious": false,
        "references": 15,
        "details": {"credential_leaked": true, "data_breach": true, "profiles": ["linkedin"]}
    }"#;
    let r: RepResp = serde_json::from_str(raw).unwrap();
    assert_eq!(r.reputation.as_deref(), Some("high"));
    let d = r.details.unwrap();
    assert_eq!(d.credential_leaked, Some(true));
    assert_eq!(d.profiles.len(), 1);
}

// ── The core: build_email_entity surfaces every signal ───────────────
fn build(json: &str) -> Entity {
    let body: RepResp = serde_json::from_str(json).unwrap();
    build_email_entity(&email_target(), &body, "scan")
}

#[test]
fn surfaces_breach_blacklist_and_reputation() {
    let e = build(
        r#"{"reputation":"low","suspicious":true,"references":42,
            "details":{"credential_leaked":true,"data_breach":true,
                       "blacklisted":true,"malicious_activity":true,
                       "first_seen":"2010-01-01","last_seen":"2024-06-01",
                       "domain_reputation":"high","days_since_domain_creation":5000,
                       "deliverable":true,"profiles":["linkedin","twitter","github"]}}"#,
    );
    assert!(e.has_tag("emailrep"));
    assert!(e.has_tag("reputation:low"));
    assert!(e.has_tag("suspicious"));
    assert!(e.has_tag("breach"));
    assert!(e.has_tag("blacklisted"));
    assert!(e.has_tag("malicious"));
    let ev = &e.evidence[0];
    assert_eq!(
        ev.attributes.get("reputation").map(String::as_str),
        Some("low")
    );
    assert_eq!(
        ev.attributes.get("references").map(String::as_str),
        Some("42")
    );
    assert_eq!(
        ev.attributes.get("credential_leaked").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("domain_age_days").map(String::as_str),
        Some("5000")
    );
    assert_eq!(
        ev.attributes.get("profiles").map(String::as_str),
        Some("linkedin,twitter,github")
    );
    assert_eq!(
        ev.attributes.get("profile_count").map(String::as_str),
        Some("3")
    );
}

#[test]
fn surfaces_the_previously_discarded_fraud_signals() {
    // spam / new_domain / domain_exists=false — the three fields the old
    // code parsed then threw away.
    let e = build(
        r#"{"details":{"spam":true,"new_domain":true,"domain_exists":false,"disposable":true}}"#,
    );
    assert!(e.has_tag("spam-source"));
    assert!(e.has_tag("new-domain"));
    assert!(e.has_tag("domain-nonexistent"));
    assert!(e.has_tag("disposable"));
    let ev = &e.evidence[0];
    assert_eq!(ev.attributes.get("spam").map(String::as_str), Some("true"));
    assert_eq!(
        ev.attributes.get("new_domain").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ev.attributes.get("domain_exists").map(String::as_str),
        Some("false")
    );
}

#[test]
fn existing_domain_is_recorded_but_not_flagged() {
    let e = build(r#"{"details":{"domain_exists":true}}"#);
    assert!(!e.has_tag("domain-nonexistent"));
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("domain_exists")
            .map(String::as_str),
        Some("true")
    );
}

#[test]
fn clean_email_gets_only_the_source_tag() {
    // A spotless report adds no risk tags — just the module tag.
    let e = build(r#"{"reputation":"high","suspicious":false,"details":{"deliverable":true}}"#);
    assert!(e.has_tag("emailrep"));
    assert!(e.has_tag("reputation:high"));
    for risk in [
        "suspicious",
        "breach",
        "blacklisted",
        "malicious",
        "spam-source",
        "new-domain",
        "domain-nonexistent",
        "disposable",
    ] {
        assert!(!e.has_tag(risk), "clean email must not be tagged {risk}");
    }
}

#[test]
fn false_flags_do_not_tag() {
    // EmailRep returns explicit `false` for absent abuse — must not tag.
    let e =
        build(r#"{"details":{"credential_leaked":false,"spam":false,"blacklisted":false}}"#);
    assert!(!e.has_tag("breach"));
    assert!(!e.has_tag("spam-source"));
    assert!(!e.has_tag("blacklisted"));
}

#[test]
fn profiles_are_capped() {
    let profiles: Vec<String> = (0..30).map(|i| format!(r#""p{i}""#)).collect();
    let e = build(&format!(
        r#"{{"details":{{"profiles":[{}]}}}}"#,
        profiles.join(",")
    ));
    let csv = e.evidence[0].attributes.get("profiles").unwrap();
    assert_eq!(csv.split(',').count(), MAX_PROFILES);
    // …but the reported count is the true total.
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("profile_count")
            .map(String::as_str),
        Some("30")
    );
}
