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
        "details": {"credentials_leaked": true, "data_breach": true, "profiles": ["linkedin"]}
    }"#;
    let r: RepResp = serde_json::from_str(raw).expect("should succeed");
    assert_eq!(r.reputation.as_deref(), Some("high"));
    let d = r.details.expect("should succeed");
    assert_eq!(d.credentials_leaked, Some(true));
    assert_eq!(d.profiles.len(), 1);
}

// ── The core: build_email_entity surfaces every signal ───────────────
fn build(json: &str) -> Entity {
    let body: RepResp = serde_json::from_str(json).expect("should succeed");
    build_email_entity(&email_target(), &body, "scan")
}

#[test]
fn surfaces_breach_blacklist_and_reputation() {
    let e = build(
        r#"{"reputation":"low","suspicious":true,"references":42,
            "details":{"credentials_leaked":true,"data_breach":true,
                       "blacklisted":true,"malicious_activity":true,
                       "first_seen":"2010-01-01","last_seen":"2024-06-01",
                       "domain_reputation":"high","days_since_domain_creation":5000,
                       "deliverable":true,"profiles":["linkedin","twitter","github"]}}"#,
    );
    assert!(e.has_tag("emailrep"));
    assert!(e.has_tag("reputation:low"));
    assert!(e.has_tag("suspicious"));
    assert!(e.has_tag(crate::core::tags::BREACH));
    assert!(e.has_tag("blacklisted"));
    assert!(e.has_tag(crate::core::tags::MALICIOUS));
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
        ev.attributes.get("credentials_leaked").map(String::as_str),
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
        crate::core::tags::BREACH,
        "blacklisted",
        crate::core::tags::MALICIOUS,
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
    let e = build(r#"{"details":{"credentials_leaked":false,"spam":false,"blacklisted":false}}"#);
    assert!(!e.has_tag("breach"));
    assert!(!e.has_tag("spam-source"));
    assert!(!e.has_tag("blacklisted"));
}

#[test]
fn profiles_are_emitted_in_full() {
    // Full-fidelity policy: every discovered profile is surfaced in the CSV,
    // never a capped subset — the profile names are a result, not a preview.
    let profiles: Vec<String> = (0..30).map(|i| format!(r#""p{i}""#)).collect();
    let e = build(&format!(
        r#"{{"details":{{"profiles":[{}]}}}}"#,
        profiles.join(",")
    ));
    let csv = e.evidence[0]
        .attributes
        .get("profiles")
        .expect("should succeed");
    assert_eq!(csv.split(',').count(), 30);
    // …and the reported count matches the true total.
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("profile_count")
            .map(String::as_str),
        Some("30")
    );
}

// ── The wire shape, from the vendor ─────────────────────────────────
/// The example response in EmailRep's own README
/// (`github.com/sublime-security/emailrep.io`), verbatim.
const VENDOR_EXAMPLE: &str = r#"{
  "email": "bill@microsoft.com",
  "reputation": "high",
  "suspicious": false,
  "references": 79,
  "details": {
    "blacklisted": false,
    "malicious_activity": false,
    "malicious_activity_recent": false,
    "credentials_leaked": true,
    "credentials_leaked_recent": false,
    "data_breach": true,
    "first_seen": "07/01/2008",
    "last_seen": "05/24/2019",
    "domain_exists": true,
    "domain_reputation": "high",
    "new_domain": false,
    "days_since_domain_creation": 10341,
    "suspicious_tld": false,
    "spam": false,
    "free_provider": false,
    "disposable": false,
    "deliverable": true,
    "accept_all": true,
    "valid_mx": true,
    "spoofable": false,
    "spf_strict": true,
    "dmarc_enforced": true,
    "profiles": [
      "myspace",
      "spotify",
      "twitter",
      "pinterest",
      "flickr",
      "linkedin",
      "vimeo",
      "angellist"
    ]
  }
}"#;

#[test]
fn the_vendors_documented_response_decodes() {
    let body: RepResp = serde_json::from_str(VENDOR_EXAMPLE).expect("the vendor's own example");
    let d = body.details.as_ref().expect("details");
    assert_eq!(
        d.credentials_leaked,
        Some(true),
        "read under the vendor's name"
    );
    assert_eq!(d.credentials_leaked_recent, Some(false));
    assert_eq!(d.profiles.len(), 8);
}

#[test]
fn a_credential_leak_alone_is_a_breach_signal() {
    // REQ-EMAILREP-002: FAILS on `credential_leaked`. The vendor documents
    // `credentials_leaked` (pastes, dark web) separately from `data_breach`;
    // read under the wrong name, a leak-only address carried no signal at all.
    let e = build(
        r#"{"details":{"credentials_leaked":true,"credentials_leaked_recent":true,"data_breach":false}}"#,
    );
    assert!(e.has_tag(crate::core::tags::BREACH));
    let attrs = &e.evidence[0].attributes;
    assert_eq!(
        attrs.get("credentials_leaked").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        attrs.get("credentials_leaked_recent").map(String::as_str),
        Some("true")
    );
}

// ── The confidence the report earns ─────────────────────────────────
const PRESENT: f64 = crate::selftest::capability_probe::SEED_PRESENT_RUNG;

#[test]
fn a_report_that_never_observed_the_address_confers_no_presence() {
    // REQ-EMAILREP-001: FAILS at the fixed 0.85, which raised every address
    // EmailRep answered for to VERIFIED through the engine's GREATEST merge.
    for (why, body) in [
        (
            "the audit's case: undeliverable, no references, no profiles",
            r#"{"email":"jdoe@gmail.com","reputation":"none","suspicious":true,"references":0,
                "details":{"deliverable":false,"domain_exists":true,"profiles":[]}}"#,
        ),
        ("an empty report", "{}"),
        (
            "a nonexistent domain",
            r#"{"details":{"domain_exists":false,"deliverable":false,"first_seen":"never"}}"#,
        ),
        (
            "references alone: the vendor counts the DOMAIN's reputation sources",
            r#"{"reputation":"high","references":79,
                "details":{"domain_reputation":"high","first_seen":"never","last_seen":"never"}}"#,
        ),
    ] {
        let e = build(body);
        assert!(e.confidence < PRESENT, "{why}: {}", e.confidence);
    }
}

#[test]
fn an_observed_address_is_present_but_not_verified_by_this_source_alone() {
    for (why, body) in [
        ("the vendor's example", VENDOR_EXAMPLE),
        ("a breach", r#"{"details":{"data_breach":true}}"#),
        (
            "a credential leak",
            r#"{"details":{"credentials_leaked":true}}"#,
        ),
        ("profiles", r#"{"details":{"profiles":["github"]}}"#),
        ("observed behaviour", r#"{"details":{"spam":true}}"#),
        (
            "a first-seen date",
            r#"{"details":{"first_seen":"07/01/2008"}}"#,
        ),
    ] {
        let e = build(body);
        assert!(e.confidence >= PRESENT, "{why}: {}", e.confidence);
        assert!(
            e.confidence < crate::core::entity::Classification::VERIFIED_MIN,
            "{why}: one third-party source is not verification: {}",
            e.confidence
        );
    }
}
