use super::*;

#[test]
fn accepts_email_and_domain() {
    let m = Hibp;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
}

#[test]
fn priority_above_free_breach_modules() {
    let m = Hibp;
    assert!(
        m.priority() > 100,
        "HIBP should run before free breach modules"
    );
}

#[test]
fn cost_is_key_gated() {
    assert_eq!(Hibp.cost(), ModuleCost::KeyGated);
}

#[test]
fn resolve_key_prefers_provided() {
    assert_eq!(resolve_key(Some("my-key")), "my-key");
}

#[test]
fn resolve_key_falls_back_to_hardcoded() {
    assert_eq!(resolve_key(None), HARDCODED_KEY);
}

#[test]
fn resolve_key_falls_back_on_empty() {
    assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
}

#[test]
fn name_is_hibp() {
    assert_eq!(Hibp.name(), "hibp");
}

#[test]
fn description_non_empty() {
    assert!(!Hibp.description().is_empty());
}

#[test]
fn max_timeout_generous() {
    assert!(Hibp.max_timeout_ms() >= 30_000);
}

#[test]
fn breach_deser_full_payload() {
    let json = r#"[{
        "Name": "Adobe",
        "Title": "Adobe",
        "Domain": "adobe.com",
        "BreachDate": "2013-10-04",
        "AddedDate": "2013-12-04",
        "ModifiedDate": "2022-05-15",
        "PwnCount": 152445165,
        "Description": "Adobe breach",
        "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
        "IsVerified": true,
        "IsFabricated": false,
        "IsSensitive": false,
        "IsRetired": false,
        "IsSpamList": false,
        "IsSubscriptionFree": false,
        "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"
    }]"#;
    let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
    assert_eq!(breaches.len(), 1);
    assert_eq!(breaches[0].name, "Adobe");
    assert_eq!(breaches[0].domain.as_deref(), Some("adobe.com"));
    assert_eq!(breaches[0].pwn_count, Some(152445165));
    assert!(breaches[0].is_verified == Some(true));
    assert_eq!(breaches[0].data_classes.len(), 4);
    assert!(breaches[0].data_classes.contains(&"Passwords".to_string()));
}

#[test]
fn breach_deser_minimal() {
    let json = r#"[{"Name": "Unknown"}]"#;
    let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
    assert_eq!(breaches.len(), 1);
    assert_eq!(breaches[0].name, "Unknown");
    assert!(breaches[0].domain.is_none());
    assert!(breaches[0].data_classes.is_empty());
}

fn one_breach(json: &str) -> Breach {
    serde_json::from_str::<Vec<Breach>>(json)
        .unwrap()
        .pop()
        .unwrap()
}

#[test]
fn breach_evidence_surfaces_every_field() {
    let b = one_breach(
        r#"[{
            "Name": "Adobe", "Title": "Adobe Systems", "Domain": "adobe.com",
            "BreachDate": "2013-10-04", "AddedDate": "2013-12-04",
            "ModifiedDate": "2022-05-15", "PwnCount": 152445165,
            "Description": "In October 2013, 153M Adobe accounts were breached.",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": true, "IsFabricated": false, "IsSensitive": false,
            "IsRetired": false, "IsSpamList": false, "IsSubscriptionFree": false,
            "LogoPath": "https://example/Adobe.png"
        }]"#,
    );
    let ev = breach_evidence(&b);
    let a = &ev.attributes;
    // Previously-discarded fields now surfaced.
    assert_eq!(a.get("title").map(String::as_str), Some("Adobe Systems"));
    assert!(a.get("description").is_some_and(|d| d.contains("153M")));
    assert_eq!(a.get("added_date").map(String::as_str), Some("2013-12-04"));
    assert_eq!(
        a.get("modified_date").map(String::as_str),
        Some("2022-05-15")
    );
    assert_eq!(a.get("verified").map(String::as_str), Some("true"));
    assert_eq!(a.get("fabricated").map(String::as_str), Some("false"));
    assert_eq!(
        a.get("logo_path").map(String::as_str),
        Some("https://example/Adobe.png")
    );
    // Core fields retained.
    assert_eq!(a.get("breach_name").map(String::as_str), Some("Adobe"));
    assert_eq!(a.get("pwn_count").map(String::as_str), Some("152445165"));
    // Summary prefers the human Title.
    assert!(ev.summary.contains("Adobe Systems"));
}

#[test]
fn breach_evidence_omits_absent_fields() {
    let b = one_breach(r#"[{"Name": "Unknown"}]"#);
    let ev = breach_evidence(&b);
    assert_eq!(
        ev.attributes.get("breach_name").map(String::as_str),
        Some("Unknown")
    );
    assert!(!ev.attributes.contains_key("title"));
    assert!(!ev.attributes.contains_key("description"));
    assert!(!ev.attributes.contains_key("fabricated"));
}

#[test]
fn tag_breach_quality_flags_low_trust_and_sensitive() {
    let b = one_breach(
        r#"[{"Name": "X", "IsFabricated": true, "IsSpamList": true,
             "IsSensitive": true, "IsRetired": false}]"#,
    );
    let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "t");
    tag_breach_quality(&mut e, &b);
    assert!(e.tags.iter().any(|t| t == "breach-fabricated"));
    assert!(e.tags.iter().any(|t| t == "breach-spam-list"));
    assert!(e.tags.iter().any(|t| t == "breach-sensitive"));
    assert!(!e.tags.iter().any(|t| t == "breach-retired"));
}

#[test]
fn tag_breach_quality_clean_breach_gets_no_quality_tags() {
    let b = one_breach(r#"[{"Name": "Clean", "IsVerified": true, "IsFabricated": false}]"#);
    let mut e = Entity::new(EntityKind::Domain, "x.com", 0.5, "t");
    tag_breach_quality(&mut e, &b);
    assert!(!e.tags.iter().any(|t| t.starts_with("breach-")));
}

fn pastes(json: &str) -> Vec<Paste> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn paste_entities_tags_email_and_reconstructs_pastebin_url() {
    let ps = pastes(
        r#"[
            {"Source":"Pastebin","Id":"abc123","Title":"dump","Date":"2019-01-01T00:00:00Z","EmailCount":42},
            {"Source":"AdHocUrl","Id":"http://example/x","Title":"other","Date":"2020-06-01T00:00:00Z","EmailCount":3}
        ]"#,
    );
    let ents = paste_entities(&ps, "victim@example.com", "s");

    let email = ents
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("email entity carrying the paste signal");
    assert!(email.has_tag("paste") && email.has_tag(tags::BREACH));
    let a = &email.evidence[0].attributes;
    assert_eq!(a.get("paste_count").map(String::as_str), Some("2"));
    // Latest date across pastes is surfaced.
    assert_eq!(
        a.get("latest_paste").map(String::as_str),
        Some("2020-06-01T00:00:00Z")
    );

    // Exactly one Url — only the Pastebin entry is URL-reconstructable.
    let urls: Vec<&str> = ents
        .iter()
        .filter(|e| e.kind == EntityKind::Url)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(urls, ["https://pastebin.com/abc123"]);
}

#[test]
fn paste_entities_empty_input_yields_nothing() {
    assert!(paste_entities(&[], "x@y.com", "s").is_empty());
}

#[test]
fn paste_url_only_reconstructs_pastebin() {
    let p = pastes(r#"[{"Source":"Pastebin","Id":"XYZ"}]"#)
        .pop()
        .unwrap();
    assert_eq!(paste_url(&p).as_deref(), Some("https://pastebin.com/XYZ"));
    // Unknown source → no fabricated URL.
    let q = pastes(r#"[{"Source":"SomeForum","Id":"XYZ"}]"#)
        .pop()
        .unwrap();
    assert!(paste_url(&q).is_none());
    // Missing id → no URL even for Pastebin.
    let r = pastes(r#"[{"Source":"Pastebin"}]"#).pop().unwrap();
    assert!(paste_url(&r).is_none());
}
