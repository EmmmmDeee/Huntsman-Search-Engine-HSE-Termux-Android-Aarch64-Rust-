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
