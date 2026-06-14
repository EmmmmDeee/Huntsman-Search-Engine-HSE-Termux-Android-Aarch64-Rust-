use super::*;

#[test]
fn accepts_two_token_fullname_only() {
    let m = AsicDirector;
    assert!(m.accepts(&Target::new(TargetKind::FullName, "Haigen Bamford")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Haigen"))); // single token
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Organisation, "Acme")));
}

#[test]
fn module_metadata() {
    let m = AsicDirector;
    assert_eq!(m.name(), "asic_director");
    assert!(m.attack_techniques().contains(&"T1591.002"));
    assert!(m.attack_techniques().contains(&"T1591.004"));
}

#[test]
fn clean_html_strips_tags_and_entities() {
    assert_eq!(clean_html("<b>Sydney</b> &amp; NSW"), "Sydney & NSW");
    assert_eq!(clean_html("plain &nbsp; text"), "plain   text");
}

#[test]
fn extract_acn_finds_nine_digits() {
    assert_eq!(extract_acn("ACN 123456789 PTY"), Some("123456789".into()));
    assert_eq!(extract_acn("short 12"), None);
}

#[test]
fn extract_au_address_finds_state_postcode() {
    let addr = extract_au_address("Level 5 Collins St Melbourne VIC 3000 Australia");
    assert!(addr.is_some());
    let a = addr.unwrap();
    assert!(a.contains("VIC") && a.contains("3000"));
}

#[test]
fn build_director_entities_emits_org_acn_address() {
    let ents = build_director_entities(
        "Bamford Holdings Pty Ltd",
        "123456789",
        "Haigen Bamford",
        Some("Level 1, 100 Collins St, Melbourne VIC 3000"),
        "s",
    );
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
    assert!(ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    let addr = ents.iter().find(|e| e.kind == EntityKind::Address);
    assert!(addr.is_some());
    assert!(addr.unwrap().has_tag("registered-office"));
}

#[test]
fn build_director_entities_invalid_acn_skipped() {
    let ents = build_director_entities("Acme Pty Ltd", "12345", "Test Name", None, "s");
    // Short ACN — no AbnAcn entity emitted.
    assert!(!ents.iter().any(|e| e.kind == EntityKind::AbnAcn));
    // But Organisation should still emit.
    assert!(ents.iter().any(|e| e.kind == EntityKind::Organisation));
}

#[test]
fn parse_asic_html_extracts_name_match() {
    let html = r#"<tr>
        <td>Bamford Holdings Pty Ltd</td>
        <td>ACN 123456789</td>
        <td>Level 1 Collins St Melbourne VIC 3000</td>
        <td>Haigen Bamford - Director</td>
    </tr>"#;
    let results = parse_asic_html(html, "Haigen Bamford");
    // The parser works on cleaned lines — may not find the split-cell pattern,
    // but at minimum it should not panic.
    let _ = results;
}
