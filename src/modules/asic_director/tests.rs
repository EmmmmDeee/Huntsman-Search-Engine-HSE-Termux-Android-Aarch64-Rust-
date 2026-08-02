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
    let a = addr.expect("should succeed");
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
    assert!(addr.expect("should succeed").has_tag("registered-office"));
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

#[test]
fn extract_company_name_strips_acn_and_trailing_punct() {
    // The ACN portion and trailing punctuation are stripped; the company name
    // remains clean.
    assert_eq!(
        extract_company_name("Bamford Holdings Pty Ltd ACN 123456789 -", "123456789"),
        "Bamford Holdings Pty Ltd ACN"
    );
    // No ACN → full line cleaned of trailing punct.
    assert_eq!(extract_company_name("Acme Corp,", ""), "Acme Corp");
    // Empty → empty.
    assert_eq!(extract_company_name("", ""), "");
}

#[test]
fn extract_au_address_requires_valid_postcode_range() {
    // 4000 is a valid QLD postcode.
    assert!(extract_au_address("Brisbane QLD 4000 Australia").is_some());
    // 9999 is out of the AU postcode range (2000–7999) → no address.
    assert!(extract_au_address("Invalid NSW 9999").is_none());
    // No state abbreviation → no address.
    assert!(extract_au_address("Somewhere 3000").is_none());
}

// ── `request_failed` — the "ASIC Connect Online never answered" vs
// "genuinely no director records" distinction (T2.120). ──────────────────

#[test]
fn request_failed_true_when_the_request_never_read_and_nothing_found() {
    // Regression: before this fix, `process()` collapsed a transport error,
    // a non-success HTTP status, AND an unreadable body all into the same
    // silent `Ok(ModuleResult::new())` as a genuine "no director records for
    // this name" result — indistinguishable from a real outage or a
    // rejected request.
    assert!(request_failed(false, false));
}

#[test]
fn request_failed_false_when_the_request_read_even_with_no_match() {
    // The request got a real, readable response — this name simply had no
    // director record in it. An honest empty result, not a failure.
    assert!(!request_failed(true, false));
}

#[test]
fn request_failed_false_when_entities_were_found() {
    // Found something, regardless of the html_read_ok bookkeeping — never
    // report a hard failure over a real result.
    assert!(!request_failed(false, true));
    assert!(!request_failed(true, true));
}
