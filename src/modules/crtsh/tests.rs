use super::*;

#[test]
fn accepts_domain_and_email() {
    let m = CrtSh;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "u")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(
        CrtSh.cost(),
        crate::core::module::ModuleCost::Free
    ));
}

#[test]
fn description_non_empty() {
    assert!(!CrtSh.description().is_empty());
}

#[test]
fn produces_declares_the_issuer_organisation() {
    // build_entities emits the non-public issuing CA as an Organisation; the
    // producer graph must declare it.
    assert!(CrtSh.produces().contains(&EntityKind::Organisation));
    assert!(CrtSh.produces().contains(&EntityKind::Domain));
}

#[test]
fn crt_entry_deser() {
    let json = r#"[{"common_name":"www.example.com","name_value":"www.example.com\nexample.com","issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"abc123"}]"#;
    let entries: Vec<CrtEntry> = serde_json::from_str(json).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].common_name.as_deref(), Some("www.example.com"));
    assert!(
        entries[0]
            .name_value
            .as_deref()
            .unwrap()
            .contains("example.com")
    );
}

#[test]
fn build_query_shapes_each_kind() {
    assert_eq!(
        build_query(TargetKind::Domain, " example.com "),
        Some("%.example.com".into())
    );
    assert_eq!(
        build_query(TargetKind::Email, " a@b.com "),
        Some("a@b.com".into())
    );
    assert_eq!(
        build_query(TargetKind::Url, "https://sub.example.com/path"),
        Some("%.sub.example.com".into())
    );
    assert_eq!(build_query(TargetKind::Username, "u"), None);
}

fn entries(json: &str) -> Vec<CrtEntry> {
    serde_json::from_str(json).unwrap()
}

#[test]
fn classifies_subdomains_dedups_and_skips_wildcards() {
    let e = entries(
        r#"[
          {"name_value":"api.example.com\n*.example.com\napi.example.com","common_name":"api.example.com","issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01"},
          {"name_value":"unrelated.org","common_name":"unrelated.org"}
        ]"#,
    );
    let out = build_entities(&e, "example.com", "s");
    let by_val = |v: &str| out.iter().find(|x| x.value == v).cloned();

    // api.example.com repeats across SANs + common_name → deduped to one.
    assert_eq!(
        out.iter().filter(|x| x.value == "api.example.com").count(),
        1
    );
    // Wildcard *.example.com skipped.
    assert!(by_val("*.example.com").is_none());

    // Subdomain → high confidence + subdomain tag.
    let api = by_val("api.example.com").unwrap();
    assert!((api.confidence - 0.75).abs() < 1e-9);
    assert!(api.has_tag(tags::CT_LOG) && api.has_tag(tags::SUBDOMAIN));
    assert_eq!(
        api.evidence[0].attributes.get("issuer").map(String::as_str),
        Some("Let's Encrypt")
    );

    // Unrelated domain → lower confidence, no subdomain tag.
    let other = by_val("unrelated.org").unwrap();
    assert!((other.confidence - 0.45).abs() < 1e-9);
    assert!(!other.has_tag(tags::SUBDOMAIN));
}

#[test]
fn subdomain_match_is_case_insensitive_against_base() {
    // Mixed-case target base must still classify the SAN as a subdomain.
    let e = entries(r#"[{"name_value":"api.example.com"}]"#);
    let out = build_entities(&e, "Example.COM", "s");
    let api = out.iter().find(|x| x.value == "api.example.com").unwrap();
    assert!((api.confidence - 0.75).abs() < 1e-9);
    assert!(api.has_tag(tags::SUBDOMAIN));
}

#[test]
fn surfaces_san_emails_above_min_length() {
    let e = entries(
        r#"[{"name_value":"admin@example.com\na@b","issuer_name":"CA","not_before":"2024-01-01"}]"#,
    );
    let out = build_entities(&e, "example.com", "s");
    let email = out.iter().find(|x| x.kind == EntityKind::Email);
    let email = email.unwrap();
    assert_eq!(email.value, "admin@example.com");
    assert!((email.confidence - 0.70).abs() < 1e-9);
    assert!(email.has_tag(tags::CT_LOG));
    // "a@b" is below MIN_EMAIL_LEN → not surfaced.
    assert!(!out.iter().any(|x| x.value == "a@b"));
}

#[test]
fn results_are_capped_highest_confidence_first() {
    // Build > MAX_ENTITIES distinct unrelated domains (conf 0.45) plus one
    // subdomain (0.75); the cap must keep the subdomain (sorted first).
    let mut sans: Vec<String> = (0..MAX_ENTITIES + 50)
        .map(|i| format!("host{i}.other-{i}.net"))
        .collect();
    sans.push("keep.example.com".to_string());
    let json = format!(r#"[{{"name_value":"{}"}}]"#, sans.join("\\n"));
    let out = build_entities(&entries(&json), "example.com", "s");
    assert_eq!(out.len(), MAX_ENTITIES);
    assert_eq!(out[0].value, "keep.example.com"); // highest confidence first
    assert!(out.windows(2).all(|w| w[0].confidence >= w[1].confidence));
}

#[test]
fn recovers_certificate_serial_as_attribution_pivot() {
    // crt.sh returns serial_number; it must now surface as cert_serial on the
    // discovered-domain evidence (an infrastructure-attribution pivot).
    let e = entries(
        r#"[{"common_name":"www.example.com","name_value":"www.example.com",
             "issuer_name":"Let's Encrypt","not_before":"2024-01-01",
             "not_after":"2024-04-01","serial_number":"04ab9f"}]"#,
    );
    let out = build_entities(&e, "example.com", "s");
    let dom = out.iter().find(|x| x.kind == EntityKind::Domain).unwrap();
    assert_eq!(
        dom.evidence[0].attributes.get("cert_serial").map(String::as_str),
        Some("04ab9f")
    );
    // Validity window still present (preserved shape).
    assert_eq!(
        dom.evidence[0].attributes.get("not_after").map(String::as_str),
        Some("2024-04-01")
    );
}

#[test]
fn absent_serial_omits_the_attribute() {
    let e = entries(r#"[{"name_value":"a.example.com","issuer_name":"CA"}]"#);
    let out = build_entities(&e, "example.com", "s");
    let dom = out.iter().find(|x| x.kind == EntityKind::Domain).unwrap();
    assert!(!dom.evidence[0].attributes.contains_key("cert_serial"));
}

#[test]
fn cert_evidence_always_stamps_issuer_and_validity() {
    let entries: Vec<CrtEntry> = serde_json::from_str(
        r#"[{"issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"abc123"}]"#,
    )
    .unwrap();
    let ev = cert_evidence(&entries[0], "summary text");
    assert_eq!(ev.source, SRC);
    assert_eq!(ev.summary, "summary text");
    assert_eq!(
        ev.attributes.get("issuer").map(String::as_str),
        Some("Let's Encrypt")
    );
    assert_eq!(
        ev.attributes.get("not_before").map(String::as_str),
        Some("2024-01-01")
    );
    assert_eq!(
        ev.attributes.get("not_after").map(String::as_str),
        Some("2024-04-01")
    );
    assert_eq!(
        ev.attributes.get("cert_serial").map(String::as_str),
        Some("abc123")
    );
}

#[test]
fn cert_evidence_stamps_empty_strings_when_fields_absent_and_omits_blank_serial() {
    let entries: Vec<CrtEntry> = serde_json::from_str(r#"[{}]"#).unwrap();
    let ev = cert_evidence(&entries[0], "s");
    assert_eq!(ev.attributes.get("issuer").map(String::as_str), Some(""));
    assert_eq!(ev.attributes.get("not_before").map(String::as_str), Some(""));
    assert_eq!(ev.attributes.get("not_after").map(String::as_str), Some(""));
    assert!(
        !ev.attributes.contains_key("cert_serial"),
        "blank serial omitted"
    );
    let empty_serial: Vec<CrtEntry> = serde_json::from_str(r#"[{"serial_number":""}]"#).unwrap();
    let ev2 = cert_evidence(&empty_serial[0], "s");
    assert!(!ev2.attributes.contains_key("cert_serial"));
}
