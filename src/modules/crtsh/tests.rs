use crate::core::confidence;
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
fn parse_dn_org_extracts_first_nonempty_o_field() {
    // The X.509 DN org parser gates the entire issuer-Organisation emit branch.
    assert_eq!(parse_dn_org("C=US, O=Let's Encrypt, CN=E5"), Some("Let's Encrypt"));
    // First O= wins when several are present.
    assert_eq!(parse_dn_org("O=Acme Pty Ltd, O=Second"), Some("Acme Pty Ltd"));
    // No O= field → None.
    assert_eq!(parse_dn_org("CN=foo, C=AU"), None);
    // Empty O= value → None (not an empty-string Organisation).
    assert_eq!(parse_dn_org("CN=foo, O=, C=AU"), None);
}

#[test]
fn crt_entry_deser() {
    let json = r#"[{"common_name":"www.example.com","name_value":"www.example.com\nexample.com","issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"abc123"}]"#;
    let entries: Vec<CrtEntry> = serde_json::from_str(json).expect("should succeed");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].common_name.as_deref(), Some("www.example.com"));
    assert!(
        entries[0]
            .name_value
            .as_deref()
            .expect("should succeed")
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

#[test]
fn apex_base_extracts_the_true_host_for_each_seed_kind() {
    // A Domain seed is its own apex.
    assert_eq!(apex_base(TargetKind::Domain, "example.com"), "example.com");
    // A Url seed reduces to its host — NOT the full URL (the bug: the raw URL as
    // base made every discovered subdomain classify as an unrelated external).
    assert_eq!(
        apex_base(TargetKind::Url, "https://sub.example.com/path?q=1"),
        "sub.example.com"
    );
    // An Email seed reduces to its domain part (after the final `@`).
    assert_eq!(apex_base(TargetKind::Email, "jane.doe@example.com"), "example.com");
}

#[test]
fn url_seed_subdomains_are_classified_against_the_host_not_the_raw_url() {
    // Regression: with a Url seed, a discovered subdomain of the seed's host must be
    // recognised as a SUBDOMAIN (0.75, tagged) — the pivot the engine recurses into —
    // instead of a 0.45 external. Feeding the raw target.value (a full URL) as the
    // base is what previously suppressed that recursion.
    let json = r#"[{"name_value":"mail.example.com","common_name":"mail.example.com"}]"#;
    // Host is the apex `example.com`; the OLD code fed the raw URL
    // `https://example.com/login` as the base, so is_or_subdomain_of never matched.
    let base = apex_base(TargetKind::Url, "https://example.com/login");
    assert_eq!(base, "example.com");
    let ents = build_entities(&entries(json), &base, "s1");
    let mail = ents
        .iter()
        .find(|e| e.value == "mail.example.com")
        .expect("discovered subdomain must be present");
    assert!(
        mail.tags.iter().any(|t| t == crate::core::tags::SUBDOMAIN),
        "a Url seed's discovered subdomain must be tagged SUBDOMAIN, got {:?}",
        mail.tags
    );
    assert!(
        mail.confidence > 0.6,
        "subdomain confidence must be the boosted tier, got {}",
        mail.confidence
    );
}

fn entries(json: &str) -> Vec<CrtEntry> {
    serde_json::from_str(json).expect("should succeed")
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
    let api = by_val("api.example.com").expect("should succeed");
    assert!((api.confidence - confidence::VERY_HIGH).abs() < 1e-9);
    assert!(api.has_tag(tags::CT_LOG) && api.has_tag(tags::SUBDOMAIN));
    assert_eq!(
        api.evidence[0].attributes.get("issuer").map(String::as_str),
        Some("Let's Encrypt")
    );

    // Unrelated domain → lower confidence, no subdomain tag.
    let other = by_val("unrelated.org").expect("should succeed");
    assert!((other.confidence - confidence::LOW_MEDIUM).abs() < 1e-9);
    assert!(!other.has_tag(tags::SUBDOMAIN));
}

#[test]
fn subdomain_match_is_case_insensitive_against_base() {
    // Mixed-case target base must still classify the SAN as a subdomain.
    let e = entries(r#"[{"name_value":"api.example.com"}]"#);
    let out = build_entities(&e, "Example.COM", "s");
    let api = out.iter().find(|x| x.value == "api.example.com").expect("should succeed");
    assert!((api.confidence - confidence::VERY_HIGH).abs() < 1e-9);
    assert!(api.has_tag(tags::SUBDOMAIN));
}

#[test]
fn surfaces_san_emails_above_min_length() {
    // Non-role local-part deliberately (see `suppresses_role_mailbox_san_email`
    // below for the role-address case) — "admin" is a role token gated by
    // `is_infrastructure_email` and would no longer surface.
    let e = entries(
        r#"[{"name_value":"jdoe@example.com\na@b","issuer_name":"CA","not_before":"2024-01-01"}]"#,
    );
    let out = build_entities(&e, "example.com", "s");
    let email = out.iter().find(|x| x.kind == EntityKind::Email);
    let email = email.expect("should succeed");
    assert_eq!(email.value, "jdoe@example.com");
    assert!((email.confidence - confidence::HIGH_PLUS).abs() < 1e-9);
    assert!(email.has_tag(tags::CT_LOG));
    // "a@b" is below MIN_EMAIL_LEN → not surfaced.
    assert!(!out.iter().any(|x| x.value == "a@b"));
}

#[test]
fn suppresses_role_mailbox_san_email() {
    // A cert-admin desk (`hostmaster@`) is infrastructure contact, not the
    // subject's own mail — the same false-positive class `whois`/`dns_intel`
    // already gate on via `is_infrastructure_email`. Regression test for the
    // audit finding (role-mailbox-as-pii) that a CT-log SAN previously bypassed
    // that gate entirely.
    let e = entries(
        r#"[{"name_value":"api.example.com\nhostmaster@example.com","issuer_name":"CA","not_before":"2024-01-01"}]"#,
    );
    let out = build_entities(&e, "example.com", "s");
    assert!(
        !out.iter().any(|x| x.kind == EntityKind::Email),
        "a role-mailbox SAN must not surface as an Email entity"
    );
    assert!(
        out.iter().any(|x| x.value == "api.example.com"),
        "the co-listed real subdomain still emits as a Domain"
    );
}

#[test]
fn results_emit_all_confidence_first_uncapped() {
    // 250 distinct unrelated external domains (conf confidence::LOW_MEDIUM) plus one subdomain
    // (confidence::VERY_HIGH). NO per-module cap: EVERY distinct entity is emitted (each a real
    // BFS pivot the engine's frontier budget bounds, not this leaf module), with
    // the subdomain ranked first and the order confidence-descending.
    let n = 250usize;
    let mut sans: Vec<String> = (0..n).map(|i| format!("host{i}.other-{i}.net")).collect();
    sans.push("keep.example.com".to_string());
    let json = format!(r#"[{{"name_value":"{}"}}]"#, sans.join("\\n"));
    let out = build_entities(&entries(&json), "example.com", "s");
    assert_eq!(
        out.len(),
        n + 1,
        "every distinct domain emitted, none truncated"
    );
    assert_eq!(out[0].value, "keep.example.com"); // highest confidence first
    assert!(out.windows(2).all(|w| w[0].confidence >= w[1].confidence));
}

#[test]
fn emits_all_enterprise_ca_issuers_uncapped() {
    // 15 distinct non-public issuing CAs → all 15 Organisation entities emitted;
    // a prior `.take(10)` on issuers dropped five custom-PKI attribution pivots.
    let certs: Vec<String> = (0..15)
        .map(|i| {
            format!(
                r#"{{"name_value":"h{i}.example.com","issuer_name":"O=Acme Enterprise CA {i}, C=US"}}"#
            )
        })
        .collect();
    let json = format!("[{}]", certs.join(","));
    let out = build_entities(&entries(&json), "example.com", "s");
    let orgs = out
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
        .count();
    assert_eq!(
        orgs, 15,
        "every distinct enterprise-CA org emitted, not capped at 10"
    );
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
    let dom = out.iter().find(|x| x.kind == EntityKind::Domain).expect("should succeed");
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
    let dom = out.iter().find(|x| x.kind == EntityKind::Domain).expect("should succeed");
    assert!(!dom.evidence[0].attributes.contains_key("cert_serial"));
}

#[test]
fn cert_evidence_always_stamps_issuer_and_validity() {
    let entries: Vec<CrtEntry> = serde_json::from_str(
        r#"[{"issuer_name":"Let's Encrypt","not_before":"2024-01-01","not_after":"2024-04-01","serial_number":"abc123"}]"#,
    )
    .expect("should succeed");
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
    let entries: Vec<CrtEntry> = serde_json::from_str(r#"[{}]"#).expect("should succeed");
    let ev = cert_evidence(&entries[0], "s");
    assert_eq!(ev.attributes.get("issuer").map(String::as_str), Some(""));
    assert_eq!(ev.attributes.get("not_before").map(String::as_str), Some(""));
    assert_eq!(ev.attributes.get("not_after").map(String::as_str), Some(""));
    assert!(
        !ev.attributes.contains_key("cert_serial"),
        "blank serial omitted"
    );
    let empty_serial: Vec<CrtEntry> = serde_json::from_str(r#"[{"serial_number":""}]"#).expect("should succeed");
    let ev2 = cert_evidence(&empty_serial[0], "s");
    assert!(!ev2.attributes.contains_key("cert_serial"));
}
