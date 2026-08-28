use super::*;

#[test]
fn is_tlsrpt_matches_version_case_insensitively() {
    assert!(is_tlsrpt("v=TLSRPTv1; rua=mailto:a@b.com"));
    assert!(is_tlsrpt("V=tlsrptV1; rua=mailto:a@b.com"));
    assert!(is_tlsrpt("  v=TLSRPTv1; rua=mailto:a@b.com")); // leading ws tolerated
    assert!(!is_tlsrpt("v=DMARC1; p=none"));
    assert!(!is_tlsrpt("v=spf1 -all"));
    assert!(!is_tlsrpt(""));
}

#[test]
fn parse_mailto_rua_yields_email() {
    // Verbatim live shape from google.com's _smtp._tls record.
    let r = parse("v=TLSRPTv1;rua=mailto:sts-reports@google.com").expect("should succeed");
    assert_eq!(r.emails, vec!["sts-reports@google.com".to_string()]);
    assert!(r.urls.is_empty());
}

#[test]
fn parse_https_rua_yields_url() {
    // Verbatim live shape from microsoft.com's _smtp._tls record.
    let r = parse("v=TLSRPTv1; rua=https://tlsrpt.azurewebsites.net/report").expect("should succeed");
    assert!(r.emails.is_empty());
    assert_eq!(
        r.urls,
        vec!["https://tlsrpt.azurewebsites.net/report".to_string()]
    );
}

#[test]
fn parse_mixed_and_multi_rua_destinations() {
    let r = parse(
        "v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://report.example.net/v1,mailto:sec@example.com",
    )
    .expect("should succeed");
    assert_eq!(r.emails, vec!["tlsrpt@example.com", "sec@example.com"]);
    assert_eq!(r.urls, vec!["https://report.example.net/v1"]);
}

#[test]
fn parse_rejects_non_tlsrpt() {
    assert_eq!(parse("v=DMARC1; p=reject; rua=mailto:d@e.com"), None);
    assert_eq!(parse("random text"), None);
}

#[test]
fn parse_valid_version_without_rua_is_empty_not_none() {
    let r = parse("v=TLSRPTv1;").expect("should succeed");
    assert!(r.emails.is_empty() && r.urls.is_empty());
}

#[test]
fn parse_skips_malformed_mailto() {
    // No '@', too short → skipped; the good one survives.
    let r = parse("v=TLSRPTv1; rua=mailto:bogus,mailto:ok@ex.com").expect("should succeed");
    assert_eq!(r.emails, vec!["ok@ex.com".to_string()]);
}

#[test]
fn report_entities_builds_gated_email_and_domain_at_named_confidence() {
    use crate::core::confidence;
    use crate::core::entity::EntityKind;

    let out = report_entities(
        &["v=TLSRPTv1; rua=mailto:tlsrpt@fabrikam.example,https://tlsrpt.azurewebsites.net/report"
            .to_string()],
        "fabrikam.example",
        "scan",
        "unit_test",
    );

    let email = out
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .expect("mailto rua → Email");
    assert_eq!(email.value, "tlsrpt@fabrikam.example");
    assert!(email.has_tag("dns") && email.has_tag("tlsrpt-report"));
    // The single canonical rung both DNS transports now share — no bare literal.
    assert!((email.confidence - confidence::ATTRIBUTED).abs() < 1e-9);

    let dom = out
        .iter()
        .find(|e| e.kind == EntityKind::Domain)
        .expect("https rua → Domain lead");
    assert_eq!(dom.value, "tlsrpt.azurewebsites.net");
    assert!((dom.confidence - confidence::MEDIUM_SOLID).abs() < 1e-9);
}

#[test]
fn report_entities_gates_infrastructure_mailboxes_and_self_endpoints() {
    use crate::core::entity::EntityKind;

    // A provider-desk reporting mailbox is dropped (not clustered as the subject),
    // and an endpoint host equal to the queried domain is not re-emitted — the
    // parity contract both DNS transports document.
    let out = report_entities(
        &["v=TLSRPTv1; rua=mailto:sts-reports@google.com,https://google.com/tlsrpt".to_string()],
        "google.com",
        "scan",
        "unit_test",
    );
    assert!(out.iter().all(|e| e.kind != EntityKind::Email), "infra mailbox gated");
    assert!(
        out.iter().all(|e| e.value != "google.com"),
        "self-reporting endpoint host is not re-emitted"
    );
}

#[test]
fn report_entities_takes_the_first_parseable_record_and_ignores_the_rest() {
    use crate::core::entity::EntityKind;

    // A leading non-TLSRPT TXT is skipped; the first TLSRPT record wins and a
    // second TLSRPT record is ignored (one valid record per domain).
    let out = report_entities(
        &[
            "v=spf1 -all".to_string(),
            "v=TLSRPTv1; rua=mailto:first@ex.com".to_string(),
            "v=TLSRPTv1; rua=mailto:second@ex.com".to_string(),
        ],
        "ex.com",
        "scan",
        "unit_test",
    );
    let emails: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Email)
        .map(|e| e.value.as_str())
        .collect();
    assert_eq!(emails, vec!["first@ex.com"]);
}

#[test]
fn report_entities_emits_one_domain_per_distinct_endpoint_host() {
    use crate::core::entity::EntityKind;

    // A rua list pointing several report URLs at the SAME collector host (two
    // paths here) must yield ONE Domain lead, matching the documented "distinct
    // host" contract — a repeated host must not mint duplicate Domain entities.
    let out = report_entities(
        &["v=TLSRPTv1; rua=https://tlsrpt.example.net/a,https://tlsrpt.example.net/b,https://other.example.org/r"
            .to_string()],
        "fabrikam.example",
        "scan",
        "unit_test",
    );
    let mut domains: Vec<&str> = out
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    domains.sort_unstable();
    assert_eq!(domains, vec!["other.example.org", "tlsrpt.example.net"]);
}
