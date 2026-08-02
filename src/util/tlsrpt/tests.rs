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
