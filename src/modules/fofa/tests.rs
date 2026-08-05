use crate::core::scan::{Target, TargetKind};

use super::*;

#[test]
fn encode_fofa_query_handles_host_filter() {
    use base64::Engine as _;
    let filter = "host=\"example.com\"";
    let encoded = encode_fofa_query(filter);
    // Verify it's valid base64 and encodes the input correctly
    assert!(!encoded.is_empty());
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("valid base64");
    assert_eq!(String::from_utf8_lossy(&decoded), filter);
}

#[test]
fn fofa_filter_builds_ip_query() {
    let target = Target::new(TargetKind::IpAddress, "1.2.3.4");
    let filter = fofa_filter(&target).expect("valid IP target");
    assert_eq!(filter, "ip=\"1.2.3.4\"");
}

#[test]
fn fofa_filter_builds_domain_query() {
    let target = Target::new(TargetKind::Domain, "example.com");
    let filter = fofa_filter(&target).expect("valid domain target");
    assert_eq!(filter, "host=\"example.com\"");
}

#[test]
fn fofa_filter_rejects_unsupported_target() {
    let target = Target::new(TargetKind::Email, "test@example.com");
    let filter = fofa_filter(&target);
    assert!(filter.is_none());
}

// ── Filter-injection hardening ──
//
// `Target::validate` restricts a seed Domain to ASCII alphanumeric/./-/_ and
// parses a seed IpAddress through `std::net::IpAddr` — neither can carry a
// `"`. But a PIVOT target built during expansion
// (`Target::new(tk, entity.value.clone())`, core/engine/mod.rs) is dispatched
// without going through that gate, and this very module mints Domain/IP
// entities straight from FOFA's own JSON response (`build_entities`, below).
// These tests construct that exact shape directly — a Target carrying a
// value `Target::validate` would already reject — to prove `fofa_filter`
// itself is safe independent of whether any particular caller validated
// first. Constructed via `Target { kind, value }` field literals rather than
// `Target::new(...)` followed by `.validate()`, since asserting the value
// SURVIVES unvalidated into the filter is exactly the point.

#[test]
fn fofa_filter_escapes_a_quote_that_would_close_the_filter_early() {
    let target = Target::new(TargetKind::Domain, "example.com\" || host=\"evil.com");
    let filter = fofa_filter(&target).expect("domain target");
    // The embedded quote must be escaped, not left to terminate the literal.
    assert_eq!(filter, "host=\"example.com\\\" || host=\\\"evil.com\"");
    // Decisive check: unescaped, exactly this substring would appear verbatim
    // and the filter would contain a live, unescaped `" || host="` splice.
    assert!(
        !filter.contains("\" || host=\""),
        "an unescaped injection substring must not survive into the filter: {filter}"
    );
}

#[test]
fn fofa_filter_escapes_a_literal_backslash_before_the_quote() {
    // Order matters: escaping the quote before the backslash would
    // double-escape the backslash this transform itself inserts. A value
    // ending in a backslash immediately before the closing position is the
    // case that catches getting the order wrong.
    let target = Target::new(TargetKind::IpAddress, "1.2.3.4\\");
    // IpAddress' own filter arm ignores parse-validity (fofa_filter is pure
    // and does not re-validate), so this constructs the same "value a real
    // Target::validate would reject" shape as the quote-injection test.
    let filter = fofa_filter(&target).expect("ip arm always returns Some");
    assert_eq!(filter, "ip=\"1.2.3.4\\\\\"");
}

#[test]
fn fofa_filter_leaves_an_ordinary_value_unescaped() {
    // No regression for the overwhelmingly common case: a clean domain/IP
    // round-trips with no backslashes inserted.
    assert_eq!(
        fofa_filter(&Target::new(TargetKind::Domain, "example.com")).unwrap(),
        "host=\"example.com\""
    );
    assert_eq!(
        fofa_filter(&Target::new(TargetKind::IpAddress, "1.2.3.4")).unwrap(),
        "ip=\"1.2.3.4\""
    );
}

#[test]
fn build_entities_emits_ip_domain_from_results() {
    let resp = FofaResp {
        error: false,
        errmsg: None,
        results: vec![FofaResult {
            host: "1.2.3.4:80".to_string(),
            ip: "1.2.3.4".to_string(),
            port: 80,
            protocol: "http".to_string(),
            title: "Example Site".to_string(),
            domain: "example.com".to_string(),
            os: "Linux".to_string(),
        }],
    };

    let result = build_entities(&resp, "test-scan");
    assert!(
        result.entities.len() >= 2,
        "should emit IP and domain entities"
    );

    let has_ip = result
        .entities
        .iter()
        .any(|e| e.kind == EntityKind::IpAddress);
    let has_domain = result.entities.iter().any(|e| e.kind == EntityKind::Domain);

    assert!(has_ip, "should have IpAddress entity");
    assert!(has_domain, "should have Domain entity");
}

#[test]
fn build_entities_skips_empty_results() {
    let resp = FofaResp {
        error: false,
        errmsg: None,
        results: vec![],
    };

    let result = build_entities(&resp, "test-scan");
    assert!(
        result.entities.is_empty(),
        "empty results should produce no entities"
    );
}

#[test]
fn build_entities_handles_error_response() {
    let resp = FofaResp {
        error: true,
        errmsg: Some("Invalid query".to_string()),
        results: vec![],
    };

    let result = build_entities(&resp, "test-scan");
    assert!(
        result.entities.is_empty(),
        "error response should produce no entities"
    );
}
