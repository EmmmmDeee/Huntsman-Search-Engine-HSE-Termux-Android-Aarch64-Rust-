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
