use super::Netlas;
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = Netlas;
    assert_eq!(m.name(), "netlas");
    assert_eq!(m.priority(), 79);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn build_entities_surfaces_previously_dropped_cert_issuer_and_http_fields() {
    use crate::core::entity::EntityKind;
    // fields=* fetches the cert issuer CA, the HTTP page title and status code;
    // they were decoded into the response structs but never surfaced. The pure
    // builder must now fold all three onto the IP entity's evidence.
    let body: super::NetlasResp = serde_json::from_value(serde_json::json!({
        "items": [{
            "data": {
                "ip": "203.0.113.10",
                "port": 443,
                "protocol": "tcp",
                "certificate": {
                    "subject": { "common_name": "example.com" },
                    "issuer": { "common_name": "Let's Encrypt R3" }
                },
                "http": { "title": "ACME Corporate Portal", "status_code": 200 }
            }
        }]
    }))
    .unwrap();
    let r = super::build_entities(&body, "203.0.113.10", "scan");
    let ip = r
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("ip entity");
    let attr = |k: &str| {
        ip.evidence[0]
            .attributes
            .get(k)
            .cloned()
            .unwrap_or_default()
    };
    assert_eq!(attr("ssl_issuer"), "Let's Encrypt R3");
    assert_eq!(attr("http_title"), "ACME Corporate Portal");
    assert_eq!(attr("http_status"), "200");
    // Pre-existing behaviour preserved: the subject CN still surfaces as ssl_cn.
    assert_eq!(attr("ssl_cn"), "example.com");
}

#[test]
fn netlas_query_by_kind() {
    use super::netlas_query;
    use crate::core::scan::Target;
    let ip_q = netlas_query(&Target::new(TargetKind::IpAddress, "1.2.3.4"));
    assert!(ip_q.starts_with("ip:"));
    let domain_q = netlas_query(&Target::new(TargetKind::Domain, "example.com"));
    assert!(domain_q.starts_with("host:"));
    let email_q = netlas_query(&Target::new(TargetKind::Email, "a@b.com"));
    assert!(email_q.starts_with("certificate.subject.email:"));
}
