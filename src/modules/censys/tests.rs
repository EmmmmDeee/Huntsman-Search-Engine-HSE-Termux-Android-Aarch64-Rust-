use super::Censys;
use super::build_entities;
use super::types::CensysResp;
use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::geo::is_valid_coords;

#[test]
fn accepts_ip_only() {
    let m = Censys;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "user")));
}

#[test]
fn cost_is_key_gated() {
    assert!(matches!(Censys.cost(), ModuleCost::KeyGated));
}

#[test]
fn module_metadata() {
    let m = Censys;
    assert_eq!(m.name(), "censys");
    assert_eq!(m.priority(), 35);
    assert_eq!(m.max_timeout_ms(), 10_000);
    let desc = m.description();
    assert!(desc.contains("Censys"));
    assert!(desc.contains("port"));
}

#[test]
fn deserialise_full_response() {
    let json = r#"{
        "result": {
            "services": [
                {
                    "port": 80,
                    "service_name": "HTTP",
                    "transport_protocol": "TCP"
                },
                {
                    "port": 443,
                    "service_name": "HTTPS",
                    "transport_protocol": "TCP"
                },
                {
                    "port": 22,
                    "service_name": "SSH",
                    "transport_protocol": "TCP"
                }
            ],
            "location": {
                "coordinates": {
                    "latitude": -33.8688,
                    "longitude": 151.2093
                },
                "country": "Australia",
                "country_code": "AU",
                "city": "Sydney",
                "province": "New South Wales"
            }
        }
    }"#;

    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    assert_eq!(host.services.len(), 3);
    assert_eq!(host.services[0].port, Some(80));
    assert_eq!(host.services[0].service_name.as_deref(), Some("HTTP"));
    assert_eq!(host.services[0].transport_protocol.as_deref(), Some("TCP"));

    let loc = host.location.unwrap();
    assert_eq!(loc.country.as_deref(), Some("Australia"));
    assert_eq!(loc.country_code.as_deref(), Some("AU"));
    assert_eq!(loc.city.as_deref(), Some("Sydney"));
    let coords = loc.coordinates.unwrap();
    assert!((coords.latitude.unwrap() - (-33.8688)).abs() < 1e-4);
    assert!((coords.longitude.unwrap() - 151.2093).abs() < 1e-4);
}

#[test]
fn deserialise_empty_result() {
    let json = r#"{ "result": { "services": [], "location": null } }"#;
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    assert!(host.services.is_empty());
    assert!(host.location.is_none());
}

#[test]
fn deserialise_missing_fields() {
    let json = r#"{ "result": { "services": [{ "port": 53 }] } }"#;
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    assert_eq!(host.services.len(), 1);
    assert_eq!(host.services[0].port, Some(53));
    assert!(host.services[0].service_name.is_none());
    assert!(host.services[0].transport_protocol.is_none());
}

#[test]
fn deserialise_no_result() {
    let json = r"{}";
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    assert!(resp.result.is_none());
}

#[test]
fn coordinate_gate_rejects_null_island() {
    // Censys uses the shared validator for its coordinates gate: a 0,0
    // "unknown location" placeholder must NOT become a Coordinates entity,
    // while an in-range data-centre coord passes. (Validates the policy the
    // process() if-let chain depends on.)
    assert!(!is_valid_coords(0.0, 0.0));
    assert!(!is_valid_coords(91.0, 10.0));
    assert!(is_valid_coords(-33.8688, 151.2093));
}

// ── build_entities unit tests ────────────────────────────────────────────────

#[test]
fn build_entities_surfaces_asn_and_org() {
    let json = r#"{
        "result": {
            "services": [{ "port": 80, "service_name": "HTTP", "transport_protocol": "TCP" }],
            "autonomous_system": {
                "asn": 13335,
                "name": "CLOUDFLARENET",
                "bgp_prefix": "1.1.1.0/24",
                "country_code": "US",
                "description": "Cloudflare, Inc."
            }
        }
    }"#;
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    let result = build_entities(host, "1.1.1.1", "scan-test");

    let entities = &result.entities;
    let asn_entity = entities
        .iter()
        .find(|e| e.kind == EntityKind::Asn)
        .expect("ASN entity must be emitted");
    assert_eq!(asn_entity.value, "AS13335");
    assert!(
        asn_entity.tags.iter().any(|t| t == "country:US"),
        "ASN entity must carry country:US tag"
    );

    // bgp_prefix in evidence attrs
    assert!(
        asn_entity.evidence.iter().any(|ev| ev
            .attributes
            .iter()
            .any(|(k, v)| k == "bgp_prefix" && v == "1.1.1.0/24")),
        "bgp_prefix must appear as evidence attr on ASN entity"
    );

    // Organisation entity
    let org_entity = entities
        .iter()
        .find(|e| e.kind == EntityKind::Organisation)
        .expect("Organisation entity must be emitted");
    assert_eq!(org_entity.value, "CLOUDFLARENET");
}

#[test]
fn build_entities_surfaces_dns_names_as_domains() {
    let json = r#"{
        "result": {
            "services": [{ "port": 443, "service_name": "HTTPS", "transport_protocol": "TCP" }],
            "dns": {
                "reverse_dns": {
                    "names": ["one.one.one.one.", "dns.cloudflare.com"]
                }
            }
        }
    }"#;
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    let result = build_entities(host, "1.1.1.1", "scan-test");

    let entities = &result.entities;
    let domains: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .collect();
    assert_eq!(domains.len(), 2, "two Domain entities expected");

    let values: Vec<&str> = domains.iter().map(|e| e.value.as_str()).collect();
    assert!(
        values.contains(&"one.one.one.one"),
        "trailing dot must be stripped"
    );
    assert!(values.contains(&"dns.cloudflare.com"));

    // Each domain must carry the ptr tag and ip evidence attr.
    for dom in &domains {
        assert!(
            dom.tags.iter().any(|t| t == "ptr"),
            "Domain entity must be ptr-tagged"
        );
        assert!(
            dom.evidence.iter().any(|ev| ev
                .attributes
                .iter()
                .any(|(k, v)| k == "ip" && v == "1.1.1.1")),
            "Domain evidence must carry ip attr"
        );
    }
}

#[test]
fn build_entities_labels_tagged_on_ip() {
    let json = r#"{
        "result": {
            "services": [{ "port": 80, "service_name": "HTTP", "transport_protocol": "TCP" }],
            "labels": ["honeypot", "cdn"]
        }
    }"#;
    let resp: CensysResp = serde_json::from_str(json).unwrap();
    let host = resp.result.unwrap();
    let result = build_entities(host, "203.0.113.5", "scan-test");

    let entities = &result.entities;
    let ip_entity = entities
        .iter()
        .find(|e| e.kind == EntityKind::IpAddress)
        .expect("IpAddress entity must be emitted");

    assert!(
        ip_entity.tags.iter().any(|t| t == "censys:honeypot"),
        "host label 'honeypot' must appear as tag 'censys:honeypot'"
    );
    assert!(
        ip_entity.tags.iter().any(|t| t == "censys:cdn"),
        "host label 'cdn' must appear as tag 'censys:cdn'"
    );
}
