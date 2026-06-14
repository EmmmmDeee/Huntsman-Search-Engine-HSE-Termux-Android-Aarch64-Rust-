use super::Censys;
use super::types::CensysResp;
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
