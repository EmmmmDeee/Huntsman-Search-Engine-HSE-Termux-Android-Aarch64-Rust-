use super::types::{CensysResp, HostResult};
use super::{Censys, build_entities};
use crate::core::entity::{Entity, EntityKind};
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
    assert_eq!(m.priority(), 78);
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

// ── build_entities (pure extraction) ───────────────────────────────

fn host(json: &str) -> HostResult {
    let resp: CensysResp = serde_json::from_str(json).expect("fixture is valid CensysResp JSON");
    resp.result.expect("fixture carries a result")
}
fn of_kind(ents: &[Entity], kind: EntityKind) -> Option<&Entity> {
    ents.iter().find(|e| e.kind == kind)
}

#[test]
fn full_host_yields_ip_coords_and_address() {
    let ents = build_entities(
        &host(
            r#"{ "result": {
                "services": [
                    { "port": 443, "service_name": "HTTPS", "transport_protocol": "TCP" },
                    { "port": 80,  "service_name": "HTTP",  "transport_protocol": "TCP" },
                    { "port": 53,  "service_name": "DNS",   "transport_protocol": "UDP" }
                ],
                "location": {
                    "coordinates": { "latitude": -33.8688, "longitude": 151.2093 },
                    "country": "Australia", "country_code": "au",
                    "city": "Sydney", "province": "New South Wales"
                }
            } }"#,
        ),
        "8.8.8.8",
        "s",
    );
    assert_eq!(ents.len(), 3);

    let ip = of_kind(&ents, EntityKind::IpAddress).expect("subject IP");
    assert!(ip.has_tag("censys"));
    let attr = |k: &str| ip.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("port_count"), Some("3"));
    // Ports are sorted + deduped.
    assert_eq!(attr("ports"), Some("53,80,443"));
    assert_eq!(
        attr("services"),
        Some("443/TCP HTTPS; 80/TCP HTTP; 53/UDP DNS")
    );
    // Protocols are a sorted, deduplicated set.
    assert_eq!(attr("protocols"), Some("TCP,UDP"));

    let geo = of_kind(&ents, EntityKind::Coordinates).expect("coords");
    assert!(geo.has_tag("geoint") && geo.has_tag("censys"));
    assert!(geo.has_tag("country:AU"), "country code is uppercased");
    assert_eq!(geo.value, "-33.868800,151.209300");
    let gattr = |k: &str| geo.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(gattr("city"), Some("Sydney"));
    assert_eq!(gattr("province"), Some("New South Wales"));
    assert_eq!(gattr("source"), Some("censys"));

    let addr = of_kind(&ents, EntityKind::Address).expect("address");
    assert_eq!(addr.value, "Sydney, New South Wales, Australia");
    assert!(addr.has_tag("censys") && addr.has_tag("geoint"));
}

#[test]
fn empty_host_yields_nothing() {
    // Neither services nor location → the builder short-circuits.
    let ents = build_entities(
        &host(r#"{ "result": { "services": [], "location": null } }"#),
        "1.2.3.4",
        "s",
    );
    assert!(ents.is_empty());
}

#[test]
fn services_only_yields_just_the_ip() {
    let ents = build_entities(
        &host(r#"{ "result": { "services": [{ "port": 22 }] } }"#),
        "1.2.3.4",
        "s",
    );
    assert_eq!(ents.len(), 1);
    let ip = &ents[0];
    assert_eq!(ip.kind, EntityKind::IpAddress);
    let attr = |k: &str| ip.evidence[0].attributes.get(k).map(String::as_str);
    assert_eq!(attr("ports"), Some("22"));
    // Missing service_name/transport default to unknown/tcp in the service list.
    assert_eq!(attr("services"), Some("22/tcp unknown"));
    // No transport_protocol on any service → no `protocols` attribute.
    assert!(!ip.evidence[0].attributes.contains_key("protocols"));
}

#[test]
fn null_island_coordinates_yield_no_coords_entity() {
    // A 0,0 placeholder location with no services: the location is present
    // (so the builder does not short-circuit) but the invalid coords are
    // dropped, leaving no entities at all.
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": 0.0, "longitude": 0.0 },
                              "country": "Nowhere", "city": "Null", "country_code": "ZZ" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(of_kind(&ents, EntityKind::Coordinates).is_none());
    assert!(
        ents.is_empty(),
        "no services and an invalid coord → nothing"
    );
}

#[test]
fn coords_without_city_or_country_yield_no_address() {
    // Valid coordinates but the city/country needed for an Address are absent.
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country_code": "AU" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert!(of_kind(&ents, EntityKind::Coordinates).is_some());
    assert!(
        of_kind(&ents, EntityKind::Address).is_none(),
        "no city/country → no Address pivot"
    );
}

#[test]
fn address_omits_province_when_absent() {
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country": "Australia", "city": "Sydney" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    assert_eq!(
        of_kind(&ents, EntityKind::Address).unwrap().value,
        "Sydney, Australia"
    );
}

#[test]
fn blank_country_code_adds_no_tag_but_keeps_other_geo_attrs() {
    let ents = build_entities(
        &host(
            r#"{ "result": { "services": [],
                "location": { "coordinates": { "latitude": -33.87, "longitude": 151.2 },
                              "country_code": "", "city": "Sydney", "country": "Australia" } } }"#,
        ),
        "1.2.3.4",
        "s",
    );
    let geo = of_kind(&ents, EntityKind::Coordinates).expect("coords");
    assert!(
        !geo.tags.iter().any(|t| t.starts_with("country:")),
        "a blank country code adds no country tag"
    );
    // The blank country_code is skipped as an attribute, but city/country remain.
    assert!(!geo.evidence[0].attributes.contains_key("country_code"));
    assert_eq!(
        geo.evidence[0].attributes.get("city").map(String::as_str),
        Some("Sydney")
    );
}
