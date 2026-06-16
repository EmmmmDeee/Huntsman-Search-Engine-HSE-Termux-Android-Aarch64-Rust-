use super::GeoIntel;
use super::ip_geo::{FreeIpApiResp, IpApiCoResp, build_freeipapi_entity, build_ipapico_entity};
use super::phone_geo::{phone_prefix_to_country, process_phone_prefix_only};
use crate::core::entity::EntityKind;
use crate::core::module::Module;
use crate::core::module::{ModuleContext, ModuleCost};
use crate::core::scan::{Target, TargetKind};
use crate::util::geo::is_valid_coords;

#[test]
fn accepts_ip_and_phone() {
    let m = GeoIntel;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
}

#[test]
fn rejects_non_ip_phone_targets() {
    let m = GeoIntel;
    assert!(!m.accepts(&Target::new(TargetKind::Coordinates, "0,0")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
    assert!(!m.accepts(&Target::new(TargetKind::FullName, "Alice Bob")));
}

#[test]
fn module_name_and_priority() {
    assert_eq!(GeoIntel.name(), "geo_intel");
    assert_eq!(GeoIntel.priority(), 22);
}

#[test]
fn cost_is_free() {
    assert!(matches!(GeoIntel.cost(), ModuleCost::Free));
}

#[test]
fn phone_prefix_au() {
    let (country, cc, lat, lon) = phone_prefix_to_country("61400000000").unwrap();
    assert_eq!(cc, "AU");
    assert!(country.contains("Australia"));
    assert!(lat < 0.0);
    assert!(lon > 100.0);
}

#[test]
fn phone_prefix_us() {
    let (_, cc, _, _) = phone_prefix_to_country("12025551234").unwrap();
    assert_eq!(cc, "US");
}

#[test]
fn caribbean_nanp_is_not_geolocated_to_the_us() {
    // Regression: a +1 number with a 4-digit Caribbean dialling prefix used to
    // fall through the 3-digit scan to `1` → US centroid. It must now return
    // None (no precise location) rather than an actively-wrong US fix.
    assert!(phone_prefix_to_country("12424567890").is_none()); // Bahamas (1242)
    assert!(phone_prefix_to_country("18764567890").is_none()); // Jamaica (1876)
    // A genuine US/Canada +1 number is unaffected.
    assert_eq!(phone_prefix_to_country("14165551234").unwrap().1, "US"); // Toronto (NANP)
}

#[test]
fn phone_prefix_uk() {
    let (_, cc, _, _) = phone_prefix_to_country("447911123456").unwrap();
    assert_eq!(cc, "GB");
}

#[test]
fn phone_prefix_3digit() {
    let (_, cc, _, _) = phone_prefix_to_country("971501234567").unwrap();
    assert_eq!(cc, "AE");
}

#[test]
fn phone_prefix_unknown() {
    assert!(phone_prefix_to_country("000").is_none());
}

fn offline_ctx() -> ModuleContext {
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    ModuleContext {
        scan_id: "t".into(),
        bus,
        http: crate::util::http::build_client(),
        keys: std::collections::HashMap::default(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
    }
}

#[tokio::test]
async fn national_number_without_marker_yields_no_coordinate() {
    // Regression: a US national number ("202-555-0100") has no '+'/'00'
    // marker. The old code stripped a (absent) '+' and matched "20" → Egypt,
    // emitting Cairo coordinates. It must now emit nothing.
    let ctx = offline_ctx();
    let t = Target::new(TargetKind::Phone, "202-555-0100");
    let out = process_phone_prefix_only(&t, &ctx).await.unwrap();
    assert!(
        out.entities.is_empty(),
        "national number must not produce a (wrong-country) coordinate: {:?}",
        out.entities
    );

    // An explicit E.164 number still geolocates (here Egypt, correctly).
    let t = Target::new(TargetKind::Phone, "+20 100 000 0000");
    let out = process_phone_prefix_only(&t, &ctx).await.unwrap();
    assert_eq!(out.entities.len(), 1);
    assert!(out.entities[0].has_tag("country:EG"));
}

#[test]
fn ip_geo_uses_shared_coord_validator() {
    // geo_intel now gates both IP sources on util::geo::is_valid_coords,
    // so out-of-range / Null-Island fixes from a hostile or buggy API are
    // rejected rather than becoming high-confidence Coordinates entities.
    assert!(is_valid_coords(-27.4766, 153.0166));
    assert!(!is_valid_coords(0.0, 0.0));
    assert!(!is_valid_coords(999.0, 10.0));
    assert!(!is_valid_coords(10.0, f64::NAN));
}

#[test]
fn ipapico_resp_deserializes() {
    let json = r#"{
        "ip": "1.1.1.1",
        "city": "South Brisbane",
        "region": "Queensland",
        "country_name": "Australia",
        "country_code": "AU",
        "postal": "4101",
        "latitude": -27.4766,
        "longitude": 153.0166,
        "timezone": "Australia/Brisbane",
        "org": "APNIC",
        "asn": "AS13335"
    }"#;
    let r: IpApiCoResp = serde_json::from_str(json).unwrap();
    assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
    assert_eq!(r.country_code.as_deref(), Some("AU"));
    assert_eq!(r.error, None);
}

#[test]
fn freeipapi_resp_deserializes() {
    let json = r#"{
        "ipAddress": "1.1.1.1",
        "latitude": -27.4766,
        "longitude": 153.0166,
        "countryName": "Australia",
        "countryCode": "AU",
        "cityName": "South Brisbane",
        "regionName": "Queensland",
        "zipCode": "4101",
        "timeZone": "+10:00",
        "isProxy": false
    }"#;
    let r: FreeIpApiResp = serde_json::from_str(json).unwrap();
    assert!((r.latitude.unwrap() - (-27.4766)).abs() < 0.001);
    assert_eq!(r.country_code.as_deref(), Some("AU"));
    assert_eq!(r.is_proxy, Some(false));
}

#[test]
fn ipapico_builder_emits_for_clean_ip_with_iso_and_skips_untrusted() {
    let json = r#"{"city":"South Brisbane","region":"Queensland","country_name":"Australia","country_code":"AU","postal":"4101","latitude":-27.4766,"longitude":153.0166,"timezone":"Australia/Brisbane","org":"APNIC","asn":"AS13335"}"#;
    let r: IpApiCoResp = serde_json::from_str(json).unwrap();
    let e = build_ipapico_entity(&r, "1.2.3.4", false, "t").expect("coords");
    assert_eq!(e.kind, EntityKind::Coordinates);
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("country_iso")
            .map(String::as_str),
        Some("AU")
    );
    assert!(e.tags.iter().any(|t| t == "country:AU"));
    assert!(e.tags.iter().any(|t| t.starts_with("au-state:")));
    assert!(build_ipapico_entity(&r, "104.16.0.1", true, "t").is_none());
    let err: IpApiCoResp = serde_json::from_str(r#"{"error":true}"#).unwrap();
    assert!(build_ipapico_entity(&err, "1.2.3.4", false, "t").is_none());
}

#[test]
fn freeipapi_builder_suppresses_proxy_and_untrusted() {
    let clean = r#"{"latitude":-27.47,"longitude":153.02,"countryName":"Australia","countryCode":"AU","cityName":"South Brisbane","isProxy":false}"#;
    let r: FreeIpApiResp = serde_json::from_str(clean).unwrap();
    assert!(build_freeipapi_entity(&r, "1.2.3.4", false, "t").is_some());
    assert!(build_freeipapi_entity(&r, "104.16.0.1", true, "t").is_none());
    let proxy: FreeIpApiResp = serde_json::from_str(
        r#"{"latitude":52.37,"longitude":4.89,"countryCode":"NL","isProxy":true}"#,
    )
    .unwrap();
    assert!(build_freeipapi_entity(&proxy, "1.2.3.4", false, "t").is_none());
}
