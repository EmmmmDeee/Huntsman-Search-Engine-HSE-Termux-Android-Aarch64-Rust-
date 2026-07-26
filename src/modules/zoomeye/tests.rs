use super::*;
use crate::core::scan::{Target, TargetKind};

/// A representative ZoomEye `host/search` match: nested `portinfo` + `geoinfo`.
fn sample_match() -> Value {
    serde_json::json!({
        "ip": "8.8.8.8",
        "portinfo": {"port": 443, "service": "https", "banner": "...", "app": "nginx"},
        "geoinfo": {
            "country": {"code": "US", "names": {"en": "United States"}},
            "city": {"names": {"en": "Ashburn"}},
            "location": {"lat": "39.0438", "lon": "-77.4874"},
            "organization": "Google LLC",
            "isp": "Google LLC",
            "asn": 15169
        }
    })
}

#[test]
fn accepts_ip_and_domain_only() {
    assert!(ZoomEye.accepts(&Target::new(TargetKind::IpAddress, "8.8.8.8")));
    assert!(ZoomEye.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!ZoomEye.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!ZoomEye.accepts(&Target::new(TargetKind::Username, "bob")));
}

#[test]
fn cost_is_key_gated_and_description_present() {
    assert!(matches!(ZoomEye.cost(), ModuleCost::KeyGated));
    assert!(!ZoomEye.description().is_empty());
}

#[test]
fn attack_techniques_are_all_catalogued_and_precise() {
    let ids = ZoomEye.attack_techniques();
    assert_eq!(ids, &["T1590.005", "T1591.001", "T1591.002", "T1596.005"]);
    for id in ids {
        assert!(
            crate::core::attack::technique(id).is_some(),
            "{id} absent from the ATT&CK catalogue"
        );
    }
}

#[test]
fn deserialises_matches() {
    let json = r#"{"total": 1, "matches": [{"ip":"8.8.8.8","portinfo":{"port":53}}]}"#;
    let resp: ZoomResp = serde_json::from_str(json).expect("should succeed");
    assert_eq!(resp.matches.len(), 1);
    assert_eq!(vstr(&resp.matches[0], "ip").as_deref(), Some("8.8.8.8"));
}

#[test]
fn error_body_deserialises_to_empty_matches() {
    let resp: ZoomResp = serde_json::from_str(r#"{"error":"invalid key","status":401}"#).expect("should succeed");
    assert!(resp.matches.is_empty());
}

#[test]
fn coords_read_nested_geoinfo_location_strings_or_numbers() {
    let (lat, lon) = coords(&sample_match()).expect("should succeed");
    assert!((lat - 39.0438).abs() < 1e-6 && (lon + 77.4874).abs() < 1e-6);
    // Numeric (not string) lat/lon also parse.
    let numeric = serde_json::json!({"geoinfo":{"location":{"lat":10.0,"lon":20.0}}});
    assert_eq!(coords(&numeric), Some((10.0, 20.0)));
    // No location → None (no false null-island fix).
    assert_eq!(coords(&serde_json::json!({"geoinfo":{}})), None);
}

#[test]
fn geo_address_combines_city_and_country() {
    assert_eq!(
        geo_address(&sample_match()).as_deref(),
        Some("Ashburn, United States")
    );
    // City only.
    let city_only = serde_json::json!({"geoinfo":{"city":{"names":{"en":"Berlin"}}}});
    assert_eq!(geo_address(&city_only).as_deref(), Some("Berlin"));
    // Country code fallback when no English name.
    let code_only = serde_json::json!({"geoinfo":{"country":{"code":"DE"}}});
    assert_eq!(geo_address(&code_only).as_deref(), Some("DE"));
    assert_eq!(geo_address(&serde_json::json!({"geoinfo":{}})), None);
}

#[test]
fn geo_asn_normalises_number_string_and_as_prefix() {
    assert_eq!(geo_asn(&sample_match()).as_deref(), Some("AS15169"));
    let as_str = serde_json::json!({"geoinfo":{"asn":"15169"}});
    assert_eq!(geo_asn(&as_str).as_deref(), Some("AS15169"));
    let prefixed = serde_json::json!({"geoinfo":{"asn":"AS15169"}});
    assert_eq!(geo_asn(&prefixed).as_deref(), Some("AS15169"));
    // Non-numeric / absent → None.
    assert_eq!(geo_asn(&serde_json::json!({"geoinfo":{"asn":"x"}})), None);
    assert_eq!(geo_asn(&serde_json::json!({"geoinfo":{}})), None);
}

#[test]
fn geo_org_prefers_organization_then_isp() {
    assert_eq!(geo_org(&sample_match()).as_deref(), Some("Google LLC"));
    let isp_only = serde_json::json!({"geoinfo":{"isp":"Telstra"}});
    assert_eq!(geo_org(&isp_only).as_deref(), Some("Telstra"));
    assert_eq!(geo_org(&serde_json::json!({"geoinfo":{}})), None);
}

#[test]
fn port_label_combines_port_and_service() {
    assert_eq!(port_label(&sample_match()).as_deref(), Some("443/https"));
    // Port without a service → bare port.
    let bare = serde_json::json!({"portinfo":{"port":22}});
    assert_eq!(port_label(&bare).as_deref(), Some("22"));
    // Port as a string still works.
    let str_port = serde_json::json!({"portinfo":{"port":"8080","service":"http-proxy"}});
    assert_eq!(port_label(&str_port).as_deref(), Some("8080/http-proxy"));
    assert_eq!(port_label(&serde_json::json!({"portinfo":{}})), None);
}

#[test]
fn port_app_and_banner_read_nested_portinfo_fields() {
    assert_eq!(port_app(&sample_match()).as_deref(), Some("nginx"));
    assert_eq!(port_banner(&sample_match()).as_deref(), Some("..."));
    // Absent → None (no fabricated app/banner).
    let bare = serde_json::json!({"portinfo": {"port": 22}});
    assert_eq!(port_app(&bare), None);
    assert_eq!(port_banner(&bare), None);
}

#[test]
fn port_detail_annotates_label_with_app_and_banner_when_present() {
    assert_eq!(
        port_detail(&sample_match(), "443/https").as_deref(),
        Some("443/https (nginx) — banner: ...")
    );
    // App only.
    let app_only = serde_json::json!({"portinfo": {"app": "OpenSSH"}});
    assert_eq!(
        port_detail(&app_only, "22").as_deref(),
        Some("22 (OpenSSH)")
    );
    // Banner only.
    let banner_only = serde_json::json!({"portinfo": {"banner": "SSH-2.0-OpenSSH_7.4"}});
    assert_eq!(
        port_detail(&banner_only, "22").as_deref(),
        Some("22 — banner: SSH-2.0-OpenSSH_7.4")
    );
    // Neither → None, not a bare duplicate of the label.
    assert_eq!(
        port_detail(&serde_json::json!({"portinfo": {}}), "80"),
        None
    );
}

#[test]
fn pstr_reads_nested_string_at_pointer_path() {
    let v = serde_json::json!({"a": {"b": "hi"}});
    assert_eq!(pstr(&v, "/a/b").as_deref(), Some("hi"));
    // Trimmed.
    let padded = serde_json::json!({"a": {"b": "  hi  "}});
    assert_eq!(pstr(&padded, "/a/b").as_deref(), Some("hi"));
    // Missing path → None.
    assert_eq!(pstr(&v, "/a/missing"), None);
    // Path resolves to a non-string (number) → None (not stringified).
    let num = serde_json::json!({"a": {"b": 42}});
    assert_eq!(pstr(&num, "/a/b"), None);
    // Present but blank after trim → None.
    let blank = serde_json::json!({"a": {"b": "   "}});
    assert_eq!(pstr(&blank, "/a/b"), None);
}

#[test]
fn geo_country_code_reads_geoinfo_country_code() {
    assert_eq!(geo_country_code(&sample_match()).as_deref(), Some("US"));
    let de = serde_json::json!({"geoinfo": {"country": {"code": "DE"}}});
    assert_eq!(geo_country_code(&de).as_deref(), Some("DE"));
    // Absent → None.
    assert_eq!(geo_country_code(&serde_json::json!({"geoinfo": {}})), None);
}
