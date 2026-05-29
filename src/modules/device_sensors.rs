//! Device location sensors — WiFi connection info and GPS/network fix via Termux.
//!
//! Merges the former `wifi_connect` and `gps_fix` modules into a single
//! passive sensor pass.  Invokes `termux-wifi-connectioninfo` (3 s ceiling)
//! followed by `termux-location -p network -r once` (15 s ceiling).
//!
//! Off-device behaviour: termux-api binary missing → no-op (no error).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::termux::termux_cmd;

const SRC: &str = "device_sensors";

pub struct DeviceSensors;

// ── WiFi deserialization ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ConnInfo {
    bssid: Option<String>,
    ssid: Option<String>,
    ip: Option<String>,
    frequency_mhz: Option<i64>,
    rssi: Option<i64>,
    link_speed_mbps: Option<i64>,
    supplicant_state: Option<String>,
}

// ── GPS deserialization ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct Fix {
    latitude: f64,
    longitude: f64,
    altitude: Option<f64>,
    accuracy: Option<f64>,
    speed: Option<f64>,
    bearing: Option<f64>,
    provider: Option<String>,
}

// ── Module impl ─────────────────────────────────────────────────────────

#[async_trait]
impl Module for DeviceSensors {
    fn name(&self) -> &'static str {
        "device_sensors"
    }
    fn description(&self) -> &'static str {
        "Device location sensors: WiFi connection info and GPS/network fix via Termux"
    }
    fn priority(&self) -> u8 {
        70
    }

    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Sensor
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Coordinates, EntityKind::MacAddress];
        KINDS
    }

    /// termux-location network provider typically returns in 1-5 s but
    /// can take 15 s indoors. Bump to 20 s for headroom.
    fn max_timeout_ms(&self) -> u64 {
        20_000
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        // ── Step 1: WiFi connection info (3 s timeout) ──────────────
        if let Some(stdout) = termux_cmd("termux-wifi-connectioninfo", &[], 3000).await {
            let wifi = parse_conn(&stdout, &ctx.scan_id);
            for e in wifi.entities {
                result.push(e);
            }
        }

        // ── Step 2: GPS / network location fix (15 s timeout) ───────
        if let Some(stdout) =
            termux_cmd("termux-location", &["-p", "network", "-r", "once"], 15_000).await
        {
            let fix = parse_fix(&stdout, &ctx.scan_id);
            for e in fix.entities {
                result.push(e);
            }
        }

        Ok(result)
    }
}

// ── WiFi parsing ────────────────────────────────────────────────────────

fn parse_conn(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let info: ConnInfo = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::new();
    let ssid = info.ssid.as_deref().unwrap_or("<hidden>");

    if let Some(ref bssid) = info.bssid
        && !bssid.is_empty()
        && bssid != "00:00:00:00:00:00"
        && bssid != "02:00:00:00:00:00"
    // "MAC restricted" placeholder
    {
        let mut e = Entity::new(EntityKind::MacAddress, bssid.as_str(), 0.95, scan_id);
        e.tag("wifi-connected");
        e.add_evidence(
            Evidence::new(SRC, format!("Connected to: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("frequency_mhz", info.frequency_mhz.unwrap_or(0).to_string())
                .with_attr("rssi_dbm", info.rssi.unwrap_or(0).to_string())
                .with_attr(
                    "link_speed_mbps",
                    info.link_speed_mbps.unwrap_or(0).to_string(),
                )
                .with_attr(
                    "supplicant_state",
                    info.supplicant_state.as_deref().unwrap_or("-"),
                ),
        );
        result.push(e);
    }

    if let Some(ref ip) = info.ip
        && !ip.is_empty()
        && ip != "0.0.0.0"
    {
        let mut e = Entity::new(EntityKind::IpAddress, ip.as_str(), 0.90, scan_id);
        e.tag("local-wifi");
        let mut ip_ev = Evidence::new(SRC, format!("Local IP on {ssid}")).with_attr("ssid", ssid);
        if let Some(ref bssid) = info.bssid {
            ip_ev = ip_ev.with_attr("bssid", bssid.as_str());
        }
        ip_ev = ip_ev
            .with_attr("frequency_mhz", info.frequency_mhz.unwrap_or(0).to_string())
            .with_attr("rssi_dbm", info.rssi.unwrap_or(0).to_string())
            .with_attr(
                "link_speed_mbps",
                info.link_speed_mbps.unwrap_or(0).to_string(),
            )
            .with_attr(
                "supplicant_state",
                info.supplicant_state.as_deref().unwrap_or("-"),
            );
        e.add_evidence(ip_ev);
        result.push(e);
    }

    result
}

// ── GPS parsing ─────────────────────────────────────────────────────────

fn parse_fix(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let fix: Fix = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let provider = fix.provider.as_deref().unwrap_or("network");
    // GPS provider gets higher confidence (cm-scale accuracy possible);
    // network provider is m-scale at best.
    let confidence = if provider == "gps" { 0.90 } else { 0.65 };
    let coords = format!("{:.7},{:.7}", fix.latitude, fix.longitude);

    let mut e = Entity::new(EntityKind::Coordinates, coords, confidence, scan_id);
    e.tag("geoint");
    e.tag(format!("provider:{provider}"));
    e.add_evidence(
        Evidence::new(SRC, format!("Location fix via {provider}"))
            .with_attr("latitude", fix.latitude.to_string())
            .with_attr("longitude", fix.longitude.to_string())
            .with_attr("altitude", fix.altitude.unwrap_or(0.0).to_string())
            .with_attr("accuracy_m", fix.accuracy.unwrap_or(0.0).to_string())
            .with_attr("speed", fix.speed.unwrap_or(0.0).to_string())
            .with_attr("bearing", fix.bearing.unwrap_or(0.0).to_string())
            .with_attr("provider", provider),
    );

    let mut result = ModuleResult {
        entities: Vec::with_capacity(1),
    };
    result.push(e);
    result
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    // ── DeviceSensors trait tests ───────────────────────────────────

    #[test]
    fn is_passive() {
        assert!(DeviceSensors.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(DeviceSensors.accepts(&Target::new(TargetKind::Domain, "x.com")));
        assert!(DeviceSensors.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(DeviceSensors.name(), "device_sensors");
        assert_eq!(DeviceSensors.priority(), 70);
    }

    #[test]
    fn max_timeout_is_20s() {
        assert_eq!(DeviceSensors.max_timeout_ms(), 20_000);
    }

    // ── WiFi parsing tests (from wifi_connect) ─────────────────────

    #[test]
    fn parses_connected_state() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","ip":"192.168.1.42",
            "frequency_mhz":2412,"rssi":-45,"link_speed_mbps":866,
            "supplicant_state":"COMPLETED"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities.len(), 2); // MAC + IP
    }

    #[test]
    fn parses_disconnected_state() {
        let json = br#"{"bssid":"02:00:00:00:00:00","ssid":"<unknown ssid>","ip":"0.0.0.0",
            "supplicant_state":"DISCONNECTED"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities.len(), 0); // both placeholders filtered
    }

    #[test]
    fn wifi_filters_all_zero_mac() {
        let json = br#"{"bssid":"00:00:00:00:00:00","ssid":"Test","ip":"10.0.0.1"}"#;
        let r = parse_conn(json, "test");
        // MAC filtered out, IP kept
        assert_eq!(r.entities.len(), 1);
        assert_eq!(r.entities[0].kind, EntityKind::IpAddress);
    }

    #[test]
    fn wifi_ssid_in_evidence() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"CafeNet","ip":"192.168.0.5",
            "frequency_mhz":5180,"rssi":-60,"link_speed_mbps":400,
            "supplicant_state":"COMPLETED"}"#;
        let r = parse_conn(json, "test");
        let mac_ev = &r.entities[0].evidence[0];
        assert_eq!(mac_ev.attributes.get("ssid").unwrap(), "CafeNet");
        assert_eq!(mac_ev.attributes.get("frequency_mhz").unwrap(), "5180");
    }

    #[test]
    fn wifi_evidence_source_is_device_sensors() {
        let json = br#"{"bssid":"aa:bb:cc:dd:ee:ff","ssid":"Net","ip":"10.0.0.1"}"#;
        let r = parse_conn(json, "test");
        assert_eq!(r.entities[0].evidence[0].source, "device_sensors");
        assert_eq!(r.entities[1].evidence[0].source, "device_sensors");
    }

    // ── GPS parsing tests (from gps_fix) ────────────────────────────

    #[test]
    fn network_fix_gets_lower_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":12.5,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn gps_fix_gets_higher_confidence() {
        let json = br#"{"latitude":-27.4698,"longitude":153.0251,"accuracy":2.0,
            "provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!((r.entities[0].confidence - 0.90).abs() < 1e-6);
    }

    #[test]
    fn coordinate_value_is_fixed_precision() {
        let json = br#"{"latitude":-27.469824123,"longitude":153.025198765,
            "provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-27.469824,153.025199");
    }

    #[test]
    fn entity_tags_and_kind() {
        let json = br#"{"latitude":51.5074,"longitude":-0.1278,"provider":"network"}"#;
        let r = parse_fix(json, "scan-gps");
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert!(e.has_tag("geoint"));
        assert!(e.has_tag("provider:network"));
        assert_eq!(e.scan_id, "scan-gps");
    }

    #[test]
    fn gps_provider_tag() {
        let json = br#"{"latitude":0.0,"longitude":0.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        assert!(r.entities[0].has_tag("provider:gps"));
    }

    #[test]
    fn evidence_attributes_populated() {
        let json = br#"{"latitude":37.7749,"longitude":-122.4194,"altitude":15.5,
            "accuracy":8.2,"speed":1.5,"bearing":90.0,"provider":"gps"}"#;
        let r = parse_fix(json, "test");
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.source, "device_sensors");
        assert_eq!(ev.attributes.get("latitude").unwrap(), "37.7749");
        assert_eq!(ev.attributes.get("longitude").unwrap(), "-122.4194");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "15.5");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "8.2");
        assert_eq!(ev.attributes.get("speed").unwrap(), "1.5");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "90");
        assert_eq!(ev.attributes.get("provider").unwrap(), "gps");
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let json = br#"{"latitude":10.0,"longitude":20.0}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        // Missing provider defaults to "network"
        assert_eq!(ev.attributes.get("provider").unwrap(), "network");
        assert_eq!(ev.attributes.get("altitude").unwrap(), "0");
        assert_eq!(ev.attributes.get("accuracy_m").unwrap(), "0");
        assert_eq!(ev.attributes.get("speed").unwrap(), "0");
        assert_eq!(ev.attributes.get("bearing").unwrap(), "0");
        // Missing provider means network confidence
        assert!((r.entities[0].confidence - 0.65).abs() < 1e-6);
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_fix(b"not json at all", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn empty_object_fails_missing_required_fields() {
        let r = parse_fix(b"{}", "test");
        // latitude and longitude are required (f64, not Option), so {} should fail deserialization
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn negative_coordinates_handled() {
        let json = br#"{"latitude":-33.8688,"longitude":151.2093,"provider":"network"}"#;
        let r = parse_fix(json, "test");
        assert_eq!(r.entities[0].value, "-33.868800,151.209300");
    }
}
