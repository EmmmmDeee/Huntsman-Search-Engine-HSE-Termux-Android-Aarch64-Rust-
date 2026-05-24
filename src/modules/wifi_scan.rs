//! Wi-Fi access-point scanner — invokes `termux-wifi-scaninfo` (Termux:API
//! package). Each visible AP becomes a `MacAddress` entity tagged `wifi-ap`
//! with SSID / frequency / signal in evidence.
//!
//! Off-device, or with `termux-api` uninstalled, the binary is absent and
//! the module no-ops via the [`termux_cmd`](crate::util::termux::termux_cmd)
//! helper — no `module_error` event.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::termux::termux_cmd;

pub struct WifiScan;

#[derive(Deserialize)]
struct Ap {
    bssid: String,
    ssid: Option<String>,
    frequency: Option<i64>,
    rssi: Option<i64>,
    timestamp: Option<i64>,
}

#[async_trait]
impl Module for WifiScan {
    fn name(&self) -> &'static str {
        "wifi_scan"
    }
    fn description(&self) -> &'static str {
        "Termux WiFi access point survey"
    }
    fn priority(&self) -> u8 {
        65
    }

    fn description(&self) -> &'static str {
        "Termux WiFi scan — list of nearby APs with BSSID / SSID / RSSI / frequency. Passive sensor."
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(stdout) = termux_cmd("termux-wifi-scaninfo", &[], 3000).await else {
            return Ok(ModuleResult::new());
        };
        Ok(parse_aps(&stdout, &ctx.scan_id))
    }
}

fn parse_aps(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let aps: Vec<Ap> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult {
        entities: Vec::with_capacity(aps.len()),
    };
    for ap in aps {
        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, 0.95, scan_id);
        e.tag("wifi-ap");
        e.add_evidence(
            Evidence::new("wifi_scan", format!("Wi-Fi AP: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("bssid", ap.bssid)
                .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
        );
        result.push(e);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(WifiScan.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(WifiScan.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    #[test]
    fn parses_sample_payload() {
        let json = br#"[
            {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"MyNet","frequency":2412,"rssi":-45,"timestamp":1},
            {"bssid":"11:22:33:44:55:66","ssid":null,"frequency":5180,"rssi":-72,"timestamp":2}
        ]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 2);
        assert_eq!(r.entities[0].kind, EntityKind::MacAddress);
        assert_eq!(r.entities[0].value, "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_aps(b"not json", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(WifiScan.name(), "wifi_scan");
        assert_eq!(WifiScan.priority(), 65);
    }

    #[test]
    fn parses_three_aps_with_all_fields() {
        let json = br#"[
            {"bssid":"aa:bb:cc:dd:ee:ff","ssid":"HomeNet","frequency":2437,"rssi":-42,"timestamp":100},
            {"bssid":"11:22:33:44:55:66","ssid":"Office5G","frequency":5745,"rssi":-68,"timestamp":200},
            {"bssid":"de:ad:be:ef:ca:fe","ssid":"CafeWifi","frequency":2462,"rssi":-55,"timestamp":300}
        ]"#;
        let r = parse_aps(json, "scan-001");
        assert_eq!(r.entities.len(), 3);

        // Verify first AP entity
        let ap0 = &r.entities[0];
        assert_eq!(ap0.kind, EntityKind::MacAddress);
        assert_eq!(ap0.value, "aa:bb:cc:dd:ee:ff");
        assert!((ap0.confidence - 0.95).abs() < 1e-6);
        assert!(ap0.has_tag("wifi-ap"));
        assert_eq!(ap0.scan_id, "scan-001");

        // Verify evidence attributes on first AP
        let ev0 = &ap0.evidence[0];
        assert_eq!(ev0.source, "wifi_scan");
        assert_eq!(ev0.attributes.get("ssid").unwrap(), "HomeNet");
        assert_eq!(ev0.attributes.get("bssid").unwrap(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(ev0.attributes.get("frequency_mhz").unwrap(), "2437");
        assert_eq!(ev0.attributes.get("rssi_dbm").unwrap(), "-42");
        assert_eq!(ev0.attributes.get("timestamp").unwrap(), "100");

        // Verify third AP (5 GHz band)
        let ap2 = &r.entities[2];
        assert_eq!(ap2.value, "de:ad:be:ef:ca:fe");
        assert_eq!(
            ap2.evidence[0].attributes.get("frequency_mhz").unwrap(),
            "2462"
        );
    }

    #[test]
    fn hidden_ssid_shows_placeholder() {
        let json = br#"[{"bssid":"ff:ff:ff:ff:ff:ff","ssid":null,"frequency":2412,"rssi":-80,"timestamp":0}]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.attributes.get("ssid").unwrap(), "<hidden>");
        assert!(ev.summary.contains("<hidden>"));
    }

    #[test]
    fn missing_optional_fields_default_to_zero() {
        let json = br#"[{"bssid":"ab:cd:ef:01:23:45"}]"#;
        let r = parse_aps(json, "test");
        assert_eq!(r.entities.len(), 1);
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.attributes.get("frequency_mhz").unwrap(), "0");
        assert_eq!(ev.attributes.get("rssi_dbm").unwrap(), "0");
        assert_eq!(ev.attributes.get("timestamp").unwrap(), "0");
    }

    #[test]
    fn empty_json_array_no_ops() {
        let r = parse_aps(b"[]", "test");
        assert_eq!(r.entities.len(), 0);
    }
}
