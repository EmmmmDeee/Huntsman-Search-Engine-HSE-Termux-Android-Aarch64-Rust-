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
    module::{Module, ModuleContext, ModuleCost, ModuleResult},
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
    fn priority(&self) -> u8 {
        65
    }
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
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

    let mut result = ModuleResult::new();
    for ap in &aps {
        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, 0.95, scan_id);
        e.tag("wifi-ap");
        e.add_evidence(
            Evidence::new("wifi_scan", format!("Wi-Fi AP: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("bssid", &ap.bssid)
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
    fn passive_and_free() {
        assert!(WifiScan.is_passive());
        assert_eq!(WifiScan.cost(), ModuleCost::Free);
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
}
