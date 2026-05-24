//! Currently-connected Wi-Fi info — invokes `termux-wifi-connectioninfo`.
//! Yields both the connected AP (MacAddress, tagged `wifi-connected`) and
//! the device's local IP on that network (IpAddress, tagged `local-wifi`).
//!
//! Off-device behaviour: termux-api binary missing → no-op (no error).

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::termux::termux_cmd;

pub struct WifiConnect;

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

#[async_trait]
impl Module for WifiConnect {
    fn name(&self) -> &'static str {
        "wifi_connect"
    }
    fn description(&self) -> &'static str {
        "Termux current WiFi connection metadata"
    }
    fn priority(&self) -> u8 {
        70
    }

    fn description(&self) -> &'static str {
        "Termux currently-connected WiFi (passive) — BSSID, SSID, signal strength of the AP this device is associated with."
    }
    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(stdout) = termux_cmd("termux-wifi-connectioninfo", &[], 3000).await else {
            return Ok(ModuleResult::new());
        };
        Ok(parse_conn(&stdout, &ctx.scan_id))
    }
}

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
            Evidence::new("wifi_connect", format!("Connected to: {ssid}"))
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
        let mut ip_ev =
            Evidence::new("wifi_connect", format!("Local IP on {ssid}")).with_attr("ssid", ssid);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(WifiConnect.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(WifiConnect.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

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
}
