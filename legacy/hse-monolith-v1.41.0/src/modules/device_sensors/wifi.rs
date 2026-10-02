use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};

use super::SRC;

#[derive(Deserialize)]
pub(super) struct ConnInfo {
    pub(super) bssid: Option<String>,
    pub(super) ssid: Option<String>,
    pub(super) ip: Option<String>,
    pub(super) frequency_mhz: Option<i64>,
    pub(super) rssi: Option<i64>,
    pub(super) link_speed_mbps: Option<i64>,
    pub(super) supplicant_state: Option<String>,
}

/// Parse `termux-wifi-connectioninfo`'s JSON into the connected access point's
/// entities (BSSID / SSID / frequency band) — the Wi-Fi the device is on, a
/// strong co-location signal (a BSSID geolocates via wardriving databases).
///
/// Blank output from a tool that exited 0 is an honest empty `Ok` (Wi-Fi off,
/// nothing to report). Non-blank output that will not parse is a malfunction
/// and surfaces as an `Err`, so a broken tool is never reported as "not
/// connected". Pure given `stdout` — unit-testable without a device.
pub(super) fn parse_conn(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if super::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let info: ConnInfo = serde_json::from_slice(stdout)
        .map_err(|e| super::unparseable(super::Sensor::WifiConnection, &e))?;

    let mut result = ModuleResult::new();
    let ssid = info.ssid.as_deref().unwrap_or("<hidden>");

    if let Some(ref bssid) = info.bssid
        && !bssid.is_empty()
        && bssid != "00:00:00:00:00:00"
        && bssid != "02:00:00:00:00:00"
    {
        let mut e = Entity::new(
            EntityKind::MacAddress,
            bssid.as_str(),
            confidence::VERY_HIGH_PLUSPLUS,
            scan_id,
        );
        e.tag("wifi-connected");
        e.tag("geolocatable");
        let mut bssid_ev = Evidence::new(SRC, format!("Connected to: {ssid}"))
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
            );
        if let Some(band) = crate::util::wifi::band(info.frequency_mhz) {
            e.tag(format!("band:{band}"));
            bssid_ev = bssid_ev.with_attr("band", band);
        }
        e.add_evidence(bssid_ev);
        result.push(e);
    }

    if let Some(ref ip) = info.ip
        && !ip.is_empty()
        && ip != "0.0.0.0"
    {
        let mut e = Entity::new(
            EntityKind::IpAddress,
            ip.as_str(),
            confidence::VERY_HIGH_PLUS,
            scan_id,
        );
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

    Ok(result)
}
