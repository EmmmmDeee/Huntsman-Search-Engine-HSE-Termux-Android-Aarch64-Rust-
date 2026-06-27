use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
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

/// Classify an 802.11 channel centre frequency (MHz) into its band.
/// Returns `None` for absent/zero/unrecognised frequencies so callers emit
/// no band tag rather than a misleading one.
pub(super) fn wifi_band(freq_mhz: Option<i64>) -> Option<&'static str> {
    match freq_mhz? {
        2400..=2500 => Some("2.4GHz"),
        4900..=5900 => Some("5GHz"),
        5925..=7125 => Some("6GHz"),
        _ => None,
    }
}

/// Parse `termux-wifi-connectioninfo`'s JSON into the connected access point's
/// entities (BSSID / SSID / frequency band) — the Wi-Fi the device is on, a
/// strong co-location signal (a BSSID geolocates via wardriving databases). Empty
/// result on unparseable JSON (tool absent / Wi-Fi off), so absence degrades to
/// "no signal". Pure given `stdout` — unit-testable without a device.
pub(super) fn parse_conn(stdout: &[u8], scan_id: &str) -> ModuleResult {
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
    {
        let mut e = Entity::new(EntityKind::MacAddress, bssid.as_str(), 0.95, scan_id);
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
        if let Some(band) = wifi_band(info.frequency_mhz) {
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
