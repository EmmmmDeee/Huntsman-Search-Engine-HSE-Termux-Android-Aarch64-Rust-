//! Wi-Fi AP scanner for signal_radar — parses `termux-wifi-scaninfo` output.

use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::SRC;

#[derive(Deserialize)]
pub(super) struct Ap {
    pub(super) bssid: String,
    pub(super) ssid: Option<String>,
    pub(super) rssi: Option<i64>,
    pub(super) frequency: Option<i64>,
    pub(super) channel_width: Option<String>,
    pub(super) timestamp: Option<i64>,
}

const SKIP_BSSIDS: &[&str] = &["00:00:00:00:00:00", "02:00:00:00:00:00"];

/// Classify an 802.11 channel centre frequency (MHz) into its band tag.
pub(super) fn wifi_band(freq_mhz: Option<i64>) -> Option<&'static str> {
    match freq_mhz? {
        2400..=2500 => Some("band:2.4GHz"),
        4900..=5900 => Some("band:5GHz"),
        5925..=7125 => Some("band:6GHz"),
        _ => None,
    }
}

/// Confidence from RSSI (dBm): stronger signal = more reliable observation.
pub(super) fn rssi_confidence(rssi: Option<i64>) -> f64 {
    match rssi {
        Some(r) if r >= -50 => 0.90,
        Some(r) if r >= -71 => 0.75,
        Some(r) if r >= -86 => 0.60,
        _ => 0.45,
    }
}

/// Parse the JSON array from `termux-wifi-scaninfo` into entities.
pub(super) fn parse_scan(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let aps: Vec<Ap> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::with_capacity(aps.len());

    for ap in aps {
        if ap.bssid.is_empty() || SKIP_BSSIDS.contains(&ap.bssid.as_str()) {
            continue;
        }

        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let confidence = rssi_confidence(ap.rssi);

        let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, confidence, scan_id);
        e.tag(crate::core::tags::WIFI_AP);
        e.tag("geolocatable");
        if let Some(band) = wifi_band(ap.frequency) {
            e.tag(band);
        }

        e.add_evidence(
            Evidence::new(SRC, format!("Wi-Fi AP scan: {ssid}"))
                .with_attr("ssid", ssid)
                .with_attr("bssid", &ap.bssid)
                .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
                .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
                .with_attr(
                    "channel_width",
                    ap.channel_width.as_deref().unwrap_or("unknown"),
                )
                .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string()),
        );

        result.push(e);
    }

    result
}
