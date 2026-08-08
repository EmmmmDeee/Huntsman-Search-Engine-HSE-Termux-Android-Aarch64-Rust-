//! Wi-Fi AP scanner for signal_radar — parses `termux-wifi-scaninfo` output.

use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
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
        Some(r) if r >= -50 => confidence::VERY_HIGH_PLUS,
        Some(r) if r >= -71 => confidence::VERY_HIGH,
        Some(r) if r >= -86 => confidence::MEDIUM_PLUS,
        _ => confidence::LOW_MEDIUM,
    }
}

/// Parse the JSON array from `termux-wifi-scaninfo` into entities.
pub(super) fn parse_scan(stdout: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if super::is_blank(stdout) {
        return Ok(ModuleResult::new());
    }
    let aps: Vec<Ap> = serde_json::from_slice(stdout)
        .map_err(|e| super::unparseable(super::Sensor::WifiScan, &e))?;

    let mut result = ModuleResult::with_capacity(aps.len());

    for ap in aps {
        if crate::util::oui::is_placeholder_bssid(&ap.bssid) {
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

        let ev = Evidence::new(SRC, format!("Wi-Fi AP scan: {ssid}"))
            .with_attr("ssid", ssid)
            .with_attr("bssid", &ap.bssid)
            .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
            .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
            .with_attr(
                "channel_width",
                ap.channel_width.as_deref().unwrap_or("unknown"),
            )
            .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string());

        // OUI classification, shared with the Bluetooth sensor via
        // [`super::tag_oui`] rather than copied into both: attribute the AP's
        // vendor/device class from a real hardware BSSID, or flag a
        // locally-administered BSSID as `randomized`.
        let ev = super::tag_oui(&mut e, ev, &ap.bssid);

        e.add_evidence(ev);

        result.push(e);

        // The SSID is a WiGLE-geolocatable pivot in its own right (a network
        // name search can surface every place that SSID was ever seen), so it
        // earns its own Ssid entity alongside the BSSID's MacAddress entity —
        // mirrors the precedent in `cli::import::push_ssids`. Skipped for the
        // hidden-network placeholder (`ap.ssid` is `None`, defaulted to
        // `"<hidden>"` above) and for an empty string; a real SSID confidence
        // sits well below the BSSID's own, since a name is easier to spoof or
        // duplicate than a hardware address.
        if !ssid.is_empty() && ssid != "<hidden>" {
            let mut se = Entity::new(EntityKind::Ssid, ssid, confidence::MEDIUM_HIGH, scan_id);
            se.tag(crate::core::tags::WIFI_AP);
            se.tag("device-sensor");

            se.add_evidence(
                Evidence::new(SRC, format!("Wi-Fi network name: {ssid}"))
                    .with_attr("bssid", &ap.bssid),
            );

            result.push(se);
        }
    }

    Ok(result)
}
