//! Wi-Fi AP scanner for signal_radar — parses `termux-wifi-scaninfo` output.
//!
//! Field names are taken from the emitter (`termux-api`'s `WifiAPI.java`), not
//! assumed. Its scan rows carry `bssid`, `frequency_mhz`, `rssi`, `ssid`,
//! `timestamp`, `channel_bandwidth_mhz`, and — conditionally —
//! `center_frequency_mhz`, `capabilities`, `operator_name` and `venue_name`.
//!
//! Two of those were previously read under names the tool does not emit
//! (`frequency` and `channel_width`), so both deserialised to `None` on every
//! real scan: no AP ever received a band tag, and every AP recorded its channel
//! width as `"unknown"`. The fixtures used the wrong spelling too, so the tests
//! agreed with the parser and neither agreed with the tool.

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
    /// Channel centre frequency. The `frequency` alias is accepted so a row
    /// captured or exported under the old (wrong) spelling still parses.
    #[serde(rename = "frequency_mhz", alias = "frequency")]
    pub(super) frequency_mhz: Option<i64>,
    /// `"20"`, `"40"`, `"80"`, `"80+80"`, `"160"`, or `"???"` — a string, as
    /// `WifiAPI` writes it.
    #[serde(rename = "channel_bandwidth_mhz", alias = "channel_width")]
    pub(super) channel_bandwidth_mhz: Option<String>,
    pub(super) timestamp: Option<i64>,
    /// The 802.11 capability string (e.g. `[WPA2-PSK-CCMP][ESS]`), omitted by
    /// the tool when empty. Carries the AP's security posture, which is the
    /// difference between "a network is here" and "an OPEN network is here".
    #[serde(default)]
    pub(super) capabilities: Option<String>,
}

/// Coarse security posture parsed from an 802.11 capability string.
///
/// Deliberately coarse: the exact cipher suite is recorded verbatim in the
/// evidence attribute, and a tag is only useful if an operator can filter on
/// it. Checked strongest-first so a `[WPA3][WPA2]` transition-mode AP is
/// reported at the strength it actually offers rather than the weakest string
/// that happens to match.
pub(super) fn security_tag(capabilities: Option<&str>) -> Option<&'static str> {
    let caps = capabilities?.to_ascii_uppercase();
    if caps.contains("WPA3") || caps.contains("SAE") {
        Some("wifi-sec:wpa3")
    } else if caps.contains("WPA2") || caps.contains("RSN") {
        Some("wifi-sec:wpa2")
    } else if caps.contains("WPA") {
        Some("wifi-sec:wpa")
    } else if caps.contains("WEP") {
        Some("wifi-sec:wep")
    } else if caps.contains("ESS") || caps.contains("IBSS") {
        // A capability string with a BSS marker and no encryption suite at all
        // is an OPEN network. Reported only on that positive evidence — an
        // absent `capabilities` key means the tool said nothing, which is not
        // the same as an open AP.
        Some("wifi-sec:open")
    } else {
        None
    }
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
        if let Some(band) = wifi_band(ap.frequency_mhz) {
            e.tag(band);
        }
        if let Some(sec) = security_tag(ap.capabilities.as_deref()) {
            e.tag(sec);
        }

        let mut ev = Evidence::new(SRC, format!("Wi-Fi AP scan: {ssid}"))
            .with_attr("ssid", ssid)
            .with_attr("bssid", &ap.bssid)
            .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
            .with_attr("frequency_mhz", ap.frequency_mhz.unwrap_or(0).to_string())
            .with_attr(
                "channel_bandwidth_mhz",
                ap.channel_bandwidth_mhz.as_deref().unwrap_or("unknown"),
            )
            .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string());
        // The raw capability string, verbatim, beside the coarse tag: the tag
        // is what an operator filters on, the string is what they cite.
        if let Some(caps) = ap.capabilities.as_deref().filter(|c| !c.is_empty()) {
            ev = ev.with_attr("capabilities", caps);
        }

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
