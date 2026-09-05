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

const SKIP_BSSIDS: &[&str] = &["00:00:00:00:00:00", "02:00:00:00:00:00"];

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
        if ap.bssid.is_empty() || SKIP_BSSIDS.contains(&ap.bssid.as_str()) {
            continue;
        }

        let ssid = ap.ssid.as_deref().unwrap_or("<hidden>");
        let confidence = rssi_confidence(ap.rssi);

        let mut e = Entity::new(EntityKind::MacAddress, &ap.bssid, confidence, scan_id);
        e.tag(crate::core::tags::WIFI_AP);
        e.tag("geolocatable");
        if let Some(band) = crate::util::wifi::band(ap.frequency) {
            e.tag(format!("band:{band}"));
        }
        // Specific 802.11 channel from the centre frequency, via the HSE BLE
        // Radar's verified frequency↔channel map (2.4/5/6 GHz) — `util::wifi::band`
        // (used just above) derives only the coarse band, never the channel number.
        let channel = ap
            .frequency
            .and_then(|f| u16::try_from(f).ok())
            .and_then(bleradar_core::wifi_frequency_to_channel);
        if let Some(ch) = channel {
            e.tag(format!("channel:{ch}"));
        }
        // Coarse RSSI proximity band from the BLE Radar's proximity model — an
        // honest signal-strength bucket (immediate/near/mid/far), never a
        // fabricated distance. Gives the radar the RSSI axis its Bluetooth path
        // structurally lacks (no-root Termux BT carries no RSSI), on the WiFi
        // sensor that does report it.
        let proximity = ap
            .rssi
            .map(|r| super::proximity_band_str(bleradar_core::proximity_label(r as f64)));
        if let Some(band) = proximity {
            e.tag(format!("proximity:{band}"));
        }

        let mut ev = Evidence::new(SRC, format!("Wi-Fi AP scan: {ssid}"))
            .with_attr("ssid", ssid)
            .with_attr("bssid", &ap.bssid)
            .with_attr("rssi_dbm", ap.rssi.unwrap_or(0).to_string())
            .with_attr("frequency_mhz", ap.frequency.unwrap_or(0).to_string())
            .with_attr(
                "channel",
                channel.map_or_else(|| "unknown".to_string(), |c| c.to_string()),
            )
            .with_attr("proximity", proximity.unwrap_or("unknown"))
            .with_attr(
                "channel_width",
                ap.channel_width.as_deref().unwrap_or("unknown"),
            )
            .with_attr("timestamp", ap.timestamp.unwrap_or(0).to_string());

        // OUI classification (parity with the WiGLE + Bluetooth paths): attribute
        // the AP's vendor/device class from a real hardware BSSID, or flag a
        // locally-administered BSSID as `randomized`. A randomized BSSID is a
        // privacy/rotating address, not a fixed access point — the exact
        // distinction AU-122 surfaces so it is never treated as a trackable pin.
        if let Some(oui) = crate::util::oui::classify_mac(&ap.bssid) {
            e.tag(format!("vendor:{}", oui.vendor));
            e.tag(format!("device:{}", oui.class.as_str()));
            let trackable = crate::util::oui::is_locally_administered(&ap.bssid) == Some(false);
            e.tag(if trackable { "trackable" } else { "randomized" });
            ev = ev
                .with_attr("vendor", oui.vendor)
                .with_attr("device_class", oui.class.as_str())
                .with_attr("trackable", trackable.to_string());
        }

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
