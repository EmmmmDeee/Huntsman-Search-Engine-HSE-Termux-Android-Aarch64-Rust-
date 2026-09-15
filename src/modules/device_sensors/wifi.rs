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
    // An SSID the tool did not report is reported as absent — not as
    // `<hidden>`, which names a different observation (a hidden network,
    // which Android reports as `<unknown ssid>`).
    let ssid = info
        .ssid
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    // Optional readings are recorded only when the tool supplied them
    // (backlog #16): a defaulted `rssi_dbm=0` would be the strongest possible
    // signal reading, `frequency_mhz=0` / `link_speed_mbps=0` measurements of
    // zero — none distinguishable from a real value once asserted. Same
    // `filter_map`/`fold` shape as `device_fix::parse_fix`.
    let readings = |ev: Evidence| -> Evidence {
        [
            ("ssid", ssid.map(str::to_string)),
            ("frequency_mhz", info.frequency_mhz.map(|v| v.to_string())),
            ("rssi_dbm", info.rssi.map(|v| v.to_string())),
            (
                "link_speed_mbps",
                info.link_speed_mbps.map(|v| v.to_string()),
            ),
            (
                "supplicant_state",
                info.supplicant_state
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key, v)))
        .fold(ev, |ev, (key, value)| ev.with_attr(key, value))
    };

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
        let mut bssid_ev = readings(Evidence::new(
            SRC,
            match ssid {
                Some(s) => format!("Connected to: {s}"),
                None => "Connected (SSID not reported)".to_string(),
            },
        ));
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
        let mut ip_ev = Evidence::new(
            SRC,
            match ssid {
                Some(s) => format!("Local IP on {s}"),
                None => "Local IP (SSID not reported)".to_string(),
            },
        );
        if let Some(ref bssid) = info.bssid {
            ip_ev = ip_ev.with_attr("bssid", bssid.as_str());
        }
        e.add_evidence(readings(ip_ev));
        result.push(e);
    }

    Ok(result)
}
