//! Serde types for `termux-wifi-scaninfo` and the WiGLE detail API.

use serde::Deserialize;

// ── Termux scan-info deserialization ────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct Ap {
    pub(super) bssid: String,
    pub(super) ssid: Option<String>,
    pub(super) frequency: Option<i64>,
    pub(super) rssi: Option<i64>,
    pub(super) timestamp: Option<i64>,
}

// ── WiGLE detail-API response ──────────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct DetailResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) results: Vec<DetailNetwork>,
}

#[derive(Deserialize)]
pub(super) struct DetailNetwork {
    #[serde(default)]
    pub(super) trilat: Option<f64>,
    #[serde(default)]
    pub(super) trilong: Option<f64>,
    #[serde(default)]
    pub(super) ssid: Option<String>,
    #[serde(default)]
    pub(super) city: Option<String>,
    #[serde(default)]
    pub(super) region: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default)]
    pub(super) postalcode: Option<String>,
    // Street-level components WiGLE's detail response carries for a located AP —
    // the precise physical address, previously dropped in favour of city/region.
    #[serde(default)]
    pub(super) road: Option<String>,
    #[serde(default)]
    pub(super) housenumber: Option<String>,
    #[serde(default)]
    pub(super) lastupdt: Option<String>,
    #[serde(default)]
    pub(super) encryption: Option<String>,
}
