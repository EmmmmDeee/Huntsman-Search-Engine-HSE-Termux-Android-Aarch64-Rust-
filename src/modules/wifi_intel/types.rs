//! Serde types for `termux-wifi-scaninfo` and the WiGLE detail API.

use serde::Deserialize;

// ── Termux scan-info deserialization ────────────────────────────────────

#[derive(Deserialize)]
pub(super) struct Ap {
    pub(super) bssid: String,
    pub(super) ssid: Option<String>,
    /// `termux-wifi-scaninfo` emits this as `frequency_mhz` (see `WifiAPI.java`),
    /// not `frequency`. Read under the wrong name it was `None` on every real
    /// scan, so this module's `.with_attr("frequency_mhz", …)` recorded a
    /// constant `0` — an attribute correctly labelled and never populated. The
    /// alias keeps the old spelling parseable.
    #[serde(rename = "frequency_mhz", alias = "frequency")]
    pub(super) frequency_mhz: Option<i64>,
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
    #[serde(default)]
    pub(super) lastupdt: Option<String>,
    #[serde(default)]
    pub(super) encryption: Option<String>,
}
