//! Internal data types for cell tower parsing.

use std::borrow::Cow;

use serde::Deserialize;

use super::helpers::json_to_str;

#[derive(Deserialize)]
pub(super) struct Cell {
    #[serde(rename = "type")]
    pub(super) cell_type: Option<String>,
    pub(super) registered: Option<bool>,
    pub(super) asu: Option<i64>,
    pub(super) dbm: Option<i64>,
    pub(super) level: Option<i64>,
    pub(super) cid: Option<i64>,
    pub(super) lac: Option<i64>,
    pub(super) tac: Option<i64>,
    pub(super) mcc: Option<serde_json::Value>, // can be string or int across Android versions
    pub(super) mnc: Option<serde_json::Value>,
    pub(super) pci: Option<i64>,
}

/// Parsed, validated identity of one cell tower. Bundling the fields that
/// `process()` and `parse_cells_survey()` both derive from a raw [`Cell`] keeps
/// the parse + skip policy in one place (it was duplicated) and keeps
/// `build_tower_device` to a small, clippy-clean argument list.
pub(super) struct TowerKey<'a> {
    pub(super) mcc: Cow<'a, str>,
    pub(super) mnc: Cow<'a, str>,
    pub(super) lac: i64,
    pub(super) cid: i64,
    pub(super) ctype: &'a str,
    pub(super) tower_id: String,
}

impl<'a> TowerKey<'a> {
    /// Parse a [`Cell`] into a usable tower identity, or `None` when it lacks the
    /// minimum keys (no MCC or no CID) — the survey skip condition, defined
    /// once. `lac` falls back to `tac` (LTE reports `tac`).
    pub(super) fn from_cell(cell: &'a Cell) -> Option<Self> {
        let mcc = json_to_str(&cell.mcc);
        if mcc.is_empty() {
            return None;
        }
        let cid = cell.cid.unwrap_or(0);
        if cid == 0 {
            return None;
        }
        let mnc = json_to_str(&cell.mnc);
        let lac = cell.lac.or(cell.tac).unwrap_or(0);
        let ctype = cell.cell_type.as_deref().unwrap_or("unknown");
        let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");
        Some(Self {
            mcc,
            mnc,
            lac,
            cid,
            ctype,
            tower_id,
        })
    }

    /// True once the tower has enough data to attempt geolocation (needs MNC
    /// and a non-zero LAC/TAC in addition to the survey minimums).
    pub(super) fn is_geolocatable(&self) -> bool {
        !self.mnc.is_empty() && self.lac != 0
    }

    /// OpenCelliD `radio` parameter for this tower's air interface.
    pub(super) fn radio_code(&self) -> &'static str {
        match self.ctype.to_lowercase().as_str() {
            "lte" => "LTE",
            "gsm" => "GSM",
            "umts" | "wcdma" => "UMTS",
            "nr" | "5g" => "NR",
            "cdma" => "CDMA",
            _ => "GSM",
        }
    }
}

#[derive(Deserialize)]
pub(super) struct OpenCellidResp {
    #[serde(default)]
    pub(super) lat: Option<f64>,
    #[serde(default)]
    pub(super) lon: Option<f64>,
    #[serde(default)]
    pub(super) range: Option<u64>,
    #[serde(default)]
    pub(super) status: Option<String>,
}
