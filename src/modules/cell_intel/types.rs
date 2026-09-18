//! Internal data types for cell tower parsing.

use std::borrow::Cow;

use serde::Deserialize;

/// The cell shape is single-sourced in [`crate::modules::device_cell`], shared
/// with `signal_radar`. Both modules parse the same tool into the same
/// `mcc-mnc-lac-cid` identity and had independently written the same wrong rule
/// for reading it — only `cid`, which no LTE or NR cell emits.
pub(super) use crate::modules::device_cell::Cell;
use crate::modules::device_cell::is_numeric_segment;

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
    /// Parse a [`Cell`] into a usable tower identity, or `None` when it lacks
    /// the minimum keys (no MCC or no cell identity) — the survey skip
    /// condition, defined once.
    ///
    /// Identity and area code both come from [`Cell`]'s accessors, which read
    /// whichever key the radio actually used: `cid` on GSM/WCDMA, `ci` on LTE,
    /// `nci` on NR, and `lac` or `tac` for the area. Reading `cid` alone — as
    /// this did — skipped every LTE and 5G cell, so on a modern handset there
    /// was never a tower to look up.
    pub(super) fn from_cell(cell: &'a Cell) -> Option<Self> {
        let mcc = cell.mcc_str();
        if !is_numeric_segment(&mcc) {
            return None;
        }
        let cid = cell.identity()?;
        let mnc = cell.mnc_str();
        let lac = cell.area_code();
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
    /// OpenCelliD signals a bad/unknown API key as a plain HTTP `200` whose
    /// entire body is `{"error":"API Key not known: <key>","code":2}` — no
    /// HTTP-level 401/403/429 at all. Live-confirmed 2026-07-15 (same shape
    /// `modules::opencellid::CellEntry::error` documents for the standalone
    /// module sharing this key). Every other field is naturally absent on
    /// this shape, so a bad key was previously indistinguishable from a
    /// genuine "no fix" `status: "error"` response.
    #[serde(default)]
    pub(super) error: Option<String>,
}
