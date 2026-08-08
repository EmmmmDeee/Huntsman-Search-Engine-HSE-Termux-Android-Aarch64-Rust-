//! Cell tower scanner for signal_radar — reads `termux-telephony-cellinfo`,
//! which already carries per-cell `dbm`/signal data (see [`Cell::dbm`]).
//!
//! # The identity field is named differently per radio
//!
//! Read from the emitting source (`termux-api`'s `TelephonyAPI.java`) rather
//! than assumed, because the assumption was wrong and cost every LTE and 5G
//! sighting:
//!
//! | radio | cell identity | area code | mcc/mnc |
//! |---|---|---|---|
//! | GSM   | `cid` | `lac` | int |
//! | WCDMA | `cid` | `lac` | int |
//! | LTE   | **`ci`**  | `tac` | int |
//! | NR/5G | **`nci`** | `tac` | String (`getMccString`) |
//! | CDMA  | — (`basestation`/`network`/`system`, no mcc/mnc) | — | — |
//!
//! This parser previously read only `cid`, so on any LTE or 5G cell the
//! identity was absent, the `cid == 0` guard fired, and the row was skipped in
//! silence. On a modern handset — which is every device this project targets —
//! that is the whole cell sensor: it could only ever report GSM and WCDMA
//! neighbours, and reported "no towers" as though it had looked.
//!
//! CDMA is deliberately still skipped: it carries no MCC/MNC at all, so it
//! cannot form the `mcc-mnc-lac-cid` identity this module emits, and the
//! networks are decommissioned.
//!
//! # Sentinels
//!
//! `TelephonyAPI` wraps most fields in `writeIfKnown`, which OMITS the key when
//! the platform reports `Integer.MAX_VALUE` ("unavailable") — so an absent
//! field, not a sentinel value, is the normal unavailable case and `Option`
//! handles it. `dbm` is the documented exception: for LTE, NR and CDMA it is
//! written unconditionally, so `2147483647` reaches this parser as a real
//! number and must be rejected here. See [`Cell::usable_dbm`].

use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};

use super::SRC;

/// Android's "value unavailable" sentinel, as an `i64`. `writeIfKnown` filters
/// this out for every field it guards; `dbm` on LTE/NR/CDMA is not guarded.
const UNAVAILABLE: i64 = i32::MAX as i64;

#[derive(Deserialize)]
pub(super) struct Cell {
    #[serde(rename = "type")]
    pub(super) cell_type: Option<String>,
    pub(super) registered: Option<bool>,
    pub(super) dbm: Option<i64>,
    /// GSM / WCDMA cell identity.
    pub(super) cid: Option<i64>,
    /// LTE cell identity (`CellIdentityLte.getCi()`).
    pub(super) ci: Option<i64>,
    /// NR cell identity (`CellIdentityNr.getNci()`).
    pub(super) nci: Option<i64>,
    pub(super) lac: Option<i64>,
    pub(super) tac: Option<i64>,
    pub(super) mcc: Option<serde_json::Value>,
    pub(super) mnc: Option<serde_json::Value>,
}

impl Cell {
    /// The cell identity under whichever key this radio uses.
    ///
    /// `0` is treated as absent alongside `None`: it is not a valid cell
    /// identity on any of these radios and was already the parser's sentinel
    /// for "missing", so keeping that meaning here preserves the existing
    /// skip behaviour rather than quietly starting to emit `…-0` towers.
    fn identity(&self) -> Option<i64> {
        self.cid
            .or(self.ci)
            .or(self.nci)
            .filter(|&v| v != 0 && v != UNAVAILABLE)
    }

    /// The area code (`lac` on GSM/WCDMA, `tac` on LTE/NR).
    fn area_code(&self) -> i64 {
        self.lac
            .or(self.tac)
            .filter(|&v| v != UNAVAILABLE)
            .unwrap_or(0)
    }

    /// Signal strength in dBm, or `None` when the platform had none.
    ///
    /// `TelephonyAPI` writes `dbm` unconditionally for LTE, NR and CDMA, so an
    /// unavailable reading arrives as `Integer.MAX_VALUE` rather than as an
    /// absent key. Recording that verbatim — which is what
    /// `dbm.unwrap_or(0).to_string()` did — publishes a signal strength of
    /// +2147483647 dBm as an observation.
    fn usable_dbm(&self) -> Option<i64> {
        self.dbm.filter(|&v| v != UNAVAILABLE)
    }
}

fn json_to_str(v: &Option<serde_json::Value>) -> String {
    v.as_ref()
        .and_then(crate::util::json::scalar_str)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
}

/// True when `s` is a non-empty run of ASCII digits — the shape every segment
/// of a `mcc-mnc-lac-cid` [`EntityKind::DeviceId`] must have.
///
/// `Target::validate` rejects a `DeviceId` whose segments are not all non-empty
/// and numeric, and only `mcc` was ever checked here. `mnc` is written through
/// `writeIfKnown`, so it is simply ABSENT when the platform does not know it —
/// producing `"505--678-12345"`, a four-segment id with an empty segment that
/// this module emits as an entity and `Target::validate` would refuse. An
/// identifier that cannot be re-targeted is not a usable pivot.
fn is_numeric_segment(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

fn tech_tag(cell_type: Option<&str>) -> &'static str {
    match cell_type.map(str::to_lowercase).as_deref() {
        Some("lte") => "lte",
        Some("nr" | "5g") => "nr",
        Some("umts" | "wcdma") => "umts",
        Some("gsm") => "gsm",
        _ => "unknown",
    }
}

/// Parse `termux-telephony-cellinfo` JSON array into DeviceId entities.
pub(super) fn parse_cells(cellinfo: &[u8], scan_id: &str) -> Result<ModuleResult> {
    if super::is_blank(cellinfo) {
        return Ok(ModuleResult::new());
    }
    let cells: Vec<Cell> = serde_json::from_slice(cellinfo)
        .map_err(|e| super::unparseable(super::Sensor::CellInfo, &e))?;

    let mut result = ModuleResult::with_capacity(cells.len());

    for cell in cells {
        let mcc = json_to_str(&cell.mcc);
        let mnc = json_to_str(&cell.mnc);
        let (Some(cid), true) = (cell.identity(), is_numeric_segment(&mcc)) else {
            continue;
        };
        // Every segment must be numeric and non-empty, or the emitted value is
        // a DeviceId that `Target::validate` would reject — see
        // `is_numeric_segment`. An absent `mnc` is the common case this catches.
        if !is_numeric_segment(&mnc) {
            continue;
        }
        let lac = cell.area_code();

        let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");
        let tech = tech_tag(cell.cell_type.as_deref());
        let registered = cell.registered.unwrap_or(false);

        let mut e = Entity::new(
            EntityKind::DeviceId,
            &tower_id,
            confidence::VERY_HIGH,
            scan_id,
        );
        e.tag(crate::core::tags::CELL_TOWER);
        e.tag(tech);
        if registered {
            e.tag("registered");
        }

        let mut ev = Evidence::new(SRC, format!("Cell tower: {tower_id}"))
            .with_attr("tower_id", &tower_id)
            .with_attr("mcc", &mcc)
            .with_attr("mnc", &mnc)
            .with_attr("lac", lac.to_string())
            .with_attr("cid", cid.to_string())
            .with_attr("tech", tech)
            .with_attr("registered", registered.to_string());
        // Recorded only when it is a real reading. `unwrap_or(0)` published a
        // fabricated "0 dBm" — an implausibly strong signal — for every cell
        // whose strength the platform did not report.
        if let Some(dbm) = cell.usable_dbm() {
            ev = ev.with_attr("dbm", dbm.to_string());
        }
        e.add_evidence(ev);

        result.push(e);
    }

    Ok(result)
}
