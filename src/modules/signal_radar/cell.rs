//! Cell tower scanner for signal_radar — the entity mapping around the
//! canonical `termux-telephony-cellinfo` shape in
//! [`crate::modules::device_cell`], shared with `cell_intel`.
//!
//! The wire shape, the per-radio identity key (`cid` / `ci` / `nci`), the
//! `Integer.MAX_VALUE` sentinel rules and the DeviceId segment rule all live
//! there, single-sourced — both consumers of this tool had independently
//! written the same wrong rule for reading it, so fixing either copy alone
//! would have left the other silently blind to every LTE and 5G cell.

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::ModuleResult,
};
use crate::modules::device_cell::{Cell, is_numeric_segment};

use super::SRC;

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
        let mcc = cell.mcc_str();
        let mnc = cell.mnc_str();
        let Some(cid) = cell.identity() else {
            continue;
        };
        // Every segment must be numeric and non-empty, or the emitted value is
        // a DeviceId that `Target::validate` would reject. An absent `mnc` is
        // the common case this catches.
        if !is_numeric_segment(&mcc) || !is_numeric_segment(&mnc) {
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
            .with_attr("mcc", mcc.as_ref())
            .with_attr("mnc", mnc.as_ref())
            .with_attr("lac", lac.to_string())
            .with_attr("cid", cid.to_string())
            .with_attr("tech", tech)
            .with_attr("registered", registered.to_string());
        // Recorded only when it is a real reading — see `Cell::usable_dbm`.
        if let Some(dbm) = cell.usable_dbm() {
            ev = ev.with_attr("dbm", dbm.to_string());
        }
        e.add_evidence(ev);

        result.push(e);
    }

    Ok(result)
}
