//! Cell tower scanner for signal_radar — reads `termux-telephony-cellinfo`,
//! which already carries per-cell `dbm`/signal data (see [`Cell::dbm`]).

use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::SRC;

#[derive(Deserialize)]
pub(super) struct Cell {
    #[serde(rename = "type")]
    pub(super) cell_type: Option<String>,
    pub(super) registered: Option<bool>,
    pub(super) dbm: Option<i64>,
    pub(super) cid: Option<i64>,
    pub(super) lac: Option<i64>,
    pub(super) tac: Option<i64>,
    pub(super) mcc: Option<serde_json::Value>,
    pub(super) mnc: Option<serde_json::Value>,
}

fn json_to_str(v: &Option<serde_json::Value>) -> String {
    v.as_ref()
        .and_then(crate::util::json::scalar_str)
        .map(std::borrow::Cow::into_owned)
        .unwrap_or_default()
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
pub(super) fn parse_cells(cellinfo: &[u8], scan_id: &str) -> ModuleResult {
    let cells: Vec<Cell> = match serde_json::from_slice(cellinfo) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult::with_capacity(cells.len());

    for cell in cells {
        let mcc = json_to_str(&cell.mcc);
        let mnc = json_to_str(&cell.mnc);
        let cid = cell.cid.unwrap_or(0);
        let lac = cell.lac.or(cell.tac).unwrap_or(0);

        if mcc.is_empty() || cid == 0 {
            continue;
        }

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

        e.add_evidence(
            Evidence::new(SRC, format!("Cell tower: {tower_id}"))
                .with_attr("tower_id", &tower_id)
                .with_attr("mcc", &mcc)
                .with_attr("mnc", &mnc)
                .with_attr("lac", lac.to_string())
                .with_attr("cid", cid.to_string())
                .with_attr("tech", tech)
                .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                .with_attr("registered", registered.to_string()),
        );

        result.push(e);
    }

    result
}
