//! Cell tower scanner for signal_radar — reads `termux-telephony-cellinfo`
//! and `termux-telephony-signalstrength` in parallel.

use serde::Deserialize;

use crate::core::{
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
    /// 5G NR: signal strength (dBm) used when `dbm` is absent.
    #[serde(rename = "csiRsrp")]
    pub(super) csi_rsrp: Option<i64>,
    pub(super) cid: Option<i64>,
    pub(super) lac: Option<i64>,
    pub(super) tac: Option<i64>,
    pub(super) mcc: Option<serde_json::Value>,
    pub(super) mnc: Option<serde_json::Value>,
    /// 5G NR: downlink ARFCN.
    #[serde(rename = "nrArfcn")]
    pub(super) nr_arfcn: Option<i64>,
    /// 5G NR: SS block band (e.g. `"n78"`).
    #[serde(rename = "ssBand")]
    pub(super) ss_band: Option<String>,
}

fn json_to_str(v: &Option<serde_json::Value>) -> String {
    match v {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn tech_tag(cell_type: Option<&str>) -> &'static str {
    match cell_type.map(|s| s.to_lowercase()).as_deref() {
        Some("lte") => "lte",
        Some("nr") | Some("5g") => "nr",
        Some("umts") | Some("wcdma") => "umts",
        Some("gsm") => "gsm",
        _ => "unknown",
    }
}

/// Returns `true` when `cell_type` is a 5G NR entry.
fn is_nr(cell_type: Option<&str>) -> bool {
    matches!(
        cell_type.map(|s| s.to_lowercase()).as_deref(),
        Some("nr") | Some("5g")
    )
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
        let nr = is_nr(cell.cell_type.as_deref());

        // For NR entries, fall back to csiRsrp when dbm is absent.
        let signal_dbm = cell
            .dbm
            .or(if nr { cell.csi_rsrp } else { None })
            .unwrap_or(0);

        let mut e = Entity::new(EntityKind::DeviceId, &tower_id, 0.75, scan_id);
        e.tag("cell-tower");
        e.tag(tech);
        if nr {
            e.tag("5g-nr");
        }
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
            .with_attr("dbm", signal_dbm.to_string())
            .with_attr("registered", registered.to_string());

        // NR-specific attributes when present.
        if let Some(arfcn) = cell.nr_arfcn {
            ev = ev.with_attr("nr_arfcn", arfcn.to_string());
        }
        if let Some(ref band) = cell.ss_band {
            ev = ev.with_attr("ss_band", band);
        }

        e.add_evidence(ev);
        result.push(e);
    }

    result
}
