//! Cellular tower survey — invokes `termux-telephony-cellinfo`.
//!
//! Each registered cell becomes a `DeviceId` entity tagged `cell-tower`
//! with an opaque `<mcc>-<mnc>-<lac|tac>-<cid>` identifier. Signal
//! strength, radio type (LTE/GSM/UMTS/NR), and ASU level are recorded
//! as evidence. Off-device → no-op via the termux_cmd helper.

use std::borrow::Cow;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleContext, ModuleResult},
    scan::Target,
};
use crate::util::termux::termux_cmd;

pub struct CellSurvey;

#[derive(Deserialize)]
struct Cell {
    #[serde(rename = "type")]
    cell_type: Option<String>,
    registered: Option<bool>,
    asu: Option<i64>,
    dbm: Option<i64>,
    level: Option<i64>,
    cid: Option<i64>,
    lac: Option<i64>,
    tac: Option<i64>,
    mcc: Option<serde_json::Value>, // can be string or int across Android versions
    mnc: Option<serde_json::Value>,
    pci: Option<i64>,
}

#[async_trait]
impl Module for CellSurvey {
    fn name(&self) -> &'static str {
        "cell_survey"
    }
    fn description(&self) -> &'static str {
        "Termux cellular tower survey for device geolocation"
    }
    fn priority(&self) -> u8 {
        62
    }

    fn is_passive(&self) -> bool {
        true
    }
    fn accepts(&self, _t: &Target) -> bool {
        true
    }

    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let Some(stdout) = termux_cmd("termux-telephony-cellinfo", &[], 3000).await else {
            return Ok(ModuleResult::new());
        };
        Ok(parse_cells(&stdout, &ctx.scan_id))
    }
}

fn parse_cells(stdout: &[u8], scan_id: &str) -> ModuleResult {
    let cells: Vec<Cell> = match serde_json::from_slice(stdout) {
        Ok(v) => v,
        Err(_) => return ModuleResult::new(),
    };

    let mut result = ModuleResult {
        entities: Vec::with_capacity(cells.len()),
    };
    for cell in &cells {
        let mcc = json_to_str(&cell.mcc);
        let mnc = json_to_str(&cell.mnc);
        let lac = cell.lac.or(cell.tac).unwrap_or(0);
        let cid = cell.cid.unwrap_or(0);
        if mcc.is_empty() || cid == 0 {
            continue;
        }

        let ctype = cell.cell_type.as_deref().unwrap_or("unknown");
        let tower_id = format!("{mcc}-{mnc}-{lac}-{cid}");

        let mut e = Entity::new(EntityKind::DeviceId, &tower_id, 0.80, scan_id);
        e.tag("cell-tower");
        e.tag(format!("radio:{ctype}"));
        e.add_evidence(
            Evidence::new("cell_survey", format!("Cell tower {ctype} {tower_id}"))
                .with_attr("type", ctype)
                .with_attr("mcc", mcc.as_ref())
                .with_attr("mnc", mnc.as_ref())
                .with_attr("lac_tac", lac.to_string())
                .with_attr("cid", cid.to_string())
                .with_attr("pci", cell.pci.unwrap_or(0).to_string())
                .with_attr("dbm", cell.dbm.unwrap_or(0).to_string())
                .with_attr("asu", cell.asu.unwrap_or(0).to_string())
                .with_attr("level", cell.level.unwrap_or(0).to_string())
                .with_attr("registered", cell.registered.unwrap_or(false).to_string()),
        );
        result.push(e);
    }
    result
}

/// `mcc`/`mnc` come as `"505"` on some Android versions and `505` on others.
/// Normalise to string; missing → empty.
fn json_to_str(v: &Option<serde_json::Value>) -> Cow<'_, str> {
    match v {
        Some(serde_json::Value::String(s)) => Cow::Borrowed(s.as_str()),
        Some(serde_json::Value::Number(n)) => Cow::Owned(n.to_string()),
        _ => Cow::Borrowed(""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn is_passive() {
        assert!(CellSurvey.is_passive());
    }

    #[test]
    fn accepts_any_target() {
        assert!(CellSurvey.accepts(&Target::new(TargetKind::Email, "x@y")));
    }

    #[test]
    fn parses_mcc_as_string_or_number() {
        let json = br#"[
            {"type":"lte","registered":true,"cid":12345,"tac":54321,
             "mcc":"505","mnc":"01","dbm":-75,"asu":30,"level":4,"pci":100},
            {"type":"gsm","registered":true,"cid":99,"lac":42,
             "mcc":505,"mnc":1,"dbm":-90,"asu":10,"level":2}
        ]"#;
        let r = parse_cells(json, "test");
        assert_eq!(r.entities.len(), 2);
        assert_eq!(r.entities[0].value, "505-01-54321-12345");
        assert_eq!(r.entities[1].value, "505-1-42-99");
    }

    #[test]
    fn skips_cells_without_mcc_or_cid() {
        let json = br#"[{"type":"lte","registered":true}]"#;
        let r = parse_cells(json, "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn malformed_json_no_ops() {
        let r = parse_cells(b"{", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn module_name_and_priority() {
        assert_eq!(CellSurvey.name(), "cell_survey");
        assert_eq!(CellSurvey.priority(), 62);
    }

    #[test]
    fn entity_tags_include_cell_tower_and_radio_type() {
        let json = br#"[
            {"type":"lte","registered":true,"cid":5678,"tac":1234,
             "mcc":"310","mnc":"260","dbm":-85,"asu":25,"level":3,"pci":42}
        ]"#;
        let r = parse_cells(json, "scan-x");
        assert_eq!(r.entities.len(), 1);
        let e = &r.entities[0];
        assert_eq!(e.kind, EntityKind::DeviceId);
        assert_eq!(e.value, "310-260-1234-5678");
        assert!((e.confidence - 0.80).abs() < 1e-6);
        assert!(e.has_tag("cell-tower"));
        assert!(e.has_tag("radio:lte"));
        assert_eq!(e.scan_id, "scan-x");
    }

    #[test]
    fn evidence_attributes_populated() {
        let json = br#"[
            {"type":"gsm","registered":false,"cid":100,"lac":200,
             "mcc":"505","mnc":"01","dbm":-95,"asu":8,"level":1,"pci":0}
        ]"#;
        let r = parse_cells(json, "test");
        let ev = &r.entities[0].evidence[0];
        assert_eq!(ev.source, "cell_survey");
        assert_eq!(ev.attributes.get("type").unwrap(), "gsm");
        assert_eq!(ev.attributes.get("mcc").unwrap(), "505");
        assert_eq!(ev.attributes.get("mnc").unwrap(), "01");
        assert_eq!(ev.attributes.get("lac_tac").unwrap(), "200");
        assert_eq!(ev.attributes.get("cid").unwrap(), "100");
        assert_eq!(ev.attributes.get("dbm").unwrap(), "-95");
        assert_eq!(ev.attributes.get("asu").unwrap(), "8");
        assert_eq!(ev.attributes.get("level").unwrap(), "1");
        assert_eq!(ev.attributes.get("registered").unwrap(), "false");
    }

    #[test]
    fn lac_falls_back_to_tac_for_lte() {
        // LTE cells use "tac" (Tracking Area Code) instead of "lac"
        let json = br#"[{"type":"lte","cid":999,"tac":555,"mcc":"310","mnc":"410"}]"#;
        let r = parse_cells(json, "test");
        assert_eq!(r.entities[0].value, "310-410-555-999");
    }

    #[test]
    fn lac_preferred_over_tac_when_both_present() {
        let json = br#"[{"type":"gsm","cid":1,"lac":10,"tac":20,"mcc":"505","mnc":"01"}]"#;
        let r = parse_cells(json, "test");
        // lac.or(tac) means lac wins when present
        assert_eq!(r.entities[0].value, "505-01-10-1");
    }

    #[test]
    fn skips_cell_with_zero_cid() {
        let json = br#"[{"type":"lte","cid":0,"tac":123,"mcc":"310","mnc":"260"}]"#;
        let r = parse_cells(json, "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn empty_json_array() {
        let r = parse_cells(b"[]", "test");
        assert_eq!(r.entities.len(), 0);
    }

    #[test]
    fn json_to_str_handles_all_variants() {
        use std::borrow::Cow;

        // String value
        let s = Some(serde_json::Value::String("505".into()));
        assert_eq!(json_to_str(&s), Cow::Borrowed("505"));

        // Number value
        let n = Some(serde_json::json!(310));
        assert_eq!(json_to_str(&n).as_ref(), "310");

        // Null value
        let null = Some(serde_json::Value::Null);
        assert_eq!(json_to_str(&null), Cow::Borrowed(""));

        // None
        assert_eq!(json_to_str(&None), Cow::Borrowed(""));
    }

    #[test]
    fn missing_type_defaults_to_unknown() {
        let json = br#"[{"cid":42,"lac":7,"mcc":"001","mnc":"01"}]"#;
        let r = parse_cells(json, "test");
        assert_eq!(r.entities.len(), 1);
        assert!(r.entities[0].has_tag("radio:unknown"));
        assert!(r.entities[0].evidence[0].summary.contains("unknown"));
    }
}
