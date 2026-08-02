//! ASIC Banned & Disqualified Persons register emitter.

use serde_json::{Map, Value};

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};

use super::{
    SRC,
    shared::{field, humanise_name, push_address},
};

/// Emit the banned/disqualified finding: an adverse-flagged Person plus the
/// registered address.
pub(super) fn emit_banned(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "BD_PER_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);

    let mut ev = Evidence::new(SRC, format!("ASIC banned/disqualified: {person_name}"))
        .with_attr("register", "ASIC Banned & Disqualified Persons")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("BD_PER_TYPE", "ban_type"),
        ("BD_PER_START_DT", "ban_start"),
        ("BD_PER_END_DT", "ban_end"),
        ("BD_PER_DOC_NUM", "document_no"),
        ("BD_PER_COMMENTS", "comments"),
    ] {
        if let Some(v) = field(rec, key) {
            ev = ev.with_attr(attr, v);
        }
    }

    let mut p = Entity::new(
        EntityKind::Person,
        &person_name,
        confidence::MEDIUM_PLUS,
        scan_id,
    );
    p.tag("au");
    p.tag("asic");
    p.tag("asic-banned");
    p.tag("regulatory-action");
    p.add_evidence(ev.clone());
    result.push(p);

    push_address(
        rec,
        "BD_PER_ADD_LOCAL",
        "BD_PER_ADD_STATE",
        "BD_PER_ADD_PCODE",
        &person_name,
        "asic-banned",
        scan_id,
        result,
    );
}
