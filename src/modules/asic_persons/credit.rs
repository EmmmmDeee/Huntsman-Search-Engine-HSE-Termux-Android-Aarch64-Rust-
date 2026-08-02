//! ASIC Credit Representatives register emitter.

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

/// Emit a credit/finance-broker representative: the Person, an ABN/ACN pivot,
/// and the registered address. The licensee they operate under (a credit
/// licence number) and authorisation period ride on the evidence.
pub(super) fn emit_credit_rep(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "CRED_REP_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);

    let mut ev = Evidence::new(SRC, format!("ASIC credit representative: {person_name}"))
        .with_attr("register", "ASIC Credit Representatives")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("CRED_REP_NUM", "credit_rep_number"),
        ("CRED_LIC_NUM", "credit_licence_no"),
        ("CRED_REP_START_DT", "authorised_from"),
        ("CRED_REP_END_DT", "authorised_to"),
        ("CRED_REP_EDRS", "dispute_scheme"),
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
    p.tag("asic-credit-rep");
    p.add_evidence(ev.clone());
    result.push(p);

    // The rep's own ABN/ACN (11- or 9-digit), when registered against the name.
    if let Some(id) = field(rec, "CRED_REP_ABN_ACN").filter(|a| {
        let n = a.chars().filter(char::is_ascii_digit).count();
        n == 11 || n == 9
    }) {
        let mut e = Entity::new(EntityKind::AbnAcn, &id, confidence::MEDIUM_PLUS, scan_id);
        e.tag("au");
        e.tag("asic");
        e.tag("asic-credit-rep");
        e.add_evidence(
            Evidence::new(
                SRC,
                format!("ABN/ACN of credit representative {person_name}"),
            )
            .with_attr("abn_acn", &id),
        );
        result.push(e);
    }

    push_address(
        rec,
        "CRED_REP_LOCALITY",
        "CRED_REP_STATE",
        "CRED_REP_PCODE",
        &person_name,
        "asic-credit-rep",
        scan_id,
        result,
    );
}
