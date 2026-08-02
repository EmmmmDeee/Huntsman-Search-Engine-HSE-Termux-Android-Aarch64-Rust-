//! ASIC Financial Advisers register emitter.

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

/// Normalise a name/organisation string for order-preserving equality: trim,
/// collapse internal whitespace, upper-case. Used to tell a genuinely-distinct
/// appointing firm apart from a self-appointment or the licensee itself.
fn norm_name(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

/// Classify a linked register name (a licensee controller) by shape: a corporate
/// legal-form suffix (`looks_like_company`) → an `Organisation` kept
/// as-registered; otherwise the controller is a natural person — a small firm's
/// controlling principal — surfaced as a humanised `Person`. Both are public
/// regulatory-ownership relationships, not contact PII. **Pure.**
fn classify_linked(name: &str) -> (EntityKind, String) {
    if crate::util::abn::looks_like_company(name) {
        (EntityKind::Organisation, name.trim().to_string())
    } else {
        (EntityKind::Person, humanise_name(name))
    }
}

/// Parse ASIC's `LICENCE_CONTROLLED_BY` field into `(controller, ceased_date)`
/// pairs. The field lists one or more controlling entities separated by `~`,
/// each optionally suffixed with a bracketed status marker, e.g.
/// `"NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED [Date Ceased: 20/05/2021]"`.
/// The controller name is everything before the first `[`; a `Date Ceased:`
/// value inside the marker (a historical controller) is returned alongside.
/// **Pure.** Entries whose cleaned name is under 3 chars are dropped.
pub(super) fn parse_controllers(raw: &str) -> Vec<(String, Option<String>)> {
    raw.split('~')
        .filter_map(|part| {
            let part = part.trim();
            let name = part.split('[').next().unwrap_or(part).trim();
            if name.len() < 3 {
                return None;
            }
            let ceased = part
                .split_once("Date Ceased:")
                .and_then(|(_, rest)| rest.split(']').next())
                .map(str::trim)
                .filter(|d| !d.is_empty())
                .map(str::to_string);
            Some((name.to_string(), ceased))
        })
        .collect()
}

/// Emit the financial-adviser profile: the adviser Person, the licensee
/// Organisation + ABN, any disciplinary action, and the registered address.
pub(super) fn emit_adviser(rec: &Map<String, Value>, scan_id: &str, result: &mut ModuleResult) {
    let Some(raw_name) = field(rec, "ADV_NAME") else {
        return;
    };
    let person_name = humanise_name(&raw_name);
    let has_discipline = field(rec, "ADV_DA_TYPE").is_some();

    let mut ev = Evidence::new(SRC, format!("ASIC financial adviser: {person_name}"))
        .with_attr("register", "ASIC Financial Advisers")
        .with_attr("matched_name", &raw_name);
    for (key, attr) in [
        ("ADV_ROLE", "adviser_role"),
        ("OVERALL_REGISTRATION_STATUS", "registration_status"),
        ("ADV_NUMBER", "adviser_number"),
        ("ADV_FIRST_PROVIDED_ADVICE", "first_advice"),
        ("LICENCE_NAME", "licensee"),
        ("LICENCE_NUMBER", "afs_licence_no"),
        ("LICENCE_CONTROLLED_BY", "licensee_controlled_by"),
        ("REP_APPOINTED_BY", "appointed_by"),
        ("REP_APPOINTED_NUM", "authorised_rep_no"),
        ("ADV_DA_TYPE", "disciplinary_action"),
        ("ADV_DA_DESCRIPTION", "disciplinary_detail"),
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
    p.tag("asic-financial-adviser");
    if has_discipline {
        p.tag("regulatory-action");
        p.tag("disciplinary-action");
    }
    p.add_evidence(ev.clone());
    result.push(p);

    // The licensee the adviser operates under — an employer/affiliation pivot.
    let licensee = field(rec, "LICENCE_NAME");
    if let Some(licensee) = &licensee {
        let mut org = Entity::new(
            EntityKind::Organisation,
            licensee,
            confidence::NOTABLE,
            scan_id,
        );
        org.tag("au");
        org.tag("asic");
        org.tag("afs-licensee");
        let mut oev = Evidence::new(SRC, format!("AFS licensee of adviser {person_name}"))
            .with_attr("licensee", licensee);
        if let Some(no) = field(rec, "LICENCE_NUMBER") {
            oev = oev.with_attr("afs_licence_no", no);
        }
        org.add_evidence(oev);
        result.push(org);
    }

    // Corporate controller(s) of the AFS licensee — the ultimate parent behind
    // the licence, a marquee ownership pivot: a small-looking advice firm is
    // frequently `LICENCE_CONTROLLED_BY` a major bank / wealth group. The field
    // is a `~`-separated list, each entry optionally carrying a
    // `[Date Ceased: DD/MM/YYYY]` marker for a historical controller.
    if let Some(raw) = field(rec, "LICENCE_CONTROLLED_BY") {
        for (name, ceased) in parse_controllers(&raw) {
            let (kind, value) = classify_linked(&name);
            let mut ent = Entity::new(kind, &value, confidence::MEDIUM_SOLID, scan_id);
            ent.tag("au");
            ent.tag("asic");
            ent.tag("afs-licensee-controller");
            let mut cev = Evidence::new(
                SRC,
                format!(
                    "Controls AFS licensee {} (adviser {person_name})",
                    licensee.as_deref().unwrap_or("(unknown)")
                ),
            )
            .with_attr("relationship", "licence_controlled_by");
            if let Some(l) = &licensee {
                cev = cev.with_attr("controls_licensee", l);
            }
            if let Some(d) = ceased {
                ent.tag("ceased");
                cev = cev.with_attr("date_ceased", d);
            }
            ent.add_evidence(cev);
            result.push(ent);
        }
    }

    // The corporate authorised representative that appointed the adviser. Often
    // a distinct practice/firm sitting BETWEEN the adviser and the licensee
    // (e.g. the adviser's own named practice), so it is a stronger personal
    // attribution pivot than the big licensee. Emitted only when it differs from
    // both the adviser's own name (a self-appointment) and the licensee (already
    // captured above) AND is company-shaped — the corporate-AR relationship is
    // inherently corporate, so a person-shaped distinct appointer is treated as
    // ambiguous noise and skipped for precision.
    if let Some(appby) = field(rec, "REP_APPOINTED_BY") {
        let n = norm_name(&appby);
        let is_self = n == norm_name(&raw_name);
        let is_licensee = licensee.as_deref().is_some_and(|l| n == norm_name(l));
        if !is_self && !is_licensee && crate::util::abn::looks_like_company(&appby) {
            let mut org = Entity::new(
                EntityKind::Organisation,
                &appby,
                confidence::MEDIUM_PLUS,
                scan_id,
            );
            org.tag("au");
            org.tag("asic");
            org.tag("authorised-rep-firm");
            let mut aev = Evidence::new(SRC, format!("Appointed {person_name} as authorised rep"))
                .with_attr("relationship", "rep_appointed_by");
            if let Some(num) = field(rec, "REP_APPOINTED_NUM") {
                aev = aev.with_attr("authorised_rep_no", num);
            }
            org.add_evidence(aev);
            result.push(org);
        }
    }

    // ABNs: the adviser's own, the licensee's, and the appointing rep firm's —
    // each a pivot into the ABR/ASIC. Dedup merges any that coincide.
    for (key, label) in [
        ("ADV_ABN", "adviser"),
        ("LICENCE_ABN", "licensee"),
        ("REP_APPOINTED_ABN", "rep_appointer"),
    ] {
        if let Some(abn) =
            field(rec, key).filter(|a| a.chars().filter(char::is_ascii_digit).count() == 11)
        {
            let mut e = Entity::new(EntityKind::AbnAcn, &abn, confidence::NOTABLE, scan_id);
            e.tag("au");
            e.tag("asic");
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!("{label} ABN from ASIC adviser record of {person_name}"),
                )
                .with_attr("abn", &abn)
                .with_attr("role", label),
            );
            result.push(e);
        }
    }

    push_address(
        rec,
        "ADV_ADD_LOCAL",
        "ADV_ADD_STATE",
        "ADV_ADD_PCODE",
        &person_name,
        "asic-financial-adviser",
        scan_id,
        result,
    );
}
