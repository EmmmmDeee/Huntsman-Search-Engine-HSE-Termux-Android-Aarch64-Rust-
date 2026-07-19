//! Associate / relationship extraction from SeekNow records.
//!
//! Maps relative/household/associate fields to Person leads with kinship
//! tags. Reaches parent helpers/imports via `use super::*`.

use super::*;
use crate::core::confidence;

/// People-search relationship arrays SeekNow returns on a name / identity
/// record, mapped to the relationship label stamped on each emitted Person.
/// These are the relatives / associates / household members that turn a
/// single subject into their human network — the single highest-value field
/// family for a person-centric scan; the shared rich-detail pass skips
/// arrays, so this dedicated extractor is what recovers them instead of
/// silently dropping them. Each becomes a `Person` carrying
/// `related_to = <subject>` so the relation layer
/// (`derive_declared_associations`) binds it to the subject — and a
/// `family-candidate` tag so the surname kinship builder corroborates it
/// independently. Order is widest-first so a name appearing under two labels
/// keeps the closest (relative > household > associate).
const RELATIONSHIP_FIELDS: &[(&str, &str)] = &[
    ("relatives", "relative"),
    ("possible_relatives", "relative"),
    ("related_persons", "relative"),
    ("relations", "relative"),
    ("family", "relative"),
    ("household", "household"),
    ("household_members", "household"),
    ("associates", "associate"),
    ("possible_associates", "associate"),
    ("known_associates", "associate"),
    ("neighbors", "neighbor"),
    ("neighbours", "neighbor"),
];

/// Confidence for a relative/associate Person — a corroborating lead, held
/// deliberately below the confidence::MEDIUM expansion floor so the family graph is recorded
/// and connected without auto-pivoting a sub-scan of every named relative.
const ASSOCIATE_CONF: f64 = confidence::LOW_MEDIUM;

/// Pull a person name from a relationship-array element: a bare string, or an
/// object carrying `full_name` / `name` / `first_name`+`last_name`.
fn associate_name(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.trim().to_string()),
        Value::Object(_) => val_str(v, "full_name")
            .or_else(|| val_str(v, "name"))
            .or_else(|| {
                let f = val_str(v, "first_name").or_else(|| val_str(v, "firstname"))?;
                let l = val_str(v, "last_name").or_else(|| val_str(v, "lastname"))?;
                Some(format!("{} {}", f.trim(), l.trim()))
            }),
        _ => None,
    }
}

/// Extract SeekNow's relatives / associates / household members as first-class
/// `Person` entities, each bound to the searched subject by a `related_to`
/// evidence attribute and a `relationship` label. This is what lets a name search
/// on one family member surface — and connect to — the others (the angle-
/// independent family graph: searching any member returns the rest). The emitted
/// Person is a secondary, record-derived lead at [`ASSOCIATE_CONF`] — deliberately
/// below the confidence::MEDIUM expansion floor, so a relative is recorded and connected but not
/// auto-pivoted into a full sub-scan (the family tree can't fan out unbounded);
/// the relation builders, not this pass, assert the edge.
pub(super) fn extract_associates(
    item: &Value,
    subject: &str,
    scan_id: &str,
    key_fp: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let subject = subject.trim();
    for (field, label) in RELATIONSHIP_FIELDS {
        let Some(arr) = item.get(*field).and_then(Value::as_array) else {
            continue;
        };
        for el in arr {
            let Some(raw) = associate_name(el) else {
                continue;
            };
            // A relationship entry must look like a real person name (a space) and
            // not be the subject re-listed.
            let name = crate::util::str_util::title_case(&raw);
            if !name.contains(' ') || name.len() < 5 || name.eq_ignore_ascii_case(subject) {
                continue;
            }
            if !seen.insert(format!("@assoc:{}", name.to_lowercase())) {
                continue;
            }
            let mut e = Entity::new(EntityKind::Person, &name, ASSOCIATE_CONF, scan_id);
            e.tag("see-know");
            e.tag(*label);
            // Relatives / household share the subject's surname cluster, so the
            // free surname-kinship builder corroborates them; associates do not,
            // so they lean on the declared `related_to` edge alone.
            e.tag(if matches!(*label, "relative" | "household") {
                "family-candidate"
            } else {
                "associate-candidate"
            });
            let mut ev = Evidence::new(SRC, format!("SeekNow {label} of {subject}"))
                .with_attr("relationship", *label)
                .with_attr("provider", "see-know.eu")
                .with_attr("api_key_origin", key_fp);
            if !subject.is_empty() {
                ev = ev.with_attr("related_to", subject);
            }
            e.add_evidence(ev);
            result.push(e);
        }
    }
}
