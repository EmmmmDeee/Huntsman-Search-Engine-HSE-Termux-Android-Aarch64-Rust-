//! Read-only provenance register derived from the scan store.
//!
//! Does not collect, infer identities, or write a second evidence copy. Output is
//! bounded; an over-limit scan fails explicitly instead of silently truncating.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::scan_store::{ScanRecord, ScanResults, ScanStatus};
use crate::sha256::{hex32, sha256};
use crate::textnorm::escape_controls_keep_lines;

/// Upper bounds for a Termux phone, including a baseline comparison.
pub const MAX_RECORDS: usize = 4_096;
pub const MAX_RENDER_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone)]
struct Row {
    id: String,
    kind: &'static str,
    identifier: String,
    source: Option<String>,
    observed_at_unix: Option<u64>,
    raw: Value,
    links: BTreeSet<String>,
    false_positive: bool,
}

fn stable_id(kind: &str, identifier: &str) -> String {
    let mut key = Vec::with_capacity(kind.len() + identifier.len() + 1);
    key.extend_from_slice(kind.as_bytes());
    key.push(0);
    key.extend_from_slice(identifier.as_bytes());
    format!("HSE-{}", &hex32(&sha256(&key))[..20])
}

fn insert(
    target: &mut BTreeMap<String, Row>,
    kind: &'static str,
    identifier: String,
    source: Option<String>,
    observed_at_unix: Option<u64>,
    raw: Value,
    links: BTreeSet<String>,
    false_positive: bool,
) -> Result<(), String> {
    if target.len() >= MAX_RECORDS {
        return Err(format!("evidence register exceeds {MAX_RECORDS} records; no records omitted"));
    }
    let id = stable_id(kind, &identifier);
    if target.contains_key(&id) {
        return Err(format!("duplicate evidence record {id}; no observation discarded"));
    }
    target.insert(id.clone(), Row {
        id, kind, identifier, source, observed_at_unix, raw, links, false_positive,
    });
    Ok(())
}

fn rows(saved: &ScanResults) -> Result<BTreeMap<String, Row>, String> {
    let mut output = BTreeMap::new();
    for entity in &saved.entities {
        insert(
            &mut output, "entity", entity.uid.clone(), None,
            Some(entity.observed_at_unix), json!(entity), BTreeSet::new(), false,
        )?;
    }
    for element in &saved.elements {
        let mut links = BTreeSet::new();
        if let Some(parent) = &element.source {
            links.insert(stable_id("element", parent));
        }
        if let Some(entity) = &element.entity {
            links.insert(stable_id("entity", entity));
        }
        insert(
            &mut output, "element", element.id.clone(), Some(element.module.clone()),
            Some(element.created / 1_000), json!(element), links, element.fp,
        )?;
    }
    let mut source_sequence: BTreeMap<&str, usize> = BTreeMap::new();
    for outcome in &saved.outcomes {
        let ordinal = source_sequence.entry(&outcome.module).or_default();
        *ordinal += 1;
        insert(
            &mut output, "source_outcome", format!("{}:{}", outcome.module, ordinal),
            Some(outcome.module.clone()), Some(outcome.observed_at_unix),
            json!(outcome), BTreeSet::new(), false,
        )?;
    }
    for correlation in &saved.correlations {
        let links = correlation.elements.iter()
            .map(|element| stable_id("element", element))
            .collect();
        insert(
            &mut output, "correlation", correlation.id.clone(),
            Some(correlation.origin.clone()), None, json!(correlation), links, false,
        )?;
    }
    for (position, pivot) in saved.lineage.iter().enumerate() {
        insert(
            &mut output, "lineage", position.to_string(), None, None,
            json!(pivot), BTreeSet::new(), false,
        )?;
    }
    if let Some(reason) = &saved.termination {
        insert(
            &mut output,
            "termination",
            "scan".to_owned(),
            None,
            None,
            json!(reason),
            BTreeSet::new(),
            false,
        )?;
    }

    // A link must resolve inside the scan. Do not invent edges to unavailable records.
    let existing: BTreeSet<String> = output.keys().cloned().collect();
    let mut reverse: Vec<(String, String)> = Vec::new();
    for row in output.values_mut() {
        row.links.retain(|linked| existing.contains(linked));
        for linked in &row.links {
            reverse.push((linked.clone(), row.id.clone()));
        }
    }
    for (target, from) in reverse {
        if let Some(row) = output.get_mut(&target) {
            row.links.insert(from);
        }
    }
    Ok(output)
}

/// Drop only per-run bookkeeping for semantic comparison. Exact raw bytes and
/// provenance remain in each record; changes to these fields are "reobserved",
/// not silently labelled identical.
fn semantic(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for key in ["scan_id", "created", "observed_at_unix", "recorded_at_unix"] {
                map.remove(key);
            }
            for child in map.values_mut() {
                semantic(child);
            }
        }
        Value::Array(items) => {
            for child in items {
                semantic(child);
            }
        }
        _ => {}
    }
}

fn signature(value: &Value, strip_clock: bool) -> Result<String, String> {
    let mut copy = value.clone();
    if strip_clock {
        semantic(&mut copy);
    }
    let bytes = serde_json::to_vec(&copy).map_err(|error| error.to_string())?;
    Ok(hex32(&sha256(&bytes)))
}

fn change(now: &Row, previous: &Row) -> Result<&'static str, String> {
    if signature(&now.raw, false)? == signature(&previous.raw, false)? {
        Ok("unchanged")
    } else if signature(&now.raw, true)? == signature(&previous.raw, true)? {
        Ok("reobserved")
    } else {
        Ok("changed")
    }
}

fn to_json(row: &Row, change_status: &str) -> Result<Value, String> {
    let mut missing = Vec::new();
    if row.observed_at_unix.is_none() {
        missing.push("observation_timestamp_not_recorded");
    }
    let status = if row.false_positive {
        "operator_flagged_false_positive"
    } else {
        "recorded_not_independently_verified"
    };
    Ok(json!({
        "RECORD_ID": row.id,
        "KIND": row.kind,
        "ENTITY": if row.kind == "entity" { Some(&row.identifier) } else { None },
        "IDENTIFIERS": [row.identifier],
        "ALIASES": [],
        "SOURCE": row.source,
        "SOURCE_URL": null,
        "RETRIEVED_UTC": null,
        "EVENT_TIMESTAMP": row.observed_at_unix.map(|unix| json!({"unix_seconds":unix})),
        "RAW_DATA": row.raw,
        "RAW_SHA256": signature(&row.raw, false)?,
        "METADATA": {"origin": "saved_scan", "false_positive_flag": row.false_positive},
        "CROSS_REFERENCES": row.links,
        "CORRELATED_ENTITIES": [],
        "RELATIONSHIPS": [],
        "TIMELINE": [],
        "SUPPORTING_EVIDENCE": [],
        "CONTRADICTORY_EVIDENCE": [],
        "ANOMALIES": [],
        "MISSING_INFORMATION": missing,
        "COMPETING_HYPOTHESES": [],
        "INFERENCES": [],
        "CONFIDENCE": null,
        "VERIFICATION_STATUS": status,
        "UNRESOLVED_UNCERTAINTIES": ["source_authenticity_not_independently_established"],
        "NEXT_INVESTIGATIVE_ACTION": null,
        "DELTA": change_status,
    }))
}

/// Construct a reproducible register from saved scan results, optionally emitting
/// only material changes and re-observations against a prior scan.
///
/// # Errors
/// Refuses duplicate keys, over-limit record sets, and oversized reports.
pub fn compile(
    scan: &ScanRecord,
    saved: &ScanResults,
    baseline: Option<(&ScanRecord, &ScanResults)>,
) -> Result<Value, String> {
    let current = rows(saved)?;
    let earlier = match baseline {
        Some((_, old)) => Some(rows(old)?),
        None => None,
    };
    let mut records = Vec::new();
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for (id, row) in &current {
        let kind = match earlier.as_ref() {
            None => "full",
            Some(old) => match old.get(id) {
                Some(prev) => change(row, prev)?,
                None => "added",
            },
        };
        *counts.entry(kind).or_default() += 1;
        if kind != "unchanged" {
            records.push(to_json(row, kind)?);
        }
    }
    if let Some(old) = &earlier {
        for (id, row) in old {
            if !current.contains_key(id) {
                *counts.entry("removed").or_default() += 1;
                records.push(to_json(row, "removed")?);
            }
        }
    }
    let material = counts.get("added").copied().unwrap_or(0)
        + counts.get("removed").copied().unwrap_or(0)
        + counts.get("changed").copied().unwrap_or(0);
    let status = if earlier.is_none() {
        "FULL_REGISTER"
    } else if material == 0 {
        "NO_MATERIAL_CHANGE"
    } else {
        "MATERIAL_CHANGE"
    };
    let report = json!({
        "format": "huntsman_evidence_register",
        "schema": 1,
        "scan": {"id":scan.id,"target":scan.target,"status":scan.status},
        "baseline":baseline.map(|(old,_)| old.id.as_str()),
        "status":status,
        "counts":counts,
        "current_record_count":current.len(),
        "baseline_record_count":earlier.as_ref().map(BTreeMap::len),
        "records":records,
        "limitations":[
            "saved_scan_not_independent_factual_corroboration",
            "source_urls_and_retrieval_utc_not_reconstructed_when_absent",
            "cross_references_resolve_only_saved_explicit_links",
            "reported_personal_attributes_are_not_authenticated",
            "delta_reobserved_ignores_only_explicit_per_run_timestamps_and_scan_id"
        ],
        "scan_complete":scan.status == ScanStatus::Finished,
        "truncated":false
    });
    let len = serde_json::to_vec(&report)
        .map_err(|error| error.to_string())?
        .len();
    if len > MAX_RENDER_BYTES {
        return Err(format!(
            "evidence report needs {len} bytes, exceeds {MAX_RENDER_BYTES}; no output truncated"
        ));
    }
    Ok(report)
}

/// Lossless field-labelled raw text view. Raw JSON remains embedded in RAW_DATA,
/// while terminal-hostile control characters are escaped only for display.
///
/// # Errors
/// JSON encoding errors or a raw report above the output bound.
pub fn raw_text(report: &Value) -> Result<String, String> {
    let mut text = format!(
        "[HUNTSMAN_EVIDENCE]\nSTATUS: {}\nSCAN: {}\nBASELINE: {}\nCOUNTS: {}\n",
        report["status"].as_str().unwrap_or("UNKNOWN"),
        report["scan"]["id"].as_str().unwrap_or("UNKNOWN"),
        report["baseline"].as_str().unwrap_or("NONE"),
        report["counts"],
    );
    for record in report["records"].as_array().into_iter().flatten() {
        let id = record["RECORD_ID"].as_str().unwrap_or("UNKNOWN");
        writeln!(text, "\n[{id}]").map_err(|error| error.to_string())?;
        let Some(fields) = record.as_object() else {
            continue;
        };
        for (key, value) in fields {
            if key == "RECORD_ID" {
                continue;
            }
            let raw = serde_json::to_string(value).map_err(|error| error.to_string())?;
            writeln!(text, "{key}: {}", escape_controls_keep_lines(&raw))
                .map_err(|error| error.to_string())?;
        }
        text.push_str("[END_RECORD]\n");
        if text.len() > MAX_RENDER_BYTES {
            return Err(format!(
                "raw evidence exceeds {MAX_RENDER_BYTES} bytes; nothing truncated"
            ));
        }
    }
    text.push_str("\n[END_HUNTSMAN_EVIDENCE]\n");
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_record_ids_and_duplicate_refusal() {
        assert_eq!(stable_id("element", "x"), stable_id("element", "x"));
        assert_ne!(stable_id("element", "x"), stable_id("entity", "x"));
        let mut saved = BTreeMap::new();
        insert(
            &mut saved,
            "element",
            "x".into(),
            None,
            None,
            json!({"x":1}),
            BTreeSet::new(),
            false,
        )
        .unwrap();
        assert!(
            insert(
                &mut saved,
                "element",
                "x".into(),
                None,
                None,
                json!({"x":2}),
                BTreeSet::new(),
                false
            )
            .is_err()
        );
    }

    #[test]
    fn per_run_timestamps_cannot_hide_material_change() {
        let mut old = json!({"value":"same","observed_at_unix":2,"detail":{"scan_id":"old"}});
        let mut next = json!({"value":"same","observed_at_unix":4,"detail":{"scan_id":"new"}});
        assert_ne!(
            signature(&old, false).unwrap(),
            signature(&next, false).unwrap()
        );
        semantic(&mut old);
        semantic(&mut next);
        assert_eq!(old, next);
        next["value"] = json!("changed");
        assert_ne!(old, next);
    }

    #[test]
    fn change_classification_preserves_raw_observations() {
        let row = |raw| Row {
            id: "a".into(),
            kind: "entity",
            identifier: "x".into(),
            source: None,
            observed_at_unix: None,
            raw,
            links: BTreeSet::new(),
            false_positive: false,
        };
        let a = row(json!({"value":"v","observed_at_unix":1}));
        let b = row(json!({"value":"v","observed_at_unix":2}));
        let c = row(json!({"value":"other","observed_at_unix":2}));
        assert_eq!(change(&a, &a).unwrap(), "unchanged");
        assert_eq!(change(&b, &a).unwrap(), "reobserved");
        assert_eq!(change(&c, &a).unwrap(), "changed");
    }
}
