//! Read-only provenance register derived from the scan store.
//!
//! Does not collect, infer identities, or write a second evidence copy. Output is
//! bounded; an over-limit scan fails explicitly instead of silently truncating.
mod matrix;
pub use matrix::{compile_matrix, matrix_raw_text};

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

impl Row {
    fn new(kind: &'static str, identifier: String, raw: Value) -> Self {
        let id = stable_id(kind, &identifier);
        Self {
            id,
            kind,
            identifier,
            source: None,
            observed_at_unix: None,
            raw,
            links: BTreeSet::new(),
            false_positive: false,
        }
    }

    fn sourced(mut self, source: &str) -> Self {
        self.source = Some(source.to_owned());
        self
    }

    fn observed(mut self, at: u64) -> Self {
        self.observed_at_unix = Some(at);
        self
    }

    fn linked(mut self, links: BTreeSet<String>) -> Self {
        self.links = links;
        self
    }

    fn flagged(mut self, flagged: bool) -> Self {
        self.false_positive = flagged;
        self
    }
}

fn insert(target: &mut BTreeMap<String, Row>, row: Row) -> Result<(), String> {
    if target.contains_key(&row.id) {
        return Err(format!(
            "duplicate evidence record {}; no observation discarded",
            row.id
        ));
    }
    if target.len() >= MAX_RECORDS {
        return Err(format!(
            "evidence register exceeds {MAX_RECORDS} records; no records omitted"
        ));
    }
    target.insert(row.id.clone(), row);
    Ok(())
}

fn rows(saved: &ScanResults) -> Result<BTreeMap<String, Row>, String> {
    let mut output = BTreeMap::new();
    for entity in &saved.entities {
        insert(
            &mut output,
            Row::new("entity", entity.uid.clone(), json!(entity)).observed(entity.observed_at_unix),
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
            &mut output,
            Row::new("element", element.id.clone(), json!(element))
                .sourced(&element.module)
                .observed(element.created / 1_000)
                .linked(links)
                .flagged(element.fp),
        )?;
    }
    let mut source_sequence: BTreeMap<&str, usize> = BTreeMap::new();
    for outcome in &saved.outcomes {
        let ordinal = source_sequence.entry(&outcome.module).or_default();
        *ordinal += 1;
        insert(
            &mut output,
            Row::new(
                "source_outcome",
                format!("{}:{ordinal}", outcome.module),
                json!(outcome),
            )
            .sourced(&outcome.module)
            .observed(outcome.observed_at_unix),
        )?;
    }
    for correlation in &saved.correlations {
        let links = correlation
            .elements
            .iter()
            .map(|element| stable_id("element", element))
            .collect();
        insert(
            &mut output,
            Row::new("correlation", correlation.id.clone(), json!(correlation))
                .sourced(&correlation.origin)
                .linked(links),
        )?;
    }
    for (position, pivot) in saved.lineage.iter().enumerate() {
        insert(
            &mut output,
            Row::new("lineage", position.to_string(), json!(pivot)),
        )?;
    }
    if let Some(reason) = &saved.termination {
        insert(
            &mut output,
            Row::new("termination", "scan".to_owned(), json!(reason)),
        )?;
    }

    add_reciprocal_links(&mut output);
    Ok(output)
}

/// Keep every explicit outbound reference, including unresolved targets. Create
/// reverse links only for targets actually present in the saved scan. Dropping
/// dangling links would silently erase material missing-evidence leads.
fn add_reciprocal_links(output: &mut BTreeMap<String, Row>) {
    let existing: BTreeSet<String> = output.keys().cloned().collect();
    let mut reverse: Vec<(String, String)> = Vec::new();
    for row in output.values() {
        for linked in &row.links {
            if existing.contains(linked) {
                reverse.push((linked.clone(), row.id.clone()));
            }
        }
    }
    for (target, from) in reverse {
        if let Some(row) = output.get_mut(&target) {
            row.links.insert(from);
        }
    }
}

/// Drop only per-run bookkeeping for semantic comparison. Exact raw bytes and
/// provenance remain in each record; changes to these fields are "reobserved",
/// not silently labelled identical.
fn semantic(value: &mut Value, kind: &str) {
    let Value::Object(map) = value else {
        return;
    };
    match kind {
        "entity" => {
            map.remove("scan_id");
            map.remove("observed_at_unix");
            if let Some(Value::Array(evidence)) = map.get_mut("evidence") {
                for item in evidence {
                    if let Some(Value::Object(provenance)) = item.get_mut("provenance") {
                        provenance.remove("scan_id");
                        provenance.remove("recorded_at_unix");
                    }
                }
            }
        }
        "element" => {
            map.remove("created");
        }
        "source_outcome" => {
            map.remove("observed_at_unix");
        }
        _ => {}
    }
}

fn signature(value: &Value, strip_clock: bool, kind: &str) -> Result<String, String> {
    let mut copy = value.clone();
    if strip_clock {
        semantic(&mut copy, kind);
    }
    let bytes = serde_json::to_vec(&copy).map_err(|error| error.to_string())?;
    Ok(hex32(&sha256(&bytes)))
}

fn change(now: &Row, previous: &Row) -> Result<&'static str, String> {
    if signature(&now.raw, false, now.kind)? == signature(&previous.raw, false, previous.kind)? {
        Ok("unchanged")
    } else if signature(&now.raw, true, now.kind)? == signature(&previous.raw, true, previous.kind)?
    {
        Ok("reobserved")
    } else {
        Ok("changed")
    }
}

fn to_json(row: &Row, change_status: &str, known: &BTreeMap<String, Row>) -> Result<Value, String> {
    let mut missing = Vec::new();
    if row.observed_at_unix.is_none() {
        missing.push("observation_timestamp_not_recorded".to_owned());
    }
    for linked in &row.links {
        if !known.contains_key(linked) {
            missing.push(format!("cross_reference_target_not_recorded:{linked}"));
        }
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
        "RAW_SHA256": signature(&row.raw, false, row.kind)?,
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
            records.push(to_json(row, kind, &current)?);
        }
    }
    if let Some(old) = &earlier {
        for (id, row) in old {
            if !current.contains_key(id) {
                *counts.entry("removed").or_default() += 1;
                records.push(to_json(row, "removed", old)?);
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
        "uncertainty_register":crate::scan_uncertainty::derive(scan, Some(saved)),
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

/// Lossless field-labelled raw text view. Raw JSON remains embedded in `RAW_DATA`,
/// while terminal-hostile control characters are escaped only for display.
///
/// # Errors
/// JSON encoding errors or a raw report above the output bound.
pub fn raw_text(report: &Value) -> Result<String, String> {
    let mut text = format!(
        "[HUNTSMAN_EVIDENCE]\nSTATUS: {}\nSCAN: {}\nBASELINE: {}\nCOUNTS: {}\nUNCERTAINTY_REGISTER: {}\n",
        report["status"].as_str().unwrap_or("UNKNOWN"),
        report["scan"]["id"].as_str().unwrap_or("UNKNOWN"),
        report["baseline"].as_str().unwrap_or("NONE"),
        report["counts"],
        report["uncertainty_register"],
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
        insert(&mut saved, Row::new("element", "x".into(), json!({"x":1}))).unwrap();
        assert!(insert(&mut saved, Row::new("element", "x".into(), json!({"x":2}))).is_err());
    }

    #[test]
    fn unresolved_cross_references_survive_and_are_explicitly_flagged() {
        let parent_id = stable_id("element", "parent");
        let child_id = stable_id("element", "child");
        let missing_id = stable_id("element", "missing-parent");
        let mut records = BTreeMap::new();
        insert(
            &mut records,
            Row::new("element", "parent".into(), json!({"value":"parent"})),
        )
        .unwrap();
        insert(
            &mut records,
            Row::new("element", "child".into(), json!({"value":"child"}))
                .linked(BTreeSet::from([parent_id.clone(), missing_id.clone()])),
        )
        .unwrap();

        add_reciprocal_links(&mut records);

        // The absent parent is not fabricated as a row or silently removed.
        assert_eq!(records.len(), 2);
        let child = &records[&child_id];
        assert!(child.links.contains(&parent_id));
        assert!(child.links.contains(&missing_id));
        assert!(records[&parent_id].links.contains(&child_id));

        let report = to_json(child, "full", &records).unwrap();
        let links = report["CROSS_REFERENCES"].as_array().unwrap();
        assert!(links.iter().any(|value| value == &json!(missing_id)));
        let missing = report["MISSING_INFORMATION"].as_array().unwrap();
        assert!(missing.iter().any(|value| {
            value == &json!(format!("cross_reference_target_not_recorded:{missing_id}"))
        }));
        assert_eq!(report["RAW_DATA"]["value"], "child");
    }

    #[test]
    fn per_run_timestamps_cannot_hide_material_change() {
        let mut old = json!({
            "value":"same","observed_at_unix":2,
            "evidence":[{"provenance":{"scan_id":"old","recorded_at_unix":2},
                         "attributes":{"created":"source fact"}}]
        });
        let mut next = json!({
            "value":"same","observed_at_unix":4,
            "evidence":[{"provenance":{"scan_id":"new","recorded_at_unix":4},
                         "attributes":{"created":"source fact"}}]
        });
        assert_ne!(
            signature(&old, false, "entity").unwrap(),
            signature(&next, false, "entity").unwrap()
        );
        semantic(&mut old, "entity");
        semantic(&mut next, "entity");
        assert_eq!(old, next);
        next["evidence"][0]["attributes"]["created"] = json!("changed");
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
