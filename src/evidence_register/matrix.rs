//! Sparse source-by-finding matrix over saved scan evidence.
//!
//! Exact data equality does not establish identity or independent corroboration.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::scan_store::{ScanRecord, ScanResults, ScanStatus};
use crate::sf_elements::DataElement;
use crate::sha256::{hex32, sha256};
use crate::textnorm::escape_unsafe_text;

use super::{MAX_RECORDS, MAX_RENDER_BYTES};

type Grid = BTreeMap<(String, String), BTreeMap<String, Cell>>;

#[derive(Default)]
struct Cell {
    ids: Vec<String>,
    flagged: usize,
}

fn stable_id(kind: &str, value: &str) -> String {
    let mut bytes = Vec::with_capacity(kind.len() + value.len() + 1);
    bytes.extend_from_slice(kind.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(value.as_bytes());
    format!("HSE-MX-{}", &hex32(&sha256(&bytes))[..20])
}

/// Report DNS-like equivalence candidates without coalescing original observations.
/// ASCII-only and type-scoped: no general-purpose person, email or Unicode folding.
fn normalization_candidate(kind: &str, value: &str) -> Option<String> {
    if !matches!(kind, "DOMAIN_NAME" | "INTERNET_NAME")
        || !value.is_ascii()
        || value.is_empty()
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return None;
    }
    let unqualified = value.strip_suffix('.').unwrap_or(value);
    (!unqualified.is_empty()).then(|| unqualified.to_ascii_lowercase())
}

fn grouped(elements: &[DataElement]) -> Result<Grid, String> {
    if elements.len() > MAX_RECORDS {
        return Err(format!(
            "matrix has {} elements, above the {}-element bound; no results truncated",
            elements.len(),
            MAX_RECORDS
        ));
    }
    let mut grid: Grid = BTreeMap::new();
    for element in elements.iter().filter(|item| item.kind != "ROOT") {
        let cell = grid
            .entry((element.kind.clone(), element.data.clone()))
            .or_default()
            .entry(element.module.clone())
            .or_default();
        cell.ids.push(element.id.clone());
        cell.flagged += usize::from(element.fp);
    }
    for modules in grid.values_mut() {
        for cell in modules.values_mut() {
            cell.ids.sort_unstable();
        }
    }
    Ok(grid)
}

fn render_row(kind: &str, value: &str, providers: BTreeMap<String, Cell>) -> Value {
    let mut flagged = 0;
    let mut total = 0;
    let source_count = providers.keys().filter(|source| !source.is_empty()).count();
    let cells: Vec<Value> = providers
        .into_iter()
        .map(|(source, cell)| {
            let count = cell.ids.len();
            flagged += cell.flagged;
            total += count;
            json!({
                "SOURCE_MODULE": if source.is_empty() { None } else { Some(source) },
                "ELEMENT_IDS": cell.ids,
                "OBSERVATIONS": count,
                "OPERATOR_FLAGGED": cell.flagged
            })
        })
        .collect();
    let candidate = normalization_candidate(kind, value);
    let normalization = candidate
        .as_ref()
        .map(|_| "ascii_dns_casefold_optional_terminal_dot");
    json!({
        "NORMALIZED_MATCH_CANDIDATE": candidate,
        "NORMALIZATION_METHOD": normalization,
        "RECORD_ID": stable_id(kind, value),
        "FINDING_TYPE": kind,
        "EXACT_VALUE": value,
        "SOURCE_MODULE_COUNT": source_count,
        "OBSERVATION_COUNT": total,
        "OPERATOR_FLAGGED_COUNT": flagged,
        "MIXED_FLAG_STATUS": flagged > 0 && flagged < total,
        "CELLS": cells,
        "VERIFICATION_STATUS": "recorded_unverified",
    })
}

/// Build a bounded sparse evidence matrix offline. Rows are exact type/value
/// pairs, while columns are recorded source-module labels.
///
/// # Errors
/// Refuses over-limit inputs or outputs instead of truncating.
pub fn compile_matrix(scan: &ScanRecord, saved: &ScanResults) -> Result<Value, String> {
    let grid = grouped(&saved.elements)?;
    let mut sources = BTreeSet::new();
    let mut multi_source_rows = 0;
    let mut mixed_flags = 0;
    let rows: Vec<Value> = grid
        .into_iter()
        .map(|((kind, value), providers)| {
            sources.extend(
                providers
                    .keys()
                    .filter(|source| !source.is_empty())
                    .cloned(),
            );
            let row = render_row(&kind, &value, providers);
            multi_source_rows += usize::from(row["SOURCE_MODULE_COUNT"].as_u64().unwrap_or(0) > 1);
            mixed_flags += usize::from(row["MIXED_FLAG_STATUS"] == true);
            row
        })
        .collect();
    // Candidate collisions are diagnostic only. Exact keys and original variants
    // remain separate rows, so the matrix cannot create a false identity match.
    let mut candidate_groups: BTreeMap<(String, String), Vec<(String, String)>> = BTreeMap::new();
    for row in &rows {
        let (Some(kind), Some(candidate), Some(value), Some(id)) = (
            row["FINDING_TYPE"].as_str(),
            row["NORMALIZED_MATCH_CANDIDATE"].as_str(),
            row["EXACT_VALUE"].as_str(),
            row["RECORD_ID"].as_str(),
        ) else {
            continue;
        };
        candidate_groups
            .entry((kind.to_owned(), candidate.to_owned()))
            .or_default()
            .push((value.to_owned(), id.to_owned()));
    }
    let normalization_candidates: Vec<Value> = candidate_groups
        .into_iter()
        .filter(|(_, variants)| variants.len() > 1)
        .map(|((kind, candidate), variants)| {
            json!({
                "FINDING_TYPE": kind,
                "CANDIDATE_VALUE": candidate,
                "EXACT_VARIANTS": variants,
                "VERIFICATION_STATUS": "unverified_candidate",
            })
        })
        .collect();
    let observed_modules: BTreeSet<&str> = sources.iter().map(String::as_str).collect();
    let mut executions = BTreeMap::new();
    for outcome in &saved.outcomes {
        *executions.entry(outcome.module.clone()).or_insert(0_usize) += 1;
    }
    let without_rows: Vec<&str> = executions
        .keys()
        .filter(|module| !observed_modules.contains(module.as_str()))
        .map(String::as_str)
        .collect();
    let flagged = saved.elements.iter().filter(|element| element.fp).count();
    let root_elements = saved.elements.iter().filter(|element| element.kind == "ROOT").count();
    let matrix_elements = saved.elements.len() - root_elements;
    let report = json!({
        "format": "huntsman_sparse_evidence_matrix",
        "schema": 1,
        "scan": {"id":scan.id,"target":scan.target,"status":scan.status},
        "axes": ["finding_type_and_exact_value", "recorded_source_module"],
        "columns": sources,
        "rows": rows,
        "normalization_candidates": normalization_candidates,
        "summary": {
            "matrix_rows": rows.len(),
            "recorded_elements": saved.elements.len(),
            "matrix_elements": matrix_elements,
            "root_elements_excluded_from_matrix": root_elements,
            "operator_flagged_elements": flagged,
            "normalization_candidate_groups": normalization_candidates.len(),
            "multi_module_exact_matches": multi_source_rows,
            "mixed_operator_flag_rows": mixed_flags,
            "module_execution_counts": executions,
            "modules_with_outcomes_but_no_element_rows": without_rows,
        },
        "uncertainty_register": crate::scan_uncertainty::derive(scan, Some(saved)),
        "limitations": [
            "matching_type_and_value_is_not_identity_resolution",
            "module_labels_are_not_proof_of_independent_upstream_sources",
            "multiple_observations_are_not_independent_corroboration",
            "source_claims_and_confidence_are_not_independently_verified",
            "operator_false_positive_flags_are_not_factual_contradictions",
            "source_execution_without_elements_does_not_establish_no_results",
            "normalization_candidates_are_not_confirmed_equivalent",
            "root_elements_remain_in_the_saved_scan_but_are_excluded_from_findings_matrix"
        ],
        "scan_complete": scan.status == ScanStatus::Finished,
        "truncated": false,
    });
    let len = serde_json::to_vec(&report)
        .map_err(|error| error.to_string())?
        .len();
    if len > MAX_RENDER_BYTES {
        return Err(format!(
            "matrix requires {len} bytes, above {MAX_RENDER_BYTES}; no output truncated"
        ));
    }
    Ok(report)
}

/// Export sparse matrix rows with original exact values and saved record IDs.
///
/// # Errors
/// Refuses serialization errors or over-limit output.
pub fn matrix_raw_text(report: &Value) -> Result<String, String> {
    let mut output = format!(
        "[HUNTSMAN_MATRIX]\nSCAN: {}\nSUMMARY: {}\nUNCERTAINTY_REGISTER: {}\n",
        report["scan"]["id"].as_str().unwrap_or("UNKNOWN"),
        escape_unsafe_text(&report["summary"].to_string()),
        escape_unsafe_text(&report["uncertainty_register"].to_string())
    );
    for row in report["rows"].as_array().into_iter().flatten() {
        let encoded = serde_json::to_string(row).map_err(|error| error.to_string())?;
        let safe = escape_unsafe_text(&encoded);
        writeln!(output, "\n[MATRIX_ROW]\n{safe}\n[END_MATRIX_ROW]")
            .map_err(|error| error.to_string())?;
        if output.len() > MAX_RENDER_BYTES {
            return Err("matrix raw export exceeds limit; no output truncated".to_owned());
        }
    }
    output.push_str("\n[END_HUNTSMAN_MATRIX]\n");
    if output.len() > MAX_RENDER_BYTES {
        return Err("matrix raw export exceeds limit; no output truncated".to_owned());
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn element(id: &str, module: &str, flagged: bool) -> DataElement {
        DataElement {
            id: id.to_owned(),
            kind: "INTERNET_NAME".to_owned(),
            data: "example.org".to_owned(),
            source: None,
            module: module.to_owned(),
            confidence: 90,
            created: 0,
            fp: flagged,
            entity: None,
            raw: Value::Null,
        }
    }

    #[test]
    fn matrix_is_sparse_and_keeps_operator_disagreement() {
        let grid = grouped(&[
            element("a", "dns", false),
            element("b", "dns", true),
            element("c", "rdap", false),
        ])
        .unwrap();
        assert_eq!(grid.len(), 1);
        let row = render_row(
            "INTERNET_NAME",
            "example.org",
            grid.into_values().next().unwrap(),
        );
        assert_eq!(row["SOURCE_MODULE_COUNT"], 2);
        assert_eq!(row["OBSERVATION_COUNT"], 3);
        assert_eq!(row["OPERATOR_FLAGGED_COUNT"], 1);
        assert_eq!(row["MIXED_FLAG_STATUS"], true);
        assert_eq!(row["CELLS"][0]["ELEMENT_IDS"], json!(["a", "b"]));
    }

    #[test]
    fn observation_order_does_not_change_matrix_cells() {
        let earlier = grouped(&[element("z", "dns", false), element("a", "dns", true)]).unwrap();
        let later = grouped(&[element("a", "dns", true), element("z", "dns", false)]).unwrap();
        let first = render_row(
            "INTERNET_NAME",
            "example.org",
            earlier.into_values().next().unwrap(),
        );
        let second = render_row(
            "INTERNET_NAME",
            "example.org",
            later.into_values().next().unwrap(),
        );
        assert_eq!(first, second);
        assert_eq!(first["CELLS"][0]["ELEMENT_IDS"], json!(["a", "z"]));
    }

    #[test]
    fn dns_normalization_is_annotated_not_silently_merged() {
        assert_eq!(
            normalization_candidate("DOMAIN_NAME", "Example.ORG."),
            Some("example.org".to_owned())
        );
        assert_eq!(
            normalization_candidate("DOMAIN_NAME", "example.org"),
            Some("example.org".to_owned())
        );
        assert_eq!(normalization_candidate("EMAILADDR", "A@B.COM"), None);
        assert_eq!(normalization_candidate("INTERNET_NAME", "éxample.org"), None);
        let mut upper = element("a", "dns", false);
        upper.kind = "DOMAIN_NAME".to_owned();
        upper.data = "Example.ORG.".to_owned();
        let mut lower = element("b", "rdap", false);
        lower.kind = "DOMAIN_NAME".to_owned();
        lower.data = "example.org".to_owned();
        let grid = grouped(&[upper, lower]).unwrap();
        assert_eq!(grid.len(), 2);
        let values: Vec<Value> = grid
            .into_iter()
            .map(|((kind, value), sources)| render_row(&kind, &value, sources))
            .collect();
        assert_eq!(
            values[0]["NORMALIZED_MATCH_CANDIDATE"],
            values[1]["NORMALIZED_MATCH_CANDIDATE"]
        );
        assert_ne!(values[0]["RECORD_ID"], values[1]["RECORD_ID"]);
    }

    #[test]
    fn root_is_not_a_source_finding() {
        let mut root = element("root", "target", false);
        root.kind = "ROOT".to_owned();
        assert!(grouped(&[root]).unwrap().is_empty());
    }

    #[test]
    fn raw_export_escapes_bidi_controls_without_losing_json_values() {
        let text = json!({
            "scan": {"id": "a"},
            "summary": {},
            "uncertainty_register": {},
            "rows": [{"EXACT_VALUE": "left\u{202e}right"}]
        });
        let raw = matrix_raw_text(&text).unwrap();
        assert!(!raw.contains('\u{202e}'));
        assert!(raw.contains(r"\u202e"));
        assert!(raw.contains("[END_HUNTSMAN_MATRIX]"));
    }

    #[test]
    fn matrix_keys_are_exact_and_stable() {
        assert_eq!(stable_id("a", "bc"), stable_id("a", "bc"));
        assert_ne!(stable_id("a", "bc"), stable_id("ab", "c"));
        assert_ne!(
            stable_id("domain", "EXAMPLE.org"),
            stable_id("domain", "example.org")
        );
    }

    #[test]
    fn missing_module_is_not_counted_as_a_source() {
        let grid = grouped(&[element("a", "", false)]).unwrap();
        let row = render_row(
            "INTERNET_NAME",
            "example.org",
            grid.into_values().next().unwrap(),
        );
        assert_eq!(row["SOURCE_MODULE_COUNT"], 0);
        assert!(row["CELLS"][0]["SOURCE_MODULE"].is_null());
    }
}
