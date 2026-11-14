//! Read-only, provenance-preserving intelligence compendium for one saved scan.
//!
//! This renderer neither collects information nor invents identity matches.
//! Twenty analytical headings index the *recorded* observations; unassessed
//! dimensions are marked explicitly. The original, complete deserialized
//! scan record, scan results, and saved execution log are embedded as JSON.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::scan_store::{LogEntry, ScanRecord, ScanResults};
use crate::sha256::{hex32, sha256};

/// Maximum finished document size on a memory-constrained Termux device.
pub const MAX_COMPENDIUM_BYTES: usize = 8 * 1024 * 1024;

/// Canonical twenty sections, in stable order.
pub const SECTIONS: [&str; 20] = [
    "EXECUTIVE INTELLIGENCE ASSESSMENT",
    "SUBJECT & ENTITY IDENTIFICATION",
    "IDENTIFIERS, ALIASES & ATTRIBUTES",
    "PUBLIC RECORDS & OFFICIAL REGISTRIES",
    "CORPORATE & FINANCIAL INTELLIGENCE",
    "DIGITAL FOOTPRINT & ONLINE PRESENCE",
    "DOMAIN, NETWORK & INFRASTRUCTURE DATA",
    "GEOSPATIAL & LOCATION INTELLIGENCE",
    "SOCIAL, MEDIA & PUBLICATION INTELLIGENCE",
    "HISTORICAL RECORDS & ARCHIVED CONTENT",
    "SECURITY EXPOSURE & BREACH METADATA",
    "ASSOCIATIONS & RELATIONSHIP MAPPING",
    "CROSS-SOURCE ENTITY CORRELATION",
    "CHRONOLOGICAL EVENT RECONSTRUCTION",
    "CONTRADICTIONS & COMPETING HYPOTHESES",
    "SOURCE RELIABILITY & CONFIDENCE SCORING",
    "EVIDENCE PROVENANCE & CHAIN OF CUSTODY",
    "RAW EVIDENCE & ORIGINAL DATASETS",
    "VERIFIED FINDINGS & INTELLIGENCE GAPS",
    "FINAL INTEGRATED INTELLIGENCE ASSESSMENT",
];

#[derive(Serialize)]
struct Original<'a> {
    #[serde(rename = "scan_record")]
    record: &'a ScanRecord,
    #[serde(rename = "scan_results")]
    results: Option<&'a ScanResults>,
    #[serde(rename = "scan_log")]
    log: &'a [LogEntry],
}

/// Failure to build a complete compendium.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RenderError {
    #[error("compendium scan id does not match stored results")]
    MismatchedScan,
    #[error("compendium exceeds {MAX_COMPENDIUM_BYTES} bytes")]
    TooLarge,
    #[error("cannot serialize full compendium evidence: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("compendium JSON is not valid UTF-8: {0}")]
    Encoding(#[from] std::str::Utf8Error),
}

fn append(out: &mut String, chunk: &str) -> Result<(), RenderError> {
    if chunk.len() > MAX_COMPENDIUM_BYTES - out.len() {
        return Err(RenderError::TooLarge);
    }
    out.push_str(chunk);
    Ok(())
}

/// Quote a free-text source value so its line breaks or headings cannot alter
/// the document's structure. This also retains the original in raw JSON.
fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"<invalid string>\"".into())
}

/// Produce a complete, deterministic, bounded UTF-8 text compendium.
///
/// A source record's "confidence" is not an identity-verification verdict.
/// Missing source outcomes and unvisited categories remain UNKNOWN.
/// The raw payload is a serialization of *stored* records, not the original
/// network response byte stream. No collection or external API calls occur.
///
/// # Errors
/// On serialization failure or if the full document cannot fit in the limit.
#[allow(clippy::too_many_lines)]
pub(crate) fn render(
    record: &ScanRecord,
    results: Option<&ScanResults>,
    log: &[LogEntry],
) -> Result<Vec<u8>, RenderError> {
    if results.is_some_and(|saved| saved.scan_id != record.id) {
        return Err(RenderError::MismatchedScan);
    }

    let original = Original {
        record,
        results,
        log,
    };
    let raw = crate::json::to_bounded_json(&original, MAX_COMPENDIUM_BYTES, false)?
        .map_err(|_| RenderError::TooLarge)?;
    let raw_sha256 = hex32(&sha256(&raw));
    let raw = std::str::from_utf8(&raw)?;

    let entities = results.map_or(&[][..], |saved| saved.entities.as_slice());
    let outcomes = results.map_or(&[][..], |saved| saved.outcomes.as_slice());
    let elements = results.map_or(&[][..], |saved| saved.elements.as_slice());
    let correlations = results.map_or(&[][..], |saved| saved.correlations.as_slice());
    let accepted = outcomes
        .iter()
        .filter(|source| source.is_accepted())
        .count();
    let unanswered = outcomes.len() - accepted;
    let flagged = elements.iter().filter(|element| element.fp).count();
    let evidence_count: usize = entities.iter().map(|entity| entity.evidence.len()).sum();
    let mut kinds = BTreeMap::<&str, usize>::new();
    for entity in entities {
        *kinds.entry(entity.kind.as_str()).or_default() += 1;
    }
    let mut out = String::new();
    append(
        &mut out,
        "COMPREHENSIVE MULTI-SOURCE OPEN-SOURCE INTELLIGENCE COMPENDIUM\n\
         HUNTSMAN SEARCH ENGINE — UNIFIED INTELLIGENCE & EVIDENCE SYSTEM\n\
         STATUS: DERIVED FROM SAVED EVIDENCE; NO NEW SOURCES QUERIED\n\
         COVERAGE: UNKNOWN BEYOND RECORDED SOURCES\n\
         VERIFICATION: NO AUTOMATIC REAL-WORLD IDENTITY VERDICT\n\
         CONSISTENCY: READ-ONLY, NON-ATOMIC SAVED-SCAN SNAPSHOT\n\n",
    )?;

    for (index, title) in SECTIONS.iter().enumerate() {
        append(&mut out, &format!("{:02} — {title}\n", index + 1))?;
        match index {
            0 => {
                if results.is_none() {
                    append(&mut out, "Saved results are unavailable.\n")?;
                }
                append(
                    &mut out,
                    &format!(
                        "Recorded entities: {}; elements: {}; source outcomes: {} (accepted {}, not accepted {}); correlations: {}; log entries: {}.\nFalse-positive-marked elements: {} (preserved in raw evidence).\nNo claim of source independence, subject identification or complete coverage is implied.\n",
                        entities.len(),
                        elements.len(),
                        outcomes.len(),
                        accepted,
                        unanswered,
                        correlations.len(),
                        log.len(),
                        flagged
                    ),
                )?;
            }
            1 => append(
                &mut out,
                &format!(
                    "Scan ID: {}\nSubject/target as entered: {}\nLookup kind: {}\nTarget event type: {}\nStatus: {}\nSubject attribution: NOT INDEPENDENTLY VERIFIED.\n",
                    quoted(&record.id),
                    quoted(&record.target),
                    quoted(&record.kind),
                    quoted(&record.target_type),
                    record.status.as_str()
                ),
            )?,
            2 => {
                append(
                    &mut out,
                    &format!(
                        "Recorded entities by source-assigned type ({} total):\n",
                        entities.len()
                    ),
                )?;
                if kinds.is_empty() {
                    append(
                        &mut out,
                        "NONE RECORDED; this does not establish absence.\n",
                    )?;
                }
                for (kind, count) in &kinds {
                    append(&mut out, &format!("- {}: {count}\n", quoted(kind)))?;
                }
                append(
                    &mut out,
                    "Individual values, aliases, attributes and source evidence are preserved under section 18.\n",
                )?;
            }
            3..=11 => append(
                &mut out,
                "SOURCE-CLASS COVERAGE NOT ESTABLISHED BY THIS RENDERER.\n\
                 The stored scan can contain relevant observations; assess the complete\n\
                 typed entities, elements and source outcomes in section 18. Absence of a\n\
                 dedicated category assessment is NOT a negative finding.\n",
            )?,
            12 => {
                append(
                    &mut out,
                    &format!(
                        "Recorded correlation records: {}. Correlations are investigative leads, not independently verified identities.\n",
                        correlations.len()
                    ),
                )?;
                for correlation in correlations {
                    append(
                        &mut out,
                        &format!(
                            "- id={} rule={} element_refs={}\n",
                            quoted(&correlation.id),
                            quoted(&correlation.rule),
                            correlation.elements.len()
                        ),
                    )?;
                }
                append(
                    &mut out,
                    "Full rules, descriptions and element references are in section 18.\n",
                )?;
            }
            13 => append(
                &mut out,
                &format!(
                    "Scan created at Unix milliseconds: {}.\nStarted: {}.\nEnded: {}.\nSource-specific event chronology has NOT been independently reconstructed; source timestamps remain in original records.\n",
                    record.created,
                    record
                        .started
                        .map_or_else(|| "NOT RECORDED".into(), |t| t.to_string()),
                    record
                        .ended
                        .map_or_else(|| "NOT RECORDED".into(), |t| t.to_string())
                ),
            )?,
            14 => append(
                &mut out,
                "CONTRADICTION ANALYSIS: NOT PERFORMED BY THIS EXPORT.\n\
                 Do not automatically reconcile competing values or infer shared identity.\n\
                 All original competing statements and false-positive flags are retained.\n",
            )?,
            15 => {
                append(
                    &mut out,
                    &format!(
                        "Recorded source executions: {}; accepted: {}; otherwise: {}.\n",
                        outcomes.len(),
                        accepted,
                        unanswered
                    ),
                )?;
                for source in outcomes {
                    append(
                        &mut out,
                        &format!(
                            "- module={} outcome={} accepted={} found={}\n",
                            quoted(&source.module),
                            source.kind.as_str(),
                            source.is_accepted(),
                            source
                                .found
                                .map_or_else(|| "UNKNOWN".into(), |n| n.to_string())
                        ),
                    )?;
                }
                append(
                    &mut out,
                    "Provider response status is not proof of source independence or factual accuracy.\n",
                )?;
            }
            16 => append(
                &mut out,
                &format!(
                    "Stored entity evidence references: {evidence_count}.\n\
                 SHA-256 of the exact UTF-8 JSON payload in section 18: {raw_sha256}.\n\
                 Integrity hash describes this export's serialized stored records, not\n\
                 independently established cryptographic chain of custody to upstream sources.\n"
                ),
            )?,
            17 => {
                append(&mut out, "BEGIN_FULL_SAVED_EVIDENCE_JSON\n")?;
                append(&mut out, raw)?;
                append(&mut out, "\nEND_FULL_SAVED_EVIDENCE_JSON\n")?;
            }
            18 => append(
                &mut out,
                &format!(
                    "Unaccepted/unanswered source executions: {unanswered}; false-positive-marked data elements: {flagged}.\n\
                 VERIFIED REAL-WORLD FINDINGS: NOT AUTOMATICALLY ESTABLISHED.\n\
                 EVIDENCE STATES: SEED / CANDIDATE / OBSERVED / CORROBORATED / VERIFIED;\n\
                 EXCEPTIONS: REJECTED / CONFLICTED / STALE. These are evaluation categories,\n\
                 not classifications assigned by this renderer.\n\
                 Missing or failed sources must not be presented as clear results.\n"
                ),
            )?,
            19 => append(
                &mut out,
                "FINAL ASSESSMENT: This compendium is an evidence-indexed saved-scan\n\
                 snapshot. Recorded observations are leads requiring source-specific\n\
                 verification; independent corroboration and comprehensive coverage\n\
                 have not been established by generating this file. The source JSON\n\
                 and execution log above are retained whole or this export fails.\n",
            )?,
            _ => unreachable!(),
        }
        append(&mut out, "\n")?;
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};

    fn fixture() -> (ScanRecord, ScanResults, Vec<LogEntry>) {
        let record = ScanRecord {
            format_version: FORMAT_VERSION,
            id: "aabbccdd00112233".into(),
            name: "Test case".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::Finished,
            created: 10,
            started: Some(11),
            ended: Some(12),
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
            owner_started: None,
        };
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: record.id.clone(),
            text: "exact source evidence\nwith a second line \u{1f50e}".into(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        let log = vec![LogEntry {
            time: 42,
            component: "fixture".into(),
            level: crate::scan_store::LogLevel::Info,
            message: "original\nunabridged".into(),
        }];
        (record, results, log)
    }

    #[test]
    fn twenty_sections_and_original_records_survive_round_trip() {
        let (record, results, log) = fixture();
        let rendered = render(&record, Some(&results), &log).unwrap();
        assert_eq!(rendered, render(&record, Some(&results), &log).unwrap());
        let text = String::from_utf8(rendered).unwrap();
        for (index, title) in SECTIONS.iter().enumerate() {
            assert!(text.contains(&format!("{:02} — {title}\n", index + 1)));
        }
        let json = text
            .split_once("BEGIN_FULL_SAVED_EVIDENCE_JSON\n")
            .unwrap()
            .1
            .split_once("\nEND_FULL_SAVED_EVIDENCE_JSON")
            .unwrap()
            .0;
        let decoded: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(
            decoded["scan_record"],
            serde_json::to_value(&record).unwrap()
        );
        assert_eq!(
            decoded["scan_results"],
            serde_json::to_value(&results).unwrap()
        );
        assert_eq!(decoded["scan_log"], serde_json::to_value(&log).unwrap());
        let sha = hex32(&sha256(json.as_bytes()));
        assert!(text.contains(&sha));
        assert!(text.contains("UNKNOWN BEYOND RECORDED SOURCES"));
        assert!(text.contains("NOT INDEPENDENTLY VERIFIED"));
    }

    #[test]
    fn oversize_refused_without_partial_output_or_data_loss() {
        let (record, mut results, log) = fixture();
        results.text = "z".repeat(MAX_COMPENDIUM_BYTES);
        let error = render(&record, Some(&results), &log).unwrap_err();
        assert!(matches!(error, RenderError::TooLarge));
    }

    #[test]
    fn cross_scan_results_refused() {
        let (record, mut results, log) = fixture();
        results.scan_id = "other".into();
        assert!(render(&record, Some(&results), &log).is_err());
    }

    #[test]
    fn target_can_not_inject_section_headings() {
        let (mut record, results, log) = fixture();
        record.target = "example.com\n20 — SPOOFED RESULT".into();
        let doc = String::from_utf8(render(&record, Some(&results), &log).unwrap()).unwrap();
        assert!(!doc.contains("example.com\n20 — SPOOFED RESULT"));
        assert!(doc.contains("20 — FINAL INTEGRATED INTELLIGENCE ASSESSMENT"));
    }
}
