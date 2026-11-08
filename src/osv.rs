//! OSV vulnerability lookup for a CVE identifier. Keyless -- the open vulnerability database
//! `api.osv.dev` serves a per-CVE record at `https://api.osv.dev/v1/vulns/{CVE}`.
//!
//! One CVE resolves to its OSV record: a `Document` keyed by the CVE id, with its summary, details,
//! CVSS severity vector, publication and modification times kept verbatim as evidence; each alias
//! (a `GHSA-…` or other database id for the same flaw) a `Document` pivot, and each reference a
//! `Url`. A `404` is the clean "OSV holds no record for this CVE" answer; a body that is not a
//! vulnerability document is schema drift. OSV reports an observation, never proof a given system
//! is affected.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_unreserved};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "osv";
const API_BASE: &str = "https://api.osv.dev/v1/vulns";

/// The CVE record, confirmed on OSV: a single-source vulnerability-existence lead.
const CVE_CONF: f64 = 0.80;
/// An alias id (GHSA and the like) for the same flaw.
const ALIAS_CONF: f64 = 0.70;
/// A reference URL OSV lists for the flaw.
const REF_CONF: f64 = 0.60;

pub type Report = crate::lookup_report::SourceReport;

#[derive(Debug, Deserialize)]
struct Vuln {
    #[serde(default)]
    id: String,
    #[serde(default)]
    summary: Option<String>,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    modified: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default)]
    severity: Vec<Severity>,
    #[serde(default)]
    references: Vec<Reference>,
}

#[derive(Debug, Deserialize)]
struct Severity {
    #[serde(default, rename = "type")]
    kind: Option<String>,
    #[serde(default)]
    score: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Reference {
    #[serde(default)]
    url: Option<String>,
}

/// Whether `id` is shaped like a CVE identifier: `CVE-YYYY-N…` with a four-digit year and at least
/// four digits of sequence, ASCII only. **Pure.**
#[must_use]
pub fn valid_cve(id: &str) -> bool {
    let mut parts = id.split('-');
    let (Some("CVE"), Some(year), Some(seq), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    year.len() == 4
        && year.bytes().all(|b| b.is_ascii_digit())
        && seq.len() >= 4
        && seq.bytes().all(|b| b.is_ascii_digit())
}

/// The canonical upper-case CVE id `raw` names, or `None` when it is not one. **Pure.**
#[must_use]
pub fn canonical_cve(raw: &str) -> Option<String> {
    let id = raw.trim().to_ascii_uppercase();
    valid_cve(&id).then_some(id)
}

/// The OSV record URL for a CVE. **Pure.**
#[must_use]
pub fn vuln_url(cve: &str) -> String {
    format!("{API_BASE}/{}", percent_encode_unreserved(cve))
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", crate::http::DEFAULT_USER_AGENT)
}

/// Look up one CVE on OSV, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the record URL.
pub fn lookup<T: Transport + ?Sized>(
    transport: &T,
    cve: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, Error> {
    let Some(cve) = canonical_cve(cve) else {
        return Ok(miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a CVE identifier",
        )));
    };
    let fetched = fetch(
        transport,
        request(vuln_url(&cve)),
        None,
        &options(),
        SRC,
        now_unix,
    )?;
    Ok(interpret(&fetched, &cve, scan_id, now_unix).unwrap_or_else(miss))
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn interpret(
    fetched: &Fetched,
    cve: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    if let Some(response) = &fetched.response {
        if response.status == 404 {
            return Err(SourceExecutionOutcome::valid_zero(SRC, now_unix).with_http_status(404));
        }
    }
    let response = whole_response(fetched, "OSV record")?;
    answer(fetched, "OSV record")?;
    let vuln: Vuln = decode_json(response, SRC, now_unix, "OSV record")?;
    // The record must be the CVE asked for; its id, or an alias, must name it. Anything else is a
    // record for a different flaw, never minted onto the queried id.
    let names_query = vuln.id.eq_ignore_ascii_case(cve)
        || vuln.aliases.iter().any(|a| a.eq_ignore_ascii_case(cve));
    if !names_query {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "OSV returned a record for a different vulnerability than the queried CVE",
        ));
    }
    let entities = build_entities(&vuln, cve, scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// Build the report entities from the confirmed record. **Pure.**
fn build_entities(vuln: &Vuln, cve: &str, scan_id: &str) -> Vec<Entity> {
    let cvss = vuln
        .severity
        .iter()
        .find(|s| s.kind.as_deref().is_some_and(|k| k.starts_with("CVSS")))
        .and_then(|s| nonblank(s.score.as_deref()));
    let aliases = vuln.aliases.join(", ");
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("OSV vulnerability record for {cve}: a public vulnerability observation, not proof any given system is affected"),
    )
    .with_attr("dataset", "OSV")
    .with_attr("record_url", vuln_url(cve))
    .with_optional_attrs([
        ("summary", nonblank(vuln.summary.as_deref())),
        ("details", nonblank(vuln.details.as_deref())),
        ("cvss", cvss),
        ("published", nonblank(vuln.published.as_deref())),
        ("modified", nonblank(vuln.modified.as_deref())),
        ("aliases", nonblank(Some(aliases.as_str()))),
    ]);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        cve,
        CVE_CONF,
        scan_id,
        evidence.clone(),
        &["osv", "vulnerability", "cve"],
    );
    for alias in &vuln.aliases {
        if let Some(alias) = nonblank(Some(alias)) {
            push_entity(
                &mut entities,
                EntityKind::Document,
                alias,
                ALIAS_CONF,
                scan_id,
                evidence.clone(),
                &["osv", "vulnerability", "alias"],
            );
        }
    }
    for reference in &vuln.references {
        if let Some(url) = reference
            .url
            .as_deref()
            .and_then(crate::canonical::canonical_url)
        {
            push_entity(
                &mut entities,
                EntityKind::Url,
                &url,
                REF_CONF,
                scan_id,
                evidence.clone(),
                &["osv", "vulnerability-reference"],
            );
        }
    }
    merge_by_uid(&mut entities);
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::{OneResponse, ScriptedTransport, json_ok};

    /// Trimmed from the live `api.osv.dev/v1/vulns/CVE-2021-44228` record, 2026-11-08.
    const LOG4SHELL: &str = r#"{"id":"CVE-2021-44228","summary":"Log4Shell","details":"Apache Log4j2 JNDI flaw","aliases":["GHSA-jfh8-c2jp-5v3q"],"modified":"2026-10-24T10:30:50Z","published":"2021-12-10T10:15:09Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],"references":[{"type":"ADVISORY","url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},{"type":"WEB","url":"https://logging.apache.org/log4j/2.x/security.html"}]}"#;

    fn report_of(body: &str, cve: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, cve, "scan-osv", 1).expect("lookup runs")
    }

    fn has(report: &Report, kind: &EntityKind, value: &str) -> bool {
        report
            .entities
            .iter()
            .any(|e| e.kind == *kind && e.raw_value == value)
    }

    fn attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Document && e.raw_value == "CVE-2021-44228")
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn valid_cve_matches_the_identifier_grammar() {
        assert!(valid_cve("CVE-2021-44228"));
        assert!(valid_cve("CVE-2000-0001"));
        assert!(!valid_cve("cve-2021-44228"));
        assert!(!valid_cve("CVE-21-44228"));
        assert!(!valid_cve("CVE-2021-44"));
        assert!(!valid_cve("CVE-2021"));
        assert!(!valid_cve("GHSA-jfh8-c2jp-5v3q"));
        assert_eq!(
            canonical_cve(" cve-2021-44228 ").as_deref(),
            Some("CVE-2021-44228")
        );
        assert_eq!(canonical_cve("not-a-cve"), None);
    }

    #[test]
    fn a_confirmed_cve_yields_a_document_with_severity_aliases_and_references() {
        let report = report_of(LOG4SHELL, "cve-2021-44228");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        assert!(has(&report, &EntityKind::Document, "CVE-2021-44228"));
        assert!(has(&report, &EntityKind::Document, "GHSA-jfh8-c2jp-5v3q"));
        assert!(has(
            &report,
            &EntityKind::Url,
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
        ));
        assert_eq!(attr(&report, "summary"), Some("Log4Shell"));
        assert_eq!(
            attr(&report, "cvss"),
            Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        );
        assert_eq!(attr(&report, "published"), Some("2021-12-10T10:15:09Z"));
    }

    #[test]
    fn a_record_matched_only_by_an_alias_is_still_the_queried_cve() {
        // OSV can answer a CVE query with a record whose own id is the GHSA, listing the CVE as an
        // alias. That still names the query and is kept.
        let body = r#"{"id":"GHSA-xxxx","aliases":["CVE-2021-44228"],"references":[]}"#;
        let report = report_of(body, "CVE-2021-44228");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn an_unknown_cve_is_a_clean_zero() {
        let transport = OneResponse::json(404, r#"{"code":5,"message":"Vulnerability not found"}"#);
        let report = lookup(&transport, "CVE-2000-0001", "scan-osv", 1).expect("runs");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn a_record_for_a_different_flaw_is_semantic_drift() {
        let body = r#"{"id":"CVE-1999-0001","aliases":[],"references":[]}"#;
        let report = report_of(body, "CVE-2021-44228");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn an_invalid_selector_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "not-a-cve", "scan-osv", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
