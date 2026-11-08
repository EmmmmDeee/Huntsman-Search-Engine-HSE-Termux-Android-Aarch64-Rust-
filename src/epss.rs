//! EPSS exploitation-probability lookup for a CVE identifier. Keyless -- FIRST's Exploit Prediction
//! Scoring System serves a per-CVE score at `https://api.first.org/data/v1/epss?cve={CVE}`.
//!
//! One CVE resolves to its EPSS score: the probability (0..1) that the flaw will be exploited in
//! the wild within 30 days, and its percentile among all scored CVEs, on a stated date. The score
//! is emitted onto a `Document` keyed by the CVE id, the same key OSV uses, so the two legs merge
//! into one enriched CVE node. An empty data array is the clean "EPSS has not scored this CVE"
//! answer. A score is a prediction, never a statement that exploitation has occurred.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_component};
use crate::osv::canonical_cve;
use crate::source_outcome::SourceExecutionOutcome;

pub const SRC: &str = "epss";
const API_BASE: &str = "https://api.first.org/data/v1/epss";
/// The EPSS score of a confirmed CVE: an enrichment onto the CVE document.
const SCORE_CONF: f64 = 0.70;

pub type Report = crate::lookup_report::SourceReport;

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default)]
    data: Vec<Row>,
}

#[derive(Debug, Deserialize)]
struct Row {
    #[serde(default)]
    cve: String,
    #[serde(default)]
    epss: Option<String>,
    #[serde(default)]
    percentile: Option<String>,
    #[serde(default)]
    date: Option<String>,
}

/// The EPSS query URL for a CVE. **Pure.**
#[must_use]
pub fn score_url(cve: &str) -> String {
    format!("{API_BASE}?cve={}", percent_encode_component(cve))
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", crate::http::DEFAULT_USER_AGENT)
}

/// Look up one CVE's EPSS score, keyless.
///
/// # Errors
/// Returns a network-boundary error when the guarded fetch refuses the score URL.
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
        request(score_url(&cve)),
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
    let response = whole_response(fetched, "EPSS score")?;
    answer(fetched, "EPSS score")?;
    let envelope: Envelope = decode_json(response, SRC, now_unix, "EPSS score")?;
    // EPSS answers the exact CVE asked for; a row for any other id is not this query's score.
    let Some(row) = envelope
        .data
        .iter()
        .find(|r| r.cve.eq_ignore_ascii_case(cve))
    else {
        // No score yet: a clean zero, not a failure. EPSS scores most but not every CVE.
        return Ok(Report {
            entities: Vec::new(),
            outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_http_status(response.status),
        });
    };
    let entities = build_entities(row, cve, scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// The CVE document carrying the EPSS score, keyed by the CVE id so it merges with OSV. **Pure.**
fn build_entities(row: &Row, cve: &str, scan_id: &str) -> Vec<Entity> {
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "EPSS exploitation-probability score for {cve}: a 30-day prediction, not evidence of exploitation"
        ),
    )
    .with_attr("dataset", "EPSS")
    .with_attr("score_url", score_url(cve))
    .with_optional_attrs([
        ("epss_probability", row.epss.as_deref()),
        ("epss_percentile", row.percentile.as_deref()),
        ("epss_date", row.date.as_deref()),
    ]);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        cve,
        SCORE_CONF,
        scan_id,
        evidence,
        &["epss", "vulnerability", "cve"],
    );
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::{ScriptedTransport, json_ok};

    /// From the live `api.first.org/data/v1/epss?cve=CVE-2021-44228` envelope, 2026-11-08.
    const SCORED: &str = r#"{"status":"OK","data":[{"cve":"CVE-2021-44228","epss":"0.999990000","percentile":"1.000000000","date":"2026-11-07"}]}"#;
    const UNSCORED: &str = r#"{"status":"OK","total":0,"data":[]}"#;

    fn report_of(body: &str, cve: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, cve, "scan-epss", 1).expect("lookup runs")
    }

    #[test]
    fn score_url_carries_the_cve() {
        assert_eq!(
            score_url("CVE-2021-44228"),
            "https://api.first.org/data/v1/epss?cve=CVE-2021-44228"
        );
    }

    #[test]
    fn a_scored_cve_enriches_the_shared_document() {
        let report = report_of(SCORED, "cve-2021-44228");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let doc = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Document && e.raw_value == "CVE-2021-44228")
            .expect("the CVE document");
        let ev = doc.evidence.first().expect("evidence");
        assert_eq!(
            ev.attributes.get("epss_probability").map(String::as_str),
            Some("0.999990000")
        );
        assert_eq!(
            ev.attributes.get("epss_percentile").map(String::as_str),
            Some("1.000000000")
        );
        assert!(doc.has_tag("epss") && doc.has_tag("cve"));
    }

    #[test]
    fn an_unscored_cve_is_a_clean_zero() {
        let report = report_of(UNSCORED, "CVE-2000-0001");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn an_invalid_selector_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "nope", "scan-epss", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
