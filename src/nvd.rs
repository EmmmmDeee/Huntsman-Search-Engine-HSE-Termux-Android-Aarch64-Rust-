//! NVD vulnerability lookup for a CVE identifier. Keyless -- the NIST National Vulnerability
//! Database serves a per-CVE record at
//! `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}`.
//!
//! One CVE resolves to NVD's authoritative record: its analysis status, English description, the
//! primary CVSS base score, severity and vector (v3.1 preferred, then v3.0, then v2), and the CWE
//! weakness ids. These enrich the same CVE `Document` OSV and EPSS key on, so the three legs merge
//! into one node. An empty result set is the clean "NVD holds no such CVE" answer. NVD's keyless
//! tier is rate-limited (about 5 requests per 30 seconds); a single on-demand lookup stays within
//! it. A record is a public vulnerability observation, not proof any given system is affected.

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport, percent_encode_component};
use crate::osv::canonical_cve;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;

pub const SRC: &str = "nvd";
const API_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// The NVD record of a confirmed CVE: an enrichment onto the CVE document.
const CVE_CONF: f64 = 0.80;

pub type Report = crate::lookup_report::SourceReport;

#[derive(Debug, Deserialize)]
struct Envelope {
    #[serde(default, rename = "totalResults")]
    total_results: u64,
    #[serde(default)]
    vulnerabilities: Vec<VulnWrap>,
}

#[derive(Debug, Deserialize)]
struct VulnWrap {
    #[serde(default)]
    cve: Cve,
}

#[derive(Debug, Default, Deserialize)]
struct Cve {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "vulnStatus")]
    vuln_status: Option<String>,
    #[serde(default)]
    published: Option<String>,
    #[serde(default, rename = "lastModified")]
    last_modified: Option<String>,
    #[serde(default)]
    descriptions: Vec<LangValue>,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    weaknesses: Vec<Weakness>,
}

#[derive(Debug, Deserialize)]
struct LangValue {
    #[serde(default)]
    lang: String,
    #[serde(default)]
    value: String,
}

#[derive(Debug, Default, Deserialize)]
struct Metrics {
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<Metric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<Metric>,
}

#[derive(Debug, Deserialize)]
struct Metric {
    #[serde(default, rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Default, Deserialize)]
struct CvssData {
    #[serde(default)]
    version: Option<String>,
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
    #[serde(default, rename = "vectorString")]
    vector_string: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Weakness {
    #[serde(default)]
    description: Vec<LangValue>,
}

/// The NVD record URL for a CVE. **Pure.**
#[must_use]
pub fn cve_url(cve: &str) -> String {
    format!("{API_BASE}?cveId={}", percent_encode_component(cve))
}

fn options() -> FetchOptions {
    FetchOptions::no_redirects().paced()
}

fn request(url: String) -> Request {
    Request::get(url)
        .header("accept", "application/json")
        .header("user-agent", crate::http::DEFAULT_USER_AGENT)
}

/// Look up one CVE on NVD, keyless.
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
        request(cve_url(&cve)),
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
    let response = whole_response(fetched, "NVD record")?;
    answer(fetched, "NVD record")?;
    let envelope: Envelope = decode_json(response, SRC, now_unix, "NVD record")?;
    let record = envelope
        .vulnerabilities
        .iter()
        .map(|w| &w.cve)
        .find(|c| c.id.eq_ignore_ascii_case(cve));
    let Some(record) = record else {
        if envelope.total_results == 0 {
            // NVD holds no such CVE: a clean zero.
            return Ok(Report {
                entities: Vec::new(),
                outcome: SourceExecutionOutcome::valid_zero(SRC, now_unix)
                    .with_http_status(response.status),
            });
        }
        // Results came back, but none is the queried id: a record for other CVEs.
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::SemanticDrift,
            Some(response.status),
            "NVD returned records none of which is the queried CVE",
        ));
    };
    let entities = build_entities(record, cve, scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len())
            .with_http_status(response.status),
        entities,
    })
}

/// The primary CVSS metric: v3.1, else v3.0, else v2. **Pure.**
fn primary_cvss(metrics: &Metrics) -> Option<&CvssData> {
    metrics
        .v31
        .first()
        .or_else(|| metrics.v30.first())
        .or_else(|| metrics.v2.first())
        .map(|m| &m.cvss_data)
}

/// The CVE document carrying the NVD fields, keyed by the CVE id so it merges with OSV. **Pure.**
fn build_entities(record: &Cve, cve: &str, scan_id: &str) -> Vec<Entity> {
    let description = record
        .descriptions
        .iter()
        .find(|d| d.lang.eq_ignore_ascii_case("en"))
        .and_then(|d| nonblank(Some(&d.value)));
    let cvss = primary_cvss(&record.metrics);
    let base_score = cvss.and_then(|c| c.base_score).map(|s| format!("{s}"));
    let cwes: Vec<&str> = record
        .weaknesses
        .iter()
        .flat_map(|w| &w.description)
        .filter(|d| d.lang.eq_ignore_ascii_case("en"))
        .filter_map(|d| nonblank(Some(&d.value)))
        .filter(|v| v.starts_with("CWE-"))
        .collect();
    let cwe = cwes.join(", ");
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!("NVD record for {cve}: the authoritative NIST vulnerability record, a public observation, not proof any given system is affected"),
    )
    .with_attr("dataset", "NVD")
    .with_attr("record_url", cve_url(cve))
    .with_optional_attrs([
        ("nvd_status", nonblank(record.vuln_status.as_deref())),
        ("nvd_description", description),
        ("nvd_cvss_version", cvss.and_then(|c| c.version.as_deref())),
        ("nvd_cvss_base_score", base_score.as_deref()),
        ("nvd_cvss_severity", cvss.and_then(|c| c.base_severity.as_deref())),
        ("nvd_cvss_vector", cvss.and_then(|c| c.vector_string.as_deref())),
        ("nvd_cwe", nonblank(Some(cwe.as_str()))),
        ("nvd_published", nonblank(record.published.as_deref())),
        ("nvd_modified", nonblank(record.last_modified.as_deref())),
    ]);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        cve,
        CVE_CONF,
        scan_id,
        evidence,
        &["nvd", "vulnerability", "cve"],
    );
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{ScriptedTransport, json_ok};

    /// Trimmed from the live NVD `cves/2.0?cveId=CVE-2021-44228` envelope, 2026-11-08.
    const LOG4SHELL: &str = r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","vulnStatus":"Analyzed","published":"2021-12-10T10:15:09.143","lastModified":"2026-10-24T10:30:50.770","descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI features do not protect against attacker-controlled LDAP."},{"lang":"es","value":"ignore"}],"metrics":{"cvssMetricV31":[{"cvssData":{"version":"3.1","baseScore":10.0,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-20"},{"lang":"en","value":"CWE-502"}]}]}}]}"#;

    fn report_of(body: &str, cve: &str) -> Report {
        let transport = ScriptedTransport::new(vec![Ok(json_ok(body))]);
        lookup(&transport, cve, "scan-nvd", 1).expect("lookup runs")
    }

    fn attr<'a>(report: &'a Report, key: &str) -> Option<&'a str> {
        report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Document)
            .and_then(|e| e.evidence.first())
            .and_then(|ev| ev.attributes.get(key))
            .map(String::as_str)
    }

    #[test]
    fn cve_url_carries_the_id() {
        assert_eq!(
            cve_url("CVE-2021-44228"),
            "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
        );
    }

    #[test]
    fn a_confirmed_cve_yields_base_score_severity_and_cwe() {
        let report = report_of(LOG4SHELL, "cve-2021-44228");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let doc = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Document && e.raw_value == "CVE-2021-44228")
            .expect("the CVE document");
        assert!(doc.has_tag("nvd") && doc.has_tag("cve"));
        assert_eq!(attr(&report, "nvd_cvss_base_score"), Some("10"));
        assert_eq!(attr(&report, "nvd_cvss_severity"), Some("CRITICAL"));
        assert_eq!(attr(&report, "nvd_cwe"), Some("CWE-20, CWE-502"));
        assert_eq!(attr(&report, "nvd_status"), Some("Analyzed"));
        assert!(attr(&report, "nvd_description").is_some_and(|d| d.starts_with("Apache Log4j2")));
    }

    #[test]
    fn a_nonexistent_cve_is_a_clean_zero() {
        let report = report_of(
            r#"{"totalResults":0,"vulnerabilities":[]}"#,
            "CVE-2000-9999",
        );
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
    }

    #[test]
    fn results_without_the_queried_cve_are_semantic_drift() {
        let body = r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-1999-0001","descriptions":[],"metrics":{},"weaknesses":[]}}]}"#;
        let report = report_of(body, "CVE-2021-44228");
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::SemanticDrift);
    }

    #[test]
    fn an_invalid_selector_never_reaches_the_network() {
        let transport = ScriptedTransport::new(vec![]);
        let report = lookup(&transport, "nope", "scan-nvd", 1).expect("runs");
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
