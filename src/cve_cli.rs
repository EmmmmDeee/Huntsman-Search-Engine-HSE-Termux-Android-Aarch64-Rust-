//! End-to-end front-end for `huntsman-recon cve`: one CVE identifier enriched across the keyless
//! vulnerability sources, `osv` (the authoritative record) then `epss` (exploitation probability),
//! merged into one CVE `Document`. Keyless. A record is a public vulnerability observation, never
//! proof that a given system is affected or has been exploited.

use crate::error::Error;
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;
use crate::{epss, kev, lookup_report, nvd, osv};

pub const CVE_USAGE: &str = "usage: huntsman-recon cve CVE-ID";
pub const CVE_HELP: &str = "\
cve CVE-ID
Enrich one CVE identifier (e.g. CVE-2021-44228) across the keyless vulnerability sources: the OSV record (summary, CVSS severity, aliases, references, publication dates), the NVD record (authoritative NIST description, CVSS base score and CWE weaknesses) the EPSS exploitation-probability score, and the CISA KEV known-exploited flag, merged into one CVE document. Keyless, from api.osv.dev, services.nvd.nist.gov, api.first.org and the CISA KEV catalogue (downloaded once and kept). A record is a public vulnerability observation, not proof any given system is affected or exploited. Makes network requests.";

/// What the lookup found: its entities and each source's row.
pub type Report = crate::lookup_report::LookupReport;
pub type CveRun = crate::source_outcome::SourceRun<Report>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CveArgs {
    pub cve: String,
}

impl CveArgs {
    /// # Errors
    /// [`Error::Invalid`] for a missing or extra argument, [`Error::InvalidValue`] when the
    /// argument is not a CVE identifier.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let [raw] = args else {
            return Err(Error::Invalid(
                "cve needs exactly one CVE identifier".into(),
            ));
        };
        let cve = osv::canonical_cve(raw)
            .ok_or_else(|| Error::InvalidValue(format!("{raw:?} is not a CVE identifier")))?;
        Ok(Self { cve })
    }
}

/// Enrich `cve` across OSV, NVD and EPSS over the shared HTTP transport, then the CISA KEV
/// catalogue over its own download-and-keep `kev`, each leg only when its module is chosen. All
/// legs key on the one CVE id, so the report merges them into one CVE document.
#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    kev: &kev::Kev,
    cve: &str,
    now_unix: u64,
) -> CveRun {
    let Some(cve) = osv::canonical_cve(cve) else {
        return CveRun::Failed(format!("{cve:?} is not a CVE identifier"));
    };
    let scan_id = crate::entity::scan_id("cve", &cve);
    let mut report = Report::default();
    for (module, leg) in [
        (osv::SRC, osv::lookup as LegFn<T>),
        (nvd::SRC, nvd::lookup as LegFn<T>),
        (epss::SRC, epss::lookup as LegFn<T>),
    ] {
        if !transport.runs_module(module) {
            continue;
        }
        match leg(transport, &cve, &scan_id, now_unix) {
            Ok(found) => {
                report.entities.extend(found.entities);
                report.outcomes.push(found.outcome);
            }
            Err(error) => report.outcomes.push(SourceExecutionOutcome::of_leg_error(
                module, now_unix, &error,
            )),
        }
    }
    let catalog = kev::check(kev, &cve, &scan_id, now_unix);
    report.entities.extend(catalog.entities);
    report.outcomes.push(catalog.outcome);
    crate::entity::merge_by_uid(&mut report.entities);
    attach_triage(&mut report, &cve, &scan_id);
    lookup_report::finish(report, &format!("no source answered for {cve}"))
}

type LegFn<T> = fn(&T, &str, &str, u64) -> Result<lookup_report::SourceReport, Error>;

/// The exploitation signals the sources reported, read off the merged CVE document's evidence.
#[derive(Debug, Default, Clone, PartialEq)]
struct Signals {
    known_exploited: bool,
    ransomware: bool,
    epss: Option<f64>,
    severity: Option<String>,
    base_score: Option<f64>,
}

/// Read every signal from the CVE document's evidence attributes across its sources. **Pure.**
fn collect_signals(doc: &crate::entity::Entity) -> Signals {
    let attr = |key: &str| -> Option<String> {
        doc.evidence
            .iter()
            .find_map(|ev| ev.attributes.get(key))
            .cloned()
    };
    // NVD states severity and base score directly. When it did not answer (its keyless tier is
    // rate-limited) but a CVSS vector is on the document (NVD's own, or OSV's), compute the base
    // score and band from the vector so the triage keeps a severity signal.
    let mut severity = attr("nvd_cvss_severity").map(|v| v.to_ascii_uppercase());
    let mut base_score = attr("nvd_cvss_base_score").and_then(|v| v.parse().ok());
    if severity.is_none() {
        if let Some(base) = attr("nvd_cvss_vector")
            .or_else(|| attr("cvss"))
            .and_then(|vector| crate::cvss::base_score(&vector))
        {
            severity = Some(base.severity.as_str().to_owned());
            base_score = Some(base.score);
        }
    }
    Signals {
        known_exploited: attr("kev_known_exploited").as_deref() == Some("true"),
        ransomware: attr("kev_ransomware_use").is_some_and(|v| v.eq_ignore_ascii_case("known")),
        epss: attr("epss_probability").and_then(|v| v.parse().ok()),
        severity,
        base_score,
    }
}

/// A conservative, derived triage over the signals: a priority tier and a one-line rationale, or
/// `None` when the sources carry no risk signal at all (only that the CVE exists), so the command
/// never invents urgency it cannot support. Known exploitation outranks any score. **Pure.**
fn triage(sig: &Signals) -> Option<(&'static str, String)> {
    let mut why = Vec::new();
    if sig.known_exploited {
        why.push("on the CISA KEV catalogue (actively exploited)".to_owned());
        if sig.ransomware {
            why.push("used in ransomware".to_owned());
        }
    }
    if let Some(epss) = sig.epss {
        why.push(format!("EPSS {epss:.4}"));
    }
    if let Some(severity) = &sig.severity {
        match sig.base_score {
            Some(score) => why.push(format!("CVSS {score} {severity}")),
            None => why.push(format!("CVSS {severity}")),
        }
    }
    if why.is_empty() {
        return None;
    }
    let high_severity = sig
        .severity
        .as_deref()
        .is_some_and(|s| s == "CRITICAL" || s == "HIGH");
    let medium_severity = sig.severity.as_deref() == Some("MEDIUM");
    let epss_high = sig.epss.is_some_and(|p| p >= 0.5);
    let epss_moderate = sig.epss.is_some_and(|p| p >= 0.1);
    let priority = if sig.known_exploited {
        "act-now"
    } else if epss_high || high_severity {
        "elevated"
    } else if epss_moderate || medium_severity {
        "moderate"
    } else {
        "lower"
    };
    Some((priority, why.join("; ")))
}

/// Attach the derived triage to the merged CVE document, clearly marked as an inferred correlation
/// of the sources, never a source claim of its own. Does nothing when there is no CVE document or
/// no risk signal. **Pure.**
fn attach_triage(report: &mut Report, cve: &str, scan_id: &str) {
    use crate::entity::{EntityKind, Evidence, EvidenceProvenance};
    let Some(doc) = report
        .entities
        .iter_mut()
        .find(|e| e.kind == EntityKind::Document && e.raw_value == cve && e.has_tag("cve"))
    else {
        return;
    };
    let Some((priority, rationale)) = triage(&collect_signals(doc)) else {
        return;
    };
    doc.add_evidence(
        Evidence::new(
            EvidenceProvenance::for_scan("cve_triage", scan_id),
            format!("Derived exploitation triage for {cve}: {priority}"),
        )
        .with_attr("assessment", "derived")
        .with_attr("triage_priority", priority)
        .with_attr("triage_rationale", rationale)
        .inferred(),
    );
    doc.tag("triage");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::RoutedTransport;

    const KEV_URL: &str =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    const KEV_BODY: &str = r#"{"catalogVersion":"2026.11.06","vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10","dueDate":"2021-12-24","knownRansomwareCampaignUse":"Known"}]}"#;

    fn kev_catalog() -> kev::Kev {
        kev::Kev::new(
            Box::new(RoutedTransport::new(&[(KEV_URL, 200, KEV_BODY)])),
            None,
        )
    }

    fn routed() -> RoutedTransport {
        RoutedTransport::new(&[
            (
                "https://api.osv.dev/v1/vulns/CVE-2021-44228",
                200,
                r#"{"id":"CVE-2021-44228","summary":"Log4Shell","aliases":["GHSA-jfh8-c2jp-5v3q"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}],"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}]}"#,
            ),
            (
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
                200,
                r#"{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","vulnStatus":"Analyzed","descriptions":[{"lang":"en","value":"Log4Shell"}],"metrics":{"cvssMetricV31":[{"cvssData":{"version":"3.1","baseScore":10.0,"baseSeverity":"CRITICAL","vectorString":"CVSS:3.1/AV:N"}}]},"weaknesses":[{"description":[{"lang":"en","value":"CWE-502"}]}]}}]}"#,
            ),
            (
                "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
                200,
                r#"{"data":[{"cve":"CVE-2021-44228","epss":"0.99999","percentile":"1.0","date":"2026-11-07"}]}"#,
            ),
        ])
    }

    #[test]
    fn parses_and_upper_cases_one_cve() {
        assert_eq!(
            CveArgs::parse(&["cve-2021-44228".into()]).unwrap().cve,
            "CVE-2021-44228"
        );
        assert!(CveArgs::parse(&[]).is_err());
        assert!(CveArgs::parse(&["CVE-2021-44228".into(), "x".into()]).is_err());
        assert!(CveArgs::parse(&["not-a-cve".into()]).is_err());
    }

    #[test]
    fn run_merges_osv_and_epss_into_one_cve_document() {
        match run(&routed(), &kev_catalog(), "cve-2021-44228", 1) {
            CveRun::Printed { report, text } => {
                assert!(text.contains("osv\tsuccess"), "{text}");
                assert!(text.contains("nvd\tsuccess"), "{text}");
                assert!(text.contains("epss\tsuccess"), "{text}");
                assert!(text.contains("cisa_kev\tsuccess"), "{text}");
                let docs: Vec<_> = report
                    .entities
                    .iter()
                    .filter(|e| {
                        e.kind == crate::entity::EntityKind::Document
                            && e.raw_value == "CVE-2021-44228"
                    })
                    .collect();
                assert_eq!(docs.len(), 1, "the two legs merge into one CVE document");
                let ev: Vec<_> = docs[0]
                    .evidence
                    .iter()
                    .map(|e| e.provenance.source.as_str())
                    .collect();
                assert!(
                    ev.contains(&"osv") && ev.contains(&"nvd") && ev.contains(&"epss"),
                    "all sources on the node: {ev:?}"
                );
            }
            CveRun::Network(why) | CveRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn triage_ranks_known_exploited_above_any_score() {
        let ke = Signals {
            known_exploited: true,
            ransomware: true,
            epss: Some(0.01),
            severity: Some("LOW".into()),
            base_score: Some(3.1),
        };
        let (p, why) = triage(&ke).expect("a known-exploited CVE always triages");
        assert_eq!(p, "act-now");
        assert!(why.contains("CISA KEV") && why.contains("ransomware"));
    }

    #[test]
    fn triage_tiers_follow_epss_and_severity() {
        let sev = |s: &str, score, epss| Signals {
            known_exploited: false,
            ransomware: false,
            epss,
            severity: Some(s.into()),
            base_score: score,
        };
        assert_eq!(
            triage(&sev("CRITICAL", Some(9.8), Some(0.01))).unwrap().0,
            "elevated"
        );
        assert_eq!(
            triage(&sev("LOW", Some(3.1), Some(0.6))).unwrap().0,
            "elevated"
        ); // EPSS drives it
        assert_eq!(
            triage(&sev("MEDIUM", Some(5.3), Some(0.2))).unwrap().0,
            "moderate"
        );
        assert_eq!(
            triage(&sev("LOW", Some(2.0), Some(0.01))).unwrap().0,
            "lower"
        );
    }

    #[test]
    fn triage_derives_severity_from_a_vector_when_nvd_is_absent() {
        // OSV returns a CVSS vector but NVD did not answer; the triage must still read severity
        // from the vector via the cvss calculator.
        use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
        let mut doc = Entity::new(EntityKind::Document, "CVE-2021-44228", 0.8, "scan");
        doc.tag("cve");
        doc.add_evidence(
            Evidence::new(EvidenceProvenance::for_scan("osv", "scan"), "osv")
                .with_attr("cvss", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"),
        );
        let sig = collect_signals(&doc);
        assert_eq!(sig.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(sig.base_score, Some(10.0));
        assert_eq!(
            triage(&sig).expect("triages on derived severity").0,
            "elevated"
        );
    }

    #[test]
    fn triage_is_none_without_any_risk_signal() {
        // Only that the CVE exists (OSV record, no NVD/EPSS/KEV): no invented urgency.
        assert_eq!(triage(&Signals::default()), None);
    }

    #[test]
    fn run_attaches_a_derived_triage_to_the_document() {
        match run(&routed(), &kev_catalog(), "cve-2021-44228", 1) {
            CveRun::Printed { report, text } => {
                let doc = report
                    .entities
                    .iter()
                    .find(|e| {
                        e.kind == crate::entity::EntityKind::Document
                            && e.raw_value == "CVE-2021-44228"
                    })
                    .expect("the CVE document");
                assert!(doc.has_tag("triage"));
                let ev = doc
                    .evidence
                    .iter()
                    .find(|ev| {
                        ev.attributes.get("assessment").map(String::as_str) == Some("derived")
                    })
                    .expect("a derived triage evidence item");
                assert!(
                    ev.is_inferred,
                    "triage must be marked inferred, not a source claim"
                );
                assert_eq!(
                    ev.attributes.get("triage_priority").map(String::as_str),
                    Some("act-now")
                );
                assert!(
                    text.contains("triage_priority"),
                    "triage shows in the report: {text}"
                );
            }
            CveRun::Network(why) | CveRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_unknown_cve_prints_its_clean_negatives() {
        let t = RoutedTransport::new(&[
            (
                "https://api.osv.dev/v1/vulns/CVE-2000-0001",
                404,
                r#"{"message":"not found"}"#,
            ),
            (
                "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2000-0001",
                200,
                r#"{"totalResults":0,"vulnerabilities":[]}"#,
            ),
            (
                "https://api.first.org/data/v1/epss?cve=CVE-2000-0001",
                200,
                r#"{"data":[]}"#,
            ),
        ]);
        match run(&t, &kev_catalog(), "CVE-2000-0001", 1) {
            CveRun::Printed { report, .. } => {
                assert!(report.entities.is_empty());
                assert!(
                    report
                        .outcomes
                        .iter()
                        .all(|o| o.kind == SourceOutcomeKind::ValidZero)
                );
            }
            CveRun::Network(why) | CveRun::Failed(why) => panic!("{why}"),
        }
    }

    #[test]
    fn an_invalid_cve_fails_without_network() {
        match run(&RoutedTransport::new(&[]), &kev::Kev::none(), "nope", 1) {
            CveRun::Failed(_) => {}
            other => panic!(
                "expected failure, got printed={}",
                matches!(other, CveRun::Printed { .. })
            ),
        }
    }
}
