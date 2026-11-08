//! End-to-end front-end for `huntsman-recon cve`: one CVE identifier enriched across the keyless
//! vulnerability sources, `osv` (the authoritative record) then `epss` (exploitation probability),
//! merged into one CVE `Document`. Keyless. A record is a public vulnerability observation, never
//! proof that a given system is affected or has been exploited.

use crate::error::Error;
use crate::http::Transport;
use crate::source_outcome::SourceExecutionOutcome;
use crate::{epss, lookup_report, osv};

pub const CVE_USAGE: &str = "usage: huntsman-recon cve CVE-ID";
pub const CVE_HELP: &str = "\
cve CVE-ID
Enrich one CVE identifier (e.g. CVE-2021-44228) across the keyless vulnerability sources: the OSV record (summary, CVSS severity, aliases, references, publication dates) and the EPSS exploitation-probability score, merged into one CVE document. Keyless, from api.osv.dev and api.first.org. A record is a public vulnerability observation, not proof any given system is affected or exploited. Makes network requests.";

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

/// Enrich `cve` across OSV and EPSS, each leg only when the transport's lookup asks its module.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, cve: &str, now_unix: u64) -> CveRun {
    let Some(cve) = osv::canonical_cve(cve) else {
        return CveRun::Failed(format!("{cve:?} is not a CVE identifier"));
    };
    let scan_id = crate::entity::scan_id("cve", &cve);
    let mut report = Report::default();
    for (module, leg) in [
        (osv::SRC, osv::lookup as LegFn<T>),
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
    crate::entity::merge_by_uid(&mut report.entities);
    lookup_report::finish(report, &format!("no source answered for {cve}"))
}

type LegFn<T> = fn(&T, &str, &str, u64) -> Result<lookup_report::SourceReport, Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_outcome::SourceOutcomeKind;
    use crate::test_support::RoutedTransport;

    fn routed() -> RoutedTransport {
        RoutedTransport::new(&[
            (
                "https://api.osv.dev/v1/vulns/CVE-2021-44228",
                200,
                r#"{"id":"CVE-2021-44228","summary":"Log4Shell","aliases":["GHSA-jfh8-c2jp-5v3q"],"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N"}],"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}]}"#,
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
        match run(&routed(), "cve-2021-44228", 1) {
            CveRun::Printed { report, text } => {
                assert!(text.contains("osv\tsuccess"), "{text}");
                assert!(text.contains("epss\tsuccess"), "{text}");
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
                    ev.contains(&"osv") && ev.contains(&"epss"),
                    "both sources on the node: {ev:?}"
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
                "https://api.first.org/data/v1/epss?cve=CVE-2000-0001",
                200,
                r#"{"data":[]}"#,
            ),
        ]);
        match run(&t, "CVE-2000-0001", 1) {
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
        match run(&RoutedTransport::new(&[]), "nope", 1) {
            CveRun::Failed(_) => {}
            other => panic!(
                "expected failure, got printed={}",
                matches!(other, CveRun::Printed { .. })
            ),
        }
    }
}
