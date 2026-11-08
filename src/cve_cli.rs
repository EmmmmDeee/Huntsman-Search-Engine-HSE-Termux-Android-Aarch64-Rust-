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
    lookup_report::finish(report, &format!("no source answered for {cve}"))
}

type LegFn<T> = fn(&T, &str, &str, u64) -> Result<lookup_report::SourceReport, Error>;

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
