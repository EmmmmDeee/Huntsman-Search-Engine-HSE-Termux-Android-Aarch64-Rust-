//! CISA Known Exploited Vulnerabilities (KEV) lookup for a CVE identifier. Keyless -- the US
//! Cybersecurity and Infrastructure Security Agency publishes one catalogue JSON at
//! `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`.
//!
//! The catalogue has no per-CVE endpoint, so it is downloaded whole and kept through the same
//! download-and-keep machinery as the threat feeds and sanctions lists
//! ([`crate::threat_feeds::load`]): a copy in the feed directory is read while it is fresh, and
//! downloaded again only once a day, so a lookup is one bounded download at most and sends nothing
//! about which CVE is looked up. The CVE is then matched on the device.
//!
//! Being on the KEV catalogue is the strongest keyless exploitation signal there is: CISA lists a
//! flaw only on evidence of active exploitation. The flag, the date CISA added it, the remediation
//! due date, the required action and whether it is used in ransomware are kept on the same CVE
//! `Document` OSV, NVD and EPSS key on, so the leg merges into one node. A CVE absent from the
//! catalogue is "not known-exploited", not proof it is not exploited; an outdated or unreadable
//! copy is inconclusive, never a clean negative.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, push_entity};
use crate::http::Transport;
use crate::osv::canonical_cve;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::nonblank;
use crate::threat_feeds::{CachedList, load};

pub const SRC: &str = "cisa_kev";
const CATALOG_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// CISA regenerates the catalogue on working days; an 18-hour copy is read before a re-download.
const MAX_AGE: u64 = 18 * 3_600;
/// The known-exploited flag on a confirmed CVE: a strong enrichment onto the CVE document.
const KEV_CONF: f64 = 0.85;

const CATALOG: CachedList = CachedList {
    id: "cisa_kev",
    source: SRC,
    url: CATALOG_URL,
    max_age: MAX_AGE,
    xml_root: None,
};

pub type Report = crate::lookup_report::SourceReport;

#[derive(Debug, Deserialize)]
struct Catalog {
    #[serde(default)]
    vulnerabilities: Vec<KevEntry>,
    #[serde(default, rename = "catalogVersion")]
    catalog_version: Option<String>,
}

#[derive(Debug, Deserialize)]
struct KevEntry {
    #[serde(default, rename = "cveID")]
    cve_id: String,
    #[serde(default, rename = "vendorProject")]
    vendor_project: Option<String>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default, rename = "vulnerabilityName")]
    vulnerability_name: Option<String>,
    #[serde(default, rename = "dateAdded")]
    date_added: Option<String>,
    #[serde(default, rename = "dueDate")]
    due_date: Option<String>,
    #[serde(default, rename = "requiredAction")]
    required_action: Option<String>,
    #[serde(default, rename = "knownRansomwareCampaignUse")]
    ransomware_use: Option<String>,
}

/// The CISA KEV catalogue, downloaded over a transport and kept in a directory.
pub struct Kev {
    transport: Option<Box<dyn Transport + Send + Sync>>,
    dir: Option<PathBuf>,
}

impl Kev {
    /// The catalogue is not consulted.
    #[must_use]
    pub fn none() -> Self {
        Self {
            transport: None,
            dir: None,
        }
    }

    /// The catalogue, downloaded over `transport` (it must carry a body of several MiB: see
    /// [`crate::threat_feeds::transport_config`]) and kept in `dir` (none keeps no copy).
    #[must_use]
    pub fn new(transport: Box<dyn Transport + Send + Sync>, dir: Option<PathBuf>) -> Self {
        Self {
            transport: Some(transport),
            dir,
        }
    }
}

/// Check one CVE against the KEV catalogue, keyless. A `Kev::none` or a module the lookup did not
/// choose yields no row.
#[must_use]
pub fn check(kev: &Kev, cve: &str, scan_id: &str, now_unix: u64) -> Report {
    let Some(transport) = kev.transport.as_deref() else {
        return miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "KEV catalogue not consulted",
        ));
    };
    if !transport.runs_module(SRC) {
        return miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "KEV catalogue not consulted",
        ));
    }
    let Some(cve) = canonical_cve(cve) else {
        return miss(SourceExecutionOutcome::inconclusive(
            SRC,
            now_unix,
            "selector is not a CVE identifier",
        ));
    };
    read(transport, kev.dir.as_deref(), &cve, scan_id, now_unix).unwrap_or_else(miss)
}

fn miss(outcome: SourceExecutionOutcome) -> Report {
    Report {
        entities: Vec::new(),
        outcome,
    }
}

fn read(
    transport: &(dyn Transport + Send + Sync),
    dir: Option<&Path>,
    cve: &str,
    scan_id: &str,
    now_unix: u64,
) -> Result<Report, SourceExecutionOutcome> {
    let copy = load(transport, dir, &CATALOG, now_unix)
        .map_err(|(kind, why)| SourceExecutionOutcome::failed(SRC, now_unix, kind, None, why))?;
    let current = copy.current_for(now_unix, MAX_AGE);
    let catalog: Catalog = serde_json::from_slice(&copy.body).map_err(|error| {
        SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            None,
            format!("KEV catalogue did not parse ({error})"),
        )
    })?;
    if catalog.vulnerabilities.is_empty() {
        return Err(SourceExecutionOutcome::failed(
            SRC,
            now_unix,
            SourceOutcomeKind::ParserDrift,
            None,
            format!("KEV catalogue held no entries in {} bytes", copy.body.len()),
        ));
    }
    let version = catalog.catalog_version.clone();
    let hit = catalog
        .vulnerabilities
        .iter()
        .find(|e| e.cve_id.eq_ignore_ascii_case(cve));
    // An outdated copy can neither confirm a fresh listing nor prove present absence.
    if !current {
        let found = hit.map_or(0, |_| 1);
        return Ok(miss(SourceExecutionOutcome::observed(
            SRC,
            now_unix,
            SourceOutcomeKind::Inconclusive,
            None,
            Some(found),
            "KEV copy refresh failed or freshness expired",
        )));
    }
    let Some(entry) = hit else {
        // Read fresh and the CVE is not listed: not known-exploited. A clean, meaningful zero.
        return Ok(miss(
            SourceExecutionOutcome::valid_zero(SRC, now_unix)
                .with_detail("not on the CISA KEV catalogue (not known-exploited)"),
        ));
    };
    let entities = build_entities(entry, cve, version.as_deref(), scan_id);
    Ok(Report {
        outcome: SourceExecutionOutcome::success(SRC, now_unix, entities.len()),
        entities,
    })
}

/// The CVE document carrying the KEV listing, keyed by the CVE id so it merges with OSV. **Pure.**
fn build_entities(
    entry: &KevEntry,
    cve: &str,
    version: Option<&str>,
    scan_id: &str,
) -> Vec<Entity> {
    let evidence = Evidence::new(
        EvidenceProvenance::for_scan(SRC, scan_id),
        format!(
            "CISA lists {cve} as a Known Exploited Vulnerability: evidence of active exploitation, not proof any given system is affected"
        ),
    )
    .with_attr("dataset", "CISA KEV")
    .with_attr("catalog_url", CATALOG_URL)
    .with_attr("kev_known_exploited", "true")
    .with_optional_attrs([
        ("catalog_version", version),
        ("kev_vendor_project", nonblank(entry.vendor_project.as_deref())),
        ("kev_product", nonblank(entry.product.as_deref())),
        ("kev_vulnerability_name", nonblank(entry.vulnerability_name.as_deref())),
        ("kev_date_added", nonblank(entry.date_added.as_deref())),
        ("kev_due_date", nonblank(entry.due_date.as_deref())),
        ("kev_required_action", nonblank(entry.required_action.as_deref())),
        ("kev_ransomware_use", nonblank(entry.ransomware_use.as_deref())),
    ]);
    let mut entities = Vec::new();
    push_entity(
        &mut entities,
        EntityKind::Document,
        cve,
        KEV_CONF,
        scan_id,
        evidence,
        &["cisa_kev", "vulnerability", "cve", "known-exploited"],
    );
    entities
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::RoutedTransport;

    /// Trimmed from the live CISA KEV catalogue, 2026-11-08.
    const CATALOG_BODY: &str = r#"{"catalogVersion":"2026.11.06","count":2,"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","vulnerabilityName":"Apache Log4j2 Remote Code Execution Vulnerability","dateAdded":"2021-12-10","dueDate":"2021-12-24","requiredAction":"Apply updates.","knownRansomwareCampaignUse":"Known"},{"cveID":"CVE-2017-0144","vendorProject":"Microsoft","product":"SMBv1","vulnerabilityName":"EternalBlue","dateAdded":"2022-03-25","dueDate":"2022-04-15","requiredAction":"Apply updates.","knownRansomwareCampaignUse":"Known"}]}"#;

    fn configured(body: &'static str) -> Kev {
        Kev::new(
            Box::new(RoutedTransport::new(&[(CATALOG_URL, 200, body)])),
            None,
        )
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
    fn a_listed_cve_is_flagged_known_exploited_with_its_fields() {
        let report = check(&configured(CATALOG_BODY), "cve-2021-44228", "scan-kev", 1);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Success);
        let doc = report
            .entities
            .iter()
            .find(|e| e.kind == EntityKind::Document && e.raw_value == "CVE-2021-44228")
            .expect("the CVE document");
        assert!(doc.has_tag("known-exploited") && doc.has_tag("cisa_kev"));
        assert_eq!(attr(&report, "kev_known_exploited"), Some("true"));
        assert_eq!(attr(&report, "kev_date_added"), Some("2021-12-10"));
        assert_eq!(attr(&report, "kev_due_date"), Some("2021-12-24"));
        assert_eq!(attr(&report, "kev_ransomware_use"), Some("Known"));
        assert_eq!(attr(&report, "catalog_version"), Some("2026.11.06"));
    }

    #[test]
    fn a_cve_absent_from_the_catalogue_is_a_clean_zero() {
        let report = check(&configured(CATALOG_BODY), "CVE-2000-0001", "scan-kev", 1);
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert!(
            report
                .outcome
                .detail
                .as_deref()
                .is_some_and(|d| d.contains("not known-exploited"))
        );
    }

    #[test]
    fn a_catalogue_that_does_not_parse_is_not_a_clean_zero() {
        let report = check(&configured("not json"), "CVE-2021-44228", "scan-kev", 1);
        assert!(report.entities.is_empty());
        assert_ne!(report.outcome.kind, SourceOutcomeKind::ValidZero);
        assert_ne!(report.outcome.kind, SourceOutcomeKind::Success);
    }

    #[test]
    fn an_unconsulted_catalogue_yields_no_finding() {
        let report = check(&Kev::none(), "CVE-2021-44228", "scan-kev", 1);
        assert!(report.entities.is_empty());
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }

    #[test]
    fn an_invalid_selector_is_inconclusive() {
        let report = check(&configured(CATALOG_BODY), "not-a-cve", "scan-kev", 1);
        assert_eq!(report.outcome.kind, SourceOutcomeKind::Inconclusive);
    }
}
