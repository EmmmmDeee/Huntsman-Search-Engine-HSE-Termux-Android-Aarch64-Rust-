//! Two saved scans side by side: what the later one found that the earlier did not, what it no
//! longer finds, and what both hold, for each Spiderfoot data type, with the correlations each
//! has that the other lacks. Spiderfoot keeps every scan but never compares two. A re-run of the
//! same target is how an operator watches it change, and two different targets compared show
//! what they share.
//!
//! An element is the same in both scans when its type and its data are, as Spiderfoot's unique
//! view counts them: the module that found it, the element it was found from and when do not
//! matter. Every element of an added or removed value is kept, each with its own source and raw
//! record, so nothing either scan found is dropped. The root, which repeats the target, is left
//! out, as the exports leave it out.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::scan_export::{self, Export};
use crate::scan_store::{ScanCorrelation, ScanRecord, ScanResults};
use crate::sf_elements::DataElement;
use crate::sf_types;
use crate::source_outcome::SourceExecutionOutcome;

/// The formats [`render`] writes besides JSON, which the scan API builds itself.
pub const FORMATS: [&str; 4] = ["json", "csv", "tsv", "xlsx"];

/// One data type in both scans, counted in distinct values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TypeChange {
    #[serde(rename = "type")]
    pub kind: String,
    pub description: String,
    /// Distinct values the earlier scan holds.
    pub base: usize,
    /// Distinct values the later scan holds.
    pub other: usize,
    /// Values only the later scan holds.
    pub added: usize,
    /// Values only the earlier scan holds.
    pub removed: usize,
    /// Values both hold.
    pub kept: usize,
}

/// How a later scan's findings differ from an earlier scan's.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison<'a> {
    /// Every type either scan holds, in type order.
    pub types: Vec<TypeChange>,
    /// Every element of the later scan whose type and data the earlier scan never found, in the
    /// later scan's order.
    pub added: Vec<&'a DataElement>,
    /// Every element of the earlier scan whose type and data the later scan does not hold, in the
    /// earlier scan's order.
    pub removed: Vec<&'a DataElement>,
    /// Correlations of the later scan whose rule and title the earlier scan does not have.
    pub correlations_added: Vec<&'a ScanCorrelation>,
    /// Correlations of the earlier scan whose rule and title the later scan does not have.
    pub correlations_removed: Vec<&'a ScanCorrelation>,
}

impl Comparison<'_> {
    /// Whether the two scans found the same values and correlations.
    #[must_use]
    pub fn unchanged(&self) -> bool {
        self.added.is_empty()
            && self.removed.is_empty()
            && self.correlations_added.is_empty()
            && self.correlations_removed.is_empty()
    }
}

fn values(results: &ScanResults) -> BTreeSet<(&str, &str)> {
    results
        .elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .map(|element| (element.kind.as_str(), element.data.as_str()))
        .collect()
}

fn findings(results: &ScanResults) -> BTreeSet<(&str, &str)> {
    results
        .correlations
        .iter()
        .map(|correlation| (correlation.rule.as_str(), correlation.title.as_str()))
        .collect()
}

/// `other`, the later scan, against `base`, the earlier one.
#[must_use]
pub fn compare<'a>(base: &'a ScanResults, other: &'a ScanResults) -> Comparison<'a> {
    let (before, after) = (values(base), values(other));
    let only =
        |results: &'a ScanResults, absent: &BTreeSet<(&str, &str)>| -> Vec<&'a DataElement> {
            results
                .elements
                .iter()
                .filter(|element| element.kind != "ROOT")
                .filter(|element| !absent.contains(&(element.kind.as_str(), element.data.as_str())))
                .collect()
        };
    let mut types: BTreeMap<&str, TypeChange> = BTreeMap::new();
    for &(kind, data) in before.union(&after) {
        let change = types.entry(kind).or_insert_with(|| TypeChange {
            kind: kind.to_owned(),
            description: sf_types::describe(kind).to_owned(),
            base: 0,
            other: 0,
            added: 0,
            removed: 0,
            kept: 0,
        });
        match (
            before.contains(&(kind, data)),
            after.contains(&(kind, data)),
        ) {
            (true, true) => {
                change.base += 1;
                change.other += 1;
                change.kept += 1;
            }
            (true, false) => {
                change.base += 1;
                change.removed += 1;
            }
            (false, _) => {
                change.other += 1;
                change.added += 1;
            }
        }
    }
    let (had, has) = (findings(base), findings(other));
    let unmatched = |results: &'a ScanResults, absent: &BTreeSet<(&str, &str)>| {
        results
            .correlations
            .iter()
            .filter(|correlation| {
                !absent.contains(&(correlation.rule.as_str(), correlation.title.as_str()))
            })
            .collect()
    };
    Comparison {
        types: types.into_values().collect(),
        added: only(other, &before),
        removed: only(base, &after),
        correlations_added: unmatched(other, &had),
        correlations_removed: unmatched(base, &has),
    }
}

/// Provider modules whose recorded outcome multisets differ across saved scans.
/// Counts are preserved per module and outcome kind, including repeated recursive lookups.
/// This detects a credential/provider swap even when aggregate coverage counts are equal.
#[must_use]
pub fn changed_source_modules(base: &ScanResults, other: &ScanResults) -> Vec<String> {
    fn by_module(outcomes: &[SourceExecutionOutcome]) -> BTreeMap<String, BTreeMap<String, usize>> {
        let mut entries: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
        for outcome in outcomes {
            *entries
                .entry(outcome.module.clone())
                .or_default()
                .entry(format!("{:?}", outcome.kind))
                .or_default() += 1;
        }
        entries
    }

    let earlier = by_module(&base.outcomes);
    let later = by_module(&other.outcomes);
    earlier
        .keys()
        .chain(later.keys())
        .filter(|module| earlier.get(*module) != later.get(*module))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The data of each element's source element in `results`, by element id.
#[must_use]
pub fn source_data(results: &ScanResults) -> BTreeMap<&str, &str> {
    results
        .elements
        .iter()
        .map(|element| (element.id.as_str(), element.data.as_str()))
        .collect()
}

/// The comparison as `csv`, `tsv` or `xlsx`: a `Change` column (`Added` or `Removed`) and the
/// scan the element is from, then Spiderfoot's element columns (Updated, Type, Module, Source,
/// F/P, Data); the workbook has a sheet per data type, as Spiderfoot's does.
///
/// # Errors
/// The format name, when it is not one of [`FORMATS`] or is `json`.
pub fn render(
    scans: [(&ScanRecord, &ScanResults); 2],
    comparison: &Comparison<'_>,
    format: &str,
) -> Result<Export, String> {
    let format = if format.eq_ignore_ascii_case("excel") {
        "xlsx".to_owned()
    } else {
        format.to_ascii_lowercase()
    };
    let [(base, base_results), (other, other_results)] = scans;
    let (before, after) = (source_data(base_results), source_data(other_results));
    let line =
        |change: &str, scan: &ScanRecord, sources: &BTreeMap<&str, &str>, element: &DataElement| {
            let source = element
                .source
                .as_deref()
                .and_then(|id| sources.get(id).copied())
                .unwrap_or("");
            let mut line = vec![change.to_owned(), scan.name.clone()];
            line.extend(scan_export::element_line(element, source));
            line
        };
    let lines: Vec<Vec<String>> = comparison
        .added
        .iter()
        .map(|element| line("Added", other, &after, element))
        .chain(
            comparison
                .removed
                .iter()
                .map(|element| line("Removed", base, &before, element)),
        )
        .collect();
    let header = [
        "Change",
        "Scan Name",
        "Updated",
        "Type",
        "Module",
        "Source",
        "F/P",
        "Data",
    ];
    let (body, content_type) =
        scan_export::tabular(&format, &header, lines, 3).ok_or_else(|| {
            format!(
                "unknown comparison format {format}; choose {}",
                FORMATS.join(", ")
            )
        })?;
    Ok(Export {
        body,
        content_type,
        filename: format!("{}-vs-{}-Huntsman.{format}", base.id, other.id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan_store::Risk;

    fn element(id: &str, kind: &str, data: &str, source: Option<&str>) -> DataElement {
        DataElement {
            id: id.into(),
            kind: kind.into(),
            data: data.into(),
            source: source.map(str::to_owned),
            module: "m".into(),
            confidence: 100,
            created: 1_700_000_000_000,
            fp: false,
            entity: None,
            raw: serde_json::Value::Null,
        }
    }

    fn correlation(rule: &str, title: &str) -> ScanCorrelation {
        ScanCorrelation {
            id: format!("{rule}-{title}"),
            rule: rule.into(),
            name: rule.into(),
            title: title.into(),
            risk: Risk::High,
            description: String::new(),
            origin: "huntsman".into(),
            logic: String::new(),
            elements: Vec::new(),
        }
    }

    fn results(
        id: &str,
        elements: Vec<DataElement>,
        correlations: Vec<ScanCorrelation>,
    ) -> ScanResults {
        ScanResults {
            format_version: crate::scan_store::FORMAT_VERSION,
            scan_id: id.into(),
            text: String::new(),
            entities: Vec::new(),
            outcomes: Vec::new(),
            elements,
            correlations,
            lineage: Vec::new(),
            termination: None,
        }
    }

    fn pair() -> (ScanResults, ScanResults) {
        let base = results(
            "a",
            vec![
                element("r", "ROOT", "example.com", None),
                element("1", "IP_ADDRESS", "192.0.2.1", Some("r")),
                element("2", "IP_ADDRESS", "192.0.2.2", Some("r")),
                element("3", "EMAILADDR", "old@example.com", Some("r")),
            ],
            vec![correlation("stale", "kept"), correlation("gone", "x")],
        );
        let other = results(
            "b",
            vec![
                element("r", "ROOT", "example.com", None),
                element("1", "IP_ADDRESS", "192.0.2.1", Some("r")),
                // The same value found again, by another module from another element: still kept.
                element("9", "IP_ADDRESS", "192.0.2.2", Some("1")),
                element("4", "TCP_PORT_OPEN", "192.0.2.1:22", Some("1")),
                element("5", "TCP_PORT_OPEN", "192.0.2.1:22", Some("r")),
            ],
            vec![correlation("stale", "kept"), correlation("new", "y")],
        );
        (base, other)
    }

    #[test]
    fn values_are_matched_by_type_and_data_and_every_element_of_a_change_is_kept() {
        let (base, other) = pair();
        let comparison = compare(&base, &other);
        let ids = |list: &[&DataElement]| list.iter().map(|e| e.id.clone()).collect::<Vec<_>>();
        assert_eq!(ids(&comparison.added), ["4", "5"]);
        assert_eq!(ids(&comparison.removed), ["3"]);
        let by_type: BTreeMap<&str, &TypeChange> = comparison
            .types
            .iter()
            .map(|t| (t.kind.as_str(), t))
            .collect();
        let ip = by_type["IP_ADDRESS"];
        assert_eq!(
            (ip.base, ip.other, ip.added, ip.removed, ip.kept),
            (2, 2, 0, 0, 2)
        );
        let port = by_type["TCP_PORT_OPEN"];
        assert_eq!(
            (port.base, port.other, port.added, port.removed, port.kept),
            (0, 1, 1, 0, 0)
        );
        let email = by_type["EMAILADDR"];
        assert_eq!(
            (
                email.base,
                email.other,
                email.added,
                email.removed,
                email.kept
            ),
            (1, 0, 0, 1, 0)
        );
        assert!(!by_type.contains_key("ROOT"), "the root repeats the target");
        assert_eq!(port.description, sf_types::describe("TCP_PORT_OPEN"));
        let rules =
            |list: &[&ScanCorrelation]| list.iter().map(|c| c.rule.clone()).collect::<Vec<_>>();
        assert_eq!(rules(&comparison.correlations_added), ["new"]);
        assert_eq!(rules(&comparison.correlations_removed), ["gone"]);
        assert!(!comparison.unchanged());
    }

    #[test]
    fn a_scan_compared_with_itself_is_unchanged() {
        let (base, _) = pair();
        let comparison = compare(&base, &base);
        assert!(comparison.unchanged());
        assert!(
            comparison
                .types
                .iter()
                .all(|t| t.added == 0 && t.removed == 0 && t.kept == t.base)
        );
    }

    #[test]
    fn provider_swaps_are_detected_when_aggregate_counts_are_identical() {
        use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

        let (mut earlier, mut later) = pair();
        earlier.outcomes = vec![
            SourceExecutionOutcome::success("alpha", 1, 1),
            SourceExecutionOutcome::failed(
                "beta",
                1,
                SourceOutcomeKind::NotConfigured,
                None,
                "not configured",
            ),
        ];
        later.outcomes = vec![
            SourceExecutionOutcome::failed(
                "alpha",
                2,
                SourceOutcomeKind::NotConfigured,
                None,
                "not configured",
            ),
            SourceExecutionOutcome::success("beta", 2, 1),
        ];
        assert_eq!(
            changed_source_modules(&earlier, &later),
            vec!["alpha".to_owned(), "beta".to_owned()]
        );
        assert!(changed_source_modules(&earlier, &earlier).is_empty());
        later.outcomes = earlier.outcomes.iter().rev().cloned().collect();
        assert!(changed_source_modules(&earlier, &later).is_empty());
    }

    #[test]
    fn the_table_names_each_change_its_scan_and_its_own_source() {
        let (base, other) = pair();
        let record = |id: &str, name: &str| ScanRecord {
            format_version: crate::scan_store::FORMAT_VERSION,
            id: id.into(),
            name: name.into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: crate::scan_store::ScanOptions::default(),
            status: crate::scan_store::ScanStatus::Finished,
            created: 0,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: crate::scan_store::RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        };
        let (a, b) = (record("a", "monday"), record("b", "tuesday"));
        let comparison = compare(&base, &other);
        let csv = render([(&a, &base), (&b, &other)], &comparison, "csv").unwrap();
        let text = String::from_utf8(csv.body).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(
            lines[0],
            "Change,Scan Name,Updated,Type,Module,Source,F/P,Data"
        );
        assert!(
            lines[1].starts_with("Added,tuesday,")
                && lines[1].ends_with(",TCP_PORT_OPEN,m,192.0.2.1,0,192.0.2.1:22"),
            "{}",
            lines[1]
        );
        assert!(
            lines[3].starts_with("Removed,monday,")
                && lines[3].ends_with(",EMAILADDR,m,example.com,0,old@example.com"),
            "{}",
            lines[3]
        );
        assert_eq!(lines.len(), 4);
        assert_eq!(csv.filename, "a-vs-b-Huntsman.csv");
        let workbook = render([(&a, &base), (&b, &other)], &comparison, "excel").unwrap();
        assert!(workbook.body.starts_with(b"PK\x03\x04"));
        assert!(render([(&a, &base), (&b, &other)], &comparison, "gexf").is_err());
    }
}
