//! Saved scans as files, in Spiderfoot's export layouts.
//!
//! CSV and TSV have Spiderfoot's columns (`Updated`, `Type`, `Module`, `Source`, `F/P`, `Data`)
//! and JSON its `scanexportjsonmulti` objects, so a script written for Spiderfoot's exports reads
//! these unchanged. GEXF is the element graph: each element a node, each edge from the element it
//! was found from. Every element's data is written whole; only the root, which repeats the target,
//! is left out, as Spiderfoot leaves it out.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Value, json};

use crate::gexf::escape_xml;
use crate::scan_store::{ScanRecord, ScanResults};
use crate::sf_elements::DataElement;
use crate::timefmt::civil_from_days;

/// The formats [`render`] writes.
pub const FORMATS: [&str; 4] = ["csv", "tsv", "json", "gexf"];

/// A rendered export: its bytes, media type and a file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub body: String,
    pub content_type: &'static str,
    pub filename: String,
}

/// `YYYY-MM-DD HH:MM:SS` in UTC, Spiderfoot's export time format.
#[must_use]
pub fn timestamp(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    let (year, month, day) = civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

/// A spreadsheet would run a cell starting `=`, `@`, or a sign followed by anything but a number,
/// as a formula. Such a cell gets a leading `'`; a signed number such as `+61412345678` is left
/// as it is.
fn guard(cell: &str) -> String {
    let risky = match cell.chars().next() {
        Some('=' | '@' | '\t' | '\r') => true,
        Some('+' | '-') => !cell[1..]
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '.' | ',' | ' ')),
        _ => false,
    };
    if risky {
        format!("'{cell}")
    } else {
        cell.to_owned()
    }
}

fn csv_cell(cell: &str) -> String {
    let cell = guard(cell);
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

/// A TSV cell keeps its text: a tab, newline or backslash is written as `\t`, `\n`, `\\`.
fn tsv_cell(cell: &str) -> String {
    guard(cell)
        .replace('\\', "\\\\")
        .replace('\t', "\\t")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Each element with the data of the element it was found from, root left out.
fn rows<'a>(results: &'a ScanResults, kind: Option<&str>) -> Vec<(&'a DataElement, &'a str)> {
    let by_id: BTreeMap<&str, &DataElement> = results
        .elements
        .iter()
        .map(|element| (element.id.as_str(), element))
        .collect();
    results
        .elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .filter(|element| kind.is_none_or(|kind| element.kind.eq_ignore_ascii_case(kind)))
        .map(|element| {
            let source = element
                .source
                .as_deref()
                .and_then(|id| by_id.get(id))
                .map_or("", |source| source.data.as_str());
            (element, source)
        })
        .collect()
}

fn file_name(scan: &ScanRecord, extension: &str) -> String {
    let safe: String = scan
        .name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .take(80)
        .collect();
    let safe = safe.trim_matches(['.', '_']);
    if safe.is_empty() {
        format!("{}-Huntsman.{extension}", scan.id)
    } else {
        format!("{safe}-Huntsman.{extension}")
    }
}

/// A CSV (`csv`) or TSV table with `header`, and its media type.
fn table(
    csv: bool,
    header: &[&str],
    lines: impl Iterator<Item = Vec<String>>,
) -> (String, &'static str) {
    let (separator, cell, content_type): (&str, fn(&str) -> String, _) = if csv {
        (",", csv_cell, "text/csv; charset=utf-8")
    } else {
        ("\t", tsv_cell, "text/tab-separated-values; charset=utf-8")
    };
    let mut body = header.join(separator);
    body.push_str("\r\n");
    for line in lines {
        let line = line
            .iter()
            .map(|value| cell(value))
            .collect::<Vec<_>>()
            .join(separator);
        body.push_str(&line);
        body.push_str("\r\n");
    }
    (body, content_type)
}

/// A scan's correlations as `csv`, `tsv` or `json`: Spiderfoot's `scancorrelationsexport`
/// columns (Rule Name, Correlation, Risk, Description), then the rule id, where the rule came
/// from and the ids of the elements each is about.
///
/// # Errors
/// The format name, when it is not one of those three.
pub fn render_correlations(
    scan: &ScanRecord,
    results: &ScanResults,
    format: &str,
) -> Result<Export, String> {
    let filename = |extension: &str| {
        file_name(scan, extension).replacen("-Huntsman.", "-Huntsman-correlations.", 1)
    };
    match format {
        "csv" | "tsv" => {
            let lines = results.correlations.iter().map(|correlation| {
                vec![
                    correlation.name.clone(),
                    correlation.title.clone(),
                    correlation.risk.as_str().to_owned(),
                    correlation.description.clone(),
                    correlation.rule.clone(),
                    correlation.origin.clone(),
                    correlation.elements.join(" "),
                ]
            });
            let (body, content_type) = table(
                format == "csv",
                &[
                    "Rule Name",
                    "Correlation",
                    "Risk",
                    "Description",
                    "Rule",
                    "Origin",
                    "Elements",
                ],
                lines,
            );
            Ok(Export {
                body,
                content_type,
                filename: filename(format),
            })
        }
        "json" => Ok(Export {
            body: serde_json::to_string(&results.correlations).unwrap_or_else(|_| "[]".to_owned()),
            content_type: "application/json; charset=utf-8",
            filename: filename("json"),
        }),
        other => Err(format!(
            "unknown correlation export format {other}; choose csv, tsv or json"
        )),
    }
}

/// One scan as `format`, optionally only elements of one type.
///
/// # Errors
/// The format name, when it is not one of [`FORMATS`].
pub fn render(
    scan: &ScanRecord,
    results: &ScanResults,
    format: &str,
    kind: Option<&str>,
) -> Result<Export, String> {
    match format {
        "csv" | "tsv" => {
            let lines = rows(results, kind).into_iter().map(|(element, source)| {
                vec![
                    timestamp(element.created),
                    element.kind.clone(),
                    element.module.clone(),
                    source.to_owned(),
                    u8::from(element.fp).to_string(),
                    element.data.clone(),
                ]
            });
            let (body, content_type) = table(
                format == "csv",
                &["Updated", "Type", "Module", "Source", "F/P", "Data"],
                lines,
            );
            Ok(Export {
                body,
                content_type,
                filename: file_name(scan, format),
            })
        }
        "json" => Ok(Export {
            body: json_rows(&[(scan, results)], kind).to_string(),
            content_type: "application/json; charset=utf-8",
            filename: file_name(scan, "json"),
        }),
        "gexf" => Ok(Export {
            body: gexf(scan, results),
            content_type: "application/gexf+xml; charset=utf-8",
            filename: file_name(scan, "gexf"),
        }),
        other => Err(format!(
            "unknown export format {other}; choose {}",
            FORMATS.join(", ")
        )),
    }
}

/// Spiderfoot's `scanexportjsonmulti` rows for several scans, each element with its raw evidence
/// as well.
#[must_use]
pub fn json_rows(scans: &[(&ScanRecord, &ScanResults)], kind: Option<&str>) -> Value {
    let mut out = Vec::new();
    for (scan, results) in scans {
        for (element, source) in rows(results, kind) {
            out.push(json!({
                "data": element.data,
                "event_type": element.kind,
                "module": element.module,
                "source_data": source,
                "false_positive": u8::from(element.fp),
                "last_seen": timestamp(element.created),
                "scan_name": scan.name,
                "scan_target": scan.target,
                "id": element.id,
                "source": element.source,
                "confidence": element.confidence,
                "raw": element.raw,
            }));
        }
    }
    Value::Array(out)
}

/// The element graph as GEXF 1.3: nodes carry type, module and data; each edge runs from the
/// element a node was found from.
#[must_use]
pub fn gexf(scan: &ScanRecord, results: &ScanResults) -> String {
    let mut out = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<gexf xmlns=\"http://gexf.net/1.3\" version=\"1.3\">\n",
    );
    let _ = writeln!(
        out,
        "<meta><creator>Huntsman</creator><description>{}</description></meta>",
        escape_xml(&format!("{} ({})", scan.name, scan.target))
    );
    out.push_str("<graph defaultedgetype=\"directed\" mode=\"static\">\n<attributes class=\"node\"><attribute id=\"0\" title=\"type\" type=\"string\"/><attribute id=\"1\" title=\"module\" type=\"string\"/><attribute id=\"2\" title=\"data\" type=\"string\"/></attributes>\n<nodes>\n");
    for element in &results.elements {
        let label: String = element.data.chars().take(120).collect();
        let _ = writeln!(
            out,
            "<node id=\"{}\" label=\"{}\"><attvalues><attvalue for=\"0\" value=\"{}\"/><attvalue for=\"1\" value=\"{}\"/><attvalue for=\"2\" value=\"{}\"/></attvalues></node>",
            escape_xml(&element.id),
            escape_xml(&label),
            escape_xml(&element.kind),
            escape_xml(&element.module),
            escape_xml(&element.data)
        );
    }
    out.push_str("</nodes>\n<edges>\n");
    for (index, element) in results.elements.iter().enumerate() {
        if let Some(source) = &element.source {
            let _ = writeln!(
                out,
                "<edge id=\"{index}\" source=\"{}\" target=\"{}\"/>",
                escape_xml(source),
                escape_xml(&element.id)
            );
        }
    }
    out.push_str("</edges>\n</graph>\n</gexf>\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};
    use crate::sf_elements::{Target, elements};

    fn scan() -> (ScanRecord, ScanResults) {
        let mut evidence = Evidence::new(EvidenceProvenance::for_scan("crtsh", "s"), "seen")
            .with_attr("ports", "443");
        evidence.provenance.recorded_at_unix = 1_700_000_000;
        let entities = vec![
            Entity::builder(EntityKind::Domain, "www.example.com", 0.9, "s")
                .evidence(evidence.clone())
                .build(),
            Entity::builder(EntityKind::Domain, "=cmd.example.com", 0.9, "s")
                .evidence(evidence)
                .build(),
        ];
        let record = ScanRecord {
            format_version: FORMAT_VERSION,
            id: "0123456789abcdef".into(),
            name: "my scan/1".into(),
            target: "example.com".into(),
            target_type: "INTERNET_NAME".into(),
            kind: "domain".into(),
            options: ScanOptions::default(),
            status: ScanStatus::Finished,
            created: 0,
            started: None,
            ended: None,
            elements: 0,
            unique: 0,
            correlations: RiskCounts::default(),
            errors: 0,
            modules_run: Vec::new(),
            owner: None,
        };
        let results = ScanResults {
            format_version: FORMAT_VERSION,
            scan_id: record.id.clone(),
            text: String::new(),
            elements: elements(
                Target {
                    value: "example.com",
                    kind: "INTERNET_NAME",
                },
                &entities,
                1_700_000_000,
            ),
            entities,
            outcomes: Vec::new(),
            correlations: Vec::new(),
            lineage: Vec::new(),
            termination: None,
        };
        (record, results)
    }

    #[test]
    fn correlations_export_with_spiderfoots_columns_first() {
        let (scan, mut results) = scan();
        results
            .correlations
            .push(crate::scan_store::ScanCorrelation {
                id: "c1".into(),
                rule: "database_exposed".into(),
                name: "Database server exposed to the Internet".into(),
                title: "Database server exposed to the Internet: 1.1.1.1:3306".into(),
                risk: crate::scan_store::Risk::High,
                description: "A database, \"open\".".into(),
                origin: "spiderfoot".into(),
                logic: "id: database_exposed".into(),
                elements: vec!["e1".into(), "e2".into()],
            });
        let csv = render_correlations(&scan, &results, "csv").unwrap();
        assert_eq!(
            csv.body,
            "Rule Name,Correlation,Risk,Description,Rule,Origin,Elements\r\nDatabase server exposed to the Internet,Database server exposed to the Internet: 1.1.1.1:3306,HIGH,\"A database, \"\"open\"\".\",database_exposed,spiderfoot,e1 e2\r\n"
        );
        assert!(csv.filename.ends_with("-Huntsman-correlations.csv"));
        let json = render_correlations(&scan, &results, "json").unwrap();
        let rows: serde_json::Value = serde_json::from_str(&json.body).unwrap();
        assert_eq!(rows[0]["logic"], "id: database_exposed");
        assert!(render_correlations(&scan, &results, "gexf").is_err());
    }

    #[test]
    fn csv_has_spiderfoots_columns_and_every_element_but_the_root() {
        let (record, results) = scan();
        let export = render(&record, &results, "csv", None).unwrap();
        let lines: Vec<&str> = export.body.lines().collect();
        assert_eq!(lines[0], "Updated,Type,Module,Source,F/P,Data");
        assert_eq!(lines.len(), results.elements.len());
        assert!(
            lines
                .contains(&"2023-11-14 22:13:20,INTERNET_NAME,crtsh,example.com,0,www.example.com")
        );
        assert!(lines.contains(
            &"2023-11-14 22:13:20,TCP_PORT_OPEN,crtsh,www.example.com,0,www.example.com:443"
        ));
        assert!(
            lines
                .iter()
                .any(|line| line.ends_with(",'=cmd.example.com"))
        );
        assert_eq!(export.filename, "my_scan_1-Huntsman.csv");
    }

    #[test]
    fn a_type_filter_keeps_only_that_type() {
        let (record, results) = scan();
        let export = render(&record, &results, "tsv", Some("tcp_port_open")).unwrap();
        let lines: Vec<&str> = export.body.lines().collect();
        assert_eq!(lines[0], "Updated\tType\tModule\tSource\tF/P\tData");
        assert_eq!(lines.len(), 3);
        assert!(
            lines[1..]
                .iter()
                .all(|line| line.contains("\tTCP_PORT_OPEN\t"))
        );
    }

    #[test]
    fn json_rows_are_spiderfoots_objects_with_the_raw_evidence() {
        let (record, results) = scan();
        let export = render(&record, &results, "json", None).unwrap();
        let rows: Vec<Value> = serde_json::from_str(&export.body).unwrap();
        let www = rows
            .iter()
            .find(|row| row["data"] == "www.example.com")
            .unwrap();
        assert_eq!(www["event_type"], "INTERNET_NAME");
        assert_eq!(www["module"], "crtsh");
        assert_eq!(www["source_data"], "example.com");
        assert_eq!(www["scan_target"], "example.com");
        assert_eq!(www["last_seen"], "2023-11-14 22:13:20");
        assert_eq!(www["raw"]["evidence"]["attributes"]["ports"], "443");
    }

    #[test]
    fn gexf_is_well_formed_with_a_node_per_element_and_an_edge_per_source() {
        let (mut record, results) = scan();
        record.name = "a<b & \"c\"".into();
        let body = render(&record, &results, "gexf", None).unwrap().body;
        assert_eq!(body.matches("<node ").count(), results.elements.len());
        assert_eq!(body.matches("<edge ").count(), results.elements.len() - 1);
        assert!(body.contains("value=\"TCP_PORT_OPEN\""));
        assert!(
            body.contains("<description>a&lt;b &amp; &quot;c&quot; (example.com)</description>")
        );
        assert!(render(&record, &results, "pdf", None).is_err());
    }

    #[test]
    fn cells_that_a_spreadsheet_would_run_are_guarded_and_signed_numbers_are_not() {
        assert_eq!(guard("=1+1"), "'=1+1");
        assert_eq!(guard("@SUM(A1)"), "'@SUM(A1)");
        assert_eq!(guard("-2+3*cmd"), "'-2+3*cmd");
        assert_eq!(guard("+61412345678"), "+61412345678");
        assert_eq!(guard("-27.4698,153.0251"), "-27.4698,153.0251");
        assert_eq!(tsv_cell("a\tb\nc"), "a\\tb\\nc");
        assert_eq!(csv_cell("a,\"b\""), "\"a,\"\"b\"\"\"");
        assert_eq!(timestamp(0), "1970-01-01 00:00:00");
    }
}
