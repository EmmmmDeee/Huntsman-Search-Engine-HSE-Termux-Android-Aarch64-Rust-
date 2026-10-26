//! Saved scans as files, in Spiderfoot's export layouts.
//!
//! CSV, TSV and Excel have Spiderfoot's columns (`Updated`, `Type`, `Module`, `Source`, `F/P`,
//! `Data`), the workbook with a sheet per data type as Spiderfoot's `buildExcel` lays it out, and
//! JSON its `scanexportjsonmulti` objects, so a script written for Spiderfoot's exports reads
//! these unchanged. Several scans export together with `Scan Name` first, as Spiderfoot's
//! `scaneventresultexportmulti` does. GEXF is the element graph: each element a node, each edge
//! from the element it was found from. Every element's data is written whole; only the root,
//! which repeats the target, is left out, as Spiderfoot leaves it out.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde::ser::{Serialize, SerializeSeq, Serializer};
use serde_json::{Value, json};

use crate::gexf::escape_xml;
use crate::scan_store::{ScanRecord, ScanResults};
use crate::sf_elements::DataElement;
use crate::textnorm::{escape_controls, escape_controls_keep_lines};
use crate::timefmt::civil_from_days;
use crate::xlsx::{self, Sheet};

/// The formats [`render`] writes. `excel` is taken for `xlsx`, as Spiderfoot takes it.
/// `html` is the client-ready investigation report ([`report`]).
pub const FORMATS: [&str; 6] = ["csv", "tsv", "xlsx", "json", "gexf", "html"];

/// The formats several scans export together in, with [`render_many`].
pub const MANY_FORMATS: [&str; 4] = ["csv", "tsv", "xlsx", "json"];

/// The formats [`render_correlations`] writes.
pub const CORRELATION_FORMATS: [&str; 4] = ["csv", "tsv", "xlsx", "json"];

/// Spiderfoot's columns for a scan's elements.
const ELEMENT_COLUMNS: [&str; 6] = ["Updated", "Type", "Module", "Source", "F/P", "Data"];

/// Spiderfoot's `scancorrelationsexport` columns, then the rule id, where the rule came from
/// and the ids of the elements each correlation is about.
const CORRELATION_COLUMNS: [&str; 7] = [
    "Rule Name",
    "Correlation",
    "Risk",
    "Description",
    "Rule",
    "Origin",
    "Elements",
];

/// A rendered export: its bytes, media type and a file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub body: Vec<u8>,
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

/// A format name as given, in lower case, with Spiderfoot's `excel` read as `xlsx`.
fn format_name(format: &str) -> String {
    let format = format.trim().to_ascii_lowercase();
    if format == "excel" {
        "xlsx".to_owned()
    } else {
        format
    }
}

/// A spreadsheet would run a cell starting `=`, `@`, or a sign followed by anything but a number,
/// as a formula. Such a cell gets a leading `'`; a signed number such as `+61412345678` is left
/// as it is. A workbook needs none of this: its cells are text, never formulas.
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

/// A CSV cell is quoted when it holds a comma, quote or line break. A control character or a
/// bidirectional control is written as an escape, so a remote value cannot drive the terminal
/// that `scans export` writes to. A line feed and a tab stay, since quoting carries them.
fn csv_cell(cell: &str) -> String {
    let cell = escape_controls_keep_lines(&guard(cell));
    if cell.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell
    }
}

/// A TSV cell keeps its text: a tab, newline or backslash is written as `\t`, `\n`, `\\`, and any
/// other control or bidirectional control as an escape, as in a CSV cell.
fn tsv_cell(cell: &str) -> String {
    escape_controls(
        &guard(cell)
            .replace('\\', "\\\\")
            .replace('\t', "\\t")
            .replace('\r', "\\r")
            .replace('\n', "\\n"),
    )
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

/// One element as a line under [`ELEMENT_COLUMNS`].
/// One element in Spiderfoot's export columns, its source element's data given.
pub(crate) fn element_line(element: &DataElement, source: &str) -> Vec<String> {
    vec![
        timestamp(element.created),
        element.kind.clone(),
        element.module.clone(),
        source.to_owned(),
        u8::from(element.fp).to_string(),
        element.data.clone(),
    ]
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
fn table(csv: bool, header: &[&str], lines: Vec<Vec<String>>) -> (String, &'static str) {
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

/// A workbook as Spiderfoot's `buildExcel` makes one: a sheet for each value of column
/// `sheet_by`, named after it and without that column, headed by `header`, sheets in name order.
fn workbook(header: &[&str], lines: Vec<Vec<String>>, sheet_by: usize) -> Vec<u8> {
    let mut header: Vec<String> = header.iter().map(|&column| column.to_owned()).collect();
    header.remove(sheet_by);
    let mut sheets: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    for mut line in lines {
        let name = line.remove(sheet_by);
        sheets
            .entry(name)
            .or_insert_with(|| vec![header.clone()])
            .push(line);
    }
    let sheets: Vec<Sheet> = sheets
        .into_iter()
        .map(|(name, rows)| Sheet { name, rows })
        .collect();
    xlsx::workbook(&sheets)
}

/// `lines` under `header` as `format` (`csv`, `tsv` or `xlsx`, a sheet per value of column
/// `sheet_by`) with its media type and file extension, or `None` for another format.
pub(crate) fn tabular(
    format: &str,
    header: &[&str],
    lines: Vec<Vec<String>>,
    sheet_by: usize,
) -> Option<(Vec<u8>, &'static str)> {
    match format {
        "csv" | "tsv" => {
            let (body, content_type) = table(format == "csv", header, lines);
            Some((body.into_bytes(), content_type))
        }
        "xlsx" => Some((workbook(header, lines, sheet_by), xlsx::CONTENT_TYPE)),
        _ => None,
    }
}

/// A scan's correlations as `csv`, `tsv`, `xlsx` (a sheet per rule, as Spiderfoot's) or `json`:
/// Spiderfoot's `scancorrelationsexport` columns (Rule Name, Correlation, Risk, Description),
/// then the rule id, where the rule came from and the ids of the elements each is about.
///
/// # Errors
/// The format name, when it is not one of [`CORRELATION_FORMATS`].
pub fn render_correlations(
    scan: &ScanRecord,
    results: &ScanResults,
    format: &str,
) -> Result<Export, String> {
    let format = format_name(format);
    let filename = file_name(scan, &format).replacen("-Huntsman.", "-Huntsman-correlations.", 1);
    if format == "json" {
        return Ok(Export {
            body: serde_json::to_vec(&results.correlations).unwrap_or_else(|_| b"[]".to_vec()),
            content_type: "application/json; charset=utf-8",
            filename,
        });
    }
    let lines = results
        .correlations
        .iter()
        .map(|correlation| {
            vec![
                correlation.name.clone(),
                correlation.title.clone(),
                correlation.risk.as_str().to_owned(),
                correlation.description.clone(),
                correlation.rule.clone(),
                correlation.origin.clone(),
                correlation.elements.join(" "),
            ]
        })
        .collect();
    let (body, content_type) =
        tabular(&format, &CORRELATION_COLUMNS, lines, 0).ok_or_else(|| {
            format!(
                "unknown correlation export format {format}; choose {}",
                CORRELATION_FORMATS.join(", ")
            )
        })?;
    Ok(Export {
        body,
        content_type,
        filename,
    })
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
    let format = format_name(format);
    let filename = file_name(scan, &format);
    let (body, content_type) = match format.as_str() {
        "json" => (
            json_rows(&[(scan, results)], kind).to_string().into_bytes(),
            "application/json; charset=utf-8",
        ),
        "gexf" => (
            gexf(scan, results).into_bytes(),
            "application/gexf+xml; charset=utf-8",
        ),
        "html" => (
            report(scan, results).into_bytes(),
            "text/html; charset=utf-8",
        ),
        _ => {
            let lines = rows(results, kind)
                .into_iter()
                .map(|(element, source)| element_line(element, source))
                .collect();
            tabular(&format, &ELEMENT_COLUMNS, lines, 1).ok_or_else(|| {
                format!(
                    "unknown export format {format}; choose {}",
                    FORMATS.join(", ")
                )
            })?
        }
    };
    Ok(Export {
        body,
        content_type,
        filename,
    })
}

/// Several scans as one `format` file (`csv`, `tsv`, `xlsx` or `json`), optionally only elements
/// of one type: Spiderfoot's `scaneventresultexportmulti` columns, `Scan Name` then the element
/// columns, the workbook with a sheet per type; JSON is [`json_rows`].
///
/// # Errors
/// The format name, when it is not one of [`MANY_FORMATS`].
pub fn render_many(
    scans: &[(&ScanRecord, &ScanResults)],
    format: &str,
    kind: Option<&str>,
) -> Result<Export, String> {
    let format = format_name(format);
    let filename = match scans {
        [(scan, _)] => file_name(scan, &format),
        _ => format!("Huntsman.{format}"),
    };
    if format == "json" {
        return Ok(Export {
            body: json_rows(scans, kind).to_string().into_bytes(),
            content_type: "application/json; charset=utf-8",
            filename,
        });
    }
    let mut header = vec!["Scan Name"];
    header.extend(ELEMENT_COLUMNS);
    let lines = scans
        .iter()
        .flat_map(|(scan, results)| {
            rows(results, kind).into_iter().map(|(element, source)| {
                let mut line = vec![scan.name.clone()];
                line.extend(element_line(element, source));
                line
            })
        })
        .collect();
    let (body, content_type) = tabular(&format, &header, lines, 2).ok_or_else(|| {
        format!(
            "unknown export format {format} for several scans; choose {}",
            MANY_FORMATS.join(", ")
        )
    })?;
    Ok(Export {
        body,
        content_type,
        filename,
    })
}

/// Serialize JSON multi-export rows one at a time, without building an unbounded Value array.
/// The wire representation is identical to `json_rows(...).to_string()`.
struct JsonRows<'a, 'b> {
    scans: &'a [(&'b ScanRecord, &'b ScanResults)],
    kind: Option<&'a str>,
}

impl Serialize for JsonRows<'_, '_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(None)?;
        for &(scan, results) in self.scans {
            for (element, source) in rows(results, self.kind) {
                sequence.serialize_element(&json!({
                    "data": element.data,
                    "event_type": element.kind,
                    "module": element.module,
                    "source_data": source,
                    "false_positive": u8::from(element.fp),
                    "last_seen": timestamp(element.created),
                    "scan_id": scan.id,
                    "scan_name": scan.name,
                    "scan_target": scan.target,
                    "id": element.id,
                    "source": element.source,
                    "confidence": element.confidence,
                    "raw": element.raw,
                }))?;
            }
        }
        sequence.end()
    }
}

/// Bounded JSON multi-export. An over-budget response is never materialized as
/// a complete JSON array; the outer error reports serialization failure and
/// the inner error reports the required byte count.
///
/// # Errors
/// A JSON serialization failure.
pub fn render_many_json_bounded(
    scans: &[(&ScanRecord, &ScanResults)],
    kind: Option<&str>,
    max_bytes: usize,
) -> Result<Result<Export, usize>, String> {
    let filename = match scans {
        [(scan, _)] => file_name(scan, "json"),
        _ => "Huntsman.json".to_owned(),
    };
    crate::json::to_bounded_json(&JsonRows { scans, kind }, max_bytes, false)
        .map(|body| {
            body.map(|body| Export {
                body,
                content_type: "application/json; charset=utf-8",
                filename,
            })
        })
        .map_err(|error| error.to_string())
}

/// Write multi-scan CSV/TSV directly into a bounded byte buffer. Each escaped
/// cell is checked before append; a rejected response is never returned partially.
///
/// # Errors
/// An unsupported format.
pub fn render_many_text_bounded(
    scans: &[(&ScanRecord, &ScanResults)],
    format: &str,
    kind: Option<&str>,
    max_bytes: usize,
) -> Result<Result<Export, usize>, String> {
    let format = format_name(format);
    let (separator, content_type): (&[u8], _) = match format.as_str() {
        "csv" => (b",", "text/csv; charset=utf-8"),
        "tsv" => (b"\t", "text/tab-separated-values; charset=utf-8"),
        _ => return Err(format!("unknown bounded tabular export format {format}")),
    };
    let filename = match scans {
        [(scan, _)] => file_name(scan, &format),
        _ => format!("Huntsman.{format}"),
    };
    let mut body = Vec::new();
    let append = |body: &mut Vec<u8>, bytes: &[u8]| -> Result<(), usize> {
        let required = body.len().saturating_add(bytes.len());
        if required > max_bytes {
            Err(required)
        } else {
            body.extend_from_slice(bytes);
            Ok(())
        }
    };
    let write = || -> Result<Vec<u8>, usize> {
        let mut header = vec!["Scan Name"];
        header.extend(ELEMENT_COLUMNS);
        let separator_text = if format == "csv" { "," } else { "\t" };
        append(&mut body, header.join(separator_text).as_bytes())?;
        append(&mut body, b"\r\n")?;
        for &(scan, results) in scans {
            for (element, source) in rows(results, kind) {
                let mut line = vec![scan.name.clone()];
                line.extend(element_line(element, source));
                for (index, cell) in line.iter().enumerate() {
                    if index != 0 {
                        append(&mut body, separator)?;
                    }
                    let escaped = if format == "csv" {
                        csv_cell(cell)
                    } else {
                        tsv_cell(cell)
                    };
                    append(&mut body, escaped.as_bytes())?;
                }
                append(&mut body, b"\r\n")?;
            }
        }
        Ok(body)
    };
    Ok(write().map(|body| Export {
        body,
        content_type,
        filename,
    }))
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
                "scan_id": scan.id,
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

/// What every report says about how to read it. Findings are leads with their sources, never an
/// identity verdict: CLAUDE.md's rule that weak correlations do not assert who someone is.
const REPORT_METHOD: &str = "Every finding below was collected by Huntsman from the public or \
operator-authorised sources named beside it, at the time shown, and is reported as that source \
returned it. A confidence is the strength of the source's own statement, not a verification of \
identity: two findings that share a value or appear together are leads that call for \
corroboration, and nothing in this report asserts who holds an address, number, account or \
domain. Sources answer differently over time, and a source that returned nothing or failed is \
listed as such under Sources consulted rather than read as an absence. Findings the analyst \
marked as false positives are left out and counted.";

/// The investigation report for a saved scan: one self-contained HTML document a client can read
/// on a phone or print to PDF. Inline styles only, no script and nothing fetched, so opening it
/// sends nothing anywhere; every value a source returned is escaped, so no scraped text can
/// become markup. Findings are grouped by kind, most confident first, each with every source that
/// reported it and when; then correlations, every source consulted and its outcome, and how to
/// read it all. **Pure.**
#[must_use]
pub fn report(scan: &ScanRecord, results: &ScanResults) -> String {
    let esc = |text: &str| escape_xml(text);
    let when = |millis: Option<u64>| {
        millis.map_or_else(
            || "not recorded".to_owned(),
            |millis| crate::timefmt::format_unix(i64::try_from(millis / 1000).unwrap_or(i64::MAX)),
        )
    };
    let kept = report_findings(results);
    let aside = results.entities.len() - kept.len();

    let mut out = String::with_capacity(4096 + 512 * kept.len());
    let title = format!("Investigation report: {}", scan.target);
    let _ = write!(
        out,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<title>{}</title><style>{REPORT_STYLE}</style></head><body><main>\n<h1>{}</h1>\n",
        esc(&title),
        esc(&title)
    );
    let _ = writeln!(
        out,
        "<table class=\"meta\"><tr><th>Subject</th><td>{}</td></tr><tr><th>Lookup</th><td>{}</td></tr>\
<tr><th>Scan</th><td>{} ({})</td></tr><tr><th>Status</th><td>{}</td></tr>\
<tr><th>Started</th><td>{}</td></tr><tr><th>Finished</th><td>{}</td></tr>\
<tr><th>Use case</th><td>{}</td></tr><tr><th>Depth</th><td>{}</td></tr>\
<tr><th>Modules asked</th><td>{}</td></tr><tr><th>Types kept</th><td>{}</td></tr>\
<tr><th>Built from</th><td>Huntsman {}</td></tr></table>",
        esc(&scan.target),
        esc(&scan.kind),
        esc(&scan.name),
        esc(&scan.id),
        scan.status.as_str(),
        when(scan.started.or(Some(scan.created))),
        when(scan.ended),
        esc(if scan.options.usecase.is_empty() {
            "all"
        } else {
            &scan.options.usecase
        }),
        match scan.options.depth {
            0 => "the target only".to_owned(),
            1 => "1 hop past the target".to_owned(),
            hops => format!("{hops} hops past the target"),
        },
        if scan.options.modules.is_empty() {
            "every module the lookup runs".to_owned()
        } else {
            esc(&scan.options.modules.join(", "))
        },
        if scan.options.types.is_empty() {
            "every type".to_owned()
        } else {
            esc(&scan.options.types.join(", "))
        },
        esc(crate::diagnostics::embedded_build_sha()),
    );

    let answered = results
        .outcomes
        .iter()
        .filter(|o| o.kind.is_accepted())
        .count();
    let _ = writeln!(
        out,
        "<h2>Summary</h2><p>{} finding{} from {} of {} source{} consulted{}; {} correlation{}.</p>",
        kept.len(),
        if kept.len() == 1 { "" } else { "s" },
        answered,
        results.outcomes.len(),
        if results.outcomes.len() == 1 { "" } else { "s" },
        if aside == 0 {
            String::new()
        } else {
            format!(
                "; {aside} set aside by the analyst as false positive{}",
                if aside == 1 { "" } else { "s" }
            )
        },
        results.correlations.len(),
        if results.correlations.len() == 1 {
            ""
        } else {
            "s"
        },
    );

    out.push_str("<h2>Findings</h2>\n");
    if kept.is_empty() {
        out.push_str("<p>No findings.</p>\n");
    }
    let mut current = "";
    for entity in &kept {
        let kind = entity.kind.as_str();
        if kind != current {
            let _ = writeln!(out, "<h3>{}</h3>", esc(kind));
            current = kind;
        }
        report_finding(&mut out, entity);
    }

    report_tail(&mut out, scan, results);
    out
}

/// The entities the report presents, by kind then most confident first, and leaving out each one
/// the analyst set aside: every element of it they saw is marked as a false positive.
fn report_findings(results: &ScanResults) -> Vec<&crate::entity::Entity> {
    let mut marks: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for element in &results.elements {
        if let Some(uid) = element.entity.as_deref() {
            let mark = marks.entry(uid).or_default();
            mark.0 += 1;
            mark.1 += usize::from(element.fp);
        }
    }
    let mut kept: Vec<&crate::entity::Entity> = results
        .entities
        .iter()
        .filter(|entity| {
            !marks
                .get(entity.uid.as_str())
                .is_some_and(|&(all, fp)| all > 0 && all == fp)
        })
        .collect();
    kept.sort_by(|a, b| {
        a.kind
            .as_str()
            .cmp(b.kind.as_str())
            .then(b.confidence.total_cmp(&a.confidence))
            .then(a.value.cmp(&b.value))
    });
    kept
}

/// One finding: its value and confidence, its tags, and every source that reported it, when, and
/// with what attributes.
fn report_finding(out: &mut String, entity: &crate::entity::Entity) {
    let esc = |text: &str| escape_xml(text);
    let _ = write!(
        out,
        "<section class=\"finding\"><p class=\"value\">{} <span class=\"conf\">{:.0}%</span></p>",
        esc(&entity.value),
        (entity.confidence * 100.0).clamp(0.0, 100.0)
    );
    if !entity.tags.is_empty() {
        let tags: Vec<String> = entity.tags.iter().map(|tag| esc(tag)).collect();
        let _ = write!(out, "<p class=\"tags\">{}</p>", tags.join(" · "));
    }
    out.push_str("<ul>");
    for evidence in &entity.evidence {
        let _ = write!(
            out,
            "<li><b>{}</b>, {}: {}",
            esc(&evidence.provenance.source),
            crate::timefmt::format_unix(
                i64::try_from(evidence.provenance.recorded_at_unix).unwrap_or(i64::MAX)
            ),
            esc(&evidence.summary)
        );
        if !evidence.attributes.is_empty() {
            out.push_str("<dl>");
            for (key, value) in &evidence.attributes {
                let _ = write!(out, "<dt>{}</dt><dd>{}</dd>", esc(key), esc(value));
            }
            out.push_str("</dl>");
        }
        out.push_str("</li>");
    }
    out.push_str("</ul></section>\n");
}

/// The report's correlations, every source consulted with its outcome, the gaps the sources that
/// did not answer leave, how to run the scan again, and how to read it all: the sections
/// `docs/CLIENT_RESEARCH_REPORT.md` requires beyond the findings.
fn report_tail(out: &mut String, scan: &ScanRecord, results: &ScanResults) {
    let esc = |text: &str| escape_xml(text);
    if !results.correlations.is_empty() {
        out.push_str("<h2>Correlations</h2>\n<ul>");
        for correlation in &results.correlations {
            let _ = write!(
                out,
                "<li><b>{}</b> {}: {}</li>",
                correlation.risk.as_str(),
                esc(&correlation.title),
                esc(&correlation.description)
            );
        }
        out.push_str("</ul>\n");
    }

    out.push_str("<h2>Sources consulted</h2>\n<table><tr><th>Source</th><th>Outcome</th><th>Found</th><th>Detail</th></tr>");
    for outcome in &results.outcomes {
        let _ = write!(
            out,
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&outcome.module),
            outcome.kind.as_str(),
            outcome
                .found
                .map_or_else(String::new, |found| found.to_string()),
            esc(outcome.detail.as_deref().unwrap_or(""))
        );
    }
    out.push_str("</table>\n");

    out.push_str("<h2>Gaps and unknowns</h2>\n");
    let gaps: Vec<_> = results
        .outcomes
        .iter()
        .filter(|outcome| !outcome.kind.is_accepted())
        .collect();
    if gaps.is_empty() {
        out.push_str("<p>Every source consulted answered.</p>\n");
    } else {
        out.push_str(
            "<p>These sources did not answer, so what they would have found is unknown, not \
absent:</p><ul>",
        );
        for outcome in gaps {
            let _ = write!(
                out,
                "<li><b>{}</b>: {}{}</li>",
                esc(&outcome.module),
                outcome.kind.as_str(),
                outcome
                    .detail
                    .as_deref()
                    .map_or_else(String::new, |detail| format!(", {}", esc(detail)))
            );
        }
        out.push_str("</ul>\n");
    }

    let _ = writeln!(
        out,
        "<h2>Reproducibility</h2><p>Run this scan again with <code>huntsman-recon scans rerun {}</code>, \
or on another installation with <code>{}</code>. Sources change over time, so a later run can \
differ.</p>",
        esc(&scan.id),
        esc(&rerun_command(scan))
    );
    let _ = write!(
        out,
        "<h2>How to read this report</h2><p>{}</p>\n</main></body></html>\n",
        esc(REPORT_METHOD)
    );
}

/// The `scans run` command line that repeats `scan`'s target, lookup and options, every word a
/// POSIX shell would read as anything but itself single-quoted, so a pasted command runs only
/// `scans run`.
fn rerun_command(scan: &ScanRecord) -> String {
    let word = |text: &str| {
        if !text.is_empty()
            && text.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ',' | ':' | '@' | '/')
            })
        {
            text.to_owned()
        } else {
            format!("'{}'", text.replace('\'', "'\\''"))
        }
    };
    let options = &scan.options;
    let mut command = format!(
        "huntsman-recon scans run {} -k {}",
        word(&scan.target),
        word(&scan.kind)
    );
    if !options.usecase.is_empty() && options.usecase != "all" {
        let _ = write!(command, " -u {}", word(&options.usecase));
    }
    if !options.types.is_empty() {
        let _ = write!(command, " -t {}", word(&options.types.join(",")));
    }
    if !options.modules.is_empty() {
        let _ = write!(command, " -m {}", word(&options.modules.join(",")));
    }
    if options.depth > 0 {
        let _ = write!(command, " --depth {}", options.depth);
    }
    command
}

/// The report's styles: readable on a phone, and printed without the screen's colours.
const REPORT_STYLE: &str = "body{font:15px/1.5 system-ui,sans-serif;color:#1d2330;background:#fff;margin:0}\
main{max-width:860px;margin:0 auto;padding:16px}h1{font-size:1.5em;margin:.2em 0 .6em}\
h2{border-bottom:2px solid #1f4e8c;padding-bottom:4px;margin-top:1.6em}h3{color:#1f4e8c;text-transform:capitalize}\
table{border-collapse:collapse;width:100%;font-size:.92em}th,td{border:1px solid #d5dbe5;padding:4px 6px;text-align:left;vertical-align:top;word-break:break-word}\
.meta th{width:9em;background:#f2f5fa}.finding{border-left:3px solid #1f4e8c;padding:2px 0 2px 10px;margin:10px 0}\
.value{font-weight:600;margin:0;word-break:break-all}.conf{font-weight:400;color:#556;font-size:.9em}\
.tags{color:#556;font-size:.85em;margin:2px 0}ul{margin:4px 0;padding-left:18px}dl{margin:2px 0 4px;font-size:.88em}\
dt{float:left;clear:left;color:#556;margin-right:6px}dd{margin:0;word-break:break-word}\
@media print{body{font-size:11pt}h2{break-after:avoid}.finding{break-inside:avoid}}";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
    use crate::scan_store::{FORMAT_VERSION, RiskCounts, ScanOptions, ScanStatus};
    use crate::sf_elements::{Target, elements};
    use crate::xlsx::tests::{cells, part, sheet_names};

    fn text(export: &Export) -> String {
        String::from_utf8(export.body.clone()).unwrap()
    }

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
            owner_started: None,
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
    fn bounded_json_multi_export_preserves_bytes_and_rejects_at_exact_boundary() {
        let (scan, results) = scan();
        let scans = [(&scan, &results), (&scan, &results)];
        let original = render_many(&scans, "json", None).unwrap();
        let exact = render_many_json_bounded(&scans, None, original.body.len())
            .unwrap()
            .unwrap();
        assert_eq!(exact, original);
        assert_eq!(
            render_many_json_bounded(&scans, None, original.body.len() - 1)
                .unwrap()
                .unwrap_err(),
            original.body.len()
        );
        let filtered = render_many(&scans, "json", Some("TCP_PORT_OPEN")).unwrap();
        assert_eq!(
            render_many_json_bounded(&scans, Some("TCP_PORT_OPEN"), filtered.body.len())
                .unwrap()
                .unwrap(),
            filtered
        );
    }

    #[test]
    fn bounded_text_multi_export_matches_spiderfoot_and_enforces_limit() {
        let (scan, results) = scan();
        let scans = [(&scan, &results), (&scan, &results)];
        for format in ["csv", "tsv"] {
            let original = render_many(&scans, format, None).unwrap();
            let exact = render_many_text_bounded(&scans, format, None, original.body.len())
                .unwrap()
                .unwrap();
            assert_eq!(exact, original);
            assert!(
                render_many_text_bounded(&scans, format, None, original.body.len() - 1)
                    .unwrap()
                    .is_err()
            );
        }
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
            text(&csv),
            "Rule Name,Correlation,Risk,Description,Rule,Origin,Elements\r\nDatabase server exposed to the Internet,Database server exposed to the Internet: 1.1.1.1:3306,HIGH,\"A database, \"\"open\"\".\",database_exposed,spiderfoot,e1 e2\r\n"
        );
        assert!(csv.filename.ends_with("-Huntsman-correlations.csv"));
        let json = render_correlations(&scan, &results, "json").unwrap();
        let rows: serde_json::Value = serde_json::from_slice(&json.body).unwrap();
        assert_eq!(rows[0]["logic"], "id: database_exposed");
        assert!(render_correlations(&scan, &results, "gexf").is_err());
        // A workbook has a sheet per rule, as Spiderfoot's has, the rule name its title.
        let book = render_correlations(&scan, &results, "XLSX").unwrap();
        assert_eq!(book.content_type, xlsx::CONTENT_TYPE);
        assert!(book.filename.ends_with("-Huntsman-correlations.xlsx"));
        assert_eq!(sheet_names(&book.body), ["Database server exposed to the"]);
        assert_eq!(
            cells(&part(&book.body, "xl/worksheets/sheet1.xml")),
            [
                vec![
                    "Correlation",
                    "Risk",
                    "Description",
                    "Rule",
                    "Origin",
                    "Elements"
                ],
                vec![
                    "Database server exposed to the Internet: 1.1.1.1:3306",
                    "HIGH",
                    "A database, \"open\".",
                    "database_exposed",
                    "spiderfoot",
                    "e1 e2",
                ],
            ]
        );
    }

    #[test]
    fn csv_has_spiderfoots_columns_and_every_element_but_the_root() {
        let (record, results) = scan();
        let export = render(&record, &results, "csv", None).unwrap();
        let body = text(&export);
        let lines: Vec<&str> = body.lines().collect();
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
        let body = text(&export);
        let lines: Vec<&str> = body.lines().collect();
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
        let rows: Vec<Value> = serde_json::from_slice(&export.body).unwrap();
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
    fn json_multi_scan_rows_preserve_scan_identity_even_when_names_and_elements_repeat() {
        let (first, results) = scan();
        let mut second = first.clone();
        second.id = "fedcba9876543210".into();
        // Equivalent element IDs and matching scan names must not erase scan provenance.
        let single = json_rows(&[(&first, &results)], None);
        let both = json_rows(&[(&first, &results), (&second, &results)], None);
        let count = single.as_array().expect("single rows").len();
        let rows = both.as_array().expect("multi rows");
        assert!(count > 0);
        assert_eq!(rows.len(), 2 * count);
        for index in 0..count {
            assert_eq!(rows[index]["scan_id"].as_str(), Some(first.id.as_str()));
            assert_eq!(
                rows[index + count]["scan_id"].as_str(),
                Some(second.id.as_str())
            );
            assert_eq!(rows[index]["id"], rows[index + count]["id"]);
            assert_eq!(rows[index]["scan_name"], rows[index + count]["scan_name"]);
            assert_eq!(
                rows[index]["scan_target"],
                rows[index + count]["scan_target"]
            );
        }
    }

    #[test]
    fn gexf_is_well_formed_with_a_node_per_element_and_an_edge_per_source() {
        let (mut record, results) = scan();
        record.name = "a<b & \"c\"".into();
        let body = text(&render(&record, &results, "gexf", None).unwrap());
        assert_eq!(body.matches("<node ").count(), results.elements.len());
        assert_eq!(body.matches("<edge ").count(), results.elements.len() - 1);
        assert!(body.contains("value=\"TCP_PORT_OPEN\""));
        assert!(
            body.contains("<description>a&lt;b &amp; &quot;c&quot; (example.com)</description>")
        );
        assert!(render(&record, &results, "pdf", None).is_err());
    }

    #[test]
    fn a_workbook_has_a_sheet_per_type_with_every_value_unguarded() {
        let (record, results) = scan();
        let export = render(&record, &results, "excel", None).unwrap();
        assert_eq!(export.filename, "my_scan_1-Huntsman.xlsx");
        assert_eq!(export.content_type, xlsx::CONTENT_TYPE);
        let names = sheet_names(&export.body);
        let mut types: Vec<&str> = results
            .elements
            .iter()
            .map(|element| element.kind.as_str())
            .filter(|&kind| kind != "ROOT")
            .collect();
        types.sort_unstable();
        types.dedup();
        assert_eq!(names, types, "a sheet per type, in name order");
        let at = names
            .iter()
            .position(|name| name == "INTERNET_NAME")
            .unwrap()
            + 1;
        let sheet = cells(&part(&export.body, &format!("xl/worksheets/sheet{at}.xml")));
        assert_eq!(sheet[0], ["Updated", "Module", "Source", "F/P", "Data"]);
        assert!(sheet.contains(&vec![
            "2023-11-14 22:13:20".to_owned(),
            "crtsh".into(),
            "example.com".into(),
            "0".into(),
            "www.example.com".into(),
        ]));
        // A cell is text, so the data is kept as it is, with no guard.
        assert!(sheet.iter().any(|row| row[4] == "=cmd.example.com"));
        let ports = render(&record, &results, "xlsx", Some("TCP_PORT_OPEN")).unwrap();
        assert_eq!(sheet_names(&ports.body), ["TCP_PORT_OPEN"]);
    }

    #[test]
    fn several_scans_export_together_with_the_scan_name_first() {
        let (record, results) = scan();
        let mut other = record.clone();
        other.name = "second".into();
        let both = [(&record, &results), (&other, &results)];
        let csv = render_many(&both, "csv", Some("TCP_PORT_OPEN")).unwrap();
        assert_eq!(csv.filename, "Huntsman.csv");
        let body = text(&csv);
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines[0], "Scan Name,Updated,Type,Module,Source,F/P,Data");
        assert_eq!(lines.len(), 5);
        assert!(lines[1].starts_with("my scan/1,2023-11-14 22:13:20,TCP_PORT_OPEN,crtsh,"));
        assert!(lines[4].starts_with("second,"));
        let book = render_many(&both, "xlsx", None).unwrap();
        let first = cells(&part(&book.body, "xl/worksheets/sheet1.xml"));
        assert_eq!(
            first[0],
            ["Scan Name", "Updated", "Module", "Source", "F/P", "Data"]
        );
        let json = render_many(&both[..1], "json", None).unwrap();
        assert_eq!(json.filename, "my_scan_1-Huntsman.json");
        assert!(render_many(&both, "gexf", None).is_err());
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

    #[test]
    fn a_cell_cannot_drive_the_terminal_in_csv_or_tsv() {
        // ESC, a C1 CSI, a right-to-left override, a carriage return and BEL, as a remote record
        // could send them.
        let hostile = "x\u{1b}[2J\u{9b}31m\u{202e}ab\rc\u{7}";
        let written = "x\\u{1b}[2J\\u{9b}31m\\u{202e}ab\\rc\\u{7}";
        assert_eq!(csv_cell(hostile), written);
        assert_eq!(tsv_cell(hostile), written);
        assert!(!csv_cell(hostile).chars().any(crate::textnorm::is_escaped));
        assert!(!tsv_cell(hostile).chars().any(crate::textnorm::is_escaped));
        // Ordinary multi-line text keeps its line feed inside quotes, and a tab in TSV stays `\t`.
        assert_eq!(csv_cell("line 1\nline 2"), "\"line 1\nline 2\"");
        assert_eq!(tsv_cell("a\tb"), "a\\tb");
    }

    /// The report is one document a client can open safely: everything a source returned is
    /// escaped, nothing is fetched or run, each finding names its source and time, the most
    /// confident first, and what the analyst marked false is left out but counted.
    #[test]
    fn the_html_report_escapes_every_source_value_and_sets_aside_what_the_analyst_marked() {
        let (scan, mut results) = scan();
        let mut hostile = Evidence::new(
            EvidenceProvenance::for_scan("crtsh", "s"),
            "<script>alert(1)</script> seen",
        )
        .with_attr("note", "\"><img src=x onerror=alert(2)>");
        hostile.provenance.recorded_at_unix = 1_700_000_000;
        let strong = Entity::builder(EntityKind::Email, "ops@example.com", 0.95, "s")
            .evidence(hostile)
            .build();
        let weak = Entity::builder(EntityKind::Email, "maybe@example.com", 0.40, "s").build();
        results.entities.push(weak.clone());
        results.entities.push(strong);
        // The analyst marked every element of the =cmd host false.
        let marked = results.entities[1].uid.clone();
        for element in results
            .elements
            .iter_mut()
            .filter(|element| element.entity.as_deref() == Some(marked.as_str()))
        {
            element.fp = true;
        }

        let export = render(&scan, &results, "HTML", None).unwrap();
        assert_eq!(export.content_type, "text/html; charset=utf-8");
        assert!(
            std::path::Path::new(&export.filename)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("html")),
            "{}",
            export.filename
        );
        let html = text(&export);
        assert!(html.starts_with("<!doctype html>"));
        for forbidden in [
            "<script",
            "<img",
            "onerror=alert(2)>",
            "src=\"http",
            "href=\"http",
            "@import",
        ] {
            assert!(!html.contains(forbidden), "{forbidden} in the report");
        }
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; seen"));
        assert!(html.contains("&quot;&gt;&lt;img src=x onerror=alert(2)&gt;"));
        assert!(html.contains("<b>crtsh</b>, 2023-11-14T22:13:20Z:"));
        let strong_at = html.find("ops@example.com").expect("the confident finding");
        let weak_at = html.find("maybe@example.com").expect("the weak finding");
        assert!(strong_at < weak_at, "most confident first within a kind");
        assert!(
            !html.contains("=cmd.example.com"),
            "a finding marked false is left out"
        );
        assert!(
            html.contains("; 1 set aside by the analyst as false positive;"),
            "{html}"
        );
        assert!(html.contains("How to read this report"));
    }

    #[test]
    fn the_html_report_names_its_gaps_and_the_command_that_runs_it_again() {
        use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
        let (mut scan, mut results) = scan();
        results.outcomes = vec![
            SourceExecutionOutcome::success("crtsh", 0, 2),
            SourceExecutionOutcome::failed(
                "hibp",
                0,
                SourceOutcomeKind::RateLimited,
                Some(429),
                "<retry later>",
            ),
        ];
        let html = text(&render(&scan, &results, "html", None).unwrap());
        assert!(html.contains("<h2>Gaps and unknowns</h2>"), "{html}");
        assert!(
            html.contains("<li><b>hibp</b>: rate_limited, &lt;retry later&gt;</li>"),
            "{html}"
        );
        let gaps = &html[html.find("<h2>Gaps").unwrap()..html.find("<h2>Reproducibility").unwrap()];
        assert!(
            !gaps.contains("crtsh"),
            "a source that answered is no gap: {gaps}"
        );
        assert!(
            html.contains("huntsman-recon scans rerun 0123456789abcdef"),
            "{html}"
        );

        // Every option is repeated, and a target the shell would split or expand is quoted.
        scan.target = "o'brien $(id)".to_owned();
        scan.kind = "username".to_owned();
        scan.options = ScanOptions {
            usecase: "passive".to_owned(),
            modules: vec!["github".to_owned(), "sfp_whois".to_owned()],
            types: vec!["USERNAME".to_owned()],
            depth: 2,
        };
        results.outcomes.truncate(1);
        let html = text(&render(&scan, &results, "html", None).unwrap());
        assert!(html.contains("Every source consulted answered."), "{html}");
        let command = "huntsman-recon scans run 'o'\\''brien $(id)' -k username -u passive \
-t USERNAME -m github,sfp_whois --depth 2";
        assert!(
            html.contains(&format!("<code>{}</code>", escape_xml(command))),
            "{html}"
        );
        assert!(html.contains("<th>Depth</th><td>2 hops past the target</td>"));
        assert!(html.contains("<th>Modules asked</th><td>github, sfp_whois</td>"));
        // A southern-hemisphere point needs no quoting: `scans run` reads its dash as a value.
        scan.target = "-33.86,151.21".to_owned();
        scan.kind = "network".to_owned();
        scan.options = ScanOptions::default();
        let html = text(&render(&scan, &results, "html", None).unwrap());
        assert!(html.contains("<code>huntsman-recon scans run -33.86,151.21 -k network</code>"));
    }
}
