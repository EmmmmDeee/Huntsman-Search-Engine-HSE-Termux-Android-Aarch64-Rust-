//! `SpiderFoot` 4.0's `sf.py` command line over Huntsman's saved scans.
//!
//! This module parses `sf.py`'s flags, detects a target's Spiderfoot type as `sf.py` does, lists
//! the modules and types, and prints a saved scan's data elements in `sf.py`'s tab, CSV and JSON
//! rows. The scan itself runs in the binary through the saved-scan service that `scans run` and
//! `serve` use, so `sf -s` runs every lookup a scan of the same target runs and keeps the scan, as
//! `sf.py` keeps its scans, and `sf -C ID` runs the correlation rules again over a saved one.

use std::collections::HashMap;
use std::fmt::Write as _;

use serde::Serialize;

use crate::error::Error;
use crate::module::reachable_modules;
use crate::scan_route::ScanKind;
use crate::sf_elements::DataElement;
use crate::sf_types;
use crate::textnorm::{escape_controls, is_escaped};

pub const SF_USAGE: &str = "usage: huntsman-recon sf [-M|-T|-V] | -C SCAN_ID | -s TARGET [-u all|footprint|investigate|passive] [-o tab|csv|json] [-t TYPE[,TYPE...]] [-r] [-q]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfMode {
    Scan,
    ListModules,
    ListTypes,
    Version,
    /// `-C ID`: run the correlation rules again over a saved scan.
    Correlate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfArgs {
    pub target: Option<String>,
    pub use_case: String,
    pub format: String,
    pub types: Vec<String>,
    pub include_source: bool,
    pub quiet: bool,
    pub mode: SfMode,
    /// The saved scan `-C` correlates.
    pub scan_id: Option<String>,
}

impl Default for SfArgs {
    fn default() -> Self {
        Self {
            target: None,
            use_case: "all".into(),
            format: "tab".into(),
            types: Vec::new(),
            include_source: false,
            quiet: false,
            mode: SfMode::Scan,
            scan_id: None,
        }
    }
}

impl SfArgs {
    /// Parse the supported SpiderFoot-compatible flag subset.
    ///
    /// # Errors
    /// Unknown flags, missing values, incompatible listing/scan modes, invalid
    /// use cases, output formats, or event types.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-s" | "--target" => {
                    parsed.target = Some(value(args, index, "-s/--target")?.to_owned());
                    index += 2;
                }
                "-u" | "--use-case" => {
                    parsed.use_case = value(args, index, "-u/--use-case")?.to_ascii_lowercase();
                    index += 2;
                }
                "-o" | "--output" | "--format" => {
                    parsed.format = value(args, index, "-o/--output")?.to_ascii_lowercase();
                    index += 2;
                }
                "-t" | "-F" | "--types" => {
                    parsed.types.extend(
                        value(args, index, "-t/-F")?
                            .split(',')
                            .filter(|item| !item.is_empty())
                            .map(str::to_ascii_uppercase),
                    );
                    index += 2;
                }
                "-r" | "--include-source" => {
                    parsed.include_source = true;
                    index += 1;
                }
                "-q" | "--quiet" => {
                    parsed.quiet = true;
                    index += 1;
                }
                "-M" | "--list-modules" => {
                    set_mode(&mut parsed, SfMode::ListModules)?;
                    index += 1;
                }
                "-T" | "--list-types" => {
                    set_mode(&mut parsed, SfMode::ListTypes)?;
                    index += 1;
                }
                "-V" | "--sf-version" => {
                    set_mode(&mut parsed, SfMode::Version)?;
                    index += 1;
                }
                "-C" | "--correlate" => {
                    parsed.scan_id = Some(value(args, index, "-C/--correlate")?.to_owned());
                    set_mode(&mut parsed, SfMode::Correlate)?;
                    index += 2;
                }
                flag if flag.starts_with('-') => {
                    return Err(Error::Invalid(format!(
                        "unsupported sf option {flag}; supported subset: {SF_USAGE}"
                    )));
                }
                value => {
                    return Err(Error::Invalid(format!(
                        "unexpected sf argument {value:?}; target must follow -s"
                    )));
                }
            }
        }

        validate_use_case(&parsed.use_case)?;
        if !matches!(parsed.format.as_str(), "tab" | "csv" | "json") {
            return Err(Error::Invalid(format!(
                "invalid sf output format {:?}; choose tab, csv, or json",
                parsed.format
            )));
        }
        for kind in &parsed.types {
            if sf_types::find(kind).is_none() {
                return Err(Error::Invalid(format!("unknown sf event type {kind}")));
            }
        }

        if parsed.mode != SfMode::Scan && parsed.target.is_some() {
            return Err(Error::Invalid(
                "sf -M, -T, -V and -C do not accept -s".into(),
            ));
        }
        if parsed.mode == SfMode::Scan && parsed.target.is_none() {
            return Err(Error::Invalid(
                "sf needs -s TARGET, -C SCAN_ID, -M, -T, or -V".into(),
            ));
        }
        Ok(parsed)
    }
}

fn set_mode(args: &mut SfArgs, mode: SfMode) -> Result<(), Error> {
    if args.mode != SfMode::Scan {
        return Err(Error::Invalid(
            "sf accepts only one of -M, -T, -V, or -C at a time".into(),
        ));
    }
    args.mode = mode;
    Ok(())
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, Error> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with('-') || *value == "-")
        .ok_or_else(|| Error::Invalid(format!("{flag} needs a value")))
}

fn validate_use_case(value: &str) -> Result<(), Error> {
    if matches!(value, "all" | "footprint" | "investigate" | "passive") {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "argument -u: invalid choice: '{value}' (choose from 'all', 'footprint', 'investigate', 'passive')"
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfAction {
    Text(String),
    Scan(SfScan),
    /// Run the correlation rules again over this saved scan.
    Correlate(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfScan {
    pub target: String,
    pub target_type: &'static str,
    /// The lookup a saved scan of the target runs.
    pub kind: ScanKind,
    pub use_case: String,
    pub format: String,
    pub types: Vec<String>,
    pub include_source: bool,
    pub quiet: bool,
}

/// Resolve parsed flags to a metadata action or one supported scan.
pub fn action(args: &SfArgs) -> Result<SfAction, Error> {
    match args.mode {
        SfMode::Version => {
            return Ok(SfAction::Text(format!(
                "Huntsman Recon {} — SpiderFoot 4.0-compatible subset.\n",
                env!("CARGO_PKG_VERSION")
            )));
        }
        SfMode::ListModules => return Ok(SfAction::Text(module_listing(args.quiet))),
        SfMode::ListTypes => return Ok(SfAction::Text(type_listing(args.quiet))),
        SfMode::Correlate => {
            return Ok(SfAction::Correlate(
                args.scan_id.clone().unwrap_or_default(),
            ));
        }
        SfMode::Scan => {}
    }
    let target = args.target.as_deref().unwrap_or_default();
    let (target_type, normalized) = sf_target_type(target).ok_or_else(|| {
        Error::Invalid(format!("sf: unable to detect target type for {target:?}"))
    })?;
    let kind = scan_kind(target_type).ok_or_else(|| {
        Error::Invalid(format!(
            "sf target type {target_type} is detected but its scan path is not available yet; sf scans a domain, IP address, email address, phone number, username or name"
        ))
    })?;
    Ok(SfAction::Scan(SfScan {
        target: normalized,
        target_type,
        kind,
        use_case: args.use_case.clone(),
        format: args.format.clone(),
        types: args.types.clone(),
        include_source: args.include_source,
        quiet: args.quiet,
    }))
}

/// The lookup a saved scan of a target of this Spiderfoot type runs, or `None` for a type no
/// lookup takes yet (a netblock or an AS number).
#[must_use]
pub fn scan_kind(target_type: &str) -> Option<ScanKind> {
    match target_type {
        "INTERNET_NAME" => Some(ScanKind::Domain),
        "IP_ADDRESS" | "IPV6_ADDRESS" => Some(ScanKind::Ip),
        "EMAILADDR" => Some(ScanKind::Email),
        "PHONE_NUMBER" => Some(ScanKind::Phone),
        "USERNAME" => Some(ScanKind::Username),
        "HUMAN_NAME" => Some(ScanKind::People),
        _ => None,
    }
}

#[must_use]
pub fn module_listing(quiet: bool) -> String {
    let mut out = String::new();
    if !quiet {
        out.push_str("[INFO] Modules available:\n");
    }
    for module in reachable_modules() {
        let cases = if module.network {
            "Footprint, Investigate"
        } else {
            "Footprint, Investigate, Passive"
        };
        writeln!(
            &mut out,
            "{:25} {} [{}]",
            module.name, module.description, cases
        )
        .expect("writing to String cannot fail");
    }
    out
}

#[must_use]
pub fn type_listing(quiet: bool) -> String {
    let mut out = String::new();
    if !quiet {
        out.push_str("[INFO] Types available:\n");
    }
    for kind in sf_types::all() {
        match sf_types::base_kind(kind.code) {
            Some(entity) => writeln!(
                &mut out,
                "{:45} {} (hse: {entity})",
                kind.code, kind.description
            ),
            None => writeln!(&mut out, "{:45} {}", kind.code, kind.description),
        }
        .expect("writing to String cannot fail");
    }
    out
}

/// A saved scan's data elements as `sf.py` prints a scan's events: one row per element but the
/// root, only the `-t` types when some were given, each with the data of the element it was
/// found from.
///
/// # Errors
/// [`Error::Invalid`] for an output format other than tab, csv or json, or JSON that cannot be
/// written.
pub fn render(scan: &SfScan, elements: &[DataElement]) -> Result<String, Error> {
    let data: HashMap<&str, &str> = elements
        .iter()
        .map(|element| (element.id.as_str(), element.data.as_str()))
        .collect();
    let rows: Vec<Row> = elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .filter(|element| {
            scan.types.is_empty()
                || scan
                    .types
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(&element.kind))
        })
        .map(|element| Row::from_element(element, &data))
        .collect();
    render_rows(&rows, &scan.format, scan.include_source)
}

/// One printed row: the saved scan's data element, in Spiderfoot's CLI columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Row {
    source: String,
    event_type: String,
    type_description: String,
    source_data: String,
    data: String,
}

impl Row {
    /// `data` maps each element's id to its data, for the source column.
    fn from_element(element: &DataElement, data: &HashMap<&str, &str>) -> Self {
        Self {
            source: element.module.clone(),
            event_type: element.kind.clone(),
            type_description: sf_types::describe(&element.kind).to_owned(),
            source_data: element
                .source
                .as_deref()
                .and_then(|source| data.get(source))
                .map(|&source| source.to_owned())
                .unwrap_or_default(),
            data: element.data.clone(),
        }
    }
}

fn render_rows(rows: &[Row], format: &str, include_source: bool) -> Result<String, Error> {
    match format {
        "tab" => Ok(render_tab(rows, include_source)),
        "csv" => Ok(render_csv(rows, include_source)),
        "json" => serde_json::to_string_pretty(rows)
            .map(|body| format!("{}\n", escape_unsafe_in_json(&body)))
            .map_err(|error| Error::Invalid(format!("sf json: {error}"))),
        _ => Err(Error::Invalid(format!(
            "invalid sf output format {format:?}; choose tab, csv, or json"
        ))),
    }
}

/// JSON escapes the control characters below U+0020 but leaves DEL, the C1 controls (U+0080 to
/// U+009F), the line and paragraph separators and the bidirectional controls as they are, and a
/// terminal or a reader can act on those. Written as `\uXXXX` the JSON reads the same. They can only
/// occur inside a string, since the JSON text around them is ASCII.
fn escape_unsafe_in_json(json: &str) -> String {
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        // Below U+007F, JSON has escaped what needs it inside strings, and the rest is layout.
        if c >= '\u{7f}' && is_escaped(c) {
            let _ = write!(out, "\\u{:04x}", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

fn render_tab(rows: &[Row], include_source: bool) -> String {
    let mut out = String::new();
    if include_source {
        out.push_str("Source\tType\tSource Data\tData\n");
    } else {
        out.push_str("Source\tType\tData\n");
    }
    for row in rows {
        if include_source {
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}",
                one_line(&row.source),
                one_line(&row.type_description),
                one_line(&row.source_data),
                one_line(&row.data)
            )
            .expect("writing to String cannot fail");
        } else {
            writeln!(
                &mut out,
                "{}\t{}\t{}",
                one_line(&row.source),
                one_line(&row.type_description),
                one_line(&row.data)
            )
            .expect("writing to String cannot fail");
        }
    }
    out
}

fn render_csv(rows: &[Row], include_source: bool) -> String {
    let mut out = String::new();
    if include_source {
        out.push_str("Source,Type,Source Data,Data\n");
    } else {
        out.push_str("Source,Type,Data\n");
    }
    for row in rows {
        let fields: Vec<String> = if include_source {
            vec![
                csv_cell(&row.source),
                csv_cell(&row.type_description),
                csv_cell(&row.source_data),
                csv_cell(&row.data),
            ]
        } else {
            vec![
                csv_cell(&row.source),
                csv_cell(&row.type_description),
                csv_cell(&row.data),
            ]
        };
        out.push_str(&fields.join(","));
        out.push('\n');
    }
    out
}

/// One cell on one line: a line break or tab becomes a space, so the cell cannot start a row or a
/// column, and any other control character is written escaped, so it cannot drive the terminal.
fn one_line(value: &str) -> String {
    escape_controls(&value.replace(['\r', '\n', '\t'], " "))
}

fn csv_cell(value: &str) -> String {
    let one_line = one_line(value);
    let guarded = if one_line
        .as_bytes()
        .first()
        .is_some_and(|first| matches!(first, b'=' | b'+' | b'-' | b'@'))
    {
        format!("'{one_line}")
    } else {
        one_line
    };
    if guarded
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[must_use]
pub fn sf_target_type(raw: &str) -> Option<(&'static str, String)> {
    let mut target = raw.trim().to_owned();
    if target.is_empty() {
        return None;
    }
    if target.contains(char::is_whitespace)
        || (!target.contains('.')
            && !target.contains(':')
            && !target.starts_with('+')
            && !target.contains('"'))
    {
        target = format!("\"{target}\"");
    }
    let value = target.as_str();
    let lower = value.to_ascii_lowercase();

    let code = if is_ipv4(value) {
        "IP_ADDRESS"
    } else if value
        .split_once('/')
        .is_some_and(|(ip, bits)| is_ipv4(ip) && valid_prefix(bits, 32))
    {
        "NETBLOCK_OWNER"
    } else if value.contains('@') {
        "EMAILADDR"
    } else if value.strip_prefix('+').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        "PHONE_NUMBER"
    } else if quoted(value) && value[1..value.len() - 1].contains(char::is_whitespace) {
        "HUMAN_NAME"
    } else if quoted(value) {
        "USERNAME"
    } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        "BGP_AS_OWNER"
    } else if is_ipv6(value) {
        "IPV6_ADDRESS"
    } else if value
        .split_once('/')
        .is_some_and(|(ip, bits)| is_ipv6(ip) && valid_prefix(bits, 128))
    {
        "NETBLOCKV6_OWNER"
    } else if is_internet_name(&lower) {
        "INTERNET_NAME"
    } else {
        return None;
    };
    Some((code, value.trim_matches('"').to_owned()))
}

fn quoted(value: &str) -> bool {
    value.len() > 2 && value.starts_with('"') && value.ends_with('"')
}

fn is_ipv4(value: &str) -> bool {
    value.parse::<std::net::Ipv4Addr>().is_ok()
}

fn is_ipv6(value: &str) -> bool {
    value.parse::<std::net::Ipv6Addr>().is_ok()
}

fn valid_prefix(value: &str, max: u8) -> bool {
    value.parse::<u8>().is_ok_and(|prefix| prefix <= max)
}

fn is_internet_name(value: &str) -> bool {
    let labels: Vec<&str> = value.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone_cli::{self, PhoneRun};
    use crate::scan_route::canonical_selector;
    use crate::scan_service::target_type;
    use crate::sf_elements::{Target, elements};
    use crate::test_support::unexpected_controls;

    #[test]
    fn target_detection_matches_rebuilt_legacy_shapes() {
        assert_eq!(
            sf_target_type("jdoe"),
            Some(("USERNAME", "jdoe".to_owned()))
        );
        assert_eq!(
            sf_target_type("Jane Doe"),
            Some(("HUMAN_NAME", "Jane Doe".to_owned()))
        );
        assert_eq!(
            sf_target_type("jane@example.org"),
            Some(("EMAILADDR", "jane@example.org".to_owned()))
        );
        assert_eq!(
            sf_target_type("+61412345678"),
            Some(("PHONE_NUMBER", "+61412345678".to_owned()))
        );
        assert_eq!(
            sf_target_type("example.org"),
            Some(("INTERNET_NAME", "example.org".to_owned()))
        );
    }

    #[test]
    fn ip_targets_follow_std_address_grammar() {
        for bogus in ["dead:beef", "::::", "cafe:babe:face", "a:b"] {
            assert_ne!(
                sf_target_type(bogus).map(|(code, _)| code),
                Some("IPV6_ADDRESS"),
                "{bogus}"
            );
        }
        for (raw, code) in [
            ("2001:db8::1", "IPV6_ADDRESS"),
            ("::1", "IPV6_ADDRESS"),
            ("::ffff:192.0.2.1", "IPV6_ADDRESS"),
            ("2001:db8::/32", "NETBLOCKV6_OWNER"),
            ("::ffff:192.0.2.0/120", "NETBLOCKV6_OWNER"),
            ("192.0.2.1", "IP_ADDRESS"),
            ("192.0.2.0/24", "NETBLOCK_OWNER"),
        ] {
            assert_eq!(sf_target_type(raw).map(|(c, _)| c), Some(code), "{raw}");
        }
        assert_ne!(
            sf_target_type("2001:db8::/129").map(|(c, _)| c),
            Some("NETBLOCKV6_OWNER")
        );
    }

    #[test]
    fn metadata_modes_are_offline_and_complete() {
        let modules = module_listing(true);
        assert!(modules.contains("phone_intl"));
        assert!(modules.contains("github_user"));
        let types = type_listing(true);
        assert!(types.contains("EMAILADDR"));
        assert!(types.contains("HUMAN_NAME"));
        assert!(types.contains("TCP_PORT_OPEN"));
        assert_eq!(types.lines().count(), sf_types::all().count());
    }

    fn args(words: &[&str]) -> Result<SfArgs, Error> {
        SfArgs::parse(
            &words
                .iter()
                .map(|word| (*word).to_owned())
                .collect::<Vec<_>>(),
        )
    }

    /// `sf -s` saves a scan routed to the lookup `scans run -k` names for the target, and the
    /// saved scan's target type is the one `sf.py` detected.
    #[test]
    fn every_scannable_target_type_routes_to_the_lookup_of_the_same_type() {
        for raw in [
            "example.org",
            "1.1.1.1",
            "2606:4700:4700::1111",
            "jane@example.org",
            "+61412345678",
            "jdoe",
            "Jane Doe",
        ] {
            let Ok(SfAction::Scan(scan)) = action(&args(&["-s", raw]).unwrap()) else {
                panic!("{raw} is not a scan");
            };
            let canonical = canonical_selector(scan.kind, &scan.target)
                .unwrap_or_else(|| panic!("{raw}: no canonical {:?}", scan.kind));
            assert_eq!(
                target_type(scan.kind, &canonical),
                scan.target_type,
                "{raw}"
            );
        }
        for raw in ["192.0.2.0/24", "2001:db8::/32"] {
            let error = action(&args(&["-s", raw]).unwrap()).unwrap_err();
            assert!(
                error.to_string().contains("not available yet"),
                "{raw}: {error}"
            );
        }
    }

    #[test]
    fn dash_c_correlates_one_saved_scan_and_takes_no_target() {
        assert_eq!(
            action(&args(&["-C", "scan-1"]).unwrap()).unwrap(),
            SfAction::Correlate("scan-1".into())
        );
        assert!(args(&["-C"]).is_err());
        assert!(args(&["-C", "scan-1", "-s", "example.org"]).is_err());
        assert!(args(&["-C", "scan-1", "-M"]).is_err());
    }

    fn phone_scan(format: &str, types: &[&str]) -> SfScan {
        SfScan {
            target: "+61412345678".into(),
            target_type: "PHONE_NUMBER",
            kind: ScanKind::Phone,
            use_case: "passive".into(),
            format: format.into(),
            types: types.iter().map(|kind| (*kind).to_owned()).collect(),
            include_source: true,
            quiet: true,
        }
    }

    /// The rows are a saved scan's elements, the root left out, each with the data of the
    /// element it was found from.
    #[test]
    fn a_saved_scans_elements_print_as_spiderfoot_rows() {
        let PhoneRun::Printed { report, .. } = phone_cli::run("+61412345678", 1) else {
            panic!("the offline phone lookup gave no report");
        };
        let target = Target {
            value: "+61412345678",
            kind: "PHONE_NUMBER",
        };
        let saved = elements(target, &report.entities, 1);
        assert!(saved.iter().any(|element| element.kind == "ROOT"));

        let rendered = render(&phone_scan("json", &[]), &saved).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let rows = value.as_array().unwrap();
        assert_eq!(rows.len(), saved.len() - 1);
        assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
        assert_eq!(value[0]["data"], "+61412345678");
        assert_eq!(value[0]["source_data"], "+61412345678");
        assert!(rows.iter().all(|row| row["event_type"] != "ROOT"));

        let only = render(&phone_scan("json", &["phone_number"]), &saved).unwrap();
        let only: serde_json::Value = serde_json::from_str(&only).unwrap();
        assert_eq!(only.as_array().unwrap().len(), 1, "{only}");
        assert!(render(&phone_scan("xml", &[]), &saved).is_err());
    }

    #[test]
    fn csv_rows_quote_and_guard_special_cells() {
        let rows = [Row {
            source: "=source".into(),
            event_type: "EMAILADDR".into(),
            type_description: "Email Address".into(),
            source_data: "a,b".into(),
            data: "jane@example.org".into(),
        }];
        let rendered = render_csv(&rows, true);
        assert!(rendered.contains("'=source"));
        assert!(rendered.contains("\"a,b\""));
    }

    #[test]
    fn a_cell_cannot_drive_the_terminal_in_any_format() {
        // A profile name the target's own page chose.
        let hostile = "Jane\u{1b}]0;x\u{7}\u{9b}2J\u{7f}\nforged\tcolumn\u{2028}";
        let rows = [Row {
            source: hostile.into(),
            event_type: "HUMAN_NAME".into(),
            type_description: "Human Name".into(),
            source_data: hostile.into(),
            data: hostile.into(),
        }];
        for (format, rendered) in [
            ("tab", render_tab(&rows, true)),
            ("csv", render_csv(&rows, true)),
            ("json", render_rows(&rows, "json", true).unwrap()),
        ] {
            assert_eq!(
                unexpected_controls(&rendered, &['\n', '\t']).len(),
                0,
                "{format}: {rendered:?}"
            );
            assert!(!rendered.contains('\u{2028}'), "{format}");
        }
        // The tab and csv cells stay one line of fixed columns.
        let tab = render_tab(&rows, false);
        assert_eq!(tab.lines().count(), 2, "{tab:?}");
        assert_eq!(tab.lines().last().unwrap().matches('\t').count(), 2);
        assert!(tab.contains("Jane\\u{1b}]0;x\\u{7}\\u{9b}2J\\u{7f} forged column"));
        // JSON reads back the same text.
        let json: serde_json::Value =
            serde_json::from_str(&render_rows(&rows, "json", true).unwrap()).unwrap();
        assert_eq!(json[0]["data"], hostile);
    }
}
