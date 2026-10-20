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
use serde_json::Value;

use crate::error::Error;
use crate::module::reachable_modules;
use crate::scan_route::ScanKind;
use crate::sf_elements::DataElement;
use crate::sf_types;
use crate::textnorm::{escape_controls, is_escaped};

pub const SF_USAGE: &str = "usage: huntsman-recon sf [-M|-T|-V] | -l IP:PORT | -C SCAN_ID | -s TARGET [-u all|footprint|investigate|passive] [-m MODULE[,MODULE...]] [-t TYPE[,TYPE...] [-f] [-x]] [-F TYPE[,TYPE...]] [--depth N] [-o tab|csv|json] [-H] [-n] [-r] [-S LENGTH] [-D DELIMITER] [-d] [-q]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfMode {
    Scan,
    ListModules,
    ListTypes,
    Version,
    /// `-C ID`: run the correlation rules again over a saved scan.
    Correlate,
    /// `-l IP:PORT`: serve the web UI there.
    Listen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // one per sf.py switch, each independent
pub struct SfArgs {
    pub target: Option<String>,
    pub use_case: String,
    pub format: String,
    /// `-t`: the types the scan collects; its other elements are not kept.
    pub types: Vec<String>,
    /// `-F`: the types printed; the scan keeps the rest.
    pub show: Vec<String>,
    /// `-f`: print only the `-t` types.
    pub only_requested: bool,
    /// `-x`: only lookups that take the target itself, printing only the `-t` types.
    pub strict: bool,
    /// `--depth N`: how many hops past the target the scan follows, as `scans run --depth`.
    pub depth: u32,
    /// `-m`: the only modules the scan asks, by Huntsman or Spiderfoot (`sfp_*`) name; empty
    /// asks every module the use case takes.
    pub modules: Vec<String>,
    pub include_source: bool,
    /// `-H`: no header line.
    pub no_headers: bool,
    /// `-n`: line breaks in data become spaces.
    pub strip_newlines: bool,
    /// `-S`: at most this many characters of each value; `None` prints them whole.
    pub max_length: Option<usize>,
    /// `-D`: the CSV delimiter.
    pub delimiter: Option<String>,
    /// `-d`: print the scan's log to stderr when it ends.
    pub debug: bool,
    pub quiet: bool,
    pub mode: SfMode,
    /// The saved scan `-C` correlates.
    pub scan_id: Option<String>,
    /// The address `-l` serves on.
    pub listen: Option<String>,
}

impl Default for SfArgs {
    fn default() -> Self {
        Self {
            target: None,
            use_case: "all".into(),
            format: "tab".into(),
            types: Vec::new(),
            show: Vec::new(),
            only_requested: false,
            strict: false,
            depth: 0,
            modules: Vec::new(),
            include_source: false,
            no_headers: false,
            strip_newlines: false,
            max_length: None,
            delimiter: None,
            debug: false,
            quiet: false,
            mode: SfMode::Scan,
            scan_id: None,
            listen: None,
        }
    }
}

impl SfArgs {
    /// Parse `sf.py`'s flags.
    ///
    /// # Errors
    /// Unknown flags, missing or unusable values, and combinations `sf.py` refuses: more than one
    /// mode, `-s` with a mode, `-f` or `-x` without `-t`, and `-D` outside CSV.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            index += parsed.take(args, index)?;
        }
        parsed.validate()?;
        Ok(parsed)
    }

    /// Read the flag at `index`; returns how many arguments it used.
    fn take(&mut self, args: &[String], index: usize) -> Result<usize, Error> {
        let flag = args[index].as_str();
        match flag {
            "-s" | "--target" => self.target = Some(value(args, index, flag)?.to_owned()),
            "-u" | "--use-case" => self.use_case = value(args, index, flag)?.to_ascii_lowercase(),
            "-o" | "--output" | "--format" => {
                self.format = value(args, index, flag)?.to_ascii_lowercase();
            }
            "-t" | "--types" => self.types.extend(type_list(value(args, index, flag)?)),
            "-F" => self.show.extend(type_list(value(args, index, flag)?)),
            "-S" => self.max_length = Some(number(value(args, index, flag)?, flag)?),
            "-D" => self.delimiter = Some(value(args, index, flag)?.to_owned()),
            "--depth" => self.depth = number(value(args, index, flag)?, flag)?,
            "-m" => self.modules.extend(module_list(value(args, index, flag)?)),
            "-C" | "--correlate" => {
                self.scan_id = Some(value(args, index, flag)?.to_owned());
                self.set_mode(SfMode::Correlate)?;
            }
            "-l" | "--listen" => {
                self.listen = Some(value(args, index, flag)?.to_owned());
                self.set_mode(SfMode::Listen)?;
            }
            _ => return self.switch(flag).map(|()| 1),
        }
        Ok(2)
    }

    /// A flag that takes no value.
    fn switch(&mut self, flag: &str) -> Result<(), Error> {
        match flag {
            "-r" | "--include-source" => self.include_source = true,
            "-q" | "--quiet" => self.quiet = true,
            "-H" => self.no_headers = true,
            "-n" => self.strip_newlines = true,
            "-f" => self.only_requested = true,
            "-x" => self.strict = true,
            "-d" | "--debug" => self.debug = true,
            "-M" | "--list-modules" | "--modules" => self.set_mode(SfMode::ListModules)?,
            "-T" | "--list-types" => self.set_mode(SfMode::ListTypes)?,
            "-V" | "--sf-version" | "--version" => self.set_mode(SfMode::Version)?,
            flag if flag.starts_with('-') => {
                return Err(Error::Invalid(format!(
                    "unsupported sf option {flag}; {SF_USAGE}"
                )));
            }
            value => {
                return Err(Error::Invalid(format!(
                    "unexpected sf argument {value:?}; target must follow -s"
                )));
            }
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), Error> {
        validate_use_case(&self.use_case)?;
        if !matches!(self.format.as_str(), "tab" | "csv" | "json") {
            return Err(Error::Invalid(format!(
                "invalid sf output format {:?}; choose tab, csv, or json",
                self.format
            )));
        }
        if let Some(kind) = self
            .types
            .iter()
            .chain(&self.show)
            .find(|kind| sf_types::find(kind).is_none())
        {
            return Err(Error::Invalid(format!("unknown sf event type {kind}")));
        }
        if self.mode != SfMode::Scan && self.target.is_some() {
            return Err(Error::Invalid(
                "sf -M, -T, -V, -l and -C do not accept -s".into(),
            ));
        }
        if self.mode == SfMode::Scan && self.target.is_none() {
            return Err(Error::Invalid(
                "sf needs -s TARGET, -C SCAN_ID, -l IP:PORT, -M, -T, or -V".into(),
            ));
        }
        // `sf.py`'s own refusals: each of these would otherwise be quietly ignored.
        if (self.only_requested || self.strict) && self.types.is_empty() {
            return Err(Error::Invalid("sf -f and -x need -t TYPE[,TYPE...]".into()));
        }
        if self.strict && !self.modules.is_empty() {
            return Err(Error::Invalid(
                "sf -x picks the modules that take the target, so it takes no -m".into(),
            ));
        }
        if !self.modules.is_empty() {
            crate::module::selection(&self.modules)
                .map_err(|error| Error::Invalid(format!("sf -m: {error}")))?;
        }
        if self.strict && self.depth > 0 {
            return Err(Error::Invalid(
                "sf -x runs only the lookups that take the target, so it takes no --depth".into(),
            ));
        }
        if self.delimiter.is_some() && self.format != "csv" {
            return Err(Error::Invalid(
                "sf -D sets the CSV delimiter, so it needs -o csv".into(),
            ));
        }
        if self.delimiter.as_deref() == Some("") {
            return Err(Error::Invalid("sf -D needs a delimiter".into()));
        }
        Ok(())
    }

    fn set_mode(&mut self, mode: SfMode) -> Result<(), Error> {
        if self.mode != SfMode::Scan {
            return Err(Error::Invalid(
                "sf accepts only one of -M, -T, -V, -l, or -C at a time".into(),
            ));
        }
        self.mode = mode;
        Ok(())
    }
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, Error> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with('-') || *value == "-")
        .ok_or_else(|| Error::Invalid(format!("{flag} needs a value")))
}

fn type_list(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_uppercase)
}

fn module_list(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_lowercase)
}

fn number<T: std::str::FromStr>(value: &str, flag: &str) -> Result<T, Error> {
    value
        .parse()
        .map_err(|_| Error::Invalid(format!("{flag} needs a whole number, not {value:?}")))
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
    /// Serve the web UI on this address.
    Listen(String),
}

/// How a scan's rows are printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfOutput {
    pub format: String,
    /// The types printed; empty prints every element but the root.
    pub show: Vec<String>,
    pub include_source: bool,
    pub no_headers: bool,
    pub strip_newlines: bool,
    pub max_length: Option<usize>,
    pub delimiter: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfScan {
    pub target: String,
    pub target_type: &'static str,
    /// The lookup a saved scan of the target runs.
    pub kind: ScanKind,
    pub use_case: String,
    /// The types the saved scan keeps; empty keeps them all.
    pub types: Vec<String>,
    pub depth: u32,
    /// The only modules the saved scan asks; empty asks every one the use case takes.
    pub modules: Vec<String>,
    pub output: SfOutput,
    pub debug: bool,
    pub quiet: bool,
}

/// Resolve parsed flags to a metadata action or one supported scan.
///
/// # Errors
/// [`Error::Invalid`] for a target whose type cannot be detected or that no lookup takes yet.
pub fn action(args: &SfArgs) -> Result<SfAction, Error> {
    match args.mode {
        SfMode::Version => {
            return Ok(SfAction::Text(format!(
                "Huntsman Recon {}: SpiderFoot 4.0's sf.py over Huntsman's saved scans.\n",
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
        SfMode::Listen => return Ok(SfAction::Listen(args.listen.clone().unwrap_or_default())),
        SfMode::Scan => {}
    }
    let target = args.target.as_deref().unwrap_or_default();
    let (target_type, normalized) = sf_target_type(target).ok_or_else(|| {
        Error::Invalid(format!("sf: unable to detect target type for {target:?}"))
    })?;
    let kind = scan_kind(target_type).ok_or_else(|| {
        Error::Invalid(format!(
            "sf target type {target_type} is detected but its scan path is not available yet; sf scans a domain, IP address, address block, email address, phone number, username or name"
        ))
    })?;
    // `-F` picks what is printed; otherwise `-f` and `-x` print only the `-t` types, as `sf.py`'s
    // `_showonlyrequested` does, and without them every element the scan kept is printed.
    let show = if !args.show.is_empty() {
        args.show.clone()
    } else if args.only_requested || args.strict {
        args.types.clone()
    } else {
        Vec::new()
    };
    Ok(SfAction::Scan(SfScan {
        target: normalized,
        target_type,
        kind,
        use_case: args.use_case.clone(),
        types: args.types.clone(),
        depth: args.depth,
        modules: args.modules.clone(),
        output: SfOutput {
            format: args.format.clone(),
            show,
            include_source: args.include_source,
            no_headers: args.no_headers,
            strip_newlines: args.strip_newlines,
            max_length: args.max_length.filter(|length| *length > 0),
            delimiter: args.delimiter.clone().unwrap_or_else(|| ",".into()),
        },
        debug: args.debug,
        quiet: args.quiet,
    }))
}

/// The lookup a saved scan of a target of this Spiderfoot type runs, or `None` for a type no
/// lookup takes yet (a bitcoin address).
#[must_use]
pub fn scan_kind(target_type: &str) -> Option<ScanKind> {
    match target_type {
        "INTERNET_NAME" => Some(ScanKind::Domain),
        "IP_ADDRESS" | "IPV6_ADDRESS" => Some(ScanKind::Ip),
        "NETBLOCK_OWNER" | "NETBLOCKV6_OWNER" => Some(ScanKind::Netblock),
        "BGP_AS_OWNER" => Some(ScanKind::Asn),
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
/// root, only the shown types when some were chosen, each with the data of the element it was
/// found from. Tab and CSV rows keep `sf.py`'s columns, a cell to a line; a JSON row carries
/// `sf.py`'s keys (`generated`, `type`, `data`, `module`, `source`) and the rest of the element
/// as well: its type code, id, source element, confidence, false-positive flag, entity and raw
/// evidence.
///
/// # Errors
/// [`Error::Invalid`] for an output format other than tab, csv or json, or JSON that cannot be
/// written.
pub fn render(output: &SfOutput, elements: &[DataElement]) -> Result<String, Error> {
    let data: HashMap<&str, &str> = elements
        .iter()
        .map(|element| (element.id.as_str(), element.data.as_str()))
        .collect();
    let rows: Vec<Row<'_>> = elements
        .iter()
        .filter(|element| element.kind != "ROOT")
        .filter(|element| {
            output.show.is_empty()
                || output
                    .show
                    .iter()
                    .any(|wanted| wanted.eq_ignore_ascii_case(&element.kind))
        })
        .map(|element| Row::new(element, &data, output))
        .collect();
    match output.format.as_str() {
        "tab" => Ok(render_tab(&rows, output)),
        "csv" => Ok(render_csv(&rows, output)),
        "json" => render_json(&rows),
        other => Err(Error::Invalid(format!(
            "invalid sf output format {other:?}; choose tab, csv, or json"
        ))),
    }
}

/// One printed row: a saved element, with its values as `-n` and `-S` leave them.
struct Row<'a> {
    element: &'a DataElement,
    type_description: String,
    source_data: String,
    data: String,
}

impl<'a> Row<'a> {
    /// `data` maps each element's id to its data, for the source column.
    fn new(element: &'a DataElement, data: &HashMap<&str, &str>, output: &SfOutput) -> Self {
        let source = element
            .source
            .as_deref()
            .and_then(|source| data.get(source))
            .copied()
            .unwrap_or_default();
        Self {
            element,
            type_description: sf_types::describe(&element.kind).to_owned(),
            source_data: shown(source, output),
            data: shown(&element.data, output),
        }
    }
}

/// A value as `sf.py` prints it: under `-n` a line feed becomes a space and a carriage return
/// goes, and under `-S` it is cut to that many characters.
fn shown(value: &str, output: &SfOutput) -> String {
    let value = if output.strip_newlines {
        value.replace('\n', " ").replace('\r', "")
    } else {
        value.to_owned()
    };
    match output.max_length {
        Some(length) => value.chars().take(length).collect(),
        None => value,
    }
}

/// `sf.py`'s JSON event, `asDict()` with `type` as the description, and the rest of the element.
#[derive(Serialize)]
struct JsonRow<'a> {
    generated: u64,
    #[serde(rename = "type")]
    type_description: &'a str,
    data: &'a str,
    module: &'a str,
    source: &'a str,
    event_type: &'a str,
    id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_id: Option<&'a str>,
    confidence: u8,
    false_positive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    entity: Option<&'a str>,
    #[serde(skip_serializing_if = "Value::is_null")]
    raw: &'a Value,
}

fn render_json(rows: &[Row<'_>]) -> Result<String, Error> {
    let rows: Vec<JsonRow<'_>> = rows
        .iter()
        .map(|row| JsonRow {
            generated: row.element.created / 1000,
            type_description: &row.type_description,
            data: &row.data,
            module: &row.element.module,
            source: &row.source_data,
            event_type: &row.element.kind,
            id: &row.element.id,
            source_id: row.element.source.as_deref(),
            confidence: row.element.confidence,
            false_positive: row.element.fp,
            entity: row.element.entity.as_deref(),
            raw: &row.element.raw,
        })
        .collect();
    serde_json::to_string_pretty(&rows)
        .map(|body| format!("{}\n", escape_unsafe_in_json(&body)))
        .map_err(|error| Error::Invalid(format!("sf json: {error}")))
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

/// `sf.py`'s tab rows: the module padded to 30 characters and the type to 45, as its
/// `ljust` pads them, then the source data under `-r`, then the data.
fn render_tab(rows: &[Row<'_>], output: &SfOutput) -> String {
    let mut out = String::new();
    if !output.no_headers {
        if output.include_source {
            let _ = writeln!(out, "{:<30}\t{:<45}\tSource Data\tData", "Source", "Type");
        } else {
            let _ = writeln!(out, "{:<30}\t{:<45}\tData", "Source", "Type");
        }
    }
    for row in rows {
        let _ = write!(
            out,
            "{:<30}\t{:<45}\t",
            one_line(&row.element.module),
            one_line(&row.type_description)
        );
        if output.include_source {
            out.push_str(&one_line(&row.source_data));
            out.push('\t');
        }
        out.push_str(&one_line(&row.data));
        out.push('\n');
    }
    out
}

/// `sf.py`'s CSV rows, with `-D`'s delimiter; a cell holding the delimiter, a quote or a line
/// break is quoted.
fn render_csv(rows: &[Row<'_>], output: &SfOutput) -> String {
    let delimiter = output.delimiter.as_str();
    let mut out = String::new();
    if !output.no_headers {
        let header: &[&str] = if output.include_source {
            &["Source", "Type", "Source Data", "Data"]
        } else {
            &["Source", "Type", "Data"]
        };
        out.push_str(&header.join(delimiter));
        out.push('\n');
    }
    for row in rows {
        let mut fields = vec![
            csv_cell(&row.element.module, delimiter),
            csv_cell(&row.type_description, delimiter),
        ];
        if output.include_source {
            fields.push(csv_cell(&row.source_data, delimiter));
        }
        fields.push(csv_cell(&row.data, delimiter));
        out.push_str(&fields.join(delimiter));
        out.push('\n');
    }
    out
}

/// One cell on one line: a line break or tab becomes a space, so the cell cannot start a row or a
/// column, and any other control character is written escaped, so it cannot drive the terminal.
fn one_line(value: &str) -> String {
    escape_controls(&value.replace(['\r', '\n', '\t'], " "))
}

fn csv_cell(value: &str, delimiter: &str) -> String {
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
    if guarded.contains(delimiter)
        || guarded
            .chars()
            .any(|character| matches!(character, '"' | '\n' | '\r'))
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
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
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
            "1.1.1.0/24",
            "2606:4700::/32",
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
        // sf.py quotes a bare number, which makes `-s 13335` a username; an AS target comes from
        // the API and runs the asn lookup.
        assert_eq!(scan_kind("BGP_AS_OWNER"), Some(ScanKind::Asn));
        assert_eq!(target_type(ScanKind::Asn, "AS13335"), "BGP_AS_OWNER");
        assert_eq!(scan_kind("BITCOIN_ADDRESS"), None);
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

    fn output(format: &str) -> SfOutput {
        SfOutput {
            format: format.into(),
            show: Vec::new(),
            include_source: true,
            no_headers: false,
            strip_newlines: false,
            max_length: None,
            delimiter: ",".into(),
        }
    }

    fn element(
        id: &str,
        kind: &str,
        data: &str,
        source: Option<&str>,
        module: &str,
    ) -> DataElement {
        DataElement {
            id: id.into(),
            kind: kind.into(),
            data: data.into(),
            source: source.map(str::to_owned),
            module: module.into(),
            confidence: 90,
            created: 1_700_000_000_123,
            fp: false,
            entity: None,
            raw: serde_json::Value::Null,
        }
    }

    /// Every evidence record an entity carries prints its own row, named for the module that made
    /// it, so a second module's finding never drops out of `sf` output.
    #[test]
    fn every_evidence_record_of_an_entity_prints_its_own_row() {
        let mut entity = Entity::new(EntityKind::Domain, "a.example.com", 0.9, "scan");
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("crtsh", "scan"),
            "certificate",
        ));
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan("robtex", "scan"),
            "passive dns",
        ));
        let target = Target {
            value: "example.com",
            kind: "INTERNET_NAME",
        };
        let saved = elements(target, &[entity], 1);
        let rendered = render(&output("json"), &saved).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let modules: Vec<&str> = value
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|row| row["module"].as_str())
            .collect();
        assert!(modules.contains(&"crtsh"), "{rendered}");
        assert!(modules.contains(&"robtex"), "{rendered}");
    }

    /// The rows are a saved scan's elements, the root left out, each with the data of the
    /// element it was found from, and a JSON row has `sf.py`'s keys.
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

        let rendered = render(&output("json"), &saved).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let rows = value.as_array().unwrap();
        assert_eq!(rows.len(), saved.len() - 1);
        assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
        assert_eq!(value[0]["type"], sf_types::describe("PHONE_NUMBER"));
        assert_eq!(value[0]["data"], "+61412345678");
        assert_eq!(value[0]["source"], "+61412345678");
        assert_eq!(value[0]["generated"], 1);
        assert!(rows.iter().all(|row| row["event_type"] != "ROOT"));

        let mut only = output("json");
        only.show = vec!["phone_number".into()];
        let only: serde_json::Value =
            serde_json::from_str(&render(&only, &saved).unwrap()).unwrap();
        assert_eq!(only.as_array().unwrap().len(), 1, "{only}");
        assert!(render(&output("xml"), &saved).is_err());
    }

    /// `-H`, `-n`, `-S` and `-D` shape the rows as `sf.py`'s storage module does, and a JSON row
    /// keeps the whole element besides.
    #[test]
    fn output_flags_shape_rows_as_sf_py_does() {
        let saved = [
            element("root", "ROOT", "example.org", None, ""),
            element(
                "a",
                "INTERNET_NAME",
                "example.org",
                Some("root"),
                "hostdomain",
            ),
            element("b", "RAW_RIR_DATA", "first;\r\nsecond", Some("a"), "rdap"),
        ];
        let tab = render(&output("tab"), &saved).unwrap();
        let mut lines = tab.lines();
        assert_eq!(
            lines.next(),
            Some(format!("{:<30}\t{:<45}\tSource Data\tData", "Source", "Type").as_str())
        );
        assert!(
            lines
                .next()
                .unwrap()
                .starts_with(&format!("{:<30}\t", "hostdomain"))
        );
        let mut bare = output("tab");
        bare.no_headers = true;
        bare.include_source = false;
        assert!(!render(&bare, &saved).unwrap().contains("Source"));

        let mut json = output("json");
        json.strip_newlines = true;
        let rows: serde_json::Value =
            serde_json::from_str(&render(&json, &saved).unwrap()).unwrap();
        assert_eq!(rows[1]["data"], "first; second");
        assert_eq!(rows[1]["source"], "example.org");
        assert_eq!(rows[1]["source_id"], "a");
        assert_eq!(rows[1]["id"], "b");
        assert_eq!(rows[1]["module"], "rdap");
        assert_eq!(rows[1]["confidence"], 90);
        assert_eq!(rows[1]["false_positive"], false);
        json.strip_newlines = false;
        json.max_length = Some(5);
        let rows: serde_json::Value =
            serde_json::from_str(&render(&json, &saved).unwrap()).unwrap();
        assert_eq!(rows[1]["data"], "first");
        assert_eq!(rows[1]["source"], "examp");

        let mut csv = output("csv");
        csv.delimiter = ";".into();
        let csv = render(&csv, &saved).unwrap();
        assert!(csv.starts_with("Source;Type;Source Data;Data\n"), "{csv}");
        assert!(csv.contains("\"first;  second\""), "{csv}");
    }

    #[test]
    fn flags_follow_sf_py_and_refuse_what_it_refuses() {
        let scan = |words: &[&str]| match action(&args(words).unwrap()).unwrap() {
            SfAction::Scan(scan) => scan,
            other => panic!("{other:?}"),
        };
        // -t picks what the scan keeps and every kept element prints; -f and -x print only
        // the -t types; -F picks what prints without changing what is kept.
        let kept = scan(&["-s", "example.org", "-t", "IP_ADDRESS"]);
        assert_eq!(kept.types, ["IP_ADDRESS"]);
        assert!(kept.output.show.is_empty());
        let only = scan(&["-s", "example.org", "-t", "IP_ADDRESS", "-f"]);
        assert_eq!(only.output.show, ["IP_ADDRESS"]);
        assert_eq!(
            scan(&["-s", "example.org", "-t", "IP_ADDRESS", "-x"])
                .output
                .show,
            ["IP_ADDRESS"]
        );
        let shown = scan(&["-s", "example.org", "-F", "ip_address,internet_name"]);
        assert!(shown.types.is_empty());
        assert_eq!(shown.output.show, ["IP_ADDRESS", "INTERNET_NAME"]);
        let shaped = scan(&[
            "-s",
            "example.org",
            "-o",
            "csv",
            "-D",
            "|",
            "-S",
            "40",
            "-n",
            "-H",
            "-d",
            "--depth",
            "2",
        ]);
        assert_eq!(shaped.output.delimiter, "|");
        assert_eq!(shaped.output.max_length, Some(40));
        assert!(shaped.output.strip_newlines && shaped.output.no_headers && shaped.debug);
        assert_eq!(shaped.depth, 2);
        // -m picks the modules the saved scan asks, by Huntsman or Spiderfoot name.
        assert_eq!(
            scan(&[
                "-s",
                "example.org",
                "-m",
                "sfp_dnsresolve, CRTSH",
                "-m",
                "rdap"
            ])
            .modules,
            ["sfp_dnsresolve", "crtsh", "rdap"]
        );
        assert!(scan(&["-s", "example.org"]).modules.is_empty());
        assert_eq!(
            scan(&["-s", "example.org", "-S", "0"]).output.max_length,
            None
        );
        assert_eq!(
            action(&args(&["-l", "127.0.0.1:5001"]).unwrap()).unwrap(),
            SfAction::Listen("127.0.0.1:5001".into())
        );
        for refused in [
            &["-s", "example.org", "-f"][..],
            &["-s", "example.org", "-x"],
            &[
                "-s",
                "example.org",
                "-t",
                "IP_ADDRESS",
                "-x",
                "--depth",
                "1",
            ],
            &["-s", "example.org", "-D", ";"],
            &["-s", "example.org", "-S", "many"],
            &["-s", "example.org", "-F", "NOT_A_TYPE"],
            &["-l", "127.0.0.1:5001", "-s", "example.org"],
            &["-l", "127.0.0.1:5001", "-M"],
            &["-s", "example.org", "-m", "sfp_not_a_module"],
            &["-s", "example.org", "-m", "nonesuch"],
            &["-s", "example.org", "-t", "IP_ADDRESS", "-x", "-m", "dns"],
        ] {
            assert!(args(refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn csv_rows_quote_and_guard_special_cells() {
        let saved = [
            element("a", "INTERNET_NAME", "a,b", None, "=source"),
            element("b", "EMAILADDR", "jane@example.org", Some("a"), "=source"),
        ];
        let rendered = render(&output("csv"), &saved).unwrap();
        assert!(rendered.contains("'=source"));
        assert!(rendered.contains("\"a,b\""));
    }

    #[test]
    fn a_cell_cannot_drive_the_terminal_in_any_format() {
        // A profile name the target's own page chose.
        let hostile = "Jane\u{1b}]0;x\u{7}\u{9b}2J\u{7f}\nforged\tcolumn\u{2028}";
        let saved = [
            element("a", "USERNAME", hostile, None, hostile),
            element("b", "HUMAN_NAME", hostile, Some("a"), hostile),
        ];
        for format in ["tab", "csv", "json"] {
            let rendered = render(&output(format), &saved).unwrap();
            assert_eq!(
                unexpected_controls(&rendered, &['\n', '\t']).len(),
                0,
                "{format}: {rendered:?}"
            );
            assert!(!rendered.contains('\u{2028}'), "{format}");
        }
        // The tab and csv cells stay one line of fixed columns.
        let mut tab = output("tab");
        tab.include_source = false;
        let tab = render(&tab, &saved).unwrap();
        assert_eq!(tab.lines().count(), 3, "{tab:?}");
        assert_eq!(tab.lines().last().unwrap().matches('\t').count(), 2);
        assert!(tab.contains("Jane\\u{1b}]0;x\\u{7}\\u{9b}2J\\u{7f} forged column"));
        // JSON reads back the same text.
        let json: serde_json::Value =
            serde_json::from_str(&render(&output("json"), &saved).unwrap()).unwrap();
        assert_eq!(json[1]["data"], hostile);
        assert_eq!(json[1]["source"], hostile);
    }
}
