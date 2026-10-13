//! Partial `SpiderFoot` 4.0 command-line compatibility over rebuilt Huntsman paths.
//!
//! The layer implements the `sf.py` 4.0 target classifier, `-M` / `-T` / `-V`, use-case
//! validation, and the `sfp__stor_stdout` output contract (`-o`, `-H`, `-n`, `-r`, `-S`, `-D`,
//! `-t` with `-f`, `-F`), with the same argument-combination refusals. Execution covers the
//! people, email, username, phone, internet-name and IP-address targets through rebuilt
//! front-ends. Unsupported target classes and options fail explicitly, never silently.

use std::fmt::Write as _;

use serde::Serialize;

use crate::domain_cli::{self, DomainRun};
use crate::email_cli::{self, EmailRun};
use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::http::Transport;
use crate::module::reachable_modules;
use crate::network_cli::{self, NetworkRun, NetworkTarget};
use crate::people_cli::{self, PeopleRun};
use crate::phone_cli::{self, PhoneRun};
use crate::textnorm::{escape_controls, is_escaped};
use crate::username_cli::{self, UsernameRun};

pub const SF_USAGE: &str = "usage: huntsman-recon sf [-M|-T|-V] | -s TARGET [-u all|footprint|investigate|passive] [-o tab|csv|json] [-t TYPE[,TYPE...] [-f]] [-F TYPE[,TYPE...]] [-H] [-n] [-r] [-S LENGTH] [-D DELIMITER] [-d] [-q] [-max-threads N]";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SfMode {
    #[default]
    Scan,
    ListModules,
    ListTypes,
    Version,
}

/// How scan rows are written: the `sfp__stor_stdout` options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfOutput {
    pub format: String,
    pub include_source: bool,
    pub no_headers: bool,
    pub strip_newlines: bool,
    /// Characters kept of each data and source-data cell; 0 keeps all.
    pub max_length: usize,
    pub delimiter: String,
}

impl Default for SfOutput {
    fn default() -> Self {
        Self {
            format: "tab".into(),
            include_source: false,
            no_headers: false,
            strip_newlines: false,
            max_length: 0,
            delimiter: ",".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SfArgs {
    pub target: Option<String>,
    pub use_case: Option<String>,
    /// `-t`: event types to collect.
    pub types: Vec<String>,
    /// `-F`: show only these event types.
    pub show_types: Vec<String>,
    /// `-f`: show only the `-t` types.
    pub filter_requested: bool,
    /// `-D`, kept apart from `output.delimiter` so `-D` without csv can be refused.
    pub delimiter: Option<String>,
    pub output: SfOutput,
    pub debug: bool,
    pub max_threads: Option<usize>,
    pub quiet: bool,
    pub mode: SfMode,
}

fn type_list(raw: &str) -> Vec<String> {
    raw.split(',')
        .filter(|item| !item.is_empty())
        .map(str::to_ascii_uppercase)
        .collect()
}

/// Options `sf.py` 4.0 accepts that this layer does not implement, each with its refusal.
fn unimplemented_option(flag: &str) -> Option<&'static str> {
    Some(match flag {
        "-m" => {
            "-m selects SpiderFoot modules; rebuilt front-ends run fixed source sets, so it is not supported yet"
        }
        "-x" => "-x strict mode needs per-module event selection, which is not supported yet",
        "-l" => "-l starts the SpiderFoot web listener; use `huntsman-recon serve --bind IP:PORT`",
        "-C" | "--correlate" => {
            "-C correlates a stored SpiderFoot scan; use `huntsman-recon correlate ARTIFACT`"
        }
        _ => return None,
    })
}

impl SfArgs {
    /// Parse the `sf.py` 4.0 flag set this layer implements.
    ///
    /// # Errors
    /// Unknown or unimplemented flags, missing or malformed values, and every argument
    /// combination `sf.py` refuses.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            let mut step = 1;
            match flag {
                "-s" | "--target" => {
                    parsed.target = Some(value(args, index, "-s")?.to_owned());
                    step = 2;
                }
                "-u" | "--use-case" => {
                    parsed.use_case = Some(value(args, index, "-u")?.to_ascii_lowercase());
                    step = 2;
                }
                "-o" | "--output" | "--format" => {
                    parsed.output.format = value(args, index, "-o")?.to_ascii_lowercase();
                    step = 2;
                }
                "-t" | "--types" => {
                    parsed.types.extend(type_list(value(args, index, "-t")?));
                    step = 2;
                }
                "-F" => {
                    parsed
                        .show_types
                        .extend(type_list(value(args, index, "-F")?));
                    step = 2;
                }
                "-S" => {
                    parsed.output.max_length = value(args, index, "-S")?
                        .parse::<usize>()
                        .map_err(|_| Error::Invalid("argument -S: invalid int value".into()))?;
                    step = 2;
                }
                "-D" => {
                    let delimiter = value(args, index, "-D")?;
                    if delimiter.is_empty() || delimiter.chars().any(|c| c.is_control() || c == '"')
                    {
                        return Err(Error::Invalid(
                            "argument -D: delimiter must be printable and not a quote".into(),
                        ));
                    }
                    parsed.delimiter = Some(delimiter.to_owned());
                    step = 2;
                }
                "-max-threads" | "--max-threads" => {
                    let threads = value(args, index, "-max-threads")?
                        .parse::<usize>()
                        .ok()
                        .filter(|threads| *threads > 0)
                        .ok_or_else(|| {
                            Error::Invalid("argument -max-threads: must be a positive int".into())
                        })?;
                    parsed.max_threads = Some(threads);
                    step = 2;
                }
                "-f" => parsed.filter_requested = true,
                "-H" => parsed.output.no_headers = true,
                "-n" => parsed.output.strip_newlines = true,
                "-r" | "--include-source" => parsed.output.include_source = true,
                "-d" | "--debug" => parsed.debug = true,
                "-q" | "--quiet" => parsed.quiet = true,
                "-M" | "--modules" | "--list-modules" => {
                    set_mode(&mut parsed, SfMode::ListModules)?;
                }
                "-T" | "--list-types" => set_mode(&mut parsed, SfMode::ListTypes)?,
                "-V" | "--version" | "--sf-version" => set_mode(&mut parsed, SfMode::Version)?,
                other if other.starts_with('-') => {
                    let reason = unimplemented_option(other)
                        .map_or_else(|| format!("unsupported sf option {other}"), str::to_owned);
                    return Err(Error::Invalid(reason));
                }
                value => {
                    return Err(Error::Invalid(format!(
                        "unexpected sf argument {value:?}; target must follow -s"
                    )));
                }
            }
            index += step;
        }
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), Error> {
        if let Some(use_case) = &self.use_case {
            validate_use_case(use_case)?;
        }
        let format = self.output.format.as_str();
        if !matches!(format, "tab" | "csv" | "json") {
            return Err(Error::Invalid(
                "Invalid output format selected. Must be 'tab', 'csv' or 'json'.".into(),
            ));
        }
        for kind in self.types.iter().chain(&self.show_types) {
            if !known_type(kind) {
                return Err(Error::Invalid(format!("unknown sf event type {kind}")));
            }
        }
        if self.mode != SfMode::Scan {
            if self.target.is_some() {
                return Err(Error::Invalid(
                    "sf listing/version modes do not accept -s".into(),
                ));
            }
            return Ok(());
        }
        if self.target.is_none() {
            return Err(Error::Invalid("sf needs -s TARGET, -M, -T, or -V".into()));
        }
        // The refusals and wording of sf.py 4.0, in its order.
        if self.output.include_source && format == "json" {
            return Err(Error::Invalid(
                "-r can only be used when your output format is tab or csv.".into(),
            ));
        }
        if self.output.no_headers && format == "json" {
            return Err(Error::Invalid(
                "-H can only be used when your output format is tab or csv.".into(),
            ));
        }
        if self.delimiter.is_some() && format != "csv" {
            return Err(Error::Invalid(
                "-D can only be used when using the csv output format.".into(),
            ));
        }
        if self.filter_requested && self.types.is_empty() {
            return Err(Error::Invalid(
                "You can only use -f with -t. Use --help for guidance.".into(),
            ));
        }
        Ok(())
    }

    /// The types `sfp__stor_stdout` shows, or `None` to show every event. `-t` replaces the
    /// `-F` list, exactly as `sf.py` assigns `_requested` after `-F`.
    #[must_use]
    pub fn shown_types(&self) -> Option<Vec<String>> {
        let show_only = self.filter_requested || !self.show_types.is_empty();
        show_only.then(|| {
            if self.types.is_empty() {
                self.show_types.clone()
            } else {
                self.types.clone()
            }
        })
    }
}

fn set_mode(args: &mut SfArgs, mode: SfMode) -> Result<(), Error> {
    if args.mode != SfMode::Scan {
        return Err(Error::Invalid(
            "sf accepts only one of -M, -T, or -V at a time".into(),
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfScan {
    pub target: String,
    pub target_type: &'static str,
    pub use_case: String,
    /// `Some(types)` shows only events of those types; `None` shows every event.
    pub shown_types: Option<Vec<String>>,
    pub output: SfOutput,
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
        SfMode::Scan => {}
    }
    let target = args.target.as_deref().unwrap_or_default();
    let (target_type, normalized) = sf_target_type(target).ok_or_else(|| {
        Error::Invalid(format!("sf: unable to detect target type for {target:?}"))
    })?;
    Ok(SfAction::Scan(SfScan {
        target: normalized,
        target_type,
        use_case: args.use_case.clone().unwrap_or_else(|| "all".into()),
        shown_types: args.shown_types(),
        output: SfOutput {
            delimiter: args
                .delimiter
                .clone()
                .unwrap_or_else(|| args.output.delimiter.clone()),
            ..args.output.clone()
        },
    }))
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
    for (code, description, kinds) in type_table() {
        writeln!(&mut out, "{code:45} {description} (hse: {kinds})")
            .expect("writing to String cannot fail");
    }
    out
}

/// What one scan printed, and the sources that failed without failing the whole scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfRun {
    pub body: String,
    pub warnings: Vec<String>,
}

/// Execute one supported sf target over the already-rebuilt lookup front-ends.
pub fn run_scan<T: Transport + ?Sized>(
    transport: &T,
    scan: &SfScan,
    now_unix: u64,
) -> Result<SfRun, Error> {
    let mut warnings = Vec::new();
    if scan.use_case == "passive" && scan.target_type != "PHONE_NUMBER" {
        return Err(Error::Invalid(format!(
            "sf passive mode has no rebuilt offline collector for {} yet",
            scan.target_type
        )));
    }

    let entities = match scan.target_type {
        "EMAILADDR" => match email_cli::run(transport, &scan.target, now_unix) {
            EmailRun::Printed { report, .. } => report.entities,
            EmailRun::Network(message) => return Err(Error::Network(message)),
            EmailRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "USERNAME" => match username_cli::run(transport, &scan.target, now_unix) {
            UsernameRun::Printed { report, .. } => report.entities,
            UsernameRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "PHONE_NUMBER" => match phone_cli::run(&scan.target, now_unix) {
            PhoneRun::Printed { report, .. } => report.entities,
            PhoneRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "HUMAN_NAME" => {
            // The people front-end skips a non-name with no request; reporting that as a
            // scan with no events would read as "nothing found".
            if !people_cli::is_name(&scan.target) {
                return Err(Error::Invalid(format!(
                    "sf target {:?} was classified HUMAN_NAME but has fewer than two alphabetic tokens; nothing was looked up",
                    scan.target
                )));
            }
            match people_cli::run(transport, &scan.target, now_unix) {
                PeopleRun::Printed { report, .. } => report.entities,
                PeopleRun::Network(message) => return Err(Error::Network(message)),
                PeopleRun::Failed(message) => return Err(Error::Invalid(message)),
            }
        }
        "INTERNET_NAME" => match domain_cli::run(transport, &scan.target, now_unix) {
            DomainRun::Printed { report, .. } => report.entities,
            DomainRun::Network(message) | DomainRun::Unavailable(message) => {
                return Err(Error::Network(message));
            }
            DomainRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "IP_ADDRESS" | "IPV6_ADDRESS" | "NETBLOCK_OWNER" | "NETBLOCKV6_OWNER" | "BGP_AS_OWNER" => {
            let (entities, partial) =
                network_entities(transport, scan.target_type, &scan.target, now_unix)?;
            warnings = partial;
            entities
        }
        other => {
            return Err(Error::Invalid(format!(
                "sf target type {other} is detected but its rebuilt scan path is not available yet"
            )));
        }
    };

    let mut rows: Vec<Row> = entities.iter().map(Row::from_entity).collect();
    if let Some(shown) = &scan.shown_types {
        rows.retain(|row| {
            shown
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(row.event_type))
        });
    }
    Ok(SfRun {
        body: render_rows(&rows, &scan.output)?,
        warnings,
    })
}

/// IP, netblock and AS targets through [`network_cli`]: the entities, plus a warning for each
/// source that failed while another answered.
fn network_entities<T: Transport + ?Sized>(
    transport: &T,
    target_type: &str,
    raw: &str,
    now_unix: u64,
) -> Result<(Vec<Entity>, Vec<String>), Error> {
    let target = if target_type == "BGP_AS_OWNER" {
        raw.parse::<u32>()
            .ok()
            .filter(|asn| *asn != 0)
            .map(NetworkTarget::Asn)
    } else {
        NetworkTarget::parse(raw)
    }
    .ok_or_else(|| Error::Invalid(format!("sf target {raw:?} is not a valid {target_type}")))?;
    match network_cli::run_target(transport, target, now_unix) {
        NetworkRun::Printed { report, .. } => {
            let warnings = report
                .outcomes
                .iter()
                .filter(|outcome| !outcome.kind.is_accepted())
                .map(|outcome| {
                    format!(
                        "{} failed ({}): {}",
                        outcome.module,
                        outcome.kind.as_str(),
                        outcome.detail.as_deref().unwrap_or("no detail")
                    )
                })
                .collect();
            Ok((report.entities, warnings))
        }
        NetworkRun::Unavailable(message) => Err(Error::Network(message)),
        NetworkRun::Failed(message) => Err(Error::Invalid(message)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Row {
    source: String,
    event_type: &'static str,
    type_description: &'static str,
    source_data: String,
    data: String,
}

impl Row {
    fn from_entity(entity: &Entity) -> Self {
        let (event_type, type_description) = sf_type(&entity.kind);
        // A target merged with what a source reported about it shows the report, not "seed".
        let evidence = entity
            .evidence
            .iter()
            .find(|item| item.provenance.source != "seed")
            .or_else(|| entity.evidence.first());
        Self {
            source: evidence
                .map(|item| item.provenance.source.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "huntsman".into()),
            event_type,
            type_description,
            source_data: evidence
                .map(|item| item.summary.clone())
                .unwrap_or_default(),
            data: entity.raw_value.clone(),
        }
    }
}

/// `-n` and `-S`, applied to a cell before it is escaped, as `sfp__stor_stdout` applies them.
fn shaped(value: &str, output: &SfOutput) -> String {
    let value = if output.strip_newlines {
        value.replace('\n', " ").replace('\r', "")
    } else {
        value.to_owned()
    };
    if output.max_length > 0 {
        value.chars().take(output.max_length).collect()
    } else {
        value
    }
}

fn render_rows(rows: &[Row], output: &SfOutput) -> Result<String, Error> {
    let rows: Vec<Row> = rows
        .iter()
        .map(|row| Row {
            source_data: shaped(&row.source_data, output),
            data: shaped(&row.data, output),
            ..row.clone()
        })
        .collect();
    match output.format.as_str() {
        "tab" => Ok(render_tab(&rows, output)),
        "csv" => Ok(render_csv(&rows, output)),
        "json" => serde_json::to_string_pretty(&rows)
            .map(|body| format!("{}\n", escape_unsafe_in_json(&body)))
            .map_err(|error| Error::Invalid(format!("sf json: {error}"))),
        _ => Err(Error::Invalid("invalid sf output format".into())),
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

fn render_tab(rows: &[Row], output: &SfOutput) -> String {
    let mut out = String::new();
    if !output.no_headers {
        if output.include_source {
            out.push_str("Source\tType\tSource Data\tData\n");
        } else {
            out.push_str("Source\tType\tData\n");
        }
    }
    for row in rows {
        let mut cells = vec![one_line(&row.source), one_line(row.type_description)];
        if output.include_source {
            cells.push(one_line(&row.source_data));
        }
        cells.push(one_line(&row.data));
        out.push_str(&cells.join("\t"));
        out.push('\n');
    }
    out
}

fn render_csv(rows: &[Row], output: &SfOutput) -> String {
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
        let mut cells = vec![
            csv_cell(&row.source, delimiter),
            csv_cell(row.type_description, delimiter),
        ];
        if output.include_source {
            cells.push(csv_cell(&row.source_data, delimiter));
        }
        cells.push(csv_cell(&row.data, delimiter));
        out.push_str(&cells.join(delimiter));
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
    // sf.py quotes every dotless target, so its CLI can never reach BGP_AS_OWNER: a bare
    // number is a USERNAME there and stays one here. `AS13335` / `ASN13335` is the explicit
    // Huntsman form for an AS target.
    if let Some(asn) = as_target(&target) {
        return Some(("BGP_AS_OWNER", asn.to_string()));
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

fn as_target(value: &str) -> Option<u32> {
    match NetworkTarget::parse(value) {
        Some(NetworkTarget::Asn(asn)) => Some(asn),
        _ => None,
    }
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

#[must_use]
pub fn type_table() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("BGP_AS_OWNER", "BGP AS Ownership", "asn"),
        ("COMPANY_NAME", "Company Name", "organisation"),
        ("DOMAIN_NAME", "Domain Name", "domain"),
        ("EMAILADDR", "Email Address", "email"),
        ("HUMAN_NAME", "Human Name", "person"),
        ("INTERNET_NAME", "Internet Name", "domain"),
        ("IPV6_ADDRESS", "IPv6 Address", "ip_address"),
        ("IP_ADDRESS", "IP Address", "ip_address"),
        ("LINKED_URL_EXTERNAL", "Linked URL - External", "url"),
        ("NETBLOCK_OWNER", "Netblock Ownership", "netblock"),
        ("NETBLOCKV6_OWNER", "IPv6 Netblock Ownership", "netblock"),
        ("PHONE_NUMBER", "Phone Number", "phone"),
        ("PHYSICAL_ADDRESS", "Physical Address", "address"),
        (
            "PHYSICAL_COORDINATES",
            "Physical Coordinates",
            "coordinates",
        ),
        ("USERNAME", "Username", "username"),
        ("WEB_ANALYTICS_ID", "Web Analytics", "tracking_id"),
        (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
            "abn_acn",
        ),
        (
            "HSE_CRYPTO_ADDRESS",
            "Crypto Address (HSE)",
            "crypto_address",
        ),
        ("HSE_DOCUMENT", "Document (HSE)", "document"),
        ("HSE_DEVICE_ID", "Device Identifier (HSE)", "device_id"),
        ("HSE_MAC_ADDRESS", "MAC Address (HSE)", "mac_address"),
        ("HSE_OTHER", "Other (HSE)", "other"),
        ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)", "ssid"),
    ]
}

fn known_type(value: &str) -> bool {
    type_table()
        .iter()
        .any(|(code, _, _)| code.eq_ignore_ascii_case(value))
}

fn sf_type(kind: &EntityKind) -> (&'static str, &'static str) {
    match kind {
        EntityKind::Person => ("HUMAN_NAME", "Human Name"),
        EntityKind::Organisation => ("COMPANY_NAME", "Company Name"),
        EntityKind::Email => ("EMAILADDR", "Email Address"),
        EntityKind::Phone => ("PHONE_NUMBER", "Phone Number"),
        EntityKind::Username => ("USERNAME", "Username"),
        EntityKind::Domain => ("DOMAIN_NAME", "Domain Name"),
        EntityKind::Url => ("LINKED_URL_EXTERNAL", "Linked URL - External"),
        EntityKind::IpAddress => ("IP_ADDRESS", "IP Address"),
        EntityKind::Coordinates => ("PHYSICAL_COORDINATES", "Physical Coordinates"),
        EntityKind::Address => ("PHYSICAL_ADDRESS", "Physical Address"),
        EntityKind::Credential | EntityKind::ApiKey | EntityKind::Other => {
            ("HSE_OTHER", "Other (HSE)")
        }
        EntityKind::Document => ("HSE_DOCUMENT", "Document (HSE)"),
        EntityKind::CryptoAddress => ("HSE_CRYPTO_ADDRESS", "Crypto Address (HSE)"),
        EntityKind::DeviceId => ("HSE_DEVICE_ID", "Device Identifier (HSE)"),
        EntityKind::Ssid => ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)"),
        EntityKind::TrackingId => ("WEB_ANALYTICS_ID", "Web Analytics"),
        EntityKind::AbnAcn => (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
        ),
        EntityKind::MacAddress => ("HSE_MAC_ADDRESS", "MAC Address (HSE)"),
        EntityKind::Asn => ("BGP_AS_OWNER", "BGP AS Ownership"),
        EntityKind::Netblock => ("NETBLOCK_OWNER", "Netblock Ownership"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::unexpected_controls;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::http::{Request, Response, TransportFailure};

    struct Fake {
        responses: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(responses: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    fn with_source(format: &str) -> SfOutput {
        SfOutput {
            format: format.into(),
            include_source: true,
            ..SfOutput::default()
        }
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| (*w).to_owned()).collect()
    }

    fn parse_err(words: &[&str]) -> String {
        match SfArgs::parse(&args(words)) {
            Err(error) => error.to_string(),
            Ok(parsed) => panic!("{words:?} parsed: {parsed:?}"),
        }
    }

    fn doh(body: &str) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
            truncated: false,
        }
    }

    fn row(event_type: &'static str, data: &str) -> Row {
        Row {
            source: "src".into(),
            event_type,
            type_description: "Desc",
            source_data: "seed\nline".into(),
            data: data.into(),
        }
    }

    #[test]
    fn shown_types_follow_stor_stdout() {
        let shown = |words: &[&str]| SfArgs::parse(&args(words)).map(|a| a.shown_types());
        // -t alone collects but shows every event; -f narrows to -t.
        assert_eq!(
            shown(&["-s", "a.example", "-t", "IP_ADDRESS"]).ok(),
            Some(None)
        );
        assert_eq!(
            shown(&["-s", "a.example", "-t", "ip_address", "-f"]).ok(),
            Some(Some(vec!["IP_ADDRESS".to_string()]))
        );
        // -F shows only its types and is not a collection request.
        assert_eq!(
            shown(&["-s", "a.example", "-F", "DOMAIN_NAME"]).ok(),
            Some(Some(vec!["DOMAIN_NAME".to_string()]))
        );
        // -t replaces the -F list, as sf.py assigns _requested after -F.
        assert_eq!(
            shown(&["-s", "a.example", "-F", "DOMAIN_NAME", "-t", "IP_ADDRESS"]).ok(),
            Some(Some(vec!["IP_ADDRESS".to_string()]))
        );
    }

    #[test]
    fn sf_py_argument_refusals_are_preserved() {
        assert!(
            parse_err(&["-s", "a.example", "-o", "json", "-r"]).contains("-r can only be used")
        );
        assert!(
            parse_err(&["-s", "a.example", "-o", "json", "-H"]).contains("-H can only be used")
        );
        assert!(parse_err(&["-s", "a.example", "-D", ";"]).contains("-D can only be used"));
        assert!(parse_err(&["-s", "a.example", "-f"]).contains("only use -f with -t"));
        assert!(parse_err(&["-s", "a.example", "-S", "x"]).contains("-S"));
        assert!(parse_err(&["-s", "a.example", "-max-threads", "0"]).contains("max-threads"));
        assert!(parse_err(&["-s", "a.example", "-m", "sfp_dnsresolve"]).contains("-m selects"));
        assert!(parse_err(&["-s", "a.example", "-x"]).contains("strict mode"));
        assert!(parse_err(&["-l", "127.0.0.1:5001"]).contains("serve --bind"));
        assert!(parse_err(&["-C", "abc"]).contains("correlate ARTIFACT"));
        assert!(
            parse_err(&["-s", "a.example", "-F", "NOT_A_TYPE"]).contains("unknown sf event type")
        );
        assert!(
            SfArgs::parse(&args(&[
                "-s",
                "a.example",
                "-o",
                "csv",
                "-D",
                ";",
                "-H",
                "-n",
                "-S",
                "9",
                "-d",
                "-max-threads",
                "4"
            ]))
            .is_ok()
        );
    }

    #[test]
    fn output_options_shape_cells_like_stor_stdout() {
        let rows = [row("IP_ADDRESS", "192.0.2.1;x"), row("DOMAIN_NAME", "a\nb")];
        let csv = SfOutput {
            format: "csv".into(),
            no_headers: true,
            delimiter: ";".into(),
            ..SfOutput::default()
        };
        let rendered = render_rows(&rows, &csv).unwrap_or_default();
        // No header, the chosen delimiter, and a cell holding it is quoted.
        assert_eq!(rendered, "src;Desc;\"192.0.2.1;x\"\nsrc;Desc;a b\n");

        let json = SfOutput {
            format: "json".into(),
            strip_newlines: true,
            max_length: 3,
            ..SfOutput::default()
        };
        let value: serde_json::Value =
            serde_json::from_str(&render_rows(&rows, &json).unwrap_or_default())
                .unwrap_or_default();
        assert_eq!(value[0]["data"], "192");
        assert_eq!(value[1]["data"], "a b");
        assert_eq!(value[1]["source_data"], "see");
    }

    #[test]
    fn ip_target_reverse_resolves_through_the_doh_pool() {
        let fake = Fake::new(vec![
            Ok(doh(
                r#"{"Status":0,"Answer":[{"type":12,"data":"one.one.one.one."}]}"#,
            )),
            Ok(doh(
                r#"{"Status":0,"Answer":[{"type":16,"data":"\"13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11\""}]}"#,
            )),
        ]);
        let scan = SfScan {
            target: "1.1.1.1".into(),
            target_type: "IP_ADDRESS",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput {
                format: "json".into(),
                ..SfOutput::default()
            },
        };
        let run = run_scan(&fake, &scan, 1).unwrap_or_else(|e| panic!("{e}"));
        assert!(run.warnings.is_empty(), "{:?}", run.warnings);
        let value: serde_json::Value = serde_json::from_str(&run.body).unwrap_or_default();
        let rows: Vec<(String, String, String)> = value
            .as_array()
            .map(|rows| {
                rows.iter()
                    .map(|r| {
                        (
                            r["event_type"].as_str().unwrap_or_default().to_owned(),
                            r["data"].as_str().unwrap_or_default().to_owned(),
                            r["source"].as_str().unwrap_or_default().to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        for want in [
            ("IP_ADDRESS", "1.1.1.1", "seed"),
            ("DOMAIN_NAME", "one.one.one.one", "dns"),
            ("NETBLOCK_OWNER", "1.1.1.0/24", "cymru"),
            ("BGP_AS_OWNER", "AS13335", "cymru"),
        ] {
            assert!(
                rows.iter()
                    .any(|(t, d, s)| (t.as_str(), d.as_str(), s.as_str()) == want),
                "missing {want:?} in {rows:?}"
            );
        }
    }

    #[test]
    fn one_failed_source_is_a_warning_not_a_lost_scan() {
        let servfail = r#"{"Status":2}"#;
        let fake = Fake::new(vec![
            Ok(doh(r#"{"Status":3}"#)),
            Ok(doh(r#"{"Status":3}"#)),
            Ok(doh(r#"{"Status":3}"#)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
        ]);
        let scan = SfScan {
            target: "192.0.2.7".into(),
            target_type: "IP_ADDRESS",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput::default(),
        };
        let run = run_scan(&fake, &scan, 1).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(run.warnings.len(), 1, "{:?}", run.warnings);
        assert!(
            run.warnings[0].starts_with("cymru failed (inconclusive)"),
            "{:?}",
            run.warnings
        );
        assert!(run.body.contains("192.0.2.7"), "{}", run.body);
    }

    #[test]
    fn as_and_netblock_targets_execute() {
        let asn = Fake::new(vec![Ok(doh(
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US\""}]}"#,
        ))]);
        let scan = SfScan {
            target: "13335".into(),
            target_type: "BGP_AS_OWNER",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput {
                include_source: true,
                ..SfOutput::default()
            },
        };
        let run = run_scan(&asn, &scan, 1).unwrap_or_else(|e| panic!("{e}"));
        // The registration record merges into the target row rather than duplicating it,
        // and that row shows the record rather than the seed placeholder.
        assert_eq!(run.body.lines().count(), 2, "{}", run.body);
        let row = run.body.lines().nth(1).unwrap_or_default();
        assert!(row.starts_with("cymru\t"), "{row}");
        assert!(row.contains("CLOUDFLARENET, US"), "{row}");
        assert!(row.ends_with("\tAS13335"), "{row}");

        let block = Fake::new(vec![Ok(doh(
            r#"{"Status":0,"Answer":[{"type":16,"data":"\"64500 | 192.0.2.0/24 | AU | apnic | 2001-01-01\""}]}"#,
        ))]);
        let scan = SfScan {
            target: "192.0.2.77/24".into(),
            target_type: "NETBLOCK_OWNER",
            use_case: "all".into(),
            shown_types: Some(vec!["BGP_AS_OWNER".into()]),
            output: SfOutput::default(),
        };
        let run = run_scan(&block, &scan, 1).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(
            run.body,
            "Source\tType\tData\ncymru\tBGP AS Ownership\tAS64500\n"
        );
    }

    #[test]
    fn ip_target_resolver_failure_is_a_network_error_not_an_empty_scan() {
        let servfail = r#"{"Status":2}"#;
        let fake = Fake::new(vec![
            Ok(doh(servfail)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
            Ok(doh(servfail)),
        ]);
        let scan = SfScan {
            target: "192.0.2.7".into(),
            target_type: "IP_ADDRESS",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput::default(),
        };
        assert!(matches!(run_scan(&fake, &scan, 1), Err(Error::Network(_))));
    }

    #[test]
    fn internet_name_reaches_the_domain_front_end() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "a b".into(),
            target_type: "INTERNET_NAME",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput::default(),
        };
        // An invalid name is refused by domain_cli itself, proving the route is wired.
        match run_scan(&fake, &scan, 1) {
            Err(Error::Invalid(message)) => {
                assert!(message.contains("invalid domain"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_human_name_without_two_alphabetic_tokens_is_refused_not_empty() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "0412 345 678".into(),
            target_type: "HUMAN_NAME",
            use_case: "all".into(),
            shown_types: None,
            output: SfOutput::default(),
        };
        match run_scan(&fake, &scan, 1) {
            Err(Error::Invalid(message)) => {
                assert!(message.contains("two alphabetic"), "{message}");
            }
            other => panic!("{other:?}"),
        }
    }

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
        // sf.py parity: a bare number is quoted into a USERNAME.
        assert_eq!(
            sf_target_type("13335"),
            Some(("USERNAME", "13335".to_owned()))
        );
        for raw in ["AS13335", "as13335", "ASN13335"] {
            assert_eq!(
                sf_target_type(raw),
                Some(("BGP_AS_OWNER", "13335".to_owned())),
                "{raw}"
            );
        }
        for raw in ["AS0", "AS", "ASX1", "AS99999999999"] {
            assert_ne!(
                sf_target_type(raw).map(|(c, _)| c),
                Some("BGP_AS_OWNER"),
                "{raw}"
            );
        }
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
    }

    #[test]
    fn phone_scan_formats_spiderfoot_rows_without_network() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "+61412345678".into(),
            target_type: "PHONE_NUMBER",
            use_case: "passive".into(),
            shown_types: None,
            output: SfOutput {
                format: "json".into(),
                ..SfOutput::default()
            },
        };
        let rendered = run_scan(&fake, &scan, 1).unwrap().body;
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
        assert_eq!(value[0]["data"], "+61412345678");
    }

    #[test]
    fn passive_networked_target_fails_before_request() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "jane@example.org".into(),
            target_type: "EMAILADDR",
            use_case: "passive".into(),
            shown_types: None,
            output: SfOutput::default(),
        };
        let error = run_scan(&fake, &scan, 1).unwrap_err();
        assert!(error.to_string().contains("passive"));
    }

    #[test]
    fn csv_rows_quote_and_guard_special_cells() {
        let rows = [Row {
            source: "=source".into(),
            event_type: "EMAILADDR",
            type_description: "Email Address",
            source_data: "a,b".into(),
            data: "jane@example.org".into(),
        }];
        let rendered = render_csv(&rows, &with_source("csv"));
        assert!(rendered.contains("'=source"));
        assert!(rendered.contains("\"a,b\""));
    }

    #[test]
    fn a_cell_cannot_drive_the_terminal_in_any_format() {
        // A profile name the target's own page chose.
        let hostile = "Jane\u{1b}]0;x\u{7}\u{9b}2J\u{7f}\nforged\tcolumn\u{2028}";
        let rows = [Row {
            source: hostile.into(),
            event_type: "HUMAN_NAME",
            type_description: "Human Name",
            source_data: hostile.into(),
            data: hostile.into(),
        }];
        for (format, rendered) in [
            ("tab", render_tab(&rows, &with_source("tab"))),
            ("csv", render_csv(&rows, &with_source("csv"))),
            ("json", render_rows(&rows, &with_source("json")).unwrap()),
        ] {
            assert_eq!(
                unexpected_controls(&rendered, &['\n', '\t']).len(),
                0,
                "{format}: {rendered:?}"
            );
            assert!(!rendered.contains('\u{2028}'), "{format}");
        }
        // The tab and csv cells stay one line of fixed columns.
        let tab = render_tab(&rows, &SfOutput::default());
        assert_eq!(tab.lines().count(), 2, "{tab:?}");
        assert_eq!(tab.lines().last().unwrap().matches('\t').count(), 2);
        assert!(tab.contains("Jane\\u{1b}]0;x\\u{7}\\u{9b}2J\\u{7f} forged column"));
        // JSON reads back the same text.
        let json: serde_json::Value =
            serde_json::from_str(&render_rows(&rows, &with_source("json")).unwrap()).unwrap();
        assert_eq!(json[0]["data"], hostile);
    }
}
