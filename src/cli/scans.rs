//! `scans`: saved Spiderfoot-style scans from the command line. It runs and reads them through the
//! same store, runner and API router as `serve`, so a scan run here shows in the web UI and one
//! started there reads here.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use super::fail;
use super::lookup::collect;
use huntsman_recon::doctor::STATE_DIR;
use huntsman_recon::environment::HUNTSMAN_HOME_ENV;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::write_atomic_private;
use huntsman_recon::http::percent_encode_component;
use huntsman_recon::keys::Keys;
use huntsman_recon::scan_api::{ApiResponse, ScanApi, SlotCheck};
use huntsman_recon::scan_service::{LookupOutput, ScanLookup, ScanRequest, ScanService};
use huntsman_recon::scan_store::{ScanOptions, ScanRecord, ScanStatus, ScanStore};
use huntsman_recon::sf_types;
use huntsman_recon::textnorm::escape_controls;
use serde_json::Value;

pub(super) const SCANS_HELP: &str = "scans run TARGET [-k KIND] [-n NAME] [-u all|footprint|investigate|passive] [-t TYPE[,TYPE...]] [--json] | scans list [--json] | scans show ID | scans summary ID | scans elements ID [-t TYPE] [--unique] [--hide-fp] [--json] | scans correlations ID | scans log ID [--level INFO|WARNING|ERROR] | scans export ID|ID,ID... [-f csv|tsv|json|gexf] [-t TYPE] [-o FILE] | scans fp ID ELEMENT[,ELEMENT...] [--unset] | scans delete ID | scans rerun ID | scans types
Saved scans, as Spiderfoot keeps them: run one on a target, then list, read, export, flag, rerun or delete it. TARGET is anything scan routes (a domain, IP address, email, phone, username, name, BSSID or LAT,LON); -k picks the lookup when the target is ambiguous. A scan keeps every result whole: the lookup's report, every entity with its evidence, every source outcome, its Spiderfoot data elements (see scans types) and its correlations. -t keeps only those element types; -u passive skips the keyed breach lookup of an email. Exports use Spiderfoot's columns (Updated, Type, Module, Source, F/P, Data); several ids give one JSON export. Scans live in $HUNTSMAN_HOME/scans, else ~/.huntsman/scans; every subcommand but types takes --dir DIR. serve shows and starts the same scans. run makes network requests; the others are offline.";

/// The synopsis line of [`SCANS_HELP`], for a usage error.
fn usage() -> &'static str {
    SCANS_HELP.lines().next().unwrap_or(SCANS_HELP)
}

/// The lookup a saved scan runs: the same front-ends as `scan` and `/api/lookup`.
pub(super) fn scan_lookup() -> ScanLookup {
    Arc::new(|kind, selector| {
        collect(kind, selector)
            .map(|found| LookupOutput {
                text: found.text,
                entities: found.entities,
                outcomes: found.outcomes,
            })
            .map_err(|refused| refused.message().to_owned())
    })
}

/// Whether a key slot holds a key, read from the environment the way the lookups read it.
pub(super) fn slot_check() -> SlotCheck {
    Arc::new(|slot| Keys::from_env().get(slot).is_some())
}

/// `$HUNTSMAN_HOME/scans`, else `~/.huntsman/scans`; only an absolute directory counts.
pub(super) fn default_scan_dir() -> Option<PathBuf> {
    let absolute = |value: OsString| {
        let path = PathBuf::from(value);
        path.is_absolute().then_some(path)
    };
    env::var_os(HUNTSMAN_HOME_ENV)
        .and_then(absolute)
        .or_else(|| {
            env::var_os("HOME")
                .and_then(absolute)
                .map(|home| home.join(STATE_DIR))
        })
        .map(|state| state.join("scans"))
}

/// Options that take a value, by every spelling, and the name each is read back by.
const VALUED: [(&str, &str); 14] = [
    ("--dir", "dir"),
    ("-k", "kind"),
    ("--kind", "kind"),
    ("-n", "name"),
    ("--name", "name"),
    ("-u", "usecase"),
    ("--usecase", "usecase"),
    ("-t", "types"),
    ("--types", "types"),
    ("-f", "format"),
    ("--format", "format"),
    ("-o", "output"),
    ("--output", "output"),
    ("--level", "level"),
];

/// Options that stand alone.
const SWITCHES: [&str; 4] = ["--json", "--unique", "--hide-fp", "--unset"];

/// The words of a `scans` command line, and its options.
struct Parsed {
    words: Vec<String>,
    values: BTreeMap<&'static str, String>,
    switches: BTreeSet<&'static str>,
}

impl Parsed {
    fn value(&self, name: &str) -> Option<&str> {
        self.values.get(name).map(String::as_str)
    }

    fn owned(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }

    fn on(&self, switch: &str) -> bool {
        self.switches.contains(switch)
    }
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        words: Vec::new(),
        values: BTreeMap::new(),
        switches: BTreeSet::new(),
    };
    let mut words = args.iter();
    while let Some(word) = words.next() {
        if let Some((flag, name)) = VALUED.iter().find(|(flag, _)| flag == word) {
            let Some(value) = words.next() else {
                return Err(format!("scans {flag} needs a value"));
            };
            if parsed.values.insert(name, value.clone()).is_some() {
                return Err(format!("scans accepts only one {flag}"));
            }
        } else if let Some(switch) = SWITCHES.iter().find(|switch| *switch == word) {
            parsed.switches.insert(switch);
        } else if word.starts_with('-') && word.len() > 1 {
            return Err(format!("scans: unknown option {}", one_line(word)));
        } else {
            parsed.words.push(word.clone());
        }
    }
    Ok(parsed)
}

/// A query string from its pairs, each value form-encoded.
fn query(pairs: &[(&str, Option<&str>)]) -> String {
    pairs
        .iter()
        .filter_map(|(key, value)| {
            value.map(|value| format!("{key}={}", percent_encode_component(value)))
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn status_exit(status: u16) -> u8 {
    match status {
        400 | 405 => EX_USAGE,
        404 => EX_NOINPUT,
        409 => EX_DATAERR,
        _ => EX_IOERR,
    }
}

/// Print an API answer, or report its error with the exit status that matches it.
fn emit(response: &ApiResponse) -> ExitCode {
    if response.status >= 400 {
        let message = serde_json::from_str::<Value>(&response.body)
            .ok()
            .and_then(|body| body["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| response.body.trim().to_owned());
        return fail(status_exit(response.status), &format!("scans: {message}"));
    }
    let pretty = serde_json::from_str::<Value>(&response.body)
        .ok()
        .and_then(|body| serde_json::to_string_pretty(&body).ok());
    println!(
        "{}",
        pretty.unwrap_or_else(|| response.body.trim_end().to_owned())
    );
    ExitCode::SUCCESS
}

fn one_line(text: &str) -> String {
    escape_controls(&text.replace(['\r', '\n', '\t'], " "))
}

fn millis(value: &Value) -> String {
    value
        .as_u64()
        .map_or_else(|| "-".to_owned(), huntsman_recon::scan_export::timestamp)
}

fn print_list(rows: &Value) {
    println!("ID\tSTATUS\tSTARTED\tFINISHED\tELEMENTS\tHIGH/MEDIUM/LOW/INFO\tTYPE\tTARGET\tNAME");
    for row in rows.as_array().into_iter().flatten() {
        let risk = &row["correlations"];
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}/{}/{}/{}\t{}\t{}\t{}",
            one_line(row["id"].as_str().unwrap_or_default()),
            one_line(row["status"].as_str().unwrap_or_default()),
            millis(&row["started"]),
            millis(&row["ended"]),
            row["elements"],
            risk["high"],
            risk["medium"],
            risk["low"],
            risk["info"],
            one_line(row["target_type"].as_str().unwrap_or_default()),
            one_line(row["target"].as_str().unwrap_or_default()),
            one_line(row["name"].as_str().unwrap_or_default()),
        );
    }
}

fn print_elements(rows: &Value) {
    println!("ID\tUPDATED\tTYPE\tMODULE\tSOURCE\tF/P\tDATA");
    for row in rows.as_array().into_iter().flatten() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            one_line(row["id"].as_str().unwrap_or_default()),
            millis(&row["created"]),
            one_line(row["type"].as_str().unwrap_or_default()),
            one_line(row["module"].as_str().unwrap_or_default()),
            one_line(row["source_data"].as_str().unwrap_or_default()),
            u8::from(row["fp"].as_bool().unwrap_or(false)),
            one_line(row["data"].as_str().unwrap_or_default()),
        );
    }
}

fn print_run(record: &ScanRecord) {
    println!(
        "scan {} {} on {} {}: {} elements ({} unique), correlations high={} medium={} low={} info={}, {} errors, sources: {}",
        record.id,
        record.status.as_str(),
        record.target_type,
        one_line(&record.target),
        record.elements,
        record.unique,
        record.correlations.high,
        record.correlations.medium,
        record.correlations.low,
        record.correlations.info,
        record.errors,
        if record.modules_run.is_empty() {
            "none".to_owned()
        } else {
            record.modules_run.join(",")
        }
    );
}

fn types_listing() -> ExitCode {
    println!("TYPE\tCATEGORY\tRAW\tDESCRIPTION");
    for kind in sf_types::all() {
        println!(
            "{}\t{}\t{}\t{}",
            kind.code,
            kind.category.as_str(),
            u8::from(kind.raw),
            kind.description
        );
    }
    ExitCode::SUCCESS
}

pub(super) fn scans_cmd(args: &[String]) -> ExitCode {
    let parsed = match parse(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            return fail(
                EX_USAGE,
                &format!("{message}\nusage: huntsman-recon {}", usage()),
            );
        }
    };
    let words: Vec<&str> = parsed.words.iter().map(String::as_str).collect();
    let Some((&command, rest)) = words.split_first() else {
        return fail(EX_USAGE, &format!("usage: huntsman-recon {}", usage()));
    };
    if !SUBCOMMANDS.contains(&command) {
        return fail(
            EX_USAGE,
            &format!(
                "scans: unknown subcommand {}\nusage: huntsman-recon {}",
                one_line(command),
                usage()
            ),
        );
    }
    if command == "types" {
        return if rest.is_empty() {
            types_listing()
        } else {
            fail(EX_USAGE, "scans types takes no argument")
        };
    }
    let api = match open(&parsed) {
        Ok(api) => api,
        Err(code) => return code,
    };
    match (command, rest) {
        ("run", _) => run(&api, &parsed, rest),
        ("export", _) => export(&api, &parsed, rest),
        ("list", []) => {
            let response = api.handle("GET", "/api/scans", "");
            if parsed.on("--json") || response.status >= 400 {
                return emit(&response);
            }
            print_list(&serde_json::from_str(&response.body).unwrap_or(Value::Null));
            ExitCode::SUCCESS
        }
        ("fp", [id, elements]) => emit(&api.handle(
            "POST",
            &format!("/api/scans/{id}/fp"),
            &query(&[
                ("ids", Some(elements)),
                ("fp", Some(if parsed.on("--unset") { "0" } else { "1" })),
            ]),
        )),
        ("fp", _) => fail(
            EX_USAGE,
            "scans fp takes a scan id and element ids, comma separated",
        ),
        ("list", _) => fail(EX_USAGE, "scans list takes no argument"),
        (_, [id]) => one_scan(&api, &parsed, command, id),
        _ => fail(EX_USAGE, &format!("scans {command} takes one scan id")),
    }
}

/// Every `scans` subcommand.
const SUBCOMMANDS: [&str; 12] = [
    "run",
    "list",
    "show",
    "summary",
    "elements",
    "correlations",
    "log",
    "export",
    "fp",
    "delete",
    "rerun",
    "types",
];

/// The store at `--dir`, or the default one, with what a stopped process left running marked
/// `ABORTED`, behind the API router `serve` uses.
fn open(parsed: &Parsed) -> Result<ScanApi, ExitCode> {
    let Some(dir) = parsed
        .value("dir")
        .map(PathBuf::from)
        .or_else(default_scan_dir)
    else {
        return Err(fail(
            EX_UNAVAILABLE,
            "scans: no scan directory: set HOME or HUNTSMAN_HOME to an absolute path, or pass --dir DIR",
        ));
    };
    let store =
        ScanStore::open(&dir).map_err(|error| fail(EX_IOERR, &format!("scans: {error}")))?;
    // One another live process is still running is left as it is.
    store
        .recover(now_ms())
        .map_err(|error| fail(EX_IOERR, &format!("scans: {error}")))?;
    Ok(ScanApi::new(
        ScanService::new(store, scan_lookup()),
        Some(slot_check()),
    ))
}

/// A subcommand on one saved scan.
fn one_scan(api: &ScanApi, parsed: &Parsed, command: &str, id: &str) -> ExitCode {
    let get = |path: String, query: &str| api.handle("GET", &path, query);
    match command {
        "show" => emit(&get(format!("/api/scans/{id}"), "")),
        "summary" | "correlations" | "log" => emit(&get(
            format!("/api/scans/{id}/{command}"),
            &query(&[("level", parsed.value("level"))]),
        )),
        "elements" => {
            let response = get(
                format!("/api/scans/{id}/elements"),
                &query(&[
                    ("type", parsed.value("types")),
                    ("unique", parsed.on("--unique").then_some("1")),
                    ("hidefp", parsed.on("--hide-fp").then_some("1")),
                ]),
            );
            if parsed.on("--json") || response.status >= 400 {
                return emit(&response);
            }
            print_elements(&serde_json::from_str(&response.body).unwrap_or(Value::Null));
            ExitCode::SUCCESS
        }
        // The rerun runs here, to its end, as `scans run` does.
        "rerun" => rerun(api, id, parsed.on("--json")),
        "delete" => emit(&api.handle("POST", &format!("/api/scans/{id}/delete"), "")),
        _ => fail(EX_USAGE, &format!("scans {command} takes no scan id")),
    }
}

fn now_ms() -> u64 {
    huntsman_recon::entity::unix_now().saturating_mul(1000)
}

fn finished(record: &ScanRecord, json: bool) -> ExitCode {
    if json {
        match serde_json::to_string_pretty(record) {
            Ok(body) => println!("{body}"),
            Err(error) => return fail(EX_IOERR, &format!("scans: {error}")),
        }
    } else {
        print_run(record);
    }
    match record.status {
        ScanStatus::Finished => ExitCode::SUCCESS,
        _ => ExitCode::from(EX_UNAVAILABLE),
    }
}

fn run(api: &ScanApi, parsed: &Parsed, rest: &[&str]) -> ExitCode {
    let [target] = rest else {
        return fail(EX_USAGE, "scans run takes one target");
    };
    let list = |value: Option<&str>| -> Vec<String> {
        value
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect()
    };
    let request = ScanRequest {
        target: (*target).to_owned(),
        name: parsed.owned("name"),
        kind: parsed.owned("kind"),
        options: ScanOptions {
            usecase: parsed.owned("usecase").unwrap_or_else(|| "all".into()),
            modules: Vec::new(),
            types: list(parsed.value("types")),
        },
    };
    match api.service().run(&request) {
        Ok(record) => finished(&record, parsed.on("--json")),
        Err(error) => fail(status_exit(error.status()), &format!("scans: {error}")),
    }
}

fn rerun(api: &ScanApi, id: &str, json: bool) -> ExitCode {
    let service = api.service();
    match service
        .rerun_request(id)
        .and_then(|request| service.run(&request))
    {
        Ok(record) => finished(&record, json),
        Err(error) => fail(status_exit(error.status()), &format!("scans: {error}")),
    }
}

fn export(api: &ScanApi, parsed: &Parsed, rest: &[&str]) -> ExitCode {
    let [ids] = rest else {
        return fail(
            EX_USAGE,
            "scans export takes one scan id, or several comma separated",
        );
    };
    let response = if ids.contains(',') {
        api.handle(
            "GET",
            "/api/scans/export",
            &query(&[
                ("ids", Some(ids)),
                ("format", parsed.value("format")),
                ("type", parsed.value("types")),
            ]),
        )
    } else {
        api.handle(
            "GET",
            &format!("/api/scans/{ids}/export"),
            &query(&[
                ("format", parsed.value("format")),
                ("type", parsed.value("types")),
            ]),
        )
    };
    if response.status >= 400 {
        return emit(&response);
    }
    let Some(path) = parsed.value("output") else {
        print!("{}", response.body);
        return ExitCode::SUCCESS;
    };
    match write_atomic_private(Path::new(path), response.body.as_bytes(), u64::MAX) {
        Ok(()) => {
            eprintln!(
                "scans: wrote {} ({} bytes)",
                one_line(path),
                response.body.len()
            );
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_IOERR, &format!("scans: {error}")),
    }
}
