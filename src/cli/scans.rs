//! `scans`: saved Spiderfoot-style scans from the command line. It runs and reads them through the
//! same store, runner and API router as `serve`, so a scan run here shows in the web UI and one
//! started there reads here.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::io::{ErrorKind, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};

use super::fail;
use super::lookup::{Refused, collect};
use huntsman_recon::doctor::STATE_DIR;
use huntsman_recon::environment::HUNTSMAN_HOME_ENV;
use huntsman_recon::exit::{EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_PIPE, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::write_atomic_private;
use huntsman_recon::http::percent_encode_component;
use huntsman_recon::scan_api::{ApiResponse, ScanApi, SlotCheck, correlation_rules};
use huntsman_recon::scan_service::{LookupOutput, ScanLookup, ScanRequest, ScanService};
use huntsman_recon::scan_store::{ScanOptions, ScanRecord, ScanStatus, ScanStore};
use huntsman_recon::sf_compat::{self, SfScan};
use huntsman_recon::sf_correlate;
use huntsman_recon::sf_types;
use huntsman_recon::textnorm::escape_controls;
use serde_json::Value;

pub(super) const SCANS_HELP: &str = "scans run TARGET [-k KIND] [-n NAME] [-u all|footprint|investigate|passive] [-t TYPE[,TYPE...]] [-m MODULE[,MODULE...]] [--depth N] [--json] | scans list [--json] | scans show ID | scans summary ID | scans analyze ID [--json] | scans reality ID ENTITY_UID | scans elements ID [-t TYPE] [--unique] [--hide-fp] [--json] | scans correlations ID [-f csv|tsv|xlsx|json] [-o FILE] [--json] | scans correlate ID [--json] | scans log ID [--level INFO|WARNING|ERROR] | scans export ID|ID,ID... [-f csv|tsv|xlsx|json|gexf] [-t TYPE] [-o FILE] | scans fp ID ELEMENT[,ELEMENT...] [--unset] | scans delete ID | scans rerun ID | scans compare EARLIER LATER [-f csv|tsv|xlsx|json] [-o FILE] [--json] | scans search VALUE [ID...] [-t TYPE] [--hide-fp] [--json] | scans rules [--json] | scans types
Saved scans, as Spiderfoot keeps them: run one on a target, then list, read, export, flag, rerun or delete it. TARGET is anything scan routes (a domain, IP address, email, phone, username, name, BSSID or LAT,LON); -k picks the lookup when the target is ambiguous. A scan keeps every result whole: the lookup's report, every entity with its evidence, every source outcome, its Spiderfoot data elements (see scans types) and its correlations. scans analyze runs shared offline analysis over saved entities without mutating them; derived relations are available, while upstream evidence ancestry and provider coverage cannot be reconstructed and are explicitly marked unavailable. scans reality ID ENTITY_UID gives the recorded attribution, possible conflicting statements and provenance of one stored entity without asserting that its identity, ownership or source independence is proven; both commands refuse evidence flagged false positive. Correlations come from Huntsman's own rules and Spiderfoot 4.0's 37 rules, run unchanged, plus any Spiderfoot-format YAML rule in $HUNTSMAN_HOME/correlations, else ~/.huntsman/correlations, or --rules DIR (a rule there with a shipped rule's id replaces it; one holding only enabled: false turns it off); scans rules lists them and names any file that could not be read, and scans correlate runs them again over a saved scan, after flagging false positives or adding a rule. --depth N follows what the scan finds, as Spiderfoot does: each email, username, domain, phone, IP address and BSSID a lookup finds is looked up in turn, N hops past the target (0, the default, runs the target's lookup only), under the shared lookup and entity budgets; each element then names the element it was found from, so the elements form the scan's discovery tree. -t keeps only those element types; -u passive skips the keyed breach lookup of every email. -m (or --modules) asks only the modules named, by Huntsman's name (see modules) or Spiderfoot's, where sfp_whois stands for every module that does its work: a module not chosen sends nothing, a lookup that asks none of them is skipped, a target none of them looks up is refused, and offline modules always run. fp flags elements as false positives, and with them every element found from them; --unset clears them the same way, refused while an element's source is still flagged. Exports use Spiderfoot's columns (Updated, Type, Module, Source, F/P, Data); xlsx (or excel) is Spiderfoot's workbook, a sheet per element type, with every value whole and never read as a formula; several ids give one export with the Scan Name first, JSON unless -f says csv, tsv or xlsx. compare sets a later scan against an earlier one, which Spiderfoot cannot: the change in each data type, then every element it found that the earlier did not (+) and every one it no longer finds (-), matched by type and value, and the correlations each has that the other lacks; -f writes the added and removed elements as CSV, TSV or Excel. search finds elements in every saved scan, or the scans named, as Spiderfoot's search box reads a query: /regex/ anywhere, a *wildcard* as the whole value, or text anywhere, all regardless of case, in an element's data, its source element's data or its module; -t keeps one type, and an empty VALUE with -t lists that type everywhere. Scans live in $HUNTSMAN_HOME/scans, else ~/.huntsman/scans; every subcommand but rules and types takes --dir DIR. serve shows and starts the same scans. run makes network requests; the others are offline.";

/// The synopsis line of [`SCANS_HELP`], for a usage error.
fn usage() -> &'static str {
    SCANS_HELP.lines().next().unwrap_or(SCANS_HELP)
}

/// The lookup a saved scan runs: the same front-ends as `scan` and `/api/lookup`.
pub(super) fn scan_lookup() -> ScanLookup {
    lookup_with(|refused| refused.message().to_owned())
}

/// [`scan_lookup`], with `refusal` turning a lookup's refusal into the message the scan logs.
fn lookup_with(refusal: impl Fn(Refused) -> String + Send + Sync + 'static) -> ScanLookup {
    Arc::new(move |kind, selector, chosen| {
        collect(kind, selector, chosen)
            .map(|found| LookupOutput {
                text: found.text,
                entities: found.entities,
                outcomes: found.outcomes,
            })
            .map_err(&refusal)
    })
}

/// Whether a key slot holds a key, read from the same places the lookups read keys:
/// `~/.huntsman.env` when it passes the default-file checks, then the environment.
pub(super) fn slot_check() -> SlotCheck {
    Arc::new(|slot| crate::cli::credentials::lookup_keys().get(slot).is_some())
}

/// `$HUNTSMAN_HOME`, else `~/.huntsman`; only an absolute directory counts.
fn state_dir() -> Option<PathBuf> {
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
}

/// `$HUNTSMAN_HOME/scans`, else `~/.huntsman/scans`.
pub(super) fn default_scan_dir() -> Option<PathBuf> {
    state_dir().map(|state| state.join("scans"))
}

/// `$HUNTSMAN_HOME/feeds`, else `~/.huntsman/feeds`: the threat feeds' downloaded copies.
pub(in crate::cli) fn default_feed_dir() -> Option<PathBuf> {
    state_dir().map(|state| state.join("feeds"))
}

/// `$HUNTSMAN_HOME/correlations`, else `~/.huntsman/correlations`: the operator's own
/// Spiderfoot-format correlation rules.
pub(super) fn default_rules_dir() -> Option<PathBuf> {
    state_dir().map(|state| state.join("correlations"))
}

/// The scan store at `dir`, with what a stopped process left running marked `ABORTED`, behind
/// the API router, its scans running Spiderfoot's rules and those in `rules_dir`. `scans` and
/// `serve` both open scans here.
pub(super) fn open_api(dir: &Path, rules_dir: Option<&Path>) -> Result<ScanApi, String> {
    open_api_with(dir, rules_dir, scan_lookup())
}

/// [`open_api`], its scans running `lookup`.
fn open_api_with(
    dir: &Path,
    rules_dir: Option<&Path>,
    lookup: ScanLookup,
) -> Result<ScanApi, String> {
    let store = ScanStore::open(dir).map_err(|error| error.to_string())?;
    // One another live process is still running is left as it is.
    store.recover(now_ms()).map_err(|error| error.to_string())?;
    let (rules, errors) = match rules_dir {
        Some(rules_dir) => sf_correlate::with_dir(rules_dir),
        None => (sf_correlate::shipped().to_vec(), Vec::new()),
    };
    Ok(ScanApi::new(
        ScanService::with_rules(store, lookup, rules, errors),
        Some(slot_check()),
    ))
}

/// Options that take a value, by every spelling, and the name each is read back by.
const VALUED: [(&str, &str); 18] = [
    ("--dir", "dir"),
    ("--depth", "depth"),
    ("--rules", "rules"),
    ("-k", "kind"),
    ("--kind", "kind"),
    ("-n", "name"),
    ("--name", "name"),
    ("-u", "usecase"),
    ("--usecase", "usecase"),
    ("-t", "types"),
    ("--types", "types"),
    ("-m", "modules"),
    ("--modules", "modules"),
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
        let message = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| body["error"].as_str().map(str::to_owned))
            .unwrap_or_else(|| response.text().trim().to_owned());
        return fail(status_exit(response.status), &format!("scans: {message}"));
    }
    let pretty = serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| serde_json::to_string_pretty(&body).ok());
    println!(
        "{}",
        pretty.unwrap_or_else(|| response.text().trim_end().to_owned())
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

/// `scans search`: every element that matches, in every saved scan or the ones named, each
/// with its scan.
fn search(api: &ScanApi, parsed: &Parsed, value: &str, ids: &[&str]) -> ExitCode {
    let ids = ids.join(",");
    let response = api.handle(
        "GET",
        "/api/scans/search",
        &query(&[
            ("value", Some(value)),
            ("type", parsed.value("types")),
            ("ids", Some(ids.as_str()).filter(|ids| !ids.is_empty())),
            ("hidefp", parsed.on("--hide-fp").then_some("1")),
        ]),
    );
    table_or_json(&response, parsed, print_search)
}

fn print_search(rows: &Value) {
    println!("SCAN\tID\tUPDATED\tTYPE\tMODULE\tSOURCE\tF/P\tDATA");
    for row in rows.as_array().into_iter().flatten() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            one_line(row["scan_id"].as_str().unwrap_or_default()),
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
    if command == "rules" {
        return if rest.is_empty() {
            rules_listing(&parsed)
        } else {
            fail(EX_USAGE, "scans rules takes no argument")
        };
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
            print_list(&serde_json::from_slice(&response.body).unwrap_or(Value::Null));
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
        ("compare", [earlier, later]) => compare(&api, &parsed, earlier, later),
        ("reality", [id, uid]) => emit(&api.handle(
            "GET",
            &format!("/api/scans/{id}/reality"),
            &query(&[("uid", Some(uid))]),
        )),
        ("reality", _) => fail(EX_USAGE, "scans reality takes a scan id and entity uid"),
        ("compare", _) => fail(
            EX_USAGE,
            "scans compare takes two scan ids, the earlier first",
        ),
        ("search", [value, ids @ ..]) => search(&api, &parsed, value, ids),
        ("search", []) => fail(
            EX_USAGE,
            "scans search takes what to find (text, *wildcard* or /regex/), then any scan ids",
        ),
        (_, [id]) => one_scan(&api, &parsed, command, id),
        _ => fail(EX_USAGE, &format!("scans {command} takes one scan id")),
    }
}

/// Every `scans` subcommand.
const SUBCOMMANDS: [&str; 18] = [
    "run",
    "list",
    "compare",
    "search",
    "show",
    "summary",
    "analyze",
    "reality",
    "elements",
    "correlations",
    "correlate",
    "log",
    "export",
    "fp",
    "delete",
    "rerun",
    "rules",
    "types",
];

/// The store at `--dir`, or the default one, running the rules in `--rules`, or the default
/// rule directory.
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
    open_api(&dir, rules_dir(parsed).as_deref())
        .map_err(|error| fail(EX_IOERR, &format!("scans: {error}")))
}

fn rules_dir(parsed: &Parsed) -> Option<PathBuf> {
    parsed
        .value("rules")
        .map(PathBuf::from)
        .or_else(default_rules_dir)
}

/// Every correlation rule a scan runs, then each rule file that could not be read; exit 65 when
/// one could not.
fn rules_listing(parsed: &Parsed) -> ExitCode {
    let (rules, errors) = match rules_dir(parsed) {
        Some(dir) => sf_correlate::with_dir(&dir),
        None => (sf_correlate::shipped().to_vec(), Vec::new()),
    };
    let rows = correlation_rules(&rules);
    if parsed.on("--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).unwrap_or_else(|_| rows.to_string())
        );
    } else {
        println!("ID\tRISK\tORIGIN\tNAME");
        for row in rows.as_array().into_iter().flatten() {
            println!(
                "{}\t{}\t{}\t{}",
                one_line(row["id"].as_str().unwrap_or_default()),
                one_line(row["risk"].as_str().unwrap_or_default()),
                one_line(row["origin"].as_str().unwrap_or_default()),
                one_line(row["name"].as_str().unwrap_or_default()),
            );
        }
    }
    for error in &errors {
        eprintln!("scans: {}", one_line(&error.to_string()));
    }
    if errors.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_DATAERR)
    }
}

/// A concise CLI view of the shared analysis. Full output is available via --json;
/// provider coverage and upstream independence are never inferred from merged entities.
fn print_analysis(result: &Value) {
    println!(
        "scan={} status={} target={}",
        one_line(result["scan"]["id"].as_str().unwrap_or_default()),
        one_line(result["scan"]["status"].as_str().unwrap_or_default()),
        one_line(result["scan"]["target"].as_str().unwrap_or_default()),
    );
    let counts = &result["counts"];
    println!(
        "saved_entities={} analyzed_entities={} derived_relations={} source_outcomes={} flagged_elements={}",
        counts["saved_entities"],
        counts["analyzed_entities"],
        counts["derived_relations"],
        counts["source_outcomes"],
        counts["flagged_elements"],
    );
    let limitations = &result["limitations"];
    println!(
        "source=saved_scan_entities scan_complete={} truncated={} evidence_ancestry=not_reconstructed provider_coverage=not_reconstructed false_positive_annotations=none_present",
        limitations["scan_complete"], limitations["truncated"],
    );
    let report = &result["report"];
    println!(
        "coreference={} correlations={} pivots={} termination={}",
        report["coreference"].as_array().map_or(0, Vec::len),
        report["correlations"].as_array().map_or(0, Vec::len),
        report["pivots"].as_array().map_or(0, Vec::len),
        one_line(report["termination"].as_str().unwrap_or("see --json")),
    );
}

fn print_correlations(rows: &Value) {
    println!("ID\tRISK\tRULE\tELEMENTS\tCORRELATION");
    for row in rows.as_array().into_iter().flatten() {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            one_line(row["id"].as_str().unwrap_or_default()),
            one_line(row["risk"].as_str().unwrap_or_default()),
            one_line(row["rule"].as_str().unwrap_or_default()),
            row["elements"].as_array().map_or(0, Vec::len),
            one_line(row["title"].as_str().unwrap_or_default()),
        );
    }
}

/// `scans compare`: the change in each data type, then every element the later scan found that
/// the earlier did not (`+`) and every one it no longer finds (`-`), then the correlations each
/// has that the other lacks. `--json` prints the API's answer; `-f` or `-o` write its file.
fn compare(api: &ScanApi, parsed: &Parsed, earlier: &str, later: &str) -> ExitCode {
    let ids = format!("{earlier},{later}");
    let response = api.handle(
        "GET",
        "/api/scans/compare",
        &query(&[("ids", Some(&ids)), ("format", parsed.value("format"))]),
    );
    if parsed.value("format").is_some() || parsed.value("output").is_some() {
        return deliver(&response, parsed.value("output"));
    }
    table_or_json(&response, parsed, print_comparison)
}

fn print_comparison(compared: &Value) {
    let scan = |side: &str| {
        let row = &compared[side];
        format!(
            "{} {} ({}, {})",
            one_line(row["id"].as_str().unwrap_or_default()),
            one_line(row["name"].as_str().unwrap_or_default()),
            one_line(row["target"].as_str().unwrap_or_default()),
            millis(&row["started"]),
        )
    };
    println!("earlier={}", scan("base"));
    println!("later={}", scan("other"));
    if compared["unchanged"].as_bool() == Some(true) {
        println!("unchanged: both scans found the same values and correlations");
    }
    println!("TYPE\tEARLIER\tLATER\tADDED\tREMOVED\tKEPT");
    for row in compared["types"].as_array().into_iter().flatten() {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            one_line(row["type"].as_str().unwrap_or_default()),
            row["base"],
            row["other"],
            row["added"],
            row["removed"],
            row["kept"],
        );
    }
    for (sign, key) in [("+", "added"), ("-", "removed")] {
        for row in compared[key].as_array().into_iter().flatten() {
            println!(
                "{sign}\t{}\t{}\t{}\t{}",
                one_line(row["type"].as_str().unwrap_or_default()),
                one_line(row["module"].as_str().unwrap_or_default()),
                one_line(row["source_data"].as_str().unwrap_or_default()),
                one_line(row["data"].as_str().unwrap_or_default()),
            );
        }
        for row in compared["correlations"][key]
            .as_array()
            .into_iter()
            .flatten()
        {
            println!(
                "{sign}\tcorrelation\t{}\t{}\t{}",
                one_line(row["risk"].as_str().unwrap_or_default()),
                one_line(row["rule"].as_str().unwrap_or_default()),
                one_line(row["title"].as_str().unwrap_or_default()),
            );
        }
    }
}

/// An API answer as a table, unless `--json` asked for the JSON or it is an error.
fn table_or_json(response: &ApiResponse, parsed: &Parsed, print: fn(&Value)) -> ExitCode {
    if parsed.on("--json") || response.status >= 400 {
        return emit(response);
    }
    print(&serde_json::from_slice(&response.body).unwrap_or(Value::Null));
    ExitCode::SUCCESS
}

/// A subcommand on one saved scan.
fn one_scan(api: &ScanApi, parsed: &Parsed, command: &str, id: &str) -> ExitCode {
    let get = |path: String, query: &str| api.handle("GET", &path, query);
    match command {
        "show" => emit(&get(format!("/api/scans/{id}"), "")),
        "analyze" => {
            let response = get(format!("/api/scans/{id}/analyze"), "");
            table_or_json(&response, parsed, print_analysis)
        }
        "summary" | "log" => emit(&get(
            format!("/api/scans/{id}/{command}"),
            &query(&[("level", parsed.value("level"))]),
        )),
        "correlations" => {
            let response = get(
                format!("/api/scans/{id}/correlations"),
                &query(&[("format", parsed.value("format"))]),
            );
            if parsed.value("format").is_some() {
                deliver(&response, parsed.value("output"))
            } else {
                table_or_json(&response, parsed, print_correlations)
            }
        }
        "correlate" => table_or_json(
            &api.handle("POST", &format!("/api/scans/{id}/correlate"), ""),
            parsed,
            print_correlations,
        ),
        "elements" => {
            let response = get(
                format!("/api/scans/{id}/elements"),
                &query(&[
                    ("type", parsed.value("types")),
                    ("unique", parsed.on("--unique").then_some("1")),
                    ("hidefp", parsed.on("--hide-fp").then_some("1")),
                ]),
            );
            table_or_json(&response, parsed, print_elements)
        }
        // The rerun runs here, to its end, as `scans run` does.
        "rerun" => rerun(api, id, parsed.on("--json")),
        "delete" => emit(&api.handle("POST", &format!("/api/scans/{id}/delete"), "")),
        _ => fail(EX_USAGE, &format!("scans {command} takes no scan id")),
    }
}

fn now_ms() -> u64 {
    huntsman_recon::clock::unix_now().saturating_mul(1000)
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
    let depth = match parsed.value("depth").map(str::parse::<u32>) {
        None => 0,
        Some(Ok(depth)) => depth,
        Some(Err(_)) => return fail(EX_USAGE, "scans run --depth takes a whole number of hops"),
    };
    let request = ScanRequest {
        target: (*target).to_owned(),
        name: parsed.owned("name"),
        kind: parsed.owned("kind"),
        options: ScanOptions {
            usecase: parsed.owned("usecase").unwrap_or_else(|| "all".into()),
            modules: list(parsed.value("modules")),
            types: list(parsed.value("types")),
            depth,
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

/// `sf -s`: one scan of the target, run to its end and saved with the others, as `sf.py` saves
/// its scans, and its elements printed in `sf.py`'s rows. It runs the lookups `scans run` runs for
/// the target, so `scans`, `serve` and `sf -C` read it afterwards. A scan no lookup could run exits
/// with the status the plain lookup gives its refusal.
pub(super) fn sf_scan(scan: &SfScan) -> ExitCode {
    let Some(dir) = default_scan_dir() else {
        return fail(
            EX_UNAVAILABLE,
            "sf: no scan directory: set HOME or HUNTSMAN_HOME to an absolute path",
        );
    };
    let first_refusal = Arc::new(Mutex::new(None::<Refused>));
    let kept = Arc::clone(&first_refusal);
    let lookup = lookup_with(move |refused| {
        let message = refused.message().to_owned();
        kept.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(refused);
        message
    });
    let api = match open_api_with(&dir, default_rules_dir().as_deref(), lookup) {
        Ok(api) => api,
        Err(error) => return fail(EX_IOERR, &format!("sf: {error}")),
    };
    let request = ScanRequest {
        target: scan.target.clone(),
        name: None,
        kind: Some(scan.kind.command().to_owned()),
        options: ScanOptions {
            usecase: scan.use_case.clone(),
            types: scan.types.clone(),
            depth: scan.depth,
            modules: scan.modules.clone(),
        },
    };
    let record = api.service().run(&request);
    if scan.debug {
        if let Ok(record) = &record {
            print_log(api.service().store(), &record.id);
        }
    }
    let record = match record {
        Ok(record) => record,
        // A target the lookup cannot take is bad data, as `sf.py` treats an unusable target.
        Err(error) if error.status() == 400 => return fail(EX_DATAERR, &format!("sf: {error}")),
        Err(error) => return fail(EX_IOERR, &format!("sf: {error}")),
    };
    if record.status != ScanStatus::Finished {
        let refused = first_refusal
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        return match refused {
            Some(refused) => fail(refused.exit_status(), refused.message()),
            None => fail(
                EX_UNAVAILABLE,
                &format!("sf: scan {} ended {}", record.id, record.status.as_str()),
            ),
        };
    }
    let elements = match api.service().store().results(&record.id) {
        Ok(results) => results.map(|results| results.elements).unwrap_or_default(),
        Err(error) => return fail(EX_IOERR, &format!("sf: {error}")),
    };
    match sf_compat::render(&scan.output, &elements) {
        Ok(body) => {
            print!("{body}");
            if !scan.quiet {
                eprintln!(
                    "[INFO] Scan {} saved with {} elements: scans show {} reads it, sf -C {} correlates it again.",
                    record.id, record.elements, record.id, record.id
                );
            }
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_DATAERR, &error.to_string()),
    }
}

/// `sf -d`: the scan's log on stderr, a line per entry, as `sf.py -d` logs as it runs.
fn print_log(store: &ScanStore, id: &str) {
    for entry in store.log(id).unwrap_or_default() {
        eprintln!(
            "[{}] {}: {}",
            entry.level.as_str(),
            one_line(&entry.component),
            one_line(&entry.message)
        );
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
    deliver(&response, parsed.value("output"))
}

/// An export to stdout, or written whole to `output`.
fn deliver(response: &ApiResponse, output: Option<&str>) -> ExitCode {
    if response.status >= 400 {
        return emit(response);
    }
    let Some(path) = output else {
        let mut stdout = std::io::stdout().lock();
        return match stdout
            .write_all(&response.body)
            .and_then(|()| stdout.flush())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) if error.kind() == ErrorKind::BrokenPipe => ExitCode::from(EX_PIPE),
            Err(error) => fail(EX_IOERR, &format!("scans: writing the export: {error}")),
        };
    };
    match write_atomic_private(Path::new(path), &response.body, u64::MAX) {
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
