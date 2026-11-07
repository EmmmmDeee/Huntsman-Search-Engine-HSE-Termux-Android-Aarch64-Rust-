//! Investigation, search, query, and SpiderFoot-facing adapters.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::{MAX_PLAIN_FILE_BYTES, fail, terminal_json_pretty, usage_error};
use huntsman_recon::classifier::{self, classify as classify_indicator};
use huntsman_recon::clock;
use huntsman_recon::docmeta;
use huntsman_recon::embedded_metadata;
use huntsman_recon::entity;
use huntsman_recon::error::Error;
use huntsman_recon::exa;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::keys::Keys;
use huntsman_recon::lookup_report::{entity_row, evidence_rows};
use huntsman_recon::phone_intl;
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::web_query::{self, EngineSet};

/// The actionable entities in `text`, each with the classifier's evidence, as `investigate`
/// prints them and `POST /api/investigate` answers them: one authority for both.
pub(in crate::cli) fn investigate_entities(text: &str) -> Vec<entity::Entity> {
    let scan_id = entity::scan_id("investigate", text);
    classifier::extract_entities(text, &scan_id)
}

pub(in crate::cli) fn investigate_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon investigate TEXT... | investigate --file FILE",
        );
    }

    let entities = if args.first().is_some_and(|arg| arg == "--file") {
        if args.len() != 2 {
            return fail(EX_USAGE, "investigate --file needs exactly one FILE");
        }
        let path = Path::new(&args[1]);
        // The metadata readers' own bound: a photo or a document is read whole.
        let bytes = match read_bounded(path, docmeta::MAX_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        };
        match file_entities(path, bytes) {
            Ok(entities) => entities,
            Err((code, message)) => return fail(code, &message),
        }
    } else {
        if args.iter().any(|arg| arg == "--file") {
            return fail(EX_USAGE, "--file must be the first investigate argument");
        }
        investigate_entities(&args.join(" "))
    };

    println!("entities={}", entities.len());
    for entity in &entities {
        println!("{}", entity_row(entity, &entity.raw_value));
        for evidence in &entity.evidence {
            for row in evidence_rows(evidence) {
                println!("{row}");
            }
        }
    }
    ExitCode::SUCCESS
}

/// What `investigate --file` reads in one file. A text file up to [`MAX_PLAIN_FILE_BYTES`] is read
/// as text, and for its embedded metadata too when it carries any; a longer text file is refused as
/// it always was. Any other file, such as a photo or a PDF, is read for its embedded metadata
/// ([`embedded_metadata::inspect`]), which is never removed or rewritten.
fn file_entities(path: &Path, bytes: Vec<u8>) -> Result<Vec<entity::Entity>, (u8, String)> {
    let label = path.display().to_string();
    let metadata = |bytes: &[u8]| {
        embedded_metadata::inspect(bytes, &label, clock::unix_now())
            .map(|inspected| inspected.entities)
            .map_err(|why| (EX_DATAERR, why))
    };
    match String::from_utf8(bytes) {
        Ok(text) => {
            if text.len() as u64 > MAX_PLAIN_FILE_BYTES {
                return Err((
                    EX_NOINPUT,
                    format!("{}: exceeds {MAX_PLAIN_FILE_BYTES} bytes", path.display()),
                ));
            }
            let mut entities = investigate_entities(&text);
            if embedded_metadata::carries_metadata(text.as_bytes()) {
                entities.extend(metadata(text.as_bytes())?);
                entity::merge_by_uid(&mut entities);
            }
            Ok(entities)
        }
        Err(binary) => metadata(binary.as_bytes()),
    }
}

/// The keyless query options, in either order and each at most once: `--adaptive`, and
/// `--all`, which asks every keyless engine instead of the default three. The rest is the
/// query; `None` when it is empty or holds anything flag-like, so a mistyped option is
/// refused rather than sent to search engines as text.
fn parse_query_flags(args: &[String]) -> Option<(bool, EngineSet, &[String])> {
    let mut adaptive = false;
    let mut engines = EngineSet::Default;
    let mut offset = 0;
    while let Some(flag) = args.get(offset).map(String::as_str) {
        match flag {
            "--adaptive" if !adaptive => adaptive = true,
            "--all" if engines == EngineSet::Default => engines = EngineSet::All,
            _ => break,
        }
        offset += 1;
    }
    let terms = &args[offset..];
    (!terms.is_empty() && !terms.iter().any(|term| term.starts_with("--")))
        .then_some((adaptive, engines, terms))
}

pub(in crate::cli) fn query_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon query QUERY...");
    }
    // Exa consumes provider credits: never enable it for ordinary or adaptive
    // queries. The explicit flag is the sole network trigger for this source.
    if args.first().is_some_and(|arg| arg == "--exa") {
        let terms = &args[1..];
        if terms.is_empty() || terms.iter().any(|term| term.starts_with("--")) {
            return fail(EX_USAGE, "usage: huntsman-recon query --exa QUERY...");
        }
        let query = terms.join(" ");
        let home = std::env::var_os("HOME");
        let keys = match Keys::resolve(None, home.as_deref()) {
            Ok(resolved) => resolved.keys,
            Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
        };
        let transport = UreqTransport::new(&TransportConfig::default());
        return match exa::search(&transport, &keys, &query, clock::unix_now()) {
            Ok(urls) => {
                let outcome = if urls.is_empty() {
                    "valid_zero"
                } else {
                    "success"
                };
                println!("engine=exa\toutcome={outcome}\tfound={}", urls.len());
                for url in &urls {
                    println!("exa\t{}\tlead_only", escape_controls(url));
                }
                println!("hits={}", urls.len());
                if urls.is_empty() {
                    ExitCode::from(EX_UNAVAILABLE)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(error) => {
                eprintln!(
                    "engine=exa\toutcome={}\tfound=none",
                    error.outcome_kind().as_str()
                );
                fail(EX_UNAVAILABLE, &error.to_string())
            }
        };
    }
    let Some((adaptive, engines, terms)) = parse_query_flags(args) else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon query [--adaptive] [--all] QUERY...",
        );
    };
    let query = terms.join(" ");
    let now = clock::unix_now();
    let transport = UreqTransport::new(&TransportConfig::default());

    if adaptive {
        return match web_query::adaptive_search(&transport, &query, now, engines) {
            Ok(report) => {
                match terminal_json_pretty(&report) {
                    Ok(serialized) => println!("{serialized}"),
                    Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
                }
                if report.hits.is_empty() {
                    ExitCode::from(EX_UNAVAILABLE)
                } else {
                    ExitCode::SUCCESS
                }
            }
            Err(Error::Invalid(message)) => fail(EX_USAGE, &message),
            Err(Error::Network(message)) => fail(EX_NOPERM, &message),
            Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
        };
    }

    match web_query::search(&transport, &query, now, engines) {
        Ok(report) => {
            print!("{}", report.render());
            if report.hits.is_empty() {
                ExitCode::from(EX_UNAVAILABLE)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(Error::Invalid(message)) => fail(EX_USAGE, &message),
        Err(Error::Network(message)) => fail(EX_NOPERM, &message),
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

pub(in crate::cli) fn sf_cmd(args: &[String]) -> ExitCode {
    let parsed = match SfArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => return usage_error(error, SF_USAGE),
    };
    let action = match sf_compat::action(&parsed) {
        Ok(action) => action,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    match action {
        SfAction::Text(body) => {
            print!("{body}");
            ExitCode::SUCCESS
        }
        // `sf.py -C ID` is `scans correlate ID`, over the same saved scans.
        SfAction::Correlate(id) => crate::cli::scans::scans_cmd(&["correlate".to_owned(), id]),
        SfAction::Scan(scan) => crate::cli::scans::sf_scan(&scan),
        // `sf.py -l IP:PORT` starts its web UI there; `serve` is Huntsman's.
        SfAction::Listen(bind) => crate::cli::service::serve_cmd(&["--bind".to_owned(), bind]),
    }
}

pub(in crate::cli) fn search_cmd(args: &[String]) -> ExitCode {
    let (query, dir) = match args {
        [query] => (query, None),
        [query, dir] => (query, Some(dir)),
        _ => return fail(EX_USAGE, "usage: huntsman-recon search QUERY [DIR]"),
    };
    if tokenize(query).is_empty() {
        return fail(
            EX_USAGE,
            "query has no searchable term (words need two or more letters or digits)",
        );
    }
    let docs = if let Some(dir) = dir {
        match load_dir(Path::new(dir)) {
            Ok(loaded) => {
                for skipped in &loaded.skipped {
                    eprintln!(
                        "skipped\t{}\t{}",
                        escape_controls(&skipped.path),
                        escape_controls(&skipped.reason)
                    );
                }
                loaded.docs
            }
            Err(e) => return fail(EX_NOINPUT, &e.to_string()),
        }
    } else {
        vec![
            Document {
                id: "brisbane".into(),
                body: "Brisbane port radar sighting".into(),
                source: "fixture".into(),
            },
            Document {
                id: "sydney".into(),
                body: "Sydney harbour note".into(),
                source: "fixture".into(),
            },
        ]
    };
    let hits = search(&docs, query);
    if hits.is_empty() {
        println!("hits=0");
    }
    for hit in &hits {
        println!(
            "{}\t{}\t{}",
            hit.score,
            escape_controls(&hit.id),
            escape_controls(&hit.source)
        );
    }
    ExitCode::SUCCESS
}

/// Source-scoped professional/research/register candidate discovery over the shared
/// guarded Rust web-query engines, with the Open Library author leg beside it (or alone,
/// with `--bibliography-only`). The output is *not* an identity attribution.
pub(in crate::cli) fn people_discover_cmd(args: &[String]) -> ExitCode {
    use huntsman_recon::people_discovery::{self, Region};

    let mut region = Region::Au;
    let mut region_seen = false;
    let mut bibliography_only = false;
    let mut name_parts = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--region" if !region_seen => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, people_discovery::PEOPLE_DISCOVER_USAGE);
                };
                let Some(parsed) = Region::parse(value) else {
                    return fail(EX_USAGE, "people-discover --region must be au or us");
                };
                region = parsed;
                region_seen = true;
                index += 2;
            }
            "--region" => return fail(EX_USAGE, "people-discover accepts --region once"),
            "--bibliography-only" if !bibliography_only => {
                bibliography_only = true;
                index += 1;
            }
            "--bibliography-only" => {
                return fail(EX_USAGE, "people-discover accepts --bibliography-only once");
            }
            flag if flag.starts_with('-') => {
                return fail(EX_USAGE, &format!("unknown people-discover option {flag}"));
            }
            name => {
                name_parts.push(name);
                index += 1;
            }
        }
    }
    if name_parts.is_empty() {
        return fail(EX_USAGE, people_discovery::PEOPLE_DISCOVER_USAGE);
    }
    let name = name_parts.join(" ");
    let transport = UreqTransport::new(&TransportConfig::default());
    let now = clock::unix_now();
    let printed = if bibliography_only {
        people_discovery::bibliography(&transport, &name, now)
            .map(|report| print_people_leads(&report, !report.leads.is_empty()))
    } else {
        people_discovery::discover(&transport, &name, region, now).map(|report| {
            let found = !report.candidates.is_empty() || !report.bibliography.leads.is_empty();
            print_people_leads(&report, found)
        })
    };
    match printed {
        Ok(code) => code,
        Err(Error::Invalid(message)) => fail(EX_USAGE, &message),
        Err(Error::Network(message)) => fail(EX_NOPERM, &message),
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

/// Print a people-discovery report as JSON, then exit 0 when some source `found` a lead and
/// 69 when none did: an empty or blocked source is never a confirmed absence.
fn print_people_leads<T: serde::Serialize>(report: &T, found: bool) -> ExitCode {
    match terminal_json_pretty(report) {
        Ok(body) => println!("{body}"),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    }
    if found {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_UNAVAILABLE)
    }
}

/// The rest of the line is the query, so `sources Ada Lovelace` reads as it does quoted.
pub(in crate::cli) fn sources_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon sources QUERY...");
    }
    let input = args.join(" ");
    let mut classified = classify_indicator(&input);
    // In prose one word is never a name, but here it is the whole query the operator typed:
    // `sources Telstra` is a name to search for, routed as an organisation at low confidence.
    if classified.kind == entity::EntityKind::Other
        && !input.contains(char::is_whitespace)
        && input.chars().filter(|c| c.is_alphabetic()).count() >= 2
        && input
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '&' | '\'' | '-'))
    {
        classified.kind = entity::EntityKind::Organisation;
        classified.confidence = 0.30;
    }
    // A handle is routed as written: the classified value drops `.`, `_` and `-`,
    // which would point `@octo-cat` at the account `octocat`.
    let value = if classified.kind == entity::EntityKind::Username {
        input.clone()
    } else if classified.kind == entity::EntityKind::Phone {
        // The generic classifier drops dialling punctuation. Route the same
        // canonical +E.164 value that the actual phone lookup accepts, rather
        // than a digit string whose country prefix could be ambiguous.
        match phone_intl::canonicalize(&input) {
            Some(canonical) => canonical,
            None => {
                return fail(
                    EX_DATAERR,
                    "phone must be explicit international form or a recognised Australian number",
                );
            }
        }
    } else {
        classified.value.clone()
    };
    // Residual and unsupported kinds have no descriptors, so the empty-route check
    // is the gate. A confidence floor here would drop low-confidence but routable
    // kinds such as `@handle` usernames.
    let routes = routes_for(&classified.kind, &value);
    if routes.is_empty() {
        return fail(EX_DATAERR, "no actionable source routes");
    }
    println!(
        "kind={} confidence={:.3} routes={}",
        classified.kind.as_str(),
        classified.confidence,
        routes.len()
    );
    for route in routes {
        println!(
            "source={} execution={} access={} url={}",
            route.source_id,
            route.execution.as_str(),
            route.access.as_str(),
            route.url
        );
    }
    ExitCode::SUCCESS
}

#[cfg(test)]
mod query_flag_tests {
    use super::{EngineSet, parse_query_flags};

    #[test]
    fn the_three_default_engines_unless_all_is_asked_for() {
        fn parse(args: &[&str]) -> Option<(bool, EngineSet, Vec<String>)> {
            let args = args
                .iter()
                .map(|item| (*item).to_owned())
                .collect::<Vec<_>>();
            parse_query_flags(&args)
                .map(|(adaptive, engines, terms)| (adaptive, engines, terms.to_vec()))
        }
        let query = |words: &[&str]| -> Vec<String> {
            words.iter().map(|word| (*word).to_owned()).collect()
        };
        assert_eq!(
            parse(&["topic"]),
            Some((false, EngineSet::Default, query(&["topic"])))
        );
        assert_eq!(
            parse(&["--adaptive", "two", "words"]),
            Some((true, EngineSet::Default, query(&["two", "words"])))
        );
        assert_eq!(
            parse(&["--all", "topic"]),
            Some((false, EngineSet::All, query(&["topic"])))
        );
        for flags in [["--adaptive", "--all"], ["--all", "--adaptive"]] {
            assert_eq!(
                parse(&[flags[0], flags[1], "topic"]),
                Some((true, EngineSet::All, query(&["topic"]))),
                "{flags:?}"
            );
        }
        // A repeated, unknown or misplaced option, or no query, is a usage error.
        for args in [
            &["--all", "--all", "topic"][..],
            &["--adaptive", "--adaptive", "topic"][..],
            &["--fast", "topic"][..],
            &["--adaptive", "--fast", "topic"][..],
            &["--unknown", "topic"][..],
            &["topic", "--all"][..],
            &["--all", "--exa", "topic"][..],
            &["--adaptive"][..],
            &["--all"][..],
        ] {
            assert_eq!(parse(args), None, "{args:?}");
        }
    }
}
