//! Investigation, search, query, and SpiderFoot-facing adapters.

use std::path::Path;
use std::process::ExitCode;

use crate::cli::{MAX_PLAIN_FILE_BYTES, fail, terminal_json_pretty, usage_error};
use huntsman_recon::classifier::{self, classify as classify_indicator};
use huntsman_recon::clock;
use huntsman_recon::entity;
use huntsman_recon::error::Error;
use huntsman_recon::exa;
use huntsman_recon::keys::Keys;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::lookup_report::{entity_row, evidence_rows};
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::web_query;

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

    let text = if args.first().is_some_and(|arg| arg == "--file") {
        if args.len() != 2 {
            return fail(EX_USAGE, "investigate --file needs exactly one FILE");
        }
        let path = Path::new(&args[1]);
        let bytes = match read_bounded(path, MAX_PLAIN_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
            Err(error) => return fail(EX_DATAERR, &error.to_string()),
        };
        match String::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return fail(EX_DATAERR, "investigate input is not UTF-8"),
        }
    } else {
        if args.iter().any(|arg| arg == "--file") {
            return fail(EX_USAGE, "--file must be the first investigate argument");
        }
        args.join(" ")
    };

    let entities = investigate_entities(&text);
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
                let outcome = if urls.is_empty() { "valid_zero" } else { "success" };
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
    let adaptive = args.first().is_some_and(|arg| arg == "--adaptive");
    let terms = if adaptive { &args[1..] } else { args };
    if terms.is_empty() {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon query [--adaptive] QUERY...",
        );
    }
    let query = terms.join(" ");
    let now = clock::unix_now();
    let transport = UreqTransport::new(&TransportConfig::default());

    if adaptive {
        return match web_query::adaptive_search(&transport, &query, now) {
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

    match web_query::search(&transport, &query, now) {
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

/// The rest of the line is the query, so `sources Ada Lovelace` reads as it does quoted.
pub(in crate::cli) fn sources_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon sources QUERY...");
    }
    let input = args.join(" ");
    let classified = classify_indicator(&input);
    // A handle is routed as written: the classified value drops `.`, `_` and `-`,
    // which would point `@octo-cat` at the account `octocat`.
    let value = if classified.kind == entity::EntityKind::Username {
        input.as_str()
    } else {
        classified.value.as_str()
    };
    // Residual and unsupported kinds have no descriptors, so the empty-route check
    // is the gate. A confidence floor here would drop low-confidence but routable
    // kinds such as `@handle` usernames.
    let routes = routes_for(&classified.kind, value);
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
