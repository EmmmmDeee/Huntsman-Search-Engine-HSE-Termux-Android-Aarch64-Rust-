//! Investigation, search, query, and SpiderFoot-facing adapters.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::cli::{
    EX_DATAERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE, MAX_ARTIFACT_BYTES, fail,
};
use huntsman_recon::classifier::{self, classify as classify_indicator};
use huntsman_recon::entity;
use huntsman_recon::error::Error;
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::web_query;

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
        let bytes = match read_bounded(path, MAX_ARTIFACT_BYTES) {
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

    let scan_id = entity::scan_id("investigate", &text);
    let entities = classifier::extract_entities(&text, &scan_id);
    println!("entities={}", entities.len());
    for entity in entities {
        println!(
            "{}\t{}\t{:.2}\t{}",
            entity.kind,
            entity.raw_value,
            entity.confidence,
            entity.tags.join(",")
        );
        for evidence in entity.evidence {
            println!(
                "evidence\t{}\t{}",
                evidence.provenance.source, evidence.summary
            );
        }
    }
    ExitCode::SUCCESS
}

pub(in crate::cli) fn query_cmd(args: &[String]) -> ExitCode {
    if args.is_empty() {
        return fail(EX_USAGE, "usage: huntsman-recon query QUERY...");
    }
    let query = args.join(" ");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());

    match web_query::search(&transport, &query, now) {
        Ok(report) => {
            for outcome in &report.outcomes {
                let kind = serde_json::to_value(outcome.kind)
                    .ok()
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unknown".into());
                println!(
                    "engine={}\toutcome={}\tfound={}",
                    outcome.module,
                    kind,
                    outcome
                        .found
                        .map_or_else(|| "none".to_owned(), |count| count.to_string())
                );
            }
            for hit in &report.hits {
                println!("{}\t{}", hit.engine, hit.url);
            }
            println!("hits={}", report.hits.len());
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
        Err(error) => return fail(EX_USAGE, &format!("{error}\n{SF_USAGE}")),
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
        SfAction::Scan(scan) => {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let transport = UreqTransport::new(&TransportConfig::default());
            match sf_compat::run_scan(&transport, &scan, now) {
                Ok(body) => {
                    print!("{body}");
                    ExitCode::SUCCESS
                }
                Err(Error::Network(message)) => fail(EX_UNAVAILABLE, &message),
                Err(Error::Invalid(message)) => fail(EX_DATAERR, &message),
                Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
            }
        }
    }
}

pub(in crate::cli) fn search_cmd(query: Option<String>, dir: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon search QUERY [DIR]");
    };
    if tokenize(&query).is_empty() {
        return fail(
            EX_USAGE,
            "query has no searchable term (words need two or more letters or digits)",
        );
    }
    let docs = if let Some(dir) = dir {
        match load_dir(Path::new(&dir)) {
            Ok(loaded) => {
                for skipped in &loaded.skipped {
                    eprintln!("skipped\t{}\t{}", skipped.path, skipped.reason);
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
    let hits = search(&docs, &query);
    if hits.is_empty() {
        println!("hits=0");
    }
    for hit in &hits {
        println!("{}\t{}\t{}", hit.score, hit.id, hit.source);
    }
    ExitCode::SUCCESS
}

pub(in crate::cli) fn sources_cmd(query: Option<String>) -> ExitCode {
    let Some(query) = query else {
        return fail(EX_USAGE, "usage: huntsman-recon sources QUERY");
    };
    let classified = classify_indicator(&query);
    // Residual and unsupported kinds have no descriptors, so the empty-route check
    // is the gate. A confidence floor here would drop low-confidence but routable
    // kinds such as `@handle` usernames.
    let routes = routes_for(&classified.kind, &classified.value);
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
