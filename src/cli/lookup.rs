//! Binary adapter commands. Business logic stays in the library crate.

use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{
    EX_DATAERR, EX_IOERR, EX_NOINPUT, EX_NOPERM, EX_UNAVAILABLE, EX_USAGE, MAX_ARTIFACT_BYTES, fail,
};
use huntsman_recon::classifier::{self, classify as classify_indicator};
use huntsman_recon::email_cli::{EMAIL_USAGE, EmailArgs, EmailRun};
use huntsman_recon::entity;
use huntsman_recon::error::Error;
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::lookup_save::{self, EMAIL_POLICY, PHONE_POLICY, USERNAME_POLICY};
use huntsman_recon::people_cli::{self, PEOPLE_USAGE, PeopleArgs, PeopleRun};
use huntsman_recon::phone_cli::{PHONE_USAGE, PhoneArgs, PhoneRun};
use huntsman_recon::scan_batch::parse_seed_list;
use huntsman_recon::scan_route::{ScanKind, infer_kind, parse_kind};
use huntsman_recon::search::{Document, load_dir, search, tokenize};
use huntsman_recon::sf_compat::{self, SF_USAGE, SfAction, SfArgs};
use huntsman_recon::source_registry::routes_for;
use huntsman_recon::textnorm::escape_controls;
use huntsman_recon::username_cli::{USERNAME_USAGE, UsernameArgs, UsernameRun};
use huntsman_recon::web_query;

pub(super) fn people_cmd(args: &[String]) -> ExitCode {
    let parsed = match PeopleArgs::parse(args) {
        Ok(p) => p,
        Err(e) => return fail(EX_USAGE, &format!("{e}\n{PEOPLE_USAGE}")),
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match people_cli::run(&transport, &parsed.name, now) {
        PeopleRun::Printed { text, report } => {
            print!("{text}");
            if let Some(path) = parsed.save {
                if report.entities.is_empty() && report.outcomes.is_empty() {
                    return ExitCode::SUCCESS;
                }
                match lookup_save::save(
                    &path,
                    &report.entities,
                    &report.outcomes,
                    lookup_save::PEOPLE_POLICY,
                ) {
                    Ok(entries) => {
                        println!("saved={}", path.display());
                        println!("entries={}", entries.len());
                        println!("tip={}", entries.last().map_or("none", |e| e.hash.as_str()));
                        ExitCode::SUCCESS
                    }
                    Err(Error::Store(msg)) => fail(EX_IOERR, &msg),
                    Err(e) => fail(EX_DATAERR, &e.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
        }
        PeopleRun::Network(msg) => fail(EX_NOPERM, &msg),
        PeopleRun::Failed(msg) => fail(EX_UNAVAILABLE, &msg),
    }
}

pub(super) fn email_cmd(args: &[String]) -> ExitCode {
    let parsed = match EmailArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(err) => {
            let message = err.to_string();
            let code = if message.contains("invalid email address") {
                EX_DATAERR
            } else {
                EX_USAGE
            };
            return fail(code, &format!("{message}\n{EMAIL_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match huntsman_recon::email_cli::run(&transport, &parsed.email, now) {
        EmailRun::Printed { text, report } => {
            print!("{text}");
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, EMAIL_POLICY) {
                    Ok(entries) => {
                        println!("saved={}", path.display());
                        println!("entries={}", entries.len());
                        println!(
                            "tip={}",
                            entries.last().map_or("none", |entry| entry.hash.as_str())
                        );
                        ExitCode::SUCCESS
                    }
                    Err(Error::Store(message)) => fail(EX_IOERR, &message),
                    Err(err) => fail(EX_DATAERR, &err.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
        }
        EmailRun::Network(message) => fail(EX_NOPERM, &message),
        EmailRun::Failed(message) => fail(EX_UNAVAILABLE, &message),
    }
}

pub(super) fn username_cmd(args: &[String]) -> ExitCode {
    let parsed = match UsernameArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let message = error.to_string();
            let code = if message.contains("username selector") {
                EX_DATAERR
            } else {
                EX_USAGE
            };
            return fail(code, &format!("{message}\n{USERNAME_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::new(&TransportConfig::default());
    match huntsman_recon::username_cli::run(&transport, &parsed.username, now) {
        UsernameRun::Printed { text, report } => {
            print!("{text}");
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, USERNAME_POLICY)
                {
                    Ok(entries) => {
                        println!("saved={}", path.display());
                        println!("entries={}", entries.len());
                        println!(
                            "tip={}",
                            entries.last().map_or("none", |entry| entry.hash.as_str())
                        );
                        ExitCode::SUCCESS
                    }
                    Err(Error::Store(message)) => fail(EX_IOERR, &message),
                    Err(error) => fail(EX_DATAERR, &error.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
        }
        UsernameRun::Failed(message) => fail(EX_UNAVAILABLE, &message),
    }
}

pub(super) fn phone_cmd(args: &[String]) -> ExitCode {
    let parsed = match PhoneArgs::parse(args) {
        Ok(parsed) => parsed,
        Err(error) => {
            let message = error.to_string();
            let code =
                if message.contains("phone must") || message.contains("unknown international") {
                    EX_DATAERR
                } else {
                    EX_USAGE
                };
            return fail(code, &format!("{message}\n{PHONE_USAGE}"));
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    match huntsman_recon::phone_cli::run(&parsed.phone, now) {
        PhoneRun::Printed { text, report } => {
            print!("{text}");
            if let Some(path) = parsed.save {
                match lookup_save::save(&path, &report.entities, &report.outcomes, PHONE_POLICY) {
                    Ok(entries) => {
                        println!("saved={}", path.display());
                        println!("entries={}", entries.len());
                        println!(
                            "tip={}",
                            entries.last().map_or("none", |entry| entry.hash.as_str())
                        );
                        ExitCode::SUCCESS
                    }
                    Err(Error::Store(message)) => fail(EX_IOERR, &message),
                    Err(error) => fail(EX_DATAERR, &error.to_string()),
                }
            } else {
                ExitCode::SUCCESS
            }
        }
        PhoneRun::Failed(message) => fail(EX_DATAERR, &message),
    }
}

pub(super) fn scan_cmd(args: &[String]) -> ExitCode {
    let mut kind: Option<&str> = None;
    let mut input_file: Option<&str> = None;
    let mut forwarded = Vec::new();
    let mut index = 0;

    while index < args.len() {
        match args[index].as_str() {
            "-k" | "--kind" => {
                if kind.is_some() {
                    return fail(EX_USAGE, "scan accepts only one -k/--kind");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan -k/--kind needs a value");
                };
                kind = Some(value.as_str());
                index += 2;
            }
            "--input-file" => {
                if input_file.is_some() {
                    return fail(EX_USAGE, "scan accepts only one --input-file");
                }
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "scan --input-file needs a value");
                };
                if value.starts_with("--") {
                    return fail(EX_USAGE, "scan --input-file needs a file path");
                }
                input_file = Some(value.as_str());
                index += 2;
            }
            value => {
                forwarded.push(value.to_owned());
                index += 1;
            }
        }
    }

    if let Some(path) = input_file {
        if !forwarded.is_empty() {
            return fail(
                EX_USAGE,
                "scan --input-file does not accept a positional selector or --save",
            );
        }
        return scan_batch_file(path, kind);
    }

    scan_one(&forwarded, kind)
}

fn scan_batch_file(path: &str, kind: Option<&str>) -> ExitCode {
    let bytes = match read_bounded(Path::new(path), MAX_ARTIFACT_BYTES) {
        Ok(bytes) => bytes,
        Err(Error::Store(message)) => return fail(EX_NOINPUT, &message),
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };
    let Ok(body) = String::from_utf8(bytes) else {
        return fail(EX_DATAERR, "scan --input-file is not UTF-8");
    };
    let seeds = match parse_seed_list(&body) {
        Ok(seeds) => seeds,
        Err(error) => return fail(EX_DATAERR, &error.to_string()),
    };

    let total = seeds.len();
    eprintln!("batch: scanning {total} seed(s) from {path}");
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let mut first_failure = None;

    for (offset, seed) in seeds.iter().enumerate() {
        eprintln!("batch [{}/{}] {}", offset + 1, total, escape_controls(seed));
        let code = scan_one(std::slice::from_ref(seed), kind);
        if code == ExitCode::SUCCESS {
            succeeded += 1;
        } else {
            failed += 1;
            first_failure.get_or_insert(code);
        }
    }

    eprintln!("batch complete: {succeeded} succeeded, {failed} failed, {total} total");
    first_failure.unwrap_or(ExitCode::SUCCESS)
}

fn scan_one(forwarded: &[String], kind: Option<&str>) -> ExitCode {
    let Some(selector) = forwarded.first() else {
        return fail(
            EX_USAGE,
            "usage: huntsman-recon scan SELECTOR [-k people|email|username|phone] [--save FILE] | scan --input-file FILE [-k people|email|username|phone]",
        );
    };
    if selector.starts_with("--") {
        return fail(EX_USAGE, "scan needs SELECTOR before options");
    }

    let route = match kind {
        Some(value) => match parse_kind(value) {
            Ok(kind) => kind,
            Err(other) => return fail(EX_USAGE, &format!("unsupported scan kind: {other}")),
        },
        None => infer_kind(selector),
    };

    eprintln!("scan_route={}", route.command());
    match route {
        ScanKind::Email => email_cmd(forwarded),
        ScanKind::Username => username_cmd(forwarded),
        ScanKind::Phone => phone_cmd(forwarded),
        ScanKind::People => people_cmd(forwarded),
    }
}

pub(super) fn investigate_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn query_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn sf_cmd(args: &[String]) -> ExitCode {
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

pub(super) fn search_cmd(query: Option<String>, dir: Option<String>) -> ExitCode {
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

pub(super) fn sources_cmd(query: Option<String>) -> ExitCode {
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
