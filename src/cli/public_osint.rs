//! Process-layer wiring for keyless, native public OSINT.
use std::process::ExitCode;
use std::time::Duration;

use super::{fail, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::entity;
use huntsman_recon::europe_pmc;
use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::public_osint::{self, Source};
use huntsman_recon::source_outcome::SourceReach;
use huntsman_recon::web_server::{LookupError, LookupQuery, LookupReport};

pub const HELP: &str = "public-osint news|notices|web|dossier|biomed QUERY...\nKeyless GDELT news, FBI notices, public web discovery, and Europe PMC biomedical publications. Read-only leads; not verified attribution or scientific claims.";

fn source_for(input: &str) -> Option<Source> {
    match input {
        "news" => Some(Source::News),
        "notices" => Some(Source::Notices),
        "web" => Some(Source::Web),
        "dossier" => Some(Source::All),
        _ => None,
    }
}

fn transport() -> UreqTransport {
    let config = TransportConfig {
        timeout: Duration::from_secs(16),
        max_body: 512 * 1024,
        ..TransportConfig::default()
    };
    UreqTransport::new(&config)
}

pub(super) fn run(args: &[String]) -> ExitCode {
    let Some((mode, remainder)) = args.split_first() else {
        return fail(EX_USAGE, HELP);
    };
    if mode == "biomed" {
        if remainder.is_empty() {
            return fail(EX_USAGE, HELP);
        }
        let query = remainder.join(" ");
        let scan = entity::scan_id("europe-pmc", &query);
        let report = match europe_pmc::search(&transport(), &query, &scan, clock::unix_now()) {
            Ok(report) => report,
            Err(error) => return fail(EX_DATAERR, error.to_string()),
        };
        match terminal_json_pretty(&report) {
            Ok(rendered) => println!("{rendered}"),
            Err(_) => return fail(EX_DATAERR, "cannot serialize Europe PMC report"),
        }
        return match SourceReach::of(&report.outcomes) {
            SourceReach::Answered => ExitCode::SUCCESS,
            _ => ExitCode::from(EX_UNAVAILABLE),
        };
    }
    let Some(source) = source_for(mode) else {
        return fail(EX_USAGE, HELP);
    };
    if remainder.is_empty() {
        return fail(EX_USAGE, HELP);
    }
    let query = remainder.join(" ");
    let scan = entity::scan_id("public-osint", &query);
    let report = match public_osint::search(&transport(), source, &query, &scan, clock::unix_now())
    {
        Ok(report) => report,
        Err(reason) => return fail(EX_DATAERR, reason),
    };
    match terminal_json_pretty(&report) {
        Ok(rendered) => println!("{rendered}"),
        Err(_) => return fail(EX_DATAERR, "cannot serialize public OSINT report"),
    }
    match SourceReach::of(&report.outcomes) {
        SourceReach::Answered => ExitCode::SUCCESS,
        _ => ExitCode::from(EX_UNAVAILABLE),
    }
}

/// Bridges public-source collectors into the existing guarded /api/lookup
/// handler. Other lookup kinds continue through the current scan router.
pub(super) fn web_lookup(query: &LookupQuery) -> Option<Result<LookupReport, LookupError>> {
    if query.kind == "biomed" {
        return Some((|| {
            let scan = entity::scan_id("europe-pmc", &query.selector);
            let report = europe_pmc::search(
                &transport(),
                &query.selector,
                &scan,
                clock::unix_now(),
            )
            .map_err(|error| LookupError {
                status: 400,
                message: error.to_string(),
            })?;
            let text = huntsman_recon::lookup_report::render(&report.entities, &report.outcomes)
                .map_err(|message| LookupError { status: 500, message })?;
            Ok(LookupReport {
                route: "public-osint",
                text,
                entities: report.entities,
                outcomes: report.outcomes,
                scan: None,
                status: None,
            })
        })());
    }
    let source = source_for(&query.kind)?;
    let scan = entity::scan_id("public-osint", &query.selector);
    Some((|| {
        let report = public_osint::search(
            &transport(),
            source,
            &query.selector,
            &scan,
            clock::unix_now(),
        )
        .map_err(|message| LookupError {
            status: 400,
            message: message.into(),
        })?;
        let text = huntsman_recon::lookup_report::render(&report.entities, &report.outcomes)
            .map_err(|message| LookupError {
                status: 500,
                message,
            })?;
        Ok(LookupReport {
            route: "public-osint",
            text,
            entities: report.entities,
            outcomes: report.outcomes,
            scan: None,
            status: None,
        })
    })())
}
