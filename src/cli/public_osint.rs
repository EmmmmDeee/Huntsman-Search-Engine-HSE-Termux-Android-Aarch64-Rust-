//! Process-layer wiring for keyless, native public OSINT.
use std::process::ExitCode;
use std::time::Duration;

use super::{fail, terminal_json_pretty};
use huntsman_recon::clock;
use huntsman_recon::entity;
use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::public_osint::{self, Source};
use huntsman_recon::source_outcome::SourceReach;
use huntsman_recon::web_server::{LookupError, LookupQuery, LookupReport};

pub const HELP: &str = "public-osint news|notices|web|telegram|dossier QUERY...\nKeyless GDELT news, FBI notices, web meta-search, and guarded Telegram public-index discovery. Results are unverified leads, not identity proofs.";

fn source_for(input: &str) -> Option<Source> {
    match input {
        "news" => Some(Source::News),
        "notices" => Some(Source::Notices),
        "web" => Some(Source::Web),
        "dossier" => Some(Source::All),
        _ => None,
    }
}

fn transport_with_timeout(seconds: u64) -> UreqTransport {
    let config = TransportConfig {
        timeout: Duration::from_secs(seconds),
        max_body: 512 * 1024,
        ..TransportConfig::default()
    };
    UreqTransport::new(&config)
}

fn transport() -> UreqTransport {
    transport_with_timeout(16)
}

fn telegram_transport() -> UreqTransport {
    // Four sequential cohorts × three engines × at most two tries each.
    // Five seconds per attempt bounds the normal worst case below the
    // localhost lookup handler's 150-second response deadline.
    transport_with_timeout(5)
}

pub(super) fn run(args: &[String]) -> ExitCode {
    let Some((mode, remainder)) = args.split_first() else {
        return fail(EX_USAGE, HELP);
    };
    if mode != "telegram" && source_for(mode).is_none() {
        return fail(EX_USAGE, HELP);
    }
    if remainder.is_empty() {
        return fail(EX_USAGE, HELP);
    }
    let query = remainder.join(" ");
    let scan = entity::scan_id("public-osint", &query);
    let report = match source_for(mode) {
        Some(source) => public_osint::search(
            &transport(),
            source,
            &query,
            &scan,
            clock::unix_now(),
        ),
        None => public_osint::telegram_index_search(
            &telegram_transport(),
            &query,
            &scan,
            clock::unix_now(),
        ),
    };
    let report = match report {
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
    let source = source_for(&query.kind);
    if source.is_none() && query.kind != "telegram" {
        return None;
    }
    let scan = entity::scan_id("public-osint", &query.selector);
    Some((|| {
        let report = match source {
            Some(source) => public_osint::search(
                &transport(),
                source,
                &query.selector,
                &scan,
                clock::unix_now(),
            ),
            None => public_osint::telegram_index_search(
                &telegram_transport(),
                &query.selector,
                &scan,
                clock::unix_now(),
            ),
        }
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
