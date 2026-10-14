//! Binary adapter commands. Business logic stays in the library crate.

use std::env;
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

use super::fail;
use huntsman_recon::diagnostics::TermuxState;
use huntsman_recon::environment::SERVE_TOKEN_ENV;
use huntsman_recon::error::Error;
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::runtime::analyze_offline_with_history;
use huntsman_recon::scan_artifact::{ArtifactError, ArtifactHistory};
use huntsman_recon::scan_route::{
    ScanKind, canonical_selector, explicit_people_is_name, infer_kind, inferred_people_is_name,
    parse_kind,
};
use huntsman_recon::web_server::{
    LookupError, LookupQuery, LookupReport, ServeConfig, Server, resolve_serve_bind,
};

use super::lookup::{Refused, collect};

/// Printed once by `serve` under Termux. Android may stop a process that Termux started while
/// Termux is in the background or the screen is off, so the page would stop answering.
const TERMUX_BACKGROUND_HINT: &str = "serve: Android may stop this server while Termux is in the background; run termux-wake-lock to keep it running with the screen off, and on Android 12 or later see \"Keep serve running on Android\" in docs/INSTALL.md";

fn bad_selector(message: &str) -> LookupError {
    LookupError {
        status: 400,
        message: message.into(),
    }
}

/// `/api/analyze`: the offline investigation spine on the seeds, as `plan` runs it, bridged to the
/// saved scans in `history` when `serve --history` gave one.
fn web_analyze(
    seeds: &[String],
    history: Option<&ArtifactHistory>,
) -> Result<serde_json::Value, LookupError> {
    analyze_offline_with_history(seeds, history).map_err(|error| LookupError {
        status: match error {
            Error::Invalid(_) => 422,
            _ => 500,
        },
        message: error.to_string(),
    })
}

/// `/api/lookup` over the same routing and front-ends as `scan`.
fn web_lookup(query: &LookupQuery) -> Result<LookupReport, LookupError> {
    let selector = vec![query.selector.clone()];
    let kind = if query.kind == "auto" {
        let kind = infer_kind(&query.selector);
        if kind == ScanKind::People && !inferred_people_is_name(&selector) {
            return Err(bad_selector(
                "not a name, phone, email, handle, domain, BSSID or LAT,LON; choose a kind to look it up anyway",
            ));
        }
        kind
    } else {
        let kind = parse_kind(&query.kind).map_err(|_| bad_selector("unknown lookup kind"))?;
        if kind == ScanKind::People && !explicit_people_is_name(&selector) {
            return Err(bad_selector("a people lookup needs two alphabetic tokens"));
        }
        kind
    };
    let canonical = canonical_selector(kind, &query.selector)
        .ok_or_else(|| bad_selector("selector is not valid for this kind"))?;
    match collect(kind, &canonical) {
        Ok(found) => Ok(LookupReport {
            route: kind.command(),
            text: found.text,
            entities: found.entities,
            outcomes: found.outcomes,
        }),
        Err(refused) => Err(LookupError {
            status: match refused {
                Refused::Data(_) => 422,
                Refused::Network(_) | Refused::Unavailable(_) => 502,
            },
            message: refused.message().to_owned(),
        }),
    }
}

/// Printed by `serve` on a public bind, where the page and every API call except health need
/// the token, and nothing else tells the operator so. The value is never printed, so it stays
/// out of terminal scrollback and logs.
fn token_hint(addr: std::net::SocketAddr) -> String {
    format!(
        "serve: this public bind needs {SERVE_TOKEN_ENV}: enter its value (echo \"${SERVE_TOKEN_ENV}\") in the page's token field, or open http://{addr}/#token=VALUE once"
    )
}

/// Printed when `HSE_AUTH_TOKEN` is set for a loopback bind, which needs no token, so the
/// operator is not left wondering whether the value guards anything.
fn loopback_token_unused() -> String {
    format!(
        "serve: a loopback bind needs no token, so the page and API answer without {SERVE_TOKEN_ENV}"
    )
}

pub(super) fn serve_cmd(args: &[String]) -> ExitCode {
    let hse_bind = env::var("HSE_BIND").ok();
    let railway_port = env::var("PORT").ok();
    let railway = [
        "RAILWAY_ENVIRONMENT",
        "RAILWAY_ENVIRONMENT_ID",
        "RAILWAY_PROJECT_ID",
        "RAILWAY_SERVICE_ID",
    ]
    .iter()
    .any(|name| env::var_os(name).is_some());
    let mut bind = match resolve_serve_bind(hse_bind.as_deref(), railway_port.as_deref(), railway) {
        Ok(bind) => bind,
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let mut history_dir: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--bind" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --bind needs ADDR");
                };
                bind.clone_from(value);
                index += 2;
            }
            "--history" => {
                let Some(value) = args.get(index + 1) else {
                    return fail(EX_USAGE, "serve --history needs DIR");
                };
                history_dir = Some(value.clone());
                index += 2;
            }
            other => {
                return fail(
                    EX_USAGE,
                    &format!(
                        "unknown serve option: {other}\nusage: huntsman-recon serve [--bind ADDR] [--history DIR]"
                    ),
                );
            }
        }
    }

    // Load the history before the listener binds, so a bad directory stops `serve` at startup
    // instead of failing each analysis. The exit codes match `correlate --history`.
    let history = match history_dir {
        Some(dir) => match ArtifactHistory::open(Path::new(&dir)) {
            Ok(history) => {
                eprintln!(
                    "serve: {} saved scan(s) in {dir} bridge the analysis",
                    history.scan_count()
                );
                Some(std::sync::Arc::new(history))
            }
            Err(ArtifactError::Io(error)) => {
                return fail(EX_NOINPUT, &format!("serve --history: {error}"));
            }
            Err(error) => return fail(EX_DATAERR, &format!("serve --history: {error}")),
        },
        None => None,
    };

    let token = env::var(SERVE_TOKEN_ENV).ok();
    let token_supplied = token.is_some();
    let config = match ServeConfig::parse(&bind, token) {
        Ok(config) => config,
        Err(Error::MissingCredential(message)) => return fail(EX_NOINPUT, &message),
        Err(Error::Invalid(message)) => return fail(EX_DATAERR, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    let config_needs_token = config.needs_token();
    let analyze_history = history.clone();
    let server = match Server::bind(config) {
        Ok(server) => server
            .with_lookup(std::sync::Arc::new(web_lookup))
            .with_analyze(std::sync::Arc::new(move |seeds: &[String]| {
                web_analyze(seeds, analyze_history.as_deref())
            })),
        Err(Error::Store(message)) => return fail(EX_UNAVAILABLE, &message),
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    };
    match server.local_addr() {
        Ok(addr) => {
            println!("serving=http://{addr}/");
            if config_needs_token {
                eprintln!("{}", token_hint(addr));
            } else if token_supplied {
                eprintln!("{}", loopback_token_unused());
            }
            if TermuxState::current() == TermuxState::Detected {
                eprintln!("{TERMUX_BACKGROUND_HINT}");
            }
        }
        Err(error) => return fail(EX_UNAVAILABLE, &error.to_string()),
    }
    // A plain write, not `eprintln!`: once stderr is closed or its reader has gone,
    // `eprintln!` panics, and the notice would end the server it reports on.
    let notice = |error: &std::io::Error| {
        let _ = writeln!(
            std::io::stderr(),
            "serve accept: {error}; waiting for open connections to finish"
        );
    };
    match server.run(notice) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}
