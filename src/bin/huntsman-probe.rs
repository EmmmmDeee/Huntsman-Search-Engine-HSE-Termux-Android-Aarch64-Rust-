use std::env;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use huntsman_recon::active_probe::{ProbeOptions, probe};
use huntsman_recon::http::UreqTransport;

const EX_USAGE: u8 = 64;
const EX_UNAVAILABLE: u8 = 69;
const EX_NOPERM: u8 = 77;
const MAX_REQUESTS: usize = 4;
const USAGE: &str = "usage: huntsman-probe --authorized [--max-requests 1..4] URL\n\nBounded authorized active web reconnaissance. Probes only a fixed same-origin surface, reports fingerprints and pivots, and never auto-follows discovered pivots.";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args
        .iter()
        .any(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let parsed = match parse_args(&args) {
        Ok(parsed) => parsed,
        Err(message) => return fail(EX_USAGE, &message),
    };
    if !parsed.authorized {
        return fail(
            EX_NOPERM,
            "active network reconnaissance requires explicit --authorized confirmation",
        );
    }

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let transport = UreqTransport::default();
    let report = match probe(
        &transport,
        &parsed.url,
        &ProbeOptions {
            max_requests: parsed.max_requests,
        },
        now_unix,
    ) {
        Ok(report) => report,
        Err(error) => return fail(EX_UNAVAILABLE, &safe(&error.to_string())),
    };

    println!(
        "base={} requests={}",
        safe(&report.base_url),
        report.requests_made
    );
    println!(
        "fingerprint title={} server={} powered_by={} hsts={} csp={}",
        opt_safe(report.fingerprint.title.as_deref()),
        opt_safe(report.fingerprint.server.as_deref()),
        opt_safe(report.fingerprint.powered_by.as_deref()),
        report.fingerprint.hsts,
        report.fingerprint.csp,
    );
    for observation in &report.observations {
        println!(
            "observation status={} outcome={:?} bytes={} truncated={} requested={} final={}",
            observation
                .status
                .map_or_else(|| "none".to_owned(), |status| status.to_string()),
            observation.outcome,
            observation.bytes,
            observation.truncated,
            safe(&observation.requested_url),
            safe(&observation.final_url),
        );
    }
    for pivot in &report.pivots {
        println!(
            "pivot same_origin={} source={} url={}",
            pivot.same_origin,
            safe(&pivot.source),
            safe(&pivot.url),
        );
    }
    ExitCode::SUCCESS
}

struct Args {
    authorized: bool,
    max_requests: usize,
    url: String,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut authorized = false;
    let mut max_requests = MAX_REQUESTS;
    let mut url: Option<String> = None;
    let mut index = 0usize;

    while index < args.len() {
        match args[index].as_str() {
            "--authorized" => {
                authorized = true;
                index += 1;
            }
            "--max-requests" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(format!("--max-requests requires a value\n{USAGE}"));
                };
                max_requests = value
                    .parse::<usize>()
                    .map_err(|_| format!("invalid --max-requests value: {value}\n{USAGE}"))?;
                if !(1..=MAX_REQUESTS).contains(&max_requests) {
                    return Err(format!(
                        "--max-requests must be between 1 and {MAX_REQUESTS}\n{USAGE}"
                    ));
                }
                index += 2;
            }
            value if value.starts_with('-') => {
                return Err(format!("unknown option: {value}\n{USAGE}"));
            }
            value => {
                if url.replace(value.to_owned()).is_some() {
                    return Err(format!("exactly one URL is required\n{USAGE}"));
                }
                index += 1;
            }
        }
    }

    let url = url.ok_or_else(|| format!("URL is required\n{USAGE}"))?;
    Ok(Args {
        authorized,
        max_requests,
        url,
    })
}

fn fail(code: u8, message: &str) -> ExitCode {
    eprintln!("{}", safe(message));
    ExitCode::from(code)
}

fn opt_safe(value: Option<&str>) -> String {
    value.map_or_else(|| "none".to_owned(), safe)
}

fn safe(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(4096)
        .collect()
}
