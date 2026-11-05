//! CLI adapter over the canonical native Rust security-tool inventory and audit.

use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::http::{TransportConfig, UreqTransport};
use huntsman_recon::security_toolkit;
use huntsman_recon::security_web;
use std::time::Duration;

pub(super) const HELP: &str = "security-tools catalog | security-tools sha256-audit HEX_SHA256 WORDLIST | security-tools headers HTTPS_ORIGIN | security-tools paths HTTPS_ORIGIN WORDLIST --authorized\n\
  catalog: the nine security-tool compatibility contracts and honest parity gaps (offline JSON).\n\
  sha256-audit: verify local newline-separated candidate bytes against ONE unsalted raw SHA-256 digest (max 2 MiB).\n\
  headers: inspect passive HTTPS response security headers, without printing sensitive values.\n\
  paths: 16 or fewer anonymous HTTPS GET probes, 150 ms apart; explicit authority required.\n\
  Nothing is uploaded, candidate text is never printed, no GPU/raw-radio operations are attempted.";

fn print_json<T: serde::Serialize>(value: &T) -> ExitCode {
    match terminal_json_pretty(value) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(error) => fail(EX_UNAVAILABLE, &error.to_string()),
    }
}

pub(super) fn run(args: &[String]) -> ExitCode {
    match args {
        [] => print_json(&security_toolkit::catalog()),
        [mode] if mode == "catalog" => print_json(&security_toolkit::catalog()),
        [mode, origin] if mode == "headers" => {
            let transport = UreqTransport::new(&TransportConfig {
                max_body: 2048,
                timeout: Duration::from_secs(7),
                ..TransportConfig::default()
            });
            match security_web::inspect_headers(&transport, origin) {
                Ok(report) => print_json(&report),
                Err(error) => fail(EX_UNAVAILABLE, &error),
            }
        }
        [mode, origin, file, flag] if mode == "paths" && flag == "--authorized" => {
            let data = match read_bounded(Path::new(file), security_web::MAX_PATHLIST_BYTES) {
                Ok(data) => data,
                Err(error) => return fail(EX_DATAERR, &error.to_string()),
            };
            let transport = UreqTransport::new(&TransportConfig {
                max_body: 2048,
                timeout: Duration::from_secs(7),
                ..TransportConfig::default()
            });
            match security_web::discover_paths(
                &transport,
                origin,
                &data,
                true,
                Duration::from_millis(150),
            ) {
                Ok(report) => print_json(&report),
                Err(error) => fail(EX_DATAERR, &error),
            }
        }
        [mode, digest, file] if mode == "sha256-audit" => {
            let data = match read_bounded(Path::new(file), security_toolkit::MAX_WORDLIST_BYTES) {
                Ok(data) => data,
                Err(error) => return fail(EX_DATAERR, &error.to_string()),
            };
            match security_toolkit::audit_sha256(digest, &data) {
                Ok(report) => print_json(&report),
                Err(error) => fail(EX_DATAERR, &error),
            }
        }
        _ => fail(EX_USAGE, HELP),
    }
}
