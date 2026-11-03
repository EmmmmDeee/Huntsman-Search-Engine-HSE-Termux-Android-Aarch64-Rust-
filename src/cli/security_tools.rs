//! CLI adapter over the canonical native Rust security-tool inventory and audit.

use std::path::Path;
use std::process::ExitCode;

use super::{fail, terminal_json_pretty};
use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};
use huntsman_recon::fsio::read_bounded;
use huntsman_recon::security_toolkit;

pub(super) const HELP: &str = "security-tools catalog | security-tools sha256-audit HEX_SHA256 WORDLIST\\n\\
  catalog: the nine security-tool compatibility contracts and honest parity gaps (offline JSON).\\n\\
  sha256-audit: verify local newline-separated candidate bytes against ONE unsalted raw SHA-256 digest (max 2 MiB).\\n\\
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
