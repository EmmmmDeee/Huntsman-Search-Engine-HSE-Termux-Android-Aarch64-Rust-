//! Offline adapter for breach candidate planning and CI-ranked evidence metadata.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;

use huntsman_recon::breach_ci::{FindingInput, USAGE, plan, rank};
use huntsman_recon::dehashed::{Field, Purpose};
use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT, EX_USAGE};

use super::{fail, terminal_json_pretty};

const MAX_EVIDENCE_FILE_BYTES: u64 = 256 * 1024;

pub(super) fn run(args: &[String]) -> ExitCode {
    match args {
        [help] if matches!(help.as_str(), "-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        [command, field, selector, flag, purpose]
            if command == "plan" && flag == "--purpose" =>
        {
            let field = match field.as_str() {
                "email" => Field::Email,
                "username" => Field::Username,
                "domain" => Field::Domain,
                _ => return fail(EX_USAGE, USAGE),
            };
            let Some(purpose) = Purpose::parse(purpose) else {
                return fail(EX_USAGE, "invalid --purpose; see breach-ci --help");
            };
            let report = match plan(field, selector, purpose) {
                Ok(report) => report,
                Err(_) => return fail(EX_DATAERR, "invalid exact-match breach selector"),
            };
            match terminal_json_pretty(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => fail(EX_DATAERR, "breach plan serialization failed"),
            }
        }
        [command, path] if command == "rank" => {
            let path = Path::new(path);
            let metadata = match fs::symlink_metadata(path) {
                Ok(meta) => meta,
                Err(_) => return fail(EX_NOINPUT, "rank input file unavailable"),
            };
            if !metadata.file_type().is_file() || metadata.len() > MAX_EVIDENCE_FILE_BYTES {
                return fail(EX_DATAERR, "rank input must be a regular file of at most 256 KiB");
            }
            let file = match File::open(path) {
                Ok(file) => file,
                Err(_) => return fail(EX_NOINPUT, "rank input file unreadable"),
            };
            let mut bytes = Vec::new();
            if file
                .take(MAX_EVIDENCE_FILE_BYTES + 1)
                .read_to_end(&mut bytes)
                .is_err()
            {
                return fail(EX_NOINPUT, "rank input read failed");
            }
            if bytes.len() > 256 * 1024 {
                return fail(EX_DATAERR, "rank input exceeds 256 KiB");
            }
            let findings: Vec<FindingInput> = match serde_json::from_slice(&bytes) {
                Ok(records) => records,
                Err(_) => return fail(EX_DATAERR, "rank input is not valid evidence-metadata JSON"),
            };
            let report = match rank(findings) {
                Ok(report) => report,
                Err(reason) => return fail(EX_DATAERR, reason),
            };
            match terminal_json_pretty(&report) {
                Ok(json) => {
                    println!("{json}");
                    ExitCode::SUCCESS
                }
                Err(_) => fail(EX_DATAERR, "breach rank serialization failed"),
            }
        }
        _ => fail(EX_USAGE, USAGE),
    }
}
