//! Release automation: the rolling latest promotion, the secret scan of release inputs, and the Termux install check.

pub mod install_check;
pub mod promote;
pub mod scan_keys;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask release <promote|scan-keys|install-check> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("promote") => promote::run(&args[1..]),
        Some("scan-keys") => scan_keys::run(&args[1..]),
        Some("install-check") => install_check::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
