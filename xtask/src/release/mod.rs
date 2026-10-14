//! Release automation: the rolling latest promotion and the secret scan of release inputs. The Termux
//! install check is `tests/release_ci.rs`, which runs `.github/scripts/install-termux.sh` offline.

pub mod promote;
pub mod scan_keys;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask release <promote|scan-keys> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("promote") => promote::run(&args[1..]),
        Some("scan-keys") => scan_keys::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
