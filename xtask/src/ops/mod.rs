//! Operations checks: the Railway checks and the prerelease cleanup. The Termux acceptance harness
//! and the lifecycle script stay shell (`scripts/`): they run on a phone with no checkout.

pub mod cleanup_prereleases;
pub mod railway;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask ops <railway|cleanup-prereleases> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("railway") => railway::run(&args[1..]),
        Some("cleanup-prereleases") => cleanup_prereleases::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
