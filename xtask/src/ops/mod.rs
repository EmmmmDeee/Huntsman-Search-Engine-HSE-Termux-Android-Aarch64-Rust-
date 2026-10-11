//! Operations checks: the Railway checks, the Termux runtime acceptance, the prerelease cleanup, and the lifecycle script.

pub mod cleanup_prereleases;
pub mod lifecycle;
pub mod railway;
pub mod termux_acceptance;

use std::process::ExitCode;

use crate::error;

const USAGE: &str =
    "usage: xtask ops <railway|termux-acceptance|cleanup-prereleases|lifecycle> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("railway") => railway::run(&args[1..]),
        Some("termux-acceptance") => termux_acceptance::run(&args[1..]),
        Some("cleanup-prereleases") => cleanup_prereleases::run(&args[1..]),
        Some("lifecycle") => lifecycle::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
