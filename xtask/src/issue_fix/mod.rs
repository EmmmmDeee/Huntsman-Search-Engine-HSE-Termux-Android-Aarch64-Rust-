//! Issue-fix automation: the path guard, the capture of the agent's change, the key scan, the prompt, the report, and the publish step.

pub mod capture;
pub mod guard;
pub mod keyscan;
pub mod prompt;
pub mod publish;
pub mod report;

use std::process::ExitCode;

use crate::error;

const USAGE: &str =
    "usage: xtask issue-fix <guard|capture|key-scan|build-prompt|report|publish> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("guard") => guard::run(&args[1..]),
        Some("capture") => capture::run(&args[1..]),
        Some("key-scan") => keyscan::run(&args[1..]),
        Some("build-prompt") => prompt::run(&args[1..]),
        Some("report") => report::run(&args[1..]),
        Some("publish") => publish::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
