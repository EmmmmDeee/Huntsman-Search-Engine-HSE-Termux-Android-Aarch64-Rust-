//! Dual-pass automation: the patch-path reader and the change applier. The planner, the red
//! classifier and the runner are still `scripts/dual-pass/` (Python and shell), which the
//! dual-pass workflow runs.

pub mod apply;
pub mod patch_paths;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask dual-pass <patch-paths|apply> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("patch-paths") => patch_paths::run(&args[1..]),
        Some("apply") => apply::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
