//! Dual-pass automation: the planner, the red classifier, the patch-path reader, the function replace, the runner, and the publisher.

pub mod apply;
pub mod patch_paths;
pub mod plan;
pub mod publisher;
pub mod red_class;
pub mod runner;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask dual-pass <plan|red-class|patch-paths|apply|run|publish> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("plan") => plan::run(&args[1..]),
        Some("red-class") => red_class::run(&args[1..]),
        Some("patch-paths") => patch_paths::run(&args[1..]),
        Some("apply") => apply::run(&args[1..]),
        Some("run") => runner::run(&args[1..]),
        Some("publish") => publisher::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
