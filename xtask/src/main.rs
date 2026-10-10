//! Repository automation, in Rust. Run as `cargo run --locked -p xtask -- <command>`, or
//! `cargo gate <mode>` for the verification gate.

#![forbid(unsafe_code)]

mod dual_pass;
mod error;
mod gate;
mod install;
mod issue_fix;
mod ops;
mod proc;
mod release;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo run --locked -p xtask -- <command>

commands:
  gate [fast|msrv|full]   the verification gate
  issue-fix ...           the issue-fix path guard, capture, key scan, and publish
  dual-pass ...           the dual-pass planner, red classifier, runner, and publisher
  release ...             the release promotion and release checks
  ops ...                 Railway, Termux acceptance, prerelease cleanup, and lifecycle
  install ...             the Termux installer";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gate") => gate::run(&args[1..]),
        Some("issue-fix") => issue_fix::run(&args[1..]),
        Some("dual-pass") => dual_pass::run(&args[1..]),
        Some("release") => release::run(&args[1..]),
        Some("ops") => ops::run(&args[1..]),
        Some("install") => install::run(&args[1..]),
        Some("-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`");
            error::usage(USAGE)
        }
        None => error::usage(USAGE),
    }
}
