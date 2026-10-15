//! Repository automation, in Rust. Run as `cargo run --locked -p xtask -- <command>`, or
//! `cargo gate <mode>` for the verification gate.

mod changelog;
mod coupling;
mod dual_pass;
mod error;
mod gate;
mod issue_fix;
mod ops;
mod proc;
mod release;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo run --locked -p xtask -- <command>

commands:
  gate [fast|msrv|full]   the verification gate
  changelog ...           the changelog fragments: check, assemble, render
  coupling                the crate's coupling clusters, bridges, and co-change pairs
  issue-fix ...           the issue-fix path guard, capture, key scan, and publish
  dual-pass ...           the dual-pass planner, red classifier, runner, and publisher
  release ...             the release promotion and release checks
  ops ...                 Railway checks and prerelease cleanup";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gate") => gate::run(&args[1..]),
        Some("changelog") => changelog::run(&args[1..]),
        Some("coupling") => coupling::run(&args[1..]),
        Some("issue-fix") => issue_fix::run(&args[1..]),
        Some("dual-pass") => dual_pass::run(&args[1..]),
        Some("release") => release::run(&args[1..]),
        Some("ops") => ops::run(&args[1..]),
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
