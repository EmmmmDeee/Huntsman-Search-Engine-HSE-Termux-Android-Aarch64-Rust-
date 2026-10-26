//! Repository automation, in Rust. Run as `cargo run --locked -p xtask -- <command>`, or
//! `cargo gate <mode>` for the verification gate.

mod changelog;
mod completion;
mod coupling;
mod dual_pass;
mod error;
mod fortify;
mod gate;
mod issue_fix;
mod oui;
mod proc;
mod roadmap;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo run --locked -p xtask -- <command>

commands:
  gate [fast|msrv|full]   the verification gate
  fortify ...             policy graph, real status, verification and economics
  changelog ...           the changelog fragments: check, assemble, render
  coupling                the crate's coupling clusters, bridges, and co-change pairs
  completion [print|write|check]   adaptive evidence-limited implementation register
  roadmap [markdown|json|check]  immutable file tree and ordered implementation handoff
  issue-fix ...           the issue-fix path guard, capture, key scan, and publish
  dual-pass ...           the dual-pass patch-path reader and change applier
  oui ...                 pack the IEEE MA-L registry into src/oui_ieee.bin, or dump a blob";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gate") => gate::run(&args[1..]),
        Some("fortify") => fortify::run(&args[1..]),
        Some("changelog") => changelog::run(&args[1..]),
        Some("coupling") => coupling::run(&args[1..]),
        Some("roadmap") => roadmap::run(&args[1..]),
        Some("completion") => completion::run(&args[1..]),
        Some("issue-fix") => issue_fix::run(&args[1..]),
        Some("dual-pass") => dual_pass::run(&args[1..]),
        Some("oui") => oui::run(&args[1..]),
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
