//! Repository automation, in Rust. Run as `cargo run --locked -p xtask -- <command>`.
//!
//! Commands:
//! - `gate [fast|msrv|full]`: the verification gate. See `gate.rs`.

#![forbid(unsafe_code)]

mod gate;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo run --locked -p xtask -- <command>\n\ncommands:\n  gate [fast|msrv|full]  run the verification gate";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("gate") => gate::run(&args[1..]),
        Some("-h" | "--help") | None => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("xtask: unknown command `{other}`\n{USAGE}");
            ExitCode::from(64)
        }
    }
}
