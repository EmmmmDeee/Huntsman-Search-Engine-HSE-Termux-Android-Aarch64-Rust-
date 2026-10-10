//! Installers: the Termux installer that builds and installs the binary on a handset.

pub mod termux;

use std::process::ExitCode;

use crate::error;

const USAGE: &str = "usage: xtask install <termux> ARGS";

pub fn run(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("termux") => termux::run(&args[1..]),
        _ => error::usage(USAGE),
    }
}
