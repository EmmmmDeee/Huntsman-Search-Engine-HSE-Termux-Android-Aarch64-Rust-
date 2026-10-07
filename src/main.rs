//! Process entry point for Huntsman Recon.
//!
//! All CLI parsing and command adapters live under `cli`; the executable root
//! only hands process arguments to that composition layer.

mod cli;

fn main() -> std::process::ExitCode {
    cli::run(std::env::args().skip(1).collect())
}
