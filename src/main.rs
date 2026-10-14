//! Process entry point for Huntsman Recon.
//!
//! All CLI parsing and command adapters live under `cli`; the executable root
//! only hands process arguments to that composition layer.

mod cli;

fn main() -> std::process::ExitCode {
    // `args_os`, not `args`: an argument that is not UTF-8 (a file name from shared storage,
    // say) is a usage error for the CLI layer to report, not a panic.
    cli::run(std::env::args_os().skip(1).collect())
}
