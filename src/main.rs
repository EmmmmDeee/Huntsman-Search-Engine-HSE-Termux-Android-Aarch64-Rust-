//! Process entry point for Huntsman Recon.
//!
//! All CLI parsing and command adapters live under `cli`; the executable root
//! only hands process arguments to that composition layer.

mod cli;

fn main() -> std::process::ExitCode {
    // `args()` panics on an argument that is not UTF-8 (a file name from shared storage, say),
    // and a panic here is exit 101 before any hook is set; a bad argument is a usage error.
    let mut argv = Vec::new();
    for (index, arg) in std::env::args_os().skip(1).enumerate() {
        match arg.into_string() {
            Ok(arg) => argv.push(arg),
            Err(raw) => return cli::argument_not_utf8(index + 1, raw.len()),
        }
    }
    cli::run(argv)
}
