//! The stderr reporter every command uses for an error, and what a failed print does.

use std::io::Write;
use std::process::ExitCode;

use huntsman_recon::exit::EX_PIPE;
use huntsman_recon::stdio_failure::status_for;
use huntsman_recon::textnorm::escape_controls_keep_lines;

/// Makes a failed write to standard output or standard error end the process with the status
/// `stdio_failure` gives it, rather than a panic: 141 without a message when the reader has gone,
/// 74 with one line otherwise. Every other panic keeps the hook installed before.
pub(super) fn exit_on_output_failure() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let Some((status, error)) = status_for(info.payload()) else {
            previous(info);
            return;
        };
        if status != EX_PIPE {
            // Not eprintln!: a second failed print inside the hook would abort the process.
            let _ = writeln!(std::io::stderr(), "output write failed: {error}");
        }
        std::process::exit(i32::from(status));
    }));
}

/// Reports an error on stderr and returns its exit status. The message may echo input from a file or
/// a service, so its control characters are written escaped; its line breaks stay.
pub(super) fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{}", escape_controls_keep_lines(msg));
    ExitCode::from(code)
}
