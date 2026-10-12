//! The stderr reporter every command uses for an error.

use std::process::ExitCode;

use huntsman_recon::textnorm::escape_controls_keep_lines;

/// Reports an error on stderr and returns its exit status. The message may echo input from a file or
/// a service, so its control characters are written escaped; its line breaks stay.
pub(super) fn fail(code: u8, msg: &str) -> ExitCode {
    eprintln!("{}", escape_controls_keep_lines(msg));
    ExitCode::from(code)
}
