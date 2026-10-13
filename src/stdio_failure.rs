//! The exit status a failed write to standard output or standard error becomes.
//!
//! `print!`, `println!`, `eprint!` and `eprintln!` panic when their write fails, and the Rust
//! runtime ignores SIGPIPE. So a reader that stops early, as `head` does, would turn the rest of a
//! run into a panic report and status 101. Each binary installs a panic hook at its process
//! boundary that asks [`status_for`] whether a panic is a failed print and, if so, exits with that
//! status instead. Either way the command stops at the failed write, so a command must write its
//! files before it prints.

use std::any::Any;

use crate::exit::{EX_IOERR, EX_PIPE};

/// How std's panic message for a failed print begins (`std::io::stdio::print_to`).
const PRINT_FAILURES: [&str; 2] = ["failed printing to stdout: ", "failed printing to stderr: "];

/// How std ends an I/O error that is EPIPE, which is 32 on Linux and Android.
const BROKEN_PIPE: &str = "(os error 32)";

/// For a panic payload that reports a failed print, the status to exit with and the I/O error it
/// names: [`EX_PIPE`] when the reader has gone, which is not an error to report, and [`EX_IOERR`]
/// for any other failure, such as a full disk. `None` for every other panic.
#[must_use]
pub fn status_for(payload: &(dyn Any + Send)) -> Option<(u8, &str)> {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())?;
    let error = PRINT_FAILURES
        .iter()
        .find_map(|prefix| message.strip_prefix(prefix))?;
    let status = if error.ends_with(BROKEN_PIPE) {
        EX_PIPE
    } else {
        EX_IOERR
    };
    Some((status, error))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(message: &str) -> Option<u8> {
        let payload: Box<dyn Any + Send> = Box::new(message.to_owned());
        status_for(payload.as_ref()).map(|(status, _)| status)
    }

    #[test]
    fn a_closed_reader_is_the_pipe_status_on_either_stream() {
        for stream in ["stdout", "stderr"] {
            assert_eq!(
                status(&format!(
                    "failed printing to {stream}: Broken pipe (os error 32)"
                )),
                Some(EX_PIPE)
            );
        }
    }

    #[test]
    fn any_other_failed_print_is_an_output_error() {
        assert_eq!(
            status("failed printing to stdout: No space left on device (os error 28)"),
            Some(EX_IOERR)
        );
    }

    #[test]
    fn other_panics_are_left_to_the_previous_hook() {
        assert_eq!(
            status("index out of bounds: the len is 0 but the index is 0"),
            None
        );
        assert_eq!(status("Broken pipe (os error 32)"), None);
        let payload: Box<dyn Any + Send> = Box::new(7_u8);
        assert!(status_for(payload.as_ref()).is_none());
    }

    #[test]
    fn a_static_message_is_read_as_well_as_a_formatted_one() {
        let payload: Box<dyn Any + Send> =
            Box::new("failed printing to stdout: Broken pipe (os error 32)");
        assert_eq!(
            status_for(payload.as_ref()),
            Some((EX_PIPE, "Broken pipe (os error 32)"))
        );
    }
}
