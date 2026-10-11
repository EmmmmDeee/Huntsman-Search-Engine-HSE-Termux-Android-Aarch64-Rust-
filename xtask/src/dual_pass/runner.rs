//! The plan stage: red on untouched main, then green within the patch budget. Not ported yet: the work package that owns this file replaces the placeholder.

use std::process::ExitCode;

pub fn run(_args: &[String]) -> ExitCode {
    crate::error::unimplemented("dual-pass run")
}
