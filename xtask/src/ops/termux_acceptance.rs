//! The Termux runtime acceptance check. Not ported yet: the work package that owns this file replaces the placeholder.

use std::process::ExitCode;

pub fn run(_args: &[String]) -> ExitCode {
    crate::error::unimplemented("ops termux-acceptance")
}
