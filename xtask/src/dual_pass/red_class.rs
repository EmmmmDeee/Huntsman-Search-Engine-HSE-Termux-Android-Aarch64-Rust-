//! Classifies a failing generated test as a valid red or not. Not ported yet: the work package that owns this file replaces the placeholder.

use std::process::ExitCode;

pub fn run(_args: &[String]) -> ExitCode {
    crate::error::unimplemented("dual-pass red-class")
}
