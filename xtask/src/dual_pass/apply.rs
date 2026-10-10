//! Applies a patch, or replaces named Rust functions, for a dual-pass change. Not ported yet: the work package that owns this file replaces the placeholder.

use std::process::ExitCode;

pub fn run(_args: &[String]) -> ExitCode {
    crate::error::unimplemented("dual-pass apply")
}
