//! The path guard: refuses a change the issue-fix agent may not make. Not ported yet: the work package that owns this file replaces the placeholder.

use std::process::ExitCode;

pub fn run(_args: &[String]) -> ExitCode {
    crate::error::unimplemented("issue-fix guard")
}
