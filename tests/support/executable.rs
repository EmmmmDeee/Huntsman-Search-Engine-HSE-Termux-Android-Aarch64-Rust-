//! The one way a test writes a program it then runs: a fake `gh`, `cargo` or `docker`, a sensor
//! shim, a git hook.
//!
//! Writing the file from the test process races running it. The test harness runs tests on
//! several threads, and a child that another thread starts holds a copy of every descriptor from
//! fork until it execs, the write descriptor of a file being written included. Running the file
//! meanwhile fails with ETXTBSY ("Text file busy", os error 26), and it did:
//! `xtask/tests/issue_fix_report.rs` failed one run in a few hundred with
//! `could not start: Text file busy (os error 26)`, as `fakes/gh` had in `tests/release_ci.rs`.
//!
//! [`write_executable`] never opens the file in the test process. A short-lived `sh` child
//! writes it from a pipe and sets its mode, then exits, so the only descriptor that ever had the
//! file open for writing belonged to a single-threaded process that started nothing and has gone
//! by the time the function returns. No lock is needed around the test's own spawns.
//! `tests/executable_policy.rs` refuses a test that sets an execute bit any other way.

#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Writes BODY to PATH (created or truncated) and sets its permission bits to MODE, for example
/// `0o755`. PATH's directory must exist. Panics, naming PATH, if the file cannot be written.
pub fn write_executable(path: &Path, body: impl AsRef<[u8]>, mode: u32) {
    let mut writer = Command::new("sh")
        .args([
            "-c",
            "cat > \"$1\" && chmod \"$2\" \"$1\"",
            "write_executable",
        ])
        .arg(path)
        .arg(format!("{mode:o}"))
        .stdin(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("sh must start to write {}: {error}", path.display()));
    let written = writer
        .stdin
        .take()
        .expect("the writer's standard input is piped")
        .write_all(body.as_ref());
    // The pipe is closed here, so `cat` sees the end of the body and the writer can exit.
    let status = writer
        .wait()
        .unwrap_or_else(|error| panic!("the writer of {} must exit: {error}", path.display()));
    // A writer that failed (a missing directory, say) closes the pipe early, so its exit status is
    // the cause to report, and a refused body only matters when the writer claims success.
    assert!(
        status.success(),
        "{} must be written with mode {mode:o}: the writer exited with {status}",
        path.display()
    );
    written.unwrap_or_else(|error| panic!("the body of {} must be sent: {error}", path.display()));
}
