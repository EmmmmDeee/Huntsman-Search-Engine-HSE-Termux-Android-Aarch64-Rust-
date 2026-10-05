//! Shared driver for the reconciler's integration suites (`install_invariants`
//! and `reconciler_device`): run `scripts/reconcile.sh` in a fixture and hand
//! back its exit code and parsed `--json` final state. Each test binary
//! compiles this module separately (`mod reconciler_harness;`), hence the
//! allow. One definition, so the two suites cannot drift in how they invoke
//! the script or read its report. Deliberately not `tests/common`, which links
//! the whole library and the HTTP app that these suites never touch.
#![allow(dead_code)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

/// The reconciler under test, from this checkout.
pub fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/reconcile.sh")
}

/// Run the reconciler in `dir` with `args` (the caller includes `--json`) and
/// the given environment overrides. Returns the exit code and the final state.
/// Panics, printing both streams, when the script did not emit JSON: that is
/// a contract violation, not a state a test should reason about.
pub fn run(dir: &Path, args: &[&str], envs: &[(&str, &OsStr)]) -> (i32, serde_json::Value) {
    let mut cmd = Command::new("bash");
    cmd.arg(script()).args(args).current_dir(dir);
    for (key, value) in envs {
        cmd.env(key, value);
    }
    let out = cmd.output().expect("bash");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let json = serde_json::from_str(&stdout).unwrap_or_else(|e| {
        panic!(
            "reconciler emitted non-JSON ({e}):\n--- stdout ---\n{stdout}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().unwrap_or(-1), json)
}
