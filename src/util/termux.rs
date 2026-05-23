//! Termux command helpers.
//!
//! Sensor modules (v0.6+) invoke `termux-*` binaries from the `termux-api`
//! package. If the binary isn't on `PATH` (off-device, or `termux-api`
//! simply not installed), these helpers return `None` rather than erroring
//! — the sensor module then no-ops with an empty `ModuleResult` instead
//! of emitting a `module_error` event.
//!
//! This is the right behaviour because sensors are inherently optional
//! enrichment: a Linux developer or a CI runner shouldn't see scan
//! failures just because `termux-location` doesn't exist on their box.

use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

/// Run a Termux command and return its stdout on success.
///
/// Returns `None` for any of:
///   - the binary doesn't exist on PATH (`Err(NotFound)`)
///   - the command exited non-zero
///   - the configured `timeout_ms` elapsed first
pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
    let fut = Command::new(cmd).args(args).output();
    let output = timeout(Duration::from_millis(timeout_ms), fut)
        .await
        .ok()? // outer timeout
        .ok()?; // spawn/io error (incl. NotFound when termux-api missing)
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}
