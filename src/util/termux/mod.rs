use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::timeout;

/// How long a `termux-*` tool that timed out or failed to spawn is skipped
/// before we re-probe it. This is the single biggest per-scan time sink on a
/// phone: with location/telephony/wifi permission ungranted (or no GPS fix),
/// the sensor tools (`termux-location` 12 s, `termux-wifi-scaninfo` /
/// `termux-telephony-cellinfo` 5 s each) hang for their FULL timeout on every
/// scan — ~20-30 s of dead wait per scan. Caching the failure skips them
/// instantly; the TTL is short enough that granting the permission (or
/// moving outdoors) is picked up within a few minutes on a long-running
/// `hse serve`, so we never permanently disable a sensor.
const UNAVAILABLE_TTL: Duration = Duration::from_secs(300);

/// `tool name -> instant after which it may be re-probed`. Process-global so
/// the skip persists across scans (the win) and across the concurrent
/// sensor modules that share these tools.
static UNAVAILABLE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn skip_until(cmd: &str) -> Option<Instant> {
    UNAVAILABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(cmd)
        .copied()
}

fn mark_unavailable(cmd: &str) {
    UNAVAILABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(cmd.to_string(), Instant::now() + UNAVAILABLE_TTL);
}

fn mark_available(cmd: &str) {
    UNAVAILABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(cmd);
}

/// Run a `termux-*` helper with a hard timeout, returning its stdout on a
/// clean exit. A tool that timed out or wouldn't spawn is cached as
/// unavailable for [`UNAVAILABLE_TTL`] and short-circuited on subsequent
/// calls — so an ungranted sensor permission costs its full timeout at most
/// once every few minutes, not once per scan.
pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
    if let Some(until) = skip_until(cmd)
        && Instant::now() < until
    {
        tracing::debug!(cmd, "termux_cmd: skipped (recently unavailable)");
        return None;
    }
    let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
    match timeout(Duration::from_millis(timeout_ms), fut).await {
        Err(_) => {
            tracing::debug!(cmd, "termux_cmd: timed out after {timeout_ms}ms");
            mark_unavailable(cmd);
            None
        }
        Ok(Err(e)) => {
            tracing::debug!(cmd, error = %e, "termux_cmd: spawn/io failed");
            mark_unavailable(cmd);
            None
        }
        Ok(Ok(output)) if !output.status.success() => {
            // A non-zero exit is a real, prompt run (tool present, just no
            // data / a handled error) — responsive, so do NOT penalise it;
            // clear any stale unavailable mark.
            tracing::debug!(cmd, code = ?output.status.code(), "termux_cmd: non-zero exit");
            mark_available(cmd);
            None
        }
        Ok(Ok(output)) => {
            mark_available(cmd);
            Some(output.stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
