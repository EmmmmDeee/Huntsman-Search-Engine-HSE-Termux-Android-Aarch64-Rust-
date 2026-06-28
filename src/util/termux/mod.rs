//! Bridge to the on-device **Termux `termux-*` API tools** — the primary
//! deployment target's sensor/telephony surface (`termux-location`,
//! `termux-wifi-scaninfo`, `termux-telephony-cellinfo`, …).
//!
//! Every call goes through [`termux_cmd`], which runs the helper under a hard
//! timeout and **caches a timeout/spawn failure** for the unavailable TTL so an
//! ungranted permission or absent GPS fix costs its full timeout at most once
//! every few minutes, never once per scan — the single biggest per-scan time sink
//! on a phone. A *prompt* non-zero exit (the tool ran, just had no data) is NOT
//! penalised, so a responsive-but-empty sensor stays live. The unavailable map is
//! process-global, so the skip is shared across concurrent sensor modules and
//! persists across scans on a long-running `hse serve`. Non-Termux platforms
//! simply fail to spawn the tools and degrade cleanly to `None` (cross-platform
//! safe — the sensor modules treat absence as "no signal").
//!
//! Two operator/device-adaptive refinements layer on top of that cache:
//!
//! * The TTL is resolved at call time from `HUNTSMAN_TERMUX_UNAVAIL_TTL`
//!   (seconds), falling back to [`DEFAULT_UNAVAILABLE_TTL`]. An operator who
//!   grants a permission mid-session can set a small value to force a faster
//!   re-probe without restarting `hse serve`.
//! * Each tool's recent *success* latencies feed a rolling estimate
//!   ([`adaptive_timeout_ms`]). On a slow device a tool that consistently
//!   completes just over the caller's fixed budget gets its budget raised
//!   (capped at [`MAX_ADAPTIVE_TIMEOUT_MS`]) instead of being hard-failed and
//!   skipped for minutes on a single unlucky slow sample.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::timeout;

/// Default for how long a `termux-*` tool that timed out or failed to spawn is
/// skipped before we re-probe it (override: `HUNTSMAN_TERMUX_UNAVAIL_TTL`,
/// seconds). This is the single biggest per-scan time sink on a phone: with
/// location/telephony/wifi permission ungranted (or no GPS fix), the sensor
/// tools (`termux-location` 12 s, `termux-wifi-scaninfo` /
/// `termux-telephony-cellinfo` 5 s each) hang for their FULL timeout on every
/// scan — ~20-30 s of dead wait per scan. Caching the failure skips them
/// instantly; the TTL is short enough that granting the permission (or
/// moving outdoors) is picked up within a few minutes on a long-running
/// `hse serve`, so we never permanently disable a sensor.
const DEFAULT_UNAVAILABLE_TTL: Duration = Duration::from_secs(300);

/// Env var (seconds) overriding [`DEFAULT_UNAVAILABLE_TTL`]. An operator who
/// just granted a permission can set this low to force a faster re-probe of a
/// tool that was cached unavailable, without restarting the process. A value
/// of `0` re-probes on the very next call.
const UNAVAILABLE_TTL_ENV: &str = "HUNTSMAN_TERMUX_UNAVAIL_TTL";

/// Parse a TTL override (seconds, as the raw env string) into a [`Duration`],
/// falling back to [`DEFAULT_UNAVAILABLE_TTL`] when the var is unset or not a
/// valid non-negative integer. Split out from the env read so the parsing/
/// fallback contract is unit-testable without mutating process environment
/// (the crate is `#![forbid(unsafe_code)]`, and `set_var` is `unsafe`).
fn unavailable_ttl_from(raw: Option<&str>) -> Duration {
    raw.and_then(|v| v.trim().parse::<u64>().ok())
        .map_or(DEFAULT_UNAVAILABLE_TTL, Duration::from_secs)
}

/// How long a `termux-*` tool stays skipped after a timeout/spawn failure,
/// resolved per call from [`UNAVAILABLE_TTL_ENV`] (seconds) with a fallback to
/// [`DEFAULT_UNAVAILABLE_TTL`]. Read at call time (not cached) so an operator's
/// mid-session change takes effect without a restart; the lookup is a single
/// env read and only happens on the rare failure path.
fn unavailable_ttl() -> Duration {
    unavailable_ttl_from(std::env::var(UNAVAILABLE_TTL_ENV).ok().as_deref())
}

/// Number of recent success latencies retained per tool for the adaptive
/// timeout estimate. Small: a handful of samples smooths out a single slow run
/// while still tracking a genuine device/condition shift quickly.
const LATENCY_WINDOW: usize = 8;

/// Multiplier applied to a tool's recent peak success latency to set its
/// adaptive timeout floor — headroom for a slightly slower-than-usual run.
const LATENCY_HEADROOM: u32 = 2;

/// Hard ceiling on any adaptively-raised timeout. Bounds the worst-case wait so
/// a pathological latency sample can never push a single call past this; well
/// under the unavailable TTL so a truly dead tool still gets cached and skipped.
const MAX_ADAPTIVE_TIMEOUT_MS: u64 = 30_000;

/// `tool name -> instant after which it may be re-probed`. Process-global so
/// the skip persists across scans (the win) and across the concurrent
/// sensor modules that share these tools.
static UNAVAILABLE: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// `tool name -> rolling window of recent success latencies (ms)`. Drives
/// [`adaptive_timeout_ms`] so a merely-slow tool on a slow device gets its
/// caller-supplied budget raised instead of being hard-failed and skipped.
/// Process-global and shared across concurrent sensor modules, like
/// [`UNAVAILABLE`]; bounded by the small fixed set of `termux-*` tool names,
/// each capped at [`LATENCY_WINDOW`] samples.
static LATENCY: LazyLock<Mutex<HashMap<String, VecDeque<u64>>>> =
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
        .insert(cmd.to_string(), Instant::now() + unavailable_ttl());
}

fn mark_available(cmd: &str) {
    UNAVAILABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(cmd);
}

/// Record a clean-exit latency (ms) for `cmd`, keeping the most recent
/// [`LATENCY_WINDOW`] samples. Only successful runs are recorded — a timeout or
/// spawn failure says nothing useful about how long the tool *takes* to succeed.
fn record_latency(cmd: &str, elapsed_ms: u64) {
    let mut map = LATENCY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let window = map.entry(cmd.to_string()).or_default();
    if window.len() == LATENCY_WINDOW {
        window.pop_front();
    }
    window.push_back(elapsed_ms);
}

/// Resolve the effective timeout for `cmd`: the larger of the caller's fixed
/// `requested_ms` budget and an adaptive floor derived from the tool's recent
/// *peak* success latency (× [`LATENCY_HEADROOM`]), clamped to
/// [`MAX_ADAPTIVE_TIMEOUT_MS`]. With no history this is exactly the requested
/// budget, so behaviour is unchanged until a tool has demonstrably succeeded
/// slowly — at which point one unlucky slow sample no longer trips a multi-minute
/// unavailable skip; the call simply waits a bit longer.
fn adaptive_timeout_ms(cmd: &str, requested_ms: u64) -> u64 {
    let peak = LATENCY
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(cmd)
        .and_then(|w| w.iter().copied().max())
        .unwrap_or(0);
    let adaptive = peak.saturating_mul(u64::from(LATENCY_HEADROOM));
    requested_ms
        .max(adaptive)
        .min(MAX_ADAPTIVE_TIMEOUT_MS.max(requested_ms))
}

/// Run a `termux-*` helper with a hard timeout, returning its stdout on a
/// clean exit. A tool that timed out or wouldn't spawn is cached as
/// unavailable for the resolved [`unavailable_ttl`] and short-circuited on
/// subsequent calls — so an ungranted sensor permission costs its full timeout
/// at most once every few minutes, not once per scan.
///
/// The caller's `timeout_ms` is a *floor*: on a slow device, a tool that has
/// recently succeeded slowly gets its budget adaptively raised
/// ([`adaptive_timeout_ms`], capped at [`MAX_ADAPTIVE_TIMEOUT_MS`]) so one
/// unlucky slow sample doesn't mark a working sensor unavailable for minutes.
pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
    if let Some(until) = skip_until(cmd)
        && Instant::now() < until
    {
        tracing::debug!(cmd, "termux_cmd: skipped (recently unavailable)");
        return None;
    }
    let effective_ms = adaptive_timeout_ms(cmd, timeout_ms);
    if effective_ms != timeout_ms {
        tracing::debug!(
            cmd,
            requested_ms = timeout_ms,
            effective_ms,
            "termux_cmd: timeout adapted to recent success latency"
        );
    }
    let started = Instant::now();
    let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
    match timeout(Duration::from_millis(effective_ms), fut).await {
        Err(_) => {
            tracing::debug!(cmd, "termux_cmd: timed out after {effective_ms}ms");
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
            // Clean exit: record how long it actually took so a consistently
            // slow-but-working tool raises its own future timeout floor.
            let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
            record_latency(cmd, elapsed_ms);
            mark_available(cmd);
            Some(output.stdout)
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
