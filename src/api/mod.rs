//! HTTP API (v0.3) — axum server + minimal SPA.
//!
//! The whole tree:
//!
//! * [`handlers`] — the request handlers (one per endpoint).
//! * [`routes`]   — the `Router` definition and the SPA static fallback.
//!
//! Binds to `127.0.0.1` by default (architecture invariant — no LAN exposure).
//! The router is wired in `cli::serve::cmd_serve` (a private `pub(super)` fn).

pub mod handlers;
pub mod key_harvest_handlers;
pub mod routes;
pub mod scan_export;
pub mod scan_handlers;
pub mod settings_handlers;
pub mod update_handlers;

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::{
    core::cancel::CancelHandle, core::engine::ScanEngine, core::event::EventBus,
    core::live::LiveScanner, core::port::StoragePort,
};

/// Registry of in-flight scan cancellations. Keyed by scan_id; the
/// handle in the map IS the same handle plumbed through that scan's
/// `ModuleContext`, so calling `.cancel()` on it stops the live scan
/// at the engine's next cancellation check. Entries are inserted by
/// `scan_create` / `scan_rerun` and removed when the spawned scan
/// task returns. (Issue #23.)
pub type CancelRegistry = Arc<Mutex<HashMap<String, CancelHandle>>>;

/// RAII guard that removes a `CancelRegistry` entry on Drop. Held by
/// the spawned scan task; the entry is removed whether the future
/// returns normally OR panics, so a runaway module that panics can't
/// leak a stale cancel handle into the singleton map. Without this
/// guard a panicking task would leave an `Arc<CancelHandle>` in the
/// map indefinitely (and `POST /scans/{id}/cancel` would 200 instead
/// of 404).
pub struct CancelRegistryGuard {
    registry: CancelRegistry,
    scan_id: String,
}

impl CancelRegistryGuard {
    /// Insert `handle` into `registry` keyed by `scan_id` and return a
    /// guard that removes the entry when dropped.
    pub fn install(registry: CancelRegistry, scan_id: String, handle: CancelHandle) -> Self {
        registry.lock().insert(scan_id.clone(), handle);
        Self { registry, scan_id }
    }
}

impl Drop for CancelRegistryGuard {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.scan_id);
    }
}

/// Live update status — written by the background auto-update task, read by the API
/// handler. Shared via `Arc<std::sync::Mutex<UpdateInfo>>` so the background
/// task and handler can access it independently of the `parking_lot` locks used
/// elsewhere in AppState.
#[derive(Clone, Debug)]
pub struct UpdateInfo {
    /// `None` = not yet checked or offline.
    pub commits_behind: Option<u64>,
    /// Unix seconds of last successful check, or 0 if never checked.
    pub last_checked: u64,
    pub phase: UpdatePhase,
}

/// Current phase of the autonomous update lifecycle.
#[derive(Clone, Debug, PartialEq)]
pub enum UpdatePhase {
    Idle,
    Checking,
    Applying,
    Restarting,
    Error(String),
}

impl Default for UpdateInfo {
    fn default() -> Self {
        Self {
            commits_behind: None,
            last_checked: 0,
            phase: UpdatePhase::Idle,
        }
    }
}

/// Maximum number of scans that can run concurrently via the HTTP API.
pub const MAX_CONCURRENT_SCANS: usize = 8;

/// Bounded grace period for in-flight scans/live sessions to actually reach a
/// terminal state after being cancelled — matches the engine's own documented
/// cooperative-cancellation latency ("~3-8s p99 at the next module-boundary
/// gate", see `core::live::LiveScanner::stop`'s doc comment). Shared by
/// `cli::serve`'s Ctrl-C/SIGTERM shutdown path and every self-restart call
/// site (the autonomous update loop and the manual `/update/trigger`
/// handler), so a binary replacement drains in-flight work exactly like a
/// graceful shutdown does.
pub const SHUTDOWN_DRAIN_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Signal every in-flight scan (`cancellations`) and every running live
/// session (`live`) to stop, then poll until none remain or `grace` elapses —
/// whichever comes first. Reuses the existing cooperative-cancellation
/// primitives (`CancelHandle` / `CancelRegistryGuard` / `LiveScanner::stop`)
/// rather than inventing a new one: a scan's `CancelRegistryGuard` removes its
/// entry from `cancellations` when the spawned task actually returns, and a
/// live session transitions out of `LiveStatus::Running` the same way
/// `DELETE /api/v1/live/{id}` already does — so polling both down to empty is
/// a direct, accurate signal that the in-flight work has genuinely wound
/// down, not just that cancellation was requested. Takes its dependencies
/// directly (not `&AppState`) and `grace` as a parameter (not the
/// [`SHUTDOWN_DRAIN_GRACE`] constant) so both are testable without
/// constructing a full server state or waiting out a real 10-second grace
/// period.
///
/// Called before every process-image replacement — `cli::serve`'s graceful
/// shutdown AND every `self_restart()` call site — because `exec()` swaps the
/// running process out from under any detached `tokio::spawn` task (a scan or
/// live session) with zero cooperative-cancellation opportunity; without
/// draining first, a self-update mid-scan silently abandoned it exactly like
/// an undrained Ctrl-C once did.
pub(crate) async fn drain_in_flight_work(
    cancellations: &CancelRegistry,
    live: &LiveScanner,
    grace: std::time::Duration,
) {
    let scan_count = cancellations.lock().len();
    let live_running: Vec<String> = live
        .list()
        .into_iter()
        .filter(|s| s.status == crate::core::live::LiveStatus::Running)
        .map(|s| s.id)
        .collect();
    if scan_count == 0 && live_running.is_empty() {
        return;
    }
    tracing::info!(
        scans = scan_count,
        live_sessions = live_running.len(),
        "shutdown: signalling in-flight work to stop"
    );

    for handle in cancellations.lock().values() {
        handle.cancel();
    }
    for id in &live_running {
        live.stop(id);
    }

    let deadline = tokio::time::Instant::now() + grace;
    loop {
        let scans_left = cancellations.lock().len();
        let live_left = live
            .list()
            .iter()
            .filter(|s| s.status == crate::core::live::LiveStatus::Running)
            .count();
        if scans_left == 0 && live_left == 0 {
            tracing::info!("shutdown: all in-flight work stopped cleanly");
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            tracing::warn!(
                scans_left,
                live_left,
                "shutdown: grace period elapsed with work still in flight — exiting anyway"
            );
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Application state shared across all HTTP handlers.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn StoragePort>,
    pub engine: Arc<ScanEngine>,
    pub bus: EventBus,
    pub live: LiveScanner,
    pub http: reqwest::Client,
    pub allow_key_write: bool,
    pub cancellations: CancelRegistry,
    /// Bounds the number of scans running concurrently via the API.
    /// Prevents resource exhaustion from rapid `POST /scans` calls.
    pub scan_semaphore: Arc<tokio::sync::Semaphore>,
    /// Shared update status written by the background auto-update task and
    /// read by `GET /api/v1/update/status`. Uses `std::sync::Mutex` (not
    /// `parking_lot`) so it can be held across `.await` points in the
    /// background task without requiring `parking_lot`'s `async`-aware lock.
    pub update_info: Arc<std::sync::Mutex<UpdateInfo>>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
