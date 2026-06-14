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
pub mod routes;
pub mod scan_export;
pub mod scan_handlers;
pub mod settings_handlers;

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

/// Maximum number of scans that can run concurrently via the HTTP API.
pub const MAX_CONCURRENT_SCANS: usize = 8;

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
    pub proxy_pool: Arc<crate::util::proxy::ProxyPool>,
    /// Bounds the number of scans running concurrently via the API.
    /// Prevents resource exhaustion from rapid `POST /scans` calls.
    pub scan_semaphore: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
