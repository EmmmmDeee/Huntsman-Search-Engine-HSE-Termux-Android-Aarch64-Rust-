//! HTTP API (v0.3) — axum server + minimal SPA.
//!
//! The whole tree:
//!
//! * [`handlers`] — the request handlers (one per endpoint).
//! * [`routes`]   — the `Router` definition and the SPA static fallback.
//!
//! Binds to `127.0.0.1` by default (architecture invariant — no LAN exposure).
//! The router is wired in [`crate::cli::cmd_serve`].

pub mod handlers;
pub mod routes;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_registry_guard_installs_and_removes_on_drop() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));
        let handle = CancelHandle::new();

        {
            let _guard =
                CancelRegistryGuard::install(Arc::clone(&registry), "scan-1".into(), handle);
            assert!(registry.lock().contains_key("scan-1"));
        }
        // Guard dropped → entry removed
        assert!(!registry.lock().contains_key("scan-1"));
    }

    #[test]
    fn cancel_registry_guard_cancel_propagates() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));
        let handle = CancelHandle::new();
        let handle_clone = handle.clone();

        let _guard = CancelRegistryGuard::install(Arc::clone(&registry), "scan-2".into(), handle);

        let stored = registry.lock().get("scan-2").cloned().unwrap();
        stored.cancel();
        assert!(handle_clone.is_cancelled());
    }

    #[test]
    fn cancel_registry_guard_multiple_scans_independent() {
        let registry: CancelRegistry = Arc::new(Mutex::new(HashMap::new()));

        let h1 = CancelHandle::new();
        let h2 = CancelHandle::new();

        let guard1 = CancelRegistryGuard::install(Arc::clone(&registry), "s1".into(), h1.clone());
        let _guard2 = CancelRegistryGuard::install(Arc::clone(&registry), "s2".into(), h2.clone());

        assert_eq!(registry.lock().len(), 2);

        drop(guard1);
        assert_eq!(registry.lock().len(), 1);
        assert!(!registry.lock().contains_key("s1"));
        assert!(registry.lock().contains_key("s2"));
    }
}

/// Application state shared across all HTTP handlers. Cloned per request via
/// axum's [`State`](axum::extract::State) extractor.
///
/// Holds four `Arc`'d (or cheaply-cloneable) singletons:
/// * `store` — SQLite WAL store (single connection behind a `parking_lot::Mutex`).
/// * `engine` — the scan engine; its `bus` field is what the SSE handler subscribes to.
/// * `bus` — the same `EventBus` exposed on `ScanEngine`, kept here for convenience
///   when a handler wants to subscribe without going through the engine.
/// * `live` — the live-session registry (v0.5+); manages periodic re-scans.
#[derive(Clone)]
pub struct AppState {
    pub store: Arc<dyn StoragePort>,
    pub engine: Arc<ScanEngine>,
    pub bus: EventBus,
    pub live: LiveScanner,
    /// Shared `reqwest::Client` — internally `Arc`-y so cloning per scan
    /// is cheap. Owning it on `AppState` lets the connection pool, DNS
    /// cache, and TLS session cache survive across scans (a noticeable
    /// win on Termux where TLS handshake cost dominates short scans).
    pub http: reqwest::Client,
    /// Set by `hse serve --allow-key-write`. When false, `PUT /api/v1/settings/keys`
    /// always returns 403 regardless of where the request came from. When true,
    /// the handler still requires the request to originate from a loopback peer.
    pub allow_key_write: bool,
    /// In-flight scan cancellation handles, keyed by scan_id. See
    /// `CancelRegistry` doc.
    pub cancellations: CancelRegistry,
}
