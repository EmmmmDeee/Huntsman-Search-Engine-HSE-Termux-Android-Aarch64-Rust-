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

use std::sync::Arc;

use crate::{
    core::engine::ScanEngine, core::event::EventBus, core::live::LiveScanner, storage::store::Store,
};

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
    pub store: Arc<Store>,
    pub engine: Arc<ScanEngine>,
    pub bus: EventBus,
    pub live: LiveScanner,
}
