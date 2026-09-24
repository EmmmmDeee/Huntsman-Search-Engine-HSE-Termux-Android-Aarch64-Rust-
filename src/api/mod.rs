//! HTTP API (v0.3) — axum server + minimal SPA.
//!
//! The whole tree:
//!
//! * [`handlers`] — the request handlers (one per endpoint).
//! * [`routes`]   — the `Router` definition and the SPA static fallback.
//!
//! Binds to `127.0.0.1` by default (architecture invariant — no LAN exposure).
//! The router is wired by the `serve` CLI adapter using the shared runtime from
//! [`crate::app::runtime`].

pub mod assurance_handlers;
pub mod auth;
pub mod cells_handlers;
pub mod handlers;
pub mod key_harvest_handlers;
pub mod live_handlers;
pub mod routes;
pub mod scan_export;
pub mod scan_handlers;
pub mod settings_handlers;
pub mod tiles;
pub mod update_handlers;

use std::sync::Arc;

use crate::{
    core::engine::ScanEngine, core::event::EventBus, core::live::LiveScanner,
    core::port::StoragePort,
};

pub use crate::core::cancel::{CancelRegistry, CancelRegistryGuard, new_cancel_registry};

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

/// Progress of the `hse cells import --country`-equivalent web action
/// (`POST /api/v1/cells/import`), mirroring [`UpdatePhase`]'s shape so
/// `GET /api/v1/cells/status` can report it and the SPA can poll the same
/// way it already polls update status. The DB's own `cell_db::last_import`
/// record (written by the underlying `download_and_import` on success)
/// remains the source of truth for *completed* imports — this only tracks
/// whether one is *currently* running, and the error from the last attempt
/// if it failed, since neither of those live in the DB.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum CellsImportPhase {
    #[default]
    Idle,
    Running,
    Error(String),
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
    /// read by `GET /api/v1/update/status`. Deliberately `std::sync::Mutex`,
    /// NOT `parking_lot` — and precisely because the guard must NEVER be held
    /// across an `.await`: every lock is taken in a synchronous scope (a plain
    /// `fn` like `update_handlers::set_phase`, or a scoped
    /// `if let Ok(mut info) = update_info.lock()` block) *after* any await,
    /// mutated, and dropped. A std `MutexGuard` is `!Send`, so the compiler
    /// REFUSES to let it span an `.await` inside these `Send` spawned tasks —
    /// a compile-time guarantee the async runtime can't be deadlocked by a
    /// guard held across a yield. A `parking_lot` guard IS `Send` and would let
    /// exactly that mistake compile, so it is the more dangerous choice here,
    /// not the "async-aware" one.
    pub update_info: Arc<std::sync::Mutex<UpdateInfo>>,
    /// Progress of an in-flight `POST /api/v1/cells/import`. Same
    /// `std::sync::Mutex` rationale as `update_info`: in the detached
    /// download+import task the guard is acquired *after* the
    /// `download_and_import(..).await` returns (see `cells_handlers`), held only
    /// for the synchronous phase write, and dropped — never across the await.
    pub cells_import: Arc<std::sync::Mutex<CellsImportPhase>>,
    /// Where the Radar view's map tiles come from and are cached
    /// (`/api/v1/tiles/…`, see [`tiles`]). Built once by `hse serve` from the
    /// env var, the data directory and the guarded HTTP client; a test hands
    /// the handler a stand-in upstream and a scratch directory instead.
    pub tiles: Arc<tiles::TileSource>,
}

/// The shared in-memory `AppState` every handler's router test builds on.
///
/// Lifted out of `scan_handlers::tests` when `live_handlers` needed the same
/// thing: two hand-maintained copies of a 25-line state constructor would drift
/// in exactly the way the checks they exercise exist to prevent.
#[cfg(test)]
pub(crate) fn test_state() -> Arc<AppState> {
    test_state_with_modules(Vec::new())
}

/// [`test_state`] with an engine that actually runs `modules` — for tests that
/// need a scan genuinely in flight (see `core::module::test_support::Gated`).
#[cfg(test)]
pub(crate) fn test_state_with_modules(
    modules: Vec<Arc<dyn crate::core::module::Module>>,
) -> Arc<AppState> {
    test_state_with_modules_and_tiles(modules, test_tile_source())
}

/// The tile source every handler test gets unless it brings its own: an
/// upstream that refuses instantly on a closed loopback port, so no test ever
/// reaches a real tile server, and a cache under the test home.
#[cfg(test)]
pub(crate) fn test_tile_source() -> tiles::TileSource {
    tiles::TileSource::new(
        "http://127.0.0.1:9/{z}/{x}/{y}.png",
        crate::util::paths::subdir("tiles"),
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .expect("test client"),
    )
}

/// [`test_state`] with a caller-supplied tile source — for the tile proxy's
/// own tests, which run a stand-in upstream.
#[cfg(test)]
pub(crate) fn test_state_with_tiles(tiles: tiles::TileSource) -> Arc<AppState> {
    test_state_with_modules_and_tiles(Vec::new(), tiles)
}

/// [`test_state`] over a caller-supplied store — for a handler test that needs
/// the store to misbehave (e.g. `core::test_support::RefusingStore`).
#[cfg(test)]
pub(crate) fn test_state_with_store(store: Arc<dyn crate::core::StoragePort>) -> Arc<AppState> {
    test_state_from_parts(Vec::new(), test_tile_source(), store)
}

#[cfg(test)]
fn test_state_with_modules_and_tiles(
    modules: Vec<Arc<dyn crate::core::module::Module>>,
    tiles: tiles::TileSource,
) -> Arc<AppState> {
    let store: Arc<dyn crate::core::StoragePort> =
        Arc::new(crate::storage::Store::open(":memory:").expect("should succeed"));
    test_state_from_parts(modules, tiles, store)
}

#[cfg(test)]
fn test_state_from_parts(
    modules: Vec<Arc<dyn crate::core::module::Module>>,
    tiles: tiles::TileSource,
    store: Arc<dyn crate::core::StoragePort>,
) -> Arc<AppState> {
    let (bus, _rx) = tokio::sync::broadcast::channel(16);
    let engine = Arc::new(crate::core::engine::ScanEngine::new(
        modules,
        Arc::clone(&store),
        bus.clone(),
    ));
    // ONE in-flight registry, shared by `queue_scan` and the live loop.
    let cancellations = new_cancel_registry();
    let live = crate::core::live::LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
        Arc::clone(&cancellations),
    );
    Arc::new(AppState {
        store,
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations,
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SCANS)),
        update_info: Arc::new(std::sync::Mutex::new(UpdateInfo::default())),
        cells_import: Arc::new(std::sync::Mutex::new(CellsImportPhase::default())),
        tiles: Arc::new(tiles),
    })
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
