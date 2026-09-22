//! Cooperative scan cancellation: a cheaply-cloneable flag the engine polls
//! between modules and long-running modules may poll themselves (issue #23).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cheaply-cloneable cooperative-cancellation flag. Every clone shares one
/// atomic via [`Arc`], so a controller (`hse serve`'s cancel endpoint, an operator
/// `Ctrl-C`) can cancel a scan while the engine and modules hold their own clones
/// and poll it. Cooperative, not pre-emptive: cancellation is observed at the next
/// poll point, never mid-instruction.
#[derive(Clone, Debug, Default)]
pub struct CancelHandle {
    flag: Arc<AtomicBool>,
}

impl CancelHandle {
    /// A fresh, un-cancelled handle.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Signal cancellation to every clone. Idempotent. `Release` ordering so the
    /// store publishes before any [`is_cancelled`](Self::is_cancelled) `Acquire`
    /// load can observe it — the standard release/acquire handshake.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// True once any clone has called [`cancel`](Self::cancel). The poll point: the
    /// engine checks it between modules and a long-running module may check it
    /// itself. `Acquire` ordering pairs with `cancel`'s `Release`.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

/// Every scan THIS process is running, keyed by scan id. The handle in the
/// map IS the one plumbed through that scan's `ModuleContext`, so calling
/// `.cancel()` on it stops the scan at the engine's next poll point.
///
/// ONE registry, whichever path spawned the scan: `api::handlers::spawn_scan`
/// installs an entry for a one-shot scan and `core::live`'s session loop
/// installs one per live iteration, each held (via [`CancelRegistryGuard`])
/// from before the engine starts until after its final status write.
/// Everything that asks "is this scan in flight here?" — `POST
/// /scans/{id}/cancel`, the `DELETE /scans/{id}` in-flight refusal, the
/// shutdown drain, and the read-time `interrupted` derivation
/// (REQ-SCANSTATUS-001) — reads this map and nothing else.
///
/// It lives in `core` rather than `api` because the live loop must populate
/// it. When only `spawn_scan` did, a live iteration's scan was invisible to
/// all four consumers: not cancellable by scan id, deletable mid-run (the
/// exact race the delete refusal documents), and reported `interrupted` by
/// the very process running it. (Issue #23.)
pub type CancelRegistry = Arc<parking_lot::Mutex<HashMap<String, CancelHandle>>>;

/// A fresh, empty [`CancelRegistry`]. One per process: `AppState` and the
/// `LiveScanner` it owns must share the SAME instance, or the live loop's
/// entries land in a map nothing reads.
#[must_use]
pub fn new_cancel_registry() -> CancelRegistry {
    Arc::new(parking_lot::Mutex::new(HashMap::new()))
}

/// RAII guard that removes a [`CancelRegistry`] entry on Drop. Held by the
/// task running the scan; the entry is removed whether the future returns
/// normally OR panics, so a runaway module that panics can't leak a stale
/// cancel handle into the process-wide map. Without this guard a panicking
/// task would leave an `Arc<CancelHandle>` in the map indefinitely (and
/// `POST /scans/{id}/cancel` would 200 instead of 404).
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

/// Compile-time proof that `CancelHandle` stays `Send + Sync + 'static`.
///
/// These bounds are load-bearing, not incidental: the engine shares one handle
/// across `tokio` tasks — `ModuleContext` (which owns a `CancelHandle`) is
/// `Arc`-wrapped and moved into `set.spawn(async move { … })` in
/// `core::engine::dispatch` — and the operator's cancel controller lives on a
/// different task from the polling modules. A future field that is not
/// `Send`/`Sync`/`'static` (an `Rc`, a `RefCell`, a borrowed reference) would
/// silently break cancellation across tasks, or fail to compile far away at the
/// spawn site with an opaque error. This assertion localises that guarantee to
/// the type it belongs to, turning any regression into an error right here.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<CancelHandle>();
};

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
