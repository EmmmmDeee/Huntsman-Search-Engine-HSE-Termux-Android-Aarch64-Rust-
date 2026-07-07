//! Cooperative scan cancellation: a cheaply-cloneable flag the engine polls
//! between modules and long-running modules may poll themselves (issue #23).

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
