//! `CancelHandle` — engine-wide cancellation primitive.
//!
//! Cheap-to-clone `Arc<AtomicBool>` wrapper. The engine polls
//! `is_cancelled()` between modules and between expansion rounds; the
//! HTTP cancel endpoint flips the flag via `cancel()` on whichever
//! handle was registered for the scan id.
//!
//! Deliberately poll-only (no async `cancelled().await`) so we don't
//! pull in tokio-util / extra deps. The granularity is one module
//! boundary — currently-running modules finish naturally (or hit their
//! own `max_timeout_ms`). For the typical 3–8 s module budget that's a
//! ~5 s p99 cancel latency, which matches the issue #23 SLA.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Cheaply-cloneable cancellation flag. All clones share the same
/// underlying `AtomicBool`; calling `cancel()` on any one of them
/// flips every clone.
#[derive(Clone, Debug, Default)]
pub struct CancelHandle {
    flag: Arc<AtomicBool>,
}

impl CancelHandle {
    /// Construct a fresh handle in the "not cancelled" state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the flag. Idempotent — calling twice is a no-op.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }

    /// Has anyone called `cancel()`?
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_handle_is_not_cancelled() {
        assert!(!CancelHandle::new().is_cancelled());
    }

    #[test]
    fn cancel_is_observable_through_clones() {
        let a = CancelHandle::new();
        let b = a.clone();
        let c = a.clone();
        assert!(!a.is_cancelled());
        assert!(!b.is_cancelled());
        b.cancel();
        // All clones share the same underlying atomic.
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
        assert!(c.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let h = CancelHandle::new();
        h.cancel();
        h.cancel();
        assert!(h.is_cancelled());
    }

    #[test]
    fn default_is_uncancelled() {
        let h: CancelHandle = Default::default();
        assert!(!h.is_cancelled());
    }
}
