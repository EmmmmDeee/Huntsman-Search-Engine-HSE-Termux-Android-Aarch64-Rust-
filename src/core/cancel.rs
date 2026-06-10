//! Cooperative scan cancellation: a cheaply-cloneable flag the engine polls
//! between modules and long-running modules may poll themselves (issue #23).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug, Default)]
pub struct CancelHandle {
    flag: Arc<AtomicBool>,
}

impl CancelHandle {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
    }
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
        b.cancel();
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
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
