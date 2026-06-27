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

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
