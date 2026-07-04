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
    /// When present, this handle also reports cancelled once the parent is
    /// cancelled — but its own [`cancel`](CancelHandle::cancel) never sets the
    /// parent. See [`CancelHandle::child`].
    parent: Option<Arc<AtomicBool>>,
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

    /// True once any clone has called [`cancel`](Self::cancel) — OR, for a
    /// [`child`](Self::child), once its parent has been cancelled. The poll point:
    /// the engine checks it between modules and a long-running module may check it
    /// itself. `Acquire` ordering pairs with `cancel`'s `Release`.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
            || self
                .parent
                .as_ref()
                .is_some_and(|p| p.load(Ordering::Acquire))
    }

    /// A child handle that reports cancelled when EITHER it or this (parent)
    /// handle is cancelled, but whose own [`cancel`](Self::cancel) does NOT cancel
    /// the parent.
    ///
    /// This lets a long-running controller give each unit of work a private
    /// deadline handle. A live/radar session gives every iteration `cancel.child()`:
    /// the engine's per-iteration wall-time watchdog trips the CHILD — aborting
    /// only that iteration — while an operator session-stop trips the PARENT and
    /// still aborts the in-flight child at the next poll. So one slow iteration no
    /// longer ends the whole session (it previously tripped the shared handle),
    /// yet Stop stays immediate. Linking is one level: a child observes its direct
    /// parent's flag, not a grandparent's.
    #[must_use]
    pub fn child(&self) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            parent: Some(Arc::clone(&self.flag)),
        }
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
