//! The keyed-module dispatch ledger: a bounded set of already-dispatched
//! (module, target) pairs. Pure bookkeeping — no engine state, no I/O — split
//! out of `engine/mod.rs` so the round loop reads as orchestration while the
//! dedup data structure lives (and is tested) in one focused place, the same
//! convention `circuit`/`timeout`/`dispatch` follow.

use std::collections::{HashSet, VecDeque};

use crate::core::scan::TargetKind;

/// A dispatch key: (module name, target kind, normalised target value).
pub(super) type DispatchKey = (&'static str, TargetKind, String);

/// Upper bound on a [`DispatchLog`]'s size. A per-scan ledger never approaches
/// it; the cap exists for the radar ledger, which persists across iterations of
/// a potentially multi-day session. At ~100k (module, target) triples this is a
/// few MB — well within the 4 GB device budget — and FIFO eviction means only
/// seeds covered long ago can ever be re-queried; recent coverage is retained.
const DISPATCH_LOG_CAP: usize = 100_000;

/// Per-scan log of (module_name, target_kind, normalised_value) triples
/// already dispatched. Prevents the same keyed API from being invoked on
/// the same normalised target across expansion rounds — the primary
/// mechanism that ensures each API key/service is utilised at most once
/// per (target, module) pair in a pivot pipeline.
///
/// Free modules are exempt: their cost is zero and re-running them on the
/// same target across rounds can corroborate entities with fresh evidence.
///
/// Public so a long-running continuous mode (radar) can own ONE ledger and
/// thread it across iterations via
/// [`ScanEngine::run_with_ledger`](super::ScanEngine::run_with_ledger) —
/// keeping a keyed/paid module from re-querying a seed it has already covered,
/// the "don't be aggressive with the APIs" guarantee for real-time radar.
///
/// Bounded with FIFO eviction so a long-lived radar ledger can't grow without
/// limit. The only operation callers need is [`DispatchLog::insert`] (dedup
/// via its bool); [`DispatchLog::remove`] releases a key that was never spent.
#[derive(Debug, Clone)]
pub struct DispatchLog {
    seen: HashSet<DispatchKey>,
    order: VecDeque<DispatchKey>,
    cap: usize,
}

impl Default for DispatchLog {
    fn default() -> Self {
        Self::new()
    }
}

impl DispatchLog {
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            cap: DISPATCH_LOG_CAP,
        }
    }

    /// Record a dispatch. Returns `true` if the key was newly inserted (the
    /// caller should dispatch), `false` if it was already present (skip — the
    /// dedup contract, identical to `HashSet::insert`). When the cap is
    /// exceeded the oldest-inserted key is evicted, so a re-encounter of a
    /// long-evicted seed legitimately dispatches again.
    pub fn insert(&mut self, key: DispatchKey) -> bool {
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        if self.order.len() > self.cap
            && let Some(evicted) = self.order.pop_front()
        {
            self.seen.remove(&evicted);
        }
        true
    }

    /// Remove a key — used when a keyed module dispatched but cleanly opted
    /// out without spending its query (`MissingKey`), so a later round (after
    /// the key-cascade hot-injects the missing key) may legitimately
    /// re-dispatch the same (module, target). Removes from both the set and
    /// the FIFO order so eviction accounting stays exact: leaving a stale
    /// order entry would make a future eviction of that entry delete a
    /// *re-inserted* live key from `seen`.
    pub fn remove(&mut self, key: &DispatchKey) {
        if self.seen.remove(key) {
            self.order.retain(|k| k != key);
        }
    }

    /// Number of keys currently tracked.
    #[must_use]
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True if no keys are tracked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
