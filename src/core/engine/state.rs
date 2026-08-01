//! Engine state types — the working entity set with dirty-tracking.

use std::collections::{HashMap, HashSet};

use crate::core::entity::Entity;

/// The scan-wide working entity set, wrapping `HashMap<String, Entity>` to
/// track which UIDs were inserted or mutated since the last
/// [`take_dirty`](Self::take_dirty) call.
///
/// Every expansion round used to checkpoint the WHOLE accumulated entity set
/// to storage, every round with dispatch activity — round 50 re-persisted
/// round 1's untouched entities all over again, making the per-round
/// checkpoint cost grow with total accumulated entities, not with what that
/// round actually changed. `take_dirty()` lets the round loop persist only
/// what changed since the last checkpoint instead.
///
/// Only the two mutating operations the engine actually performs on the
/// working set (`insert`, `get_mut`) are wrapped, so dirty-tracking can never
/// be forgotten at a call site — every existing `get_mut` in this engine
/// already writes through the returned reference (verified: none are used
/// read-only), so marking dirty unconditionally on a successful lookup is
/// exactly right for the current call sites, and merely conservative (never
/// incorrect) for a hypothetical future read-only one. Read-only access
/// (`.values()`, `.len()`, `.get()`, `.contains_key()`, iteration, …) goes
/// through [`Deref`](std::ops::Deref) to the inner map, unrestricted — live correlation
/// (`correlate_incremental`) still reads the FULL working set every round,
/// which is correct: a correlation rule can legitimately relate an entity
/// from round 1 to one from round 5, so narrowing correlation's input to
/// only the dirty subset would silently miss cross-round correlations. Only
/// the checkpoint's PERSISTENCE volume is narrowed here, never correlation's
/// input, and never what any reader sees.
#[derive(Default)]
pub struct TrackedEntityMap {
    map: HashMap<String, Entity>,
    dirty: HashSet<String>,
}

impl TrackedEntityMap {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            dirty: HashSet::new(),
        }
    }

    pub fn insert(&mut self, uid: String, entity: Entity) -> Option<Entity> {
        self.dirty.insert(uid.clone());
        self.map.insert(uid, entity)
    }

    pub fn get_mut(&mut self, uid: &str) -> Option<&mut Entity> {
        // Single lookup (previously `contains_key` + `get_mut`, hashing the
        // key twice on this hot path): only mark dirty on an actual hit.
        let entity = self.map.get_mut(uid)?;
        self.dirty.insert(uid.to_string());
        Some(entity)
    }

    /// Snapshot every entity inserted or mutated since the last call (or
    /// since construction), clearing dirty-tracking. Empty if nothing
    /// changed — the caller should skip an empty-result checkpoint exactly
    /// as it already skips one on a round with no dispatch activity.
    pub fn take_dirty(&mut self) -> Vec<Entity> {
        // `drain()`, not `mem::take()`: this runs once per round, and
        // `mem::take` would drop the HashSet's backing allocation and force
        // a fresh one on every round's subsequent inserts. `drain()` clears
        // the set while keeping its capacity for reuse.
        self.dirty
            .drain()
            .filter_map(|uid| self.map.get(&uid).cloned())
            .collect()
    }

    /// Unwrap into the plain map for the one-time final flush
    /// (`finalise_scan` persists everything unconditionally, dirty or not,
    /// so it has no use for dirty-tracking).
    pub fn into_inner(self) -> HashMap<String, Entity> {
        self.map
    }
}

impl std::ops::Deref for TrackedEntityMap {
    type Target = HashMap<String, Entity>;

    fn deref(&self) -> &HashMap<String, Entity> {
        &self.map
    }
}
