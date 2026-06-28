//! Multi-key pool manager with per-service cycling, validation, and
//! rate-limit awareness. Complements `util/keys.rs` (single env-var
//! keys) by supporting multiple keys per service with intelligent
//! rotation.
//!
//! The pool is the **self-funding** core: keys HSE harvests while scanning are
//! reusable by the cascade regardless of provenance. Selection
//! ([`KeyPool::next_key`]) load-spreads across usable keys and prefers proven,
//! [`KeyEntry::corroboration`]-confirmed credentials on a tie; live confirmation
//! ([`add_and_validate`]) settles a key's status, corroborates it, and also
//! records it in the cross-scan retention bank
//! ([`crate::util::key_vault::record_verification`]) as a verified duplicate.
//! Corroborated keys are retained preferentially by [`KeyPool::prune_degraded`].
//!
//! Module layout (topological, leaves first):
//! * [`types`] — `KeyEntry` / `KeyStatus` / `KeyTier` and per-key scoring;
//! * [`pool`] — the in-memory `KeyPool` and all mutation/selection;
//! * [`persistence`] — atomic load/save with single-entry lenient salvage;
//! * [`validation`] — async live endpoint probe and `add_and_validate`.
//!
//! Storage: `$HOME/.huntsman/key_pool.json` (mode 0600).

pub mod persistence;
pub mod pool;
pub mod types;
pub mod validation;

pub use persistence::{load_pool, pool_path, save_pool, save_pool_best_effort, write_secret_file};
pub use pool::{KeyPool, PoolData, ServiceHealth, StatusBreakdown};
pub use types::{KeyEntry, KeyStatus, KeyTier, key_id};
pub use validation::{add_and_validate, merge_pool_into_env, validate_key};

// Re-export service_defs items so existing call-sites that reach through
// `key_pool::find_service` / `key_pool::service_defs` continue to compile.
pub use crate::util::service_defs::{KeyPlacement, ServiceDef, find_service, service_defs};

// ── Shared pool singleton ────────────────────────────────────────────────────

static GLOBAL_POOL: std::sync::OnceLock<std::sync::Arc<KeyPool>> = std::sync::OnceLock::new();

/// The process-wide key pool, loaded from disk on first access and shared
/// thereafter via a cheap `Arc` clone.
///
/// Loaded exactly once ([`std::sync::OnceLock`]); every caller observes the same
/// [`KeyPool`], whose interior mutability (a `Mutex<PoolData>`) lets overlapping
/// `hse serve` scans harvest and rotate keys concurrently against one shared
/// store. Mutations are persisted explicitly by the caller via [`save_pool`] /
/// [`save_pool_best_effort`]; the singleton itself is never reloaded, so an
/// on-disk edit takes effect on the next process start.
#[must_use]
pub fn global_pool() -> std::sync::Arc<KeyPool> {
    std::sync::Arc::clone(GLOBAL_POOL.get_or_init(|| std::sync::Arc::new(load_pool())))
}

#[cfg(test)]
mod tests;
