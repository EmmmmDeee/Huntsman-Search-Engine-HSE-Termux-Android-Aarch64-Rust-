//! Multi-key pool manager with per-service cycling, validation, and
//! rate-limit awareness. Complements `util/keys.rs` (single env-var
//! keys) by supporting multiple keys per service with intelligent
//! rotation.
//!
//! Storage: `$HOME/.huntsman/key_pool.json` (mode 0600).

pub mod persistence;
pub mod pool;
pub mod types;
pub mod validation;

pub use persistence::{load_pool, pool_path, save_pool, save_pool_best_effort, write_secret_file};
pub use pool::{KeyPool, PoolData};
pub use types::{KeyEntry, KeyStatus, KeyTier, key_id};
pub use validation::{add_and_validate, merge_pool_into_env, validate_key};

// Re-export service_defs items so existing call-sites that reach through
// `key_pool::find_service` / `key_pool::service_defs` continue to compile.
pub use crate::util::service_defs::{KeyPlacement, ServiceDef, find_service, service_defs};

// ── Shared pool singleton ────────────────────────────────────────────────────

static GLOBAL_POOL: std::sync::OnceLock<std::sync::Arc<KeyPool>> = std::sync::OnceLock::new();

pub fn global_pool() -> std::sync::Arc<KeyPool> {
    std::sync::Arc::clone(GLOBAL_POOL.get_or_init(|| std::sync::Arc::new(load_pool())))
}

#[cfg(test)]
mod tests;
