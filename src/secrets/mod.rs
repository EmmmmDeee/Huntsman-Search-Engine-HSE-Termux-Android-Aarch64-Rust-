//! Secrets & API-key lifecycle — the cohesive cluster extracted from `util`.
//!
//! Everything about discovering, storing, validating, rotating, and reporting on
//! API keys lives here, so the key-management surface is one navigable module
//! instead of nine files scattered through the `util` grab-bag:
//!
//! * [`keys`] — the canonical key registry (`KNOWN_KEYS`), env loading, signup hints.
//! * [`key_pool`] — the rotating multi-key pool (status, health, use counts).
//! * [`key_vault`] — the on-disk vault of every key ever harvested.
//! * [`key_roi`] — acquisition ranking (which unset key is highest-leverage).
//! * [`key_health`] — auth-failure detection from real scan outcomes.
//! * [`key_harvest`] — the proactive key-harvesting engine + pattern catalogue.
//! * [`found_keys`] — the universal response-body key scanner.
//! * [`service_defs`] — poolable-service definitions.
//! * [`osint_providers`] — OSINT-tooling service classification.

pub mod found_keys;
pub mod key_harvest;
pub mod key_health;
pub mod key_pool;
pub mod key_roi;
pub mod key_vault;
pub mod keys;
pub mod osint_providers;
pub mod service_defs;
