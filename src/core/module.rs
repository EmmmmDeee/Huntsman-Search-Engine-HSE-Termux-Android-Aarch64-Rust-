//! Module trait + context types. This is the only contract modules need to
//! satisfy. The engine knows nothing else about any specific module.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::Serialize;

use crate::core::{
    entity::Entity,
    error::{Error, Result},
    event::EventBus,
    scan::Target,
};

/// Module funding/access cost — drives the `free_only` filter on a scan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCost {
    /// Public endpoint, no key, no rate-limit billing.
    Free,
    /// Requires an API key, but the key is free to register for.
    KeyGated,
    /// Requires a paid subscription.
    Paid,
}

/// Public information about a module — exposed via `hse modules` and the
/// future `/api/v1/modules` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct ModuleInfo {
    pub name: &'static str,
    pub priority: u8,
    pub cost: ModuleCost,
    pub passive: bool,
}

/// All modules implement this trait. Default methods give sensible answers
/// so existing modules can be added without ceremony.
#[async_trait]
pub trait Module: Send + Sync {
    /// Short, stable, snake_case identifier.
    fn name(&self) -> &'static str;

    /// Higher = run earlier. 0..=255.
    fn priority(&self) -> u8;

    /// True if this module produces meaningful output for the given target.
    fn accepts(&self, target: &Target) -> bool;

    /// Run the module. Returns the entities found.
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult>;

    /// Default: `Free`. Override for key-gated or paid sources.
    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    /// Default: `false`. Override `true` for local-sensor / no-network modules
    /// (e.g. arp_scan, gps_fix, email_to_username).
    fn is_passive(&self) -> bool {
        false
    }

    /// Built from the other methods — don't override.
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: self.name(),
            priority: self.priority(),
            cost: self.cost(),
            passive: self.is_passive(),
        }
    }
}

/// Shared per-scan context handed to every module invocation.
#[derive(Clone)]
pub struct ModuleContext {
    pub scan_id: String,
    pub bus: EventBus,
    pub http: reqwest::Client,
    pub keys: HashMap<String, String>,
}

impl ModuleContext {
    /// Fetch a required key by env-var name. Returns `Error::MissingKey` if
    /// absent — the engine logs this and moves on without aborting the scan.
    pub fn key(&self, name: &str) -> Result<&str> {
        self.keys
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| Error::MissingKey(name.into()))
    }

    /// Fetch an optional key — None if absent (no error).
    pub fn key_opt(&self, name: &str) -> Option<&str> {
        self.keys.get(name).map(String::as_str)
    }
}

#[derive(Debug, Default)]
pub struct ModuleResult {
    pub entities: Vec<Entity>,
}

impl ModuleResult {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, entity: Entity) {
        self.entities.push(entity);
    }

    pub fn extend(&mut self, entities: impl IntoIterator<Item = Entity>) {
        self.entities.extend(entities);
    }

    pub fn is_empty(&self) -> bool {
        self.entities.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entities.len()
    }
}
