use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::Serialize;

use crate::core::{
    entity::Entity,
    error::{Error, Result},
    event::EventBus,
    scan::Target,
};
use crate::storage::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCost {
    Free,
    KeyGated,
    Paid,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ModuleInfo {
    pub name: &'static str,
    pub priority: u8,
    pub cost: ModuleCost,
    pub passive: bool,
    pub description: &'static str,
}

#[async_trait]
pub trait Module: Send + Sync {
    fn name(&self) -> &'static str;
    fn priority(&self) -> u8;
    fn accepts(&self, target: &Target) -> bool;
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult>;

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn is_passive(&self) -> bool {
        false
    }

    /// `ScanOptions::module_timeout_ms` overrides this when set.
    fn max_timeout_ms(&self) -> u64 {
        crate::MODULE_TIMEOUT_MS
    }

    fn description(&self) -> &'static str {
        ""
    }

    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: self.name(),
            priority: self.priority(),
            cost: self.cost(),
            passive: self.is_passive(),
            description: self.description(),
        }
    }
}

#[derive(Clone)]
pub struct ModuleContext {
    pub scan_id: String,
    pub bus: EventBus,
    pub http: reqwest::Client,
    pub keys: HashMap<String, String>,
    pub cancel: crate::core::cancel::CancelHandle,
    pub store: Arc<Store>,
}

impl ModuleContext {
    pub fn key(&self, name: &str) -> Result<&str> {
        self.keys
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| Error::MissingKey(name.into()))
    }

    pub fn key_opt(&self, name: &str) -> Option<&str> {
        self.keys.get(name).map(String::as_str)
    }

    pub fn find_existing(&self, kind: &str, value: &str) -> Option<Entity> {
        self.store.find_entity(kind, value).ok().flatten()
    }

    pub fn existing_by_kind(&self, kind: &str, limit: usize) -> Vec<Entity> {
        self.store.entities_by_kind(kind, limit).unwrap_or_default()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cache_response(
        &self,
        module: &str,
        endpoint: &str,
        query_key: &str,
        query_value: &str,
        response: &str,
        item_count: usize,
        ttl_hours: u32,
    ) {
        let _ = self.store.cache_api_response(
            module,
            endpoint,
            query_key,
            query_value,
            response,
            item_count,
            &self.scan_id,
            ttl_hours,
        );
    }

    pub fn get_cached(
        &self,
        module: &str,
        endpoint: &str,
        query_key: &str,
        query_value: &str,
        max_age_hours: u32,
    ) -> Option<String> {
        self.store
            .cached_response(module, endpoint, query_key, query_value, max_age_hours)
            .ok()
            .flatten()
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

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            entities: Vec::with_capacity(cap),
        }
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
