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

/// Public information about a module — exposed via `hse modules` and
/// `GET /api/v1/modules`.
///
/// Marked `#[non_exhaustive]` so future per-module metadata (e.g. tags,
/// example targets) can be added without forcing a major-version bump
/// on downstream consumers that exhaustively destructure this struct.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct ModuleInfo {
    pub name: &'static str,
    pub priority: u8,
    pub cost: ModuleCost,
    pub passive: bool,
    /// One-sentence operator-facing summary of what the module does.
    /// Drives the wizard's per-row tooltip (`title="..."`). May be empty
    /// for modules added without a description, but the
    /// `all_registered_modules_have_descriptions` regression test in
    /// `tests/smoke.rs` blocks that in CI.
    pub description: &'static str,
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

    /// Maximum time the engine will wait for one `process()` call before
    /// emitting `ModuleError { error: "timeout" }`.
    ///
    /// Default is the crate-wide `MODULE_TIMEOUT_MS` (3 s). Modules that
    /// legitimately need longer (GPS fixes can take 15 s, two-stage
    /// WHOIS referrals can take ~8 s) override this so the engine
    /// doesn't kill them prematurely.
    ///
    /// User-supplied `ScanOptions::module_timeout_ms` still wins — this
    /// is only consulted when the user hasn't pinned a global cap.
    fn max_timeout_ms(&self) -> u64 {
        crate::MODULE_TIMEOUT_MS
    }

    /// One-sentence summary of what this module does, in operator
    /// language. Shown as the wizard's hover tooltip on the module-
    /// picker grid (issue #28). Default empty for backward compat —
    /// the `all_registered_modules_have_descriptions` regression test
    /// in `tests/smoke.rs` asserts every registered module overrides
    /// this with a non-empty string so new modules can't silently slip
    /// through review without one.
    fn description(&self) -> &'static str {
        ""
    }

    /// Built from the other methods — don't override.
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

/// Shared per-scan context handed to every module invocation.
#[derive(Clone)]
pub struct ModuleContext {
    pub scan_id: String,
    pub bus: EventBus,
    pub http: reqwest::Client,
    pub keys: HashMap<String, String>,
    /// Engine-wide cancellation flag for this scan (issue #23). The
    /// engine checks `cancel.is_cancelled()` between modules; modules
    /// running long-running internal loops MAY poll it themselves to
    /// abort mid-process for faster cancel latency. Default-constructed
    /// handles never fire.
    pub cancel: crate::core::cancel::CancelHandle,
    /// Shared proxy pool for free scraping modules. Populated once at
    /// scan start; modules call `ctx.proxy_pool.next()` to rotate.
    pub proxy_pool: std::sync::Arc<crate::util::proxy::ProxyPool>,
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

    /// Report that a key received a rate-limit (429) or auth failure (401/403).
    /// Marks the key in the global pool so subsequent scans rotate to the next one.
    pub fn report_key_exhausted(&self, service: &str, key_value: &str, status: u16) {
        let pool = crate::util::key_pool::global_pool();
        pool.record_error(service, key_value);
        let key_status = if status == 429 {
            crate::util::key_pool::KeyStatus::RateLimited
        } else {
            crate::util::key_pool::KeyStatus::Invalid
        };
        pool.mark_status(service, key_value, key_status);
        let _ = crate::util::key_pool::save_pool(&pool);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn make_ctx(keys: HashMap<String, String>) -> ModuleContext {
        let (bus, _rx) = tokio::sync::broadcast::channel(1);
        ModuleContext {
            scan_id: "test".into(),
            bus,
            http: reqwest::Client::new(),
            keys,
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: Default::default(),
        }
    }

    // ── ModuleContext::key ───────────────────────────────────────────────

    #[test]
    fn key_returns_ok_when_present() {
        let ctx = make_ctx(HashMap::from([(
            "HUNTSMAN_FOO".to_string(),
            "bar".to_string(),
        )]));
        let val = ctx.key("HUNTSMAN_FOO").unwrap();
        assert_eq!(val, "bar");
    }

    #[test]
    fn key_returns_missing_key_error_when_absent() {
        let ctx = make_ctx(HashMap::new());
        let err = ctx.key("NO_SUCH_KEY").unwrap_err();
        assert!(
            matches!(err, Error::MissingKey(ref k) if k == "NO_SUCH_KEY"),
            "expected MissingKey, got: {err:?}",
        );
    }

    // ── ModuleContext::key_opt ───────────────────────────────────────────

    #[test]
    fn key_opt_returns_some_when_present() {
        let ctx = make_ctx(HashMap::from([(
            "HUNTSMAN_FOO".to_string(),
            "bar".to_string(),
        )]));
        assert_eq!(ctx.key_opt("HUNTSMAN_FOO"), Some("bar"));
    }

    #[test]
    fn key_opt_returns_none_when_absent() {
        let ctx = make_ctx(HashMap::new());
        assert_eq!(ctx.key_opt("NO_SUCH_KEY"), None);
    }

    // ── ModuleResult ────────────────────────────────────────────────────

    #[test]
    fn new_result_is_empty() {
        let r = ModuleResult::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn with_capacity_is_empty_but_pre_allocated() {
        let r = ModuleResult::with_capacity(16);
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert!(r.entities.capacity() >= 16);
    }

    #[test]
    fn push_increments_len() {
        let mut r = ModuleResult::new();
        r.push(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        assert_eq!(r.len(), 1);
        assert!(!r.is_empty());
    }

    #[test]
    fn extend_adds_multiple_entities() {
        let mut r = ModuleResult::new();
        let entities = vec![
            Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
            Entity::new(EntityKind::Domain, "example.com", 0.7, "s"),
            Entity::new(EntityKind::IpAddress, "1.2.3.4", 0.9, "s"),
        ];
        r.extend(entities);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn is_empty_and_len_track_correctly() {
        let mut r = ModuleResult::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);

        r.push(Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"));
        assert!(!r.is_empty());
        assert_eq!(r.len(), 1);

        r.push(Entity::new(EntityKind::Domain, "x.com", 0.6, "s"));
        assert_eq!(r.len(), 2);
    }

    // ── ModuleCost serde ────────────────────────────────────────────────

    #[test]
    fn module_cost_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&ModuleCost::Free).unwrap(),
            "\"free\""
        );
        assert_eq!(
            serde_json::to_string(&ModuleCost::KeyGated).unwrap(),
            "\"key_gated\""
        );
        assert_eq!(
            serde_json::to_string(&ModuleCost::Paid).unwrap(),
            "\"paid\""
        );
    }

    // ── ModuleInfo via trait defaults ────────────────────────────────────

    /// Minimal module that only overrides the required methods, leaving all
    /// defaulted methods at their trait-provided values.
    struct StubModule;

    #[async_trait]
    impl Module for StubModule {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn priority(&self) -> u8 {
            42
        }
        fn accepts(&self, _target: &Target) -> bool {
            true
        }
        async fn process(&self, _target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
    }

    #[test]
    fn module_info_reflects_trait_defaults() {
        let m = StubModule;
        let info = m.info();

        assert_eq!(info.name, "stub");
        assert_eq!(info.priority, 42);
        assert_eq!(info.cost, ModuleCost::Free);
        assert!(!info.passive);
        assert_eq!(info.description, "");
    }
}
