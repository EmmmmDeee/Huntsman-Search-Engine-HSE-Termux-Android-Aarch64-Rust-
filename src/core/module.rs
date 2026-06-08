//! Module trait + context types. This is the only contract modules need to
//! satisfy. The engine knows nothing else about any specific module.

use std::collections::HashMap;

use async_trait::async_trait;
use serde::Serialize;

use crate::core::{
    entity::{Entity, EntityKind},
    error::{Error, Result},
    event::EventBus,
    scan::{Target, TargetKind},
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

/// Coarse functional category for a module. Drives UI grouping in the
/// module-picker and the module-graph view. Spiderfoot 4.0 ships
/// equivalent labels (`Footprint`, `Investigate`, `Passive`) attached
/// to each `sfp_*` plugin; this enum is HSE's analogue.
///
/// Categories are derived metadata only — the engine does not gate
/// dispatch on them. They exist so the operator can filter the module
/// catalogue (`hse modules --category geo`) and so the SPA can render
/// the registry as a tabbed grid rather than one long list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleCategory {
    /// DNS, certificate transparency, WHOIS, subdomain enumeration.
    DnsRecon,
    /// Breach corpora, paste exposure, stealer logs, leaked credentials.
    Breach,
    /// IP / ASN / BGP / Shodan-style infrastructure intel.
    Infrastructure,
    /// Search-engine scraping (Google, Bing, DuckDuckGo, ...).
    Search,
    /// Geolocation, geocoding, address resolution, BSSID lookup.
    Geo,
    /// Social profiles and username-search across platforms.
    Social,
    /// Email parsing, header geo, locale, verification.
    Email,
    /// Phone-number metadata, carrier, area code geo.
    Phone,
    /// Corporate / company registry / business intel.
    Corporate,
    /// Threat intel: malware, C2, abuse lists.
    Threat,
    /// Local device sensors (GPS, WiFi, cell, ARP, local interfaces).
    Sensor,
    /// People-centric enrichment (proxycurl, keybase, epieos).
    People,
    /// Site / app web-crawling, web-server fingerprinting.
    Web,
    /// Anything that doesn't fit a more specific bucket.
    Other,
}

impl ModuleCategory {
    /// Stable snake_case identifier (matches serde output).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DnsRecon => "dns_recon",
            Self::Breach => "breach",
            Self::Infrastructure => "infrastructure",
            Self::Search => "search",
            Self::Geo => "geo",
            Self::Social => "social",
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Corporate => "corporate",
            Self::Threat => "threat",
            Self::Sensor => "sensor",
            Self::People => "people",
            Self::Web => "web",
            Self::Other => "other",
        }
    }
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
    /// Functional category — group label for the UI module picker.
    pub category: ModuleCategory,
    /// `TargetKind`s this module dispatches on (the explicit declaration
    /// from `Module::consumes()`, not the probed default). Drives the
    /// dispatch index in `crate::core::dependency::ModuleGraph` and the
    /// `/api/v1/modules/graph` payload.
    pub consumes: Vec<&'static str>,
    /// `EntityKind`s this module is documented to emit. Empty when the
    /// module hasn't declared its output. Used by the UI to render the
    /// pivot-chain flow.
    pub produces: Vec<String>,
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

    /// Per-`process()` budget the engine allows **on Termux** (Android, no
    /// root) when the user hasn't pinned a global timeout. Defaults to
    /// [`max_timeout_ms`](Module::max_timeout_ms) — almost every module
    /// behaves identically on a phone. Override DOWN for modules that are
    /// reliably slow-and-low-yield over a mobile/captive network (heavy SERP
    /// scrapers, deep crawlers): live device transcripts showed such modules
    /// burning the full cap for zero results, wall-time the phone could spend
    /// on modules that actually resolve.
    ///
    /// The engine still clamps the result to its Termux cap, and an explicit
    /// `ScanOptions::module_timeout_ms` overrides this entirely. Modules that
    /// genuinely need their time on a phone too — e.g. a GPS cold-fix — simply
    /// keep the default and are bounded only by the cap.
    fn termux_timeout_ms(&self) -> u64 {
        self.max_timeout_ms()
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

    /// Functional category for the module-picker UI. Default `Other`.
    ///
    /// This is metadata only — the engine does not gate dispatch on
    /// category. Override to group the module under one of the
    /// named [`ModuleCategory`] buckets so it appears under the right
    /// tab in the SPA's module grid.
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Other
    }

    /// The `TargetKind`s this module dispatches on.
    ///
    /// Default: probe every `TargetKind` against `accepts()` and
    /// return the matches. Modules whose `accepts()` gate is purely
    /// `matches!(t.kind, ...)` (the vast majority) get correct
    /// behaviour for free. Modules that gate by value shape MUST
    /// override this method explicitly so the dependency graph and
    /// dispatch index reflect their true input set.
    ///
    /// Returned vec is small (≤ 14) so allocation cost is negligible
    /// — this is invoked once per module at engine construction.
    fn consumes(&self) -> Vec<TargetKind> {
        crate::core::dependency::ALL_TARGET_KINDS
            .iter()
            .copied()
            .filter(|k| self.accepts(&Target::new(*k, crate::core::dependency::PROBE_VALUE)))
            .collect()
    }

    /// The `EntityKind`s this module is documented to emit.
    ///
    /// Default: empty. Override to document the module's outputs so
    /// the dependency-graph view in the UI can render the full pivot
    /// chain. Empty doesn't mean the module produces nothing — it
    /// means the module hasn't declared its outputs yet (back-compat).
    fn produces(&self) -> &'static [EntityKind] {
        &[]
    }

    /// Built from the other methods — don't override.
    fn info(&self) -> ModuleInfo {
        ModuleInfo {
            name: self.name(),
            priority: self.priority(),
            cost: self.cost(),
            passive: self.is_passive(),
            description: self.description(),
            category: self.category(),
            consumes: self
                .consumes()
                .into_iter()
                .map(|k| k.canonical_str())
                .collect(),
            produces: self
                .produces()
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
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
        // The in-memory marks above are immediate; persistence is offloaded.
        persist_key_pool(pool);
    }
}

/// Persist the key pool to disk *off* the async runtime. `save_pool` does a
/// blocking `fsync` + `rename`, and this is reached from async keyed-error
/// handling on a tokio worker — a burst of 401/403/429s across keyed modules
/// would otherwise stall the executor. Inside a runtime we hand the blocking I/O
/// to `spawn_blocking` (fire-and-forget; the in-memory state is already updated
/// and persistence is best-effort); outside one (CLI / tests) we save inline.
fn persist_key_pool(pool: std::sync::Arc<crate::util::key_pool::KeyPool>) {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => {
            handle.spawn_blocking(move || {
                crate::util::key_pool::save_pool_best_effort(&pool);
            });
        }
        Err(_) => {
            crate::util::key_pool::save_pool_best_effort(&pool);
        }
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
        assert_eq!(info.category, ModuleCategory::Other);
        // StubModule.accepts() returns true for every kind, so the
        // probe-based default surfaces every TargetKind in `consumes`.
        assert_eq!(
            info.consumes.len(),
            crate::core::dependency::ALL_TARGET_KINDS.len()
        );
        assert!(info.produces.is_empty());
    }

    struct CategorisedModule;
    #[async_trait]
    impl Module for CategorisedModule {
        fn name(&self) -> &'static str {
            "categorised"
        }
        fn priority(&self) -> u8 {
            10
        }
        fn accepts(&self, t: &Target) -> bool {
            matches!(t.kind, TargetKind::Domain)
        }
        async fn process(&self, _t: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
            Ok(ModuleResult::new())
        }
        fn category(&self) -> ModuleCategory {
            ModuleCategory::DnsRecon
        }
        fn produces(&self) -> &'static [EntityKind] {
            const KINDS: &[EntityKind] = &[EntityKind::IpAddress, EntityKind::Domain];
            KINDS
        }
    }

    #[test]
    fn override_category_and_produces_propagate_to_info() {
        let m = CategorisedModule;
        let info = m.info();
        assert_eq!(info.category, ModuleCategory::DnsRecon);
        assert_eq!(info.consumes, vec!["domain"]);
        assert_eq!(info.produces, vec!["ip_address", "domain"]);
    }

    #[test]
    fn module_category_as_str_round_trips_serde() {
        for cat in [
            ModuleCategory::DnsRecon,
            ModuleCategory::Breach,
            ModuleCategory::Geo,
            ModuleCategory::Other,
        ] {
            let json = serde_json::to_string(&cat).unwrap();
            // serde-snake_case strips quotes
            let body = json.trim_matches('"');
            assert_eq!(body, cat.as_str());
        }
    }
}
