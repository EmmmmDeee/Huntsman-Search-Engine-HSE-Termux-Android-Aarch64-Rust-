//! Shared harness for the integration-test crates (`smoke`, `halting`, `api`).
//!
//! Each test binary compiles this module separately (`mod common;`), so items
//! unused by one crate are dead code there — hence the allow. The point of
//! centralising it is the WAL hygiene: the three crates had hand-rolled
//! near-identical harnesses that DRIFTED — `halting`/`api` removed the
//! `-wal`/`-shm` sidecars (with a comment explaining stale sidecars resurrect
//! old state and flake tests), while `smoke` removed only the main DB file and
//! silently carried that exact latent flake. One definition ends the drift.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use huntsman_search_engine::{
    api::{AppState, routes::router},
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        live::LiveScanner,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Target, TargetKind},
    },
    storage::Store,
    util::{http::build_client, uid::scan_id},
};

/// Fresh per-test SQLite path under the OS temp dir: `hse-<prefix>-<pid>-<suffix>.db`.
/// Removes the main DB **and** its WAL/SHM sidecars — in WAL mode a stale
/// `-wal`/`-shm` left from a prior run can resurrect old state or corrupt the
/// fresh handle, making tests flaky.
pub fn tmp_db(prefix: &str, suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-{prefix}-{}-{suffix}.db", std::process::id()));
    let s = p.to_string_lossy().into_owned();
    let _ = std::fs::remove_file(&s);
    let _ = std::fs::remove_file(format!("{s}-wal"));
    let _ = std::fs::remove_file(format!("{s}-shm"));
    s
}

/// Full engine harness over a fresh store: the (engine, store, scan_id,
/// target, ctx) tuple the scan-driving tests start from. `prefix` namespaces
/// the DB file per test crate so parallel crates can't collide.
pub fn engine_setup(
    prefix: &str,
    modules: Vec<Arc<dyn Module>>,
    suffix: &str,
    kind: TargetKind,
    value: &str,
) -> (ScanEngine, Arc<Store>, String, Target, ModuleContext) {
    let path = tmp_db(prefix, suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    );
    let sid = scan_id(kind.canonical_str(), value);
    let target = Target::new(kind, value.to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
        cancel: Default::default(),
    };
    (engine, store, sid, target, ctx)
}

/// Fresh per-test scratch DIRECTORY under the OS temp dir:
/// `hse-<prefix>-<pid>/`. For tests that write output files (exports,
/// dossiers) rather than a database; created if absent.
pub fn tmp_dir(prefix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("hse-{prefix}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ── Synthetic modules (moved from tests/smoke.rs and tests/api.rs) ──────────

/// Echoes the seed back as an entity of the same kind.
pub struct SyntheticModule;

#[async_trait]
impl Module for SyntheticModule {
    fn name(&self) -> &'static str {
        "synthetic"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn description(&self) -> &'static str {
        "test-only echo module"
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.95, &ctx.scan_id);
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

/// Accepts Email, produces ONE Username derived from the local part.
pub struct EmailToUsernameSynth;

#[async_trait]
impl Module for EmailToUsernameSynth {
    fn name(&self) -> &'static str {
        "synth_e2u"
    }
    fn priority(&self) -> u8 {
        80
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let local = target.value.split('@').next().unwrap_or("anon");
        // High base confidence so c_effective() ≥ 0.75 expansion threshold.
        let mut e = Entity::new(EntityKind::Username, local, 0.95, &ctx.scan_id);
        e.tag("derived");
        r.push(e);
        Ok(r)
    }
}

/// A keyed module with no key configured: returns `Err(MissingKey)`, which the
/// engine must treat as a CLEAN SKIP (needs-key notice), not a module error.
pub struct NeedsKeyModule;

#[async_trait]
impl Module for NeedsKeyModule {
    fn name(&self) -> &'static str {
        "needs_key"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _t: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        Err(huntsman_search_engine::core::error::Error::MissingKey(
            "HUNTSMAN_VIRUSTOTAL_KEY".into(),
        ))
    }
}

/// Accepts Username, produces ONE Phone (synthetic).
pub struct UsernameToPhoneSynth;

#[async_trait]
impl Module for UsernameToPhoneSynth {
    fn name(&self) -> &'static str {
        "synth_u2p"
    }
    fn priority(&self) -> u8 {
        70
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let phone = format!("+1{:0>10}", target.value.len() * 1111);
        let mut e = Entity::new(EntityKind::Phone, &phone, 0.95, &ctx.scan_id);
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

/// Adversarial generative module: for an Email target it emits a *brand-new,
/// never-before-seen* Email each call (local part grows by one char), so the
/// monotone visited-set can never block it. Left unbounded it would expand
/// forever — used to prove the recursion HALTS purely on the entity budget.
pub struct HydraModule;

#[async_trait]
impl Module for HydraModule {
    fn name(&self) -> &'static str {
        "hydra"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let local = target.value.split('@').next().unwrap_or("a");
        // High confidence so it always clears the expansion floor; unique each
        // round so `visited` never short-circuits it.
        let next = format!("{local}x@h.test");
        let mut e = Entity::new(EntityKind::Email, next, 0.95, &ctx.scan_id);
        e.tag("hydra");
        r.push(e);
        Ok(r)
    }
}

/// Accepts Email, produces a low-confidence Username — should be ignored
/// by expansion when min_expand_confidence is 0.75.
pub struct LowConfidenceModule;

#[async_trait]
impl Module for LowConfidenceModule {
    fn name(&self) -> &'static str {
        "synth_low"
    }
    fn priority(&self) -> u8 {
        60
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let local = target.value.split('@').next().unwrap_or("anon");
        // Base confidence 0.3 → c_effective 0.3 → below 0.75 threshold.
        let mut e = Entity::new(EntityKind::Username, local, 0.3, &ctx.scan_id);
        e.tag("low");
        r.push(e);
        Ok(r)
    }
}

// ── Key-chaining harness ───────────────────────────────────────────────────

const CHAIN_TEST_SERVICE: &str = "shodan";
const CHAIN_TEST_ENV: &str = "HUNTSMAN_SHODAN_KEY";

pub struct KeyDiscovererModule;

#[async_trait]
impl Module for KeyDiscovererModule {
    fn name(&self) -> &'static str {
        "key_discoverer"
    }
    fn priority(&self) -> u8 {
        // Higher than KeyConsumerModule so it runs first.
        // Also marked Paid so the concurrent dispatcher routes it into
        // Phase 1 (synchronous) before Phase 2 spawns the consumer.
        150
    }
    fn cost(&self) -> huntsman_search_engine::core::module::ModuleCost {
        huntsman_search_engine::core::module::ModuleCost::Paid
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        // Simulate oathnet_pro discovering a key in breach data.
        let pool = huntsman_search_engine::util::key_pool::global_pool();
        let entry = huntsman_search_engine::util::key_pool::KeyEntry::new(
            "test-shodan-key-chained-via-hot-inject",
        );
        pool.add(CHAIN_TEST_SERVICE, entry);

        // Emit a marker entity proving this module ran.
        let mut r = ModuleResult::new();
        let mut e = Entity::new(
            EntityKind::Email,
            "discoverer@chainmarker.io",
            0.95,
            &ctx.scan_id,
        );
        e.tag("key-discoverer-fired");
        r.push(e);
        Ok(r)
    }
}

pub struct KeyConsumerModule;

#[async_trait]
impl Module for KeyConsumerModule {
    fn name(&self) -> &'static str {
        "key_consumer"
    }
    fn priority(&self) -> u8 {
        // Lower than discoverer so it runs after the hot-inject fires.
        50
    }
    fn cost(&self) -> huntsman_search_engine::core::module::ModuleCost {
        huntsman_search_engine::core::module::ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, _target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        // Only emit if the chained key reached us via hot-inject.
        if let Some(key) = ctx.key_opt(CHAIN_TEST_ENV)
            && key == "test-shodan-key-chained-via-hot-inject"
        {
            let mut e = Entity::new(
                EntityKind::Email,
                "consumer@chainmarker.io",
                0.95,
                &ctx.scan_id,
            );
            e.tag("key-consumer-saw-key");
            r.push(e);
        }
        Ok(r)
    }
}

/// Emits a mega-domain (facebook.com) and a target-specific domain from a
/// username — to exercise the expansion gate that skips incidentally-discovered
/// mega-domains. Both are high-confidence + corroborated so they clear the gate.
pub struct UsernameToDomainsSynth;
#[async_trait]
impl Module for UsernameToDomainsSynth {
    fn name(&self) -> &'static str {
        "u2domains"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn description(&self) -> &'static str {
        "test: username → domains"
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Username)
    }
    async fn process(&self, _t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        for d in ["facebook.com", "johndoe-personal.com"] {
            let mut e = Entity::new(EntityKind::Domain, d, 0.95, &ctx.scan_id);
            e.corroboration = 3;
            r.push(e);
        }
        Ok(r)
    }
}

/// Records each Domain target it is dispatched on by emitting a marker entity,
/// so a test can assert which domains the engine chose to expand.
pub struct DomainSensor;
#[async_trait]
impl Module for DomainSensor {
    fn name(&self) -> &'static str {
        "domain_sensor"
    }
    fn priority(&self) -> u8 {
        90
    }
    fn description(&self) -> &'static str {
        "test: marks domains it runs on"
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }
    async fn process(&self, t: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(
            EntityKind::Url,
            format!("sensed://{}", t.value),
            0.95,
            &ctx.scan_id,
        );
        e.tag("domain-sensor");
        r.push(e);
        Ok(r)
    }
}

/// Tags an entity with the per-scan regional-search ambient it observes —
/// used to prove `util::regional`'s isolation end-to-end through the real
/// engine, mirroring `key_chaining_*`'s "prove the wiring, not just the
/// primitive" style.
pub struct RegionalProbeModule;

#[async_trait]
impl Module for RegionalProbeModule {
    fn name(&self) -> &'static str {
        "regional_probe"
    }
    fn priority(&self) -> u8 {
        100
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }
    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut r = ModuleResult::new();
        let mut e = Entity::new(EntityKind::Email, &target.value, 0.95, &ctx.scan_id);
        e.tag(
            if huntsman_search_engine::util::regional::regional_enabled() {
                "regional-was-true"
            } else {
                "regional-was-false"
            },
        );
        r.push(e);
        Ok(r)
    }
}

/// Clear any pre-existing keys for the chain-test service from the process-
/// global pool so the key-chaining tests are hermetic. The global pool is a
/// `OnceLock` seeded from the persisted `~/.huntsman/key_pool.json`, which can
/// already hold real `shodan` keys (from prior CLI use or scans); those perturb
/// `next_key("shodan")` selection and make the hot-inject assertion flaky
/// depending on test order / the developer's local pool. Removal is in-memory
/// only (never writes the file), so it cannot affect real keys on disk.
pub fn reset_chain_pool() {
    let pool = huntsman_search_engine::util::key_pool::global_pool();
    let existing: Vec<String> = pool
        .snapshot()
        .services
        .get(CHAIN_TEST_SERVICE)
        .into_iter()
        .flatten()
        .map(|e| e.value.clone())
        .collect();
    for value in existing {
        pool.remove(CHAIN_TEST_SERVICE, &value);
    }
}

// ── API helpers (moved from tests/api.rs) ──────────────────────────────────

/// Return a fresh temp-db path, removing any leftover files from prior runs.
pub fn tmp_db_for_api(suffix: &str) -> String {
    tmp_db("api", suffix)
}

/// Build a complete axum `Router` backed by a fresh SQLite store.
/// Each test gets its own database via the `suffix` parameter.
pub fn test_app(suffix: &str) -> axum::Router {
    let (router, _store, _state) = test_app_with_store_and_state(suffix);
    router
}

/// Like [`test_app`] but also hands back the shared store so a test can seed
/// entities directly (synchronous, FTS-indexed in the same transaction as the
/// write) without depending on an async scan completing.
pub fn test_app_with_store(suffix: &str) -> (axum::Router, Arc<Store>) {
    let (router, store, _state) = test_app_with_store_and_state(suffix);
    (router, store)
}

/// Like [`test_app`] but also hands back the shared `Arc<AppState>` so a test
/// can manipulate state the HTTP surface doesn't expose directly (e.g.
/// seeding `cancellations` to simulate an in-flight scan deterministically,
/// without racing a real spawned scan's completion).
pub fn test_app_with_state(suffix: &str) -> (axum::Router, Arc<AppState>) {
    let (router, _store, state) = test_app_with_store_and_state(suffix);
    (router, state)
}

fn test_app_with_store_and_state(suffix: &str) -> (axum::Router, Arc<Store>, Arc<AppState>) {
    let path = tmp_db_for_api(suffix);
    let store = Arc::new(Store::open(&path).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let modules: Vec<Arc<dyn Module>> = vec![Arc::new(SyntheticModule)];
    let engine = Arc::new(ScanEngine::new(
        modules,
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
    ));
    let live = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        reqwest::Client::new(),
        Default::default(),
    );
    let state = Arc::new(AppState {
        store: Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        engine,
        bus,
        live,
        http: reqwest::Client::new(),
        allow_key_write: false,
        cancellations: Arc::new(parking_lot::Mutex::new(HashMap::new())),
        scan_semaphore: Arc::new(tokio::sync::Semaphore::new(
            huntsman_search_engine::api::MAX_CONCURRENT_SCANS,
        )),
        update_info: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::UpdateInfo::default(),
        )),
        cells_import: Arc::new(std::sync::Mutex::new(
            huntsman_search_engine::api::CellsImportPhase::default(),
        )),
    });
    (router(Arc::clone(&state), "127.0.0.1:8080"), store, state)
}
