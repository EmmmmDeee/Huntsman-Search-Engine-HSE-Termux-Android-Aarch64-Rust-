//! End-to-end smoke tests: synthetic modules, real engine, real SQLite.
//! Proves the trait + engine + store + autonomous-expansion wire together.

use std::sync::Arc;

use async_trait::async_trait;
use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Scan, ScanOptions, Target, TargetKind},
    },
    storage::store::Store,
    util::{http::build_client, uid::scan_id},
};

/// Echoes the seed back as an entity of the same kind.
struct SyntheticModule;

#[async_trait]
impl Module for SyntheticModule {
    fn name(&self) -> &'static str {
        "synthetic"
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
        e.tag("synthetic");
        r.push(e);
        Ok(r)
    }
}

/// Accepts Email, produces ONE Username derived from the local part.
struct EmailToUsernameSynth;

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

/// Accepts Username, produces ONE Phone (synthetic).
struct UsernameToPhoneSynth;

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

/// Accepts Email, produces a low-confidence Username — should be ignored
/// by expansion when min_expand_confidence is 0.75.
struct LowConfidenceModule;

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

#[tokio::test]
async fn engine_dispatches_synthetic_module_end_to_end() {
    let tmp = tempfile_path("end_to_end");
    let _ = std::fs::remove_file(&tmp);

    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(8);
    let engine = ScanEngine::new(
        vec![Arc::new(SyntheticModule)],
        Arc::clone(&store),
        bus.clone(),
    );

    let sid = scan_id("email", "test@example.com");
    let target = Target::new(TargetKind::Email, "test@example.com");
    let scan = Scan::new(sid.clone(), target.clone());

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
    };

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(result.entity_count, 1);

    let stored = store.entities_for_scan(&sid).unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].value, "test@example.com");
    assert!(stored[0].has_tag("synthetic"));

    let _ = std::fs::remove_file(&tmp);
}

#[tokio::test]
async fn scan_options_allowlist_excludes_module() {
    let (engine, store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "allowlist",
        TargetKind::Email,
        "test@example.com",
    );
    let opts = ScanOptions {
        modules: Some(vec!["nonexistent".into()]),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(result.entity_count, 0, "synthetic should be skipped");
    drop(store);
}

#[tokio::test]
async fn expansion_depth_zero_is_single_round() {
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "depth_zero",
        TargetKind::Email,
        "alice@example.com",
    );
    // depth=0 — username produced, but never re-dispatched.
    let scan = Scan::new(sid.clone(), target.clone());
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 1,
        "depth 0 should not expand username to phone"
    );
}

#[tokio::test]
async fn expansion_depth_one_chains_two_modules() {
    let (engine, store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "depth_one",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 2,
        "expansion should yield username + phone"
    );
    let entities = store.entities_for_scan(&sid).unwrap();
    let kinds: Vec<&EntityKind> = entities.iter().map(|e| &e.kind).collect();
    assert!(kinds.contains(&&EntityKind::Username));
    assert!(kinds.contains(&&EntityKind::Phone));
}

#[tokio::test]
async fn expansion_respects_min_expand_confidence() {
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(LowConfidenceModule),
            Arc::new(UsernameToPhoneSynth),
        ],
        "low_conf",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 1,
        min_expand_confidence: 0.75,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(
        result.entity_count, 1,
        "low-confidence username should not trigger expansion"
    );
}

#[tokio::test]
async fn expansion_respects_max_entities_budget() {
    // 3 modules chain forever in principle, but max_entities=1 stops after seed round.
    let (engine, _store, sid, target, ctx) = setup(
        vec![
            Arc::new(EmailToUsernameSynth),
            Arc::new(UsernameToPhoneSynth),
        ],
        "max_ent",
        TargetKind::Email,
        "alice@example.com",
    );
    let opts = ScanOptions {
        depth: 5,
        max_entities: Some(1),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Seed produces 1 entity; budget hits at depth 1 entry → no expansion.
    assert!(
        result.entity_count <= 1,
        "max_entities=1 should cap at 1 (got {})",
        result.entity_count
    );
}

#[tokio::test]
async fn expansion_visited_prevents_cycle() {
    // SyntheticModule echoes the seed email back as the same email entity.
    // With depth>0, expansion would try to re-scan it — visited set must stop that.
    let (engine, _store, sid, target, ctx) = setup(
        vec![Arc::new(SyntheticModule)],
        "cycle",
        TargetKind::Email,
        "loop@example.com",
    );
    let opts = ScanOptions {
        depth: 3,
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);
    let result = engine.run(scan, target, ctx).await.unwrap();
    // Seed scanned once → 1 entity; expansion sees only the seed (visited) → 0 new targets.
    assert_eq!(result.entity_count, 1, "cycle should terminate");
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn setup(
    modules: Vec<Arc<dyn Module>>,
    suffix: &str,
    kind: TargetKind,
    value: &str,
) -> (ScanEngine, Arc<Store>, String, Target, ModuleContext) {
    let tmp = tempfile_path(suffix);
    let _ = std::fs::remove_file(&tmp);
    let store = Arc::new(Store::open(&tmp).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::new(modules, Arc::clone(&store), bus.clone());
    let sid = scan_id(&format!("{kind:?}").to_lowercase(), value);
    let target = Target::new(kind, value.to_string());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
    };
    (engine, store, sid, target, ctx)
}

fn tempfile_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-smoke-{}-{}.db", std::process::id(), suffix));
    p.to_string_lossy().into_owned()
}
