//! End-to-end smoke test: synthetic module, real engine, real SQLite.
//! Proves the trait + engine + store wire together correctly.

use std::sync::Arc;

use async_trait::async_trait;
use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        entity::{Entity, EntityKind},
        error::Result,
        module::{Module, ModuleContext, ModuleResult},
        scan::{Scan, Target, TargetKind},
    },
    storage::store::Store,
    util::{http::build_client, uid::scan_id},
};

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
    use huntsman_search_engine::core::scan::ScanOptions;

    let tmp = tempfile_path("allowlist");
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
    let opts = ScanOptions {
        modules: Some(vec!["nonexistent".into()]),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(opts);

    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
    };

    let result = engine.run(scan, target, ctx).await.unwrap();
    assert_eq!(result.entity_count, 0, "synthetic should be skipped");

    let _ = std::fs::remove_file(&tmp);
}

fn tempfile_path(suffix: &str) -> String {
    let mut p = std::env::temp_dir();
    p.push(format!("hse-smoke-{}-{}.db", std::process::id(), suffix));
    p.to_string_lossy().into_owned()
}
