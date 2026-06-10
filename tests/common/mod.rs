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

use std::sync::Arc;

use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        module::{Module, ModuleContext},
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
        proxy_pool: Default::default(),
    };
    (engine, store, sid, target, ctx)
}
