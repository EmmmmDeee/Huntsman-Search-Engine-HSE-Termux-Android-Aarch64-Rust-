//! Every module-state mutation the engine performs goes through the injected
//! [`ModuleRuntime`], so a module-free engine (`NoopModuleRuntime`) has no
//! effect on process-wide module state, and a test double can observe exactly
//! what the engine asked for.
//!
//! The SeekNow per-scan cap was the one mutation outside the seam: the engine
//! called `util::see_know::set_scan_cap_override` directly, under an
//! architecture-test exemption, so an engine built with the no-op runtime
//! still wrote the override into the real process-wide budget. The exemption
//! is gone (core may no longer name that function) and the engine now asks
//! the runtime; this proves it asks with the clamped value.
mod common;

use std::sync::{Arc, Mutex};

use huntsman_search_engine::{
    core::{
        engine::ScanEngine,
        module::ModuleContext,
        module_runtime::ModuleRuntime,
        scan::{Scan, ScanOptions, Target, TargetKind},
    },
    storage::Store,
    util::{http::build_client, uid::scan_id},
};

#[derive(Default)]
struct RecordingRuntime {
    caps: Mutex<Vec<u32>>,
}

impl ModuleRuntime for RecordingRuntime {
    fn set_seeknow_scan_cap(&self, cap: u32) {
        self.caps.lock().unwrap().push(cap);
    }
}

async fn run_with_cap(suffix: &str, cap: Option<u32>) -> Vec<u32> {
    let runtime = Arc::new(RecordingRuntime::default());
    let store = Arc::new(Store::open(&common::tmp_db("seam", suffix)).unwrap());
    let (bus, _rx) = tokio::sync::broadcast::channel(64);
    let engine = ScanEngine::with_runtime_and_host(
        vec![Arc::new(common::SyntheticModule)],
        Arc::clone(&store) as Arc<dyn huntsman_search_engine::core::StoragePort>,
        bus.clone(),
        Arc::clone(&runtime) as Arc<dyn ModuleRuntime>,
        Arc::new(huntsman_search_engine::util::engine_host::UtilEngineHost),
    );
    let value = format!("{suffix}@example.com");
    let sid = scan_id("email", &value);
    let target = Target::new(TargetKind::Email, value.clone());
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        http: build_client(),
        keys: Default::default(),
        cancel: Default::default(),
    };
    let scan = Scan::new(sid, target.clone()).with_options(ScanOptions {
        seeknow_scan_cap: cap,
        ..Default::default()
    });
    engine.run(scan, target, ctx).await.unwrap();
    let caps = runtime.caps.lock().unwrap().clone();
    caps
}

#[tokio::test]
async fn the_seeknow_scan_cap_reaches_the_module_runtime_clamped() {
    assert_eq!(run_with_cap("cap-set", Some(9)).await, vec![9]);
    assert_eq!(
        run_with_cap("cap-clamped", Some(5_000)).await,
        vec![500],
        "the engine clamps a per-scan cap to 500 before handing it to the runtime"
    );
}

#[tokio::test]
async fn no_cap_requested_means_no_cap_installed() {
    assert!(run_with_cap("cap-none", None).await.is_empty());
}
