//! `hse selftest` — fully offline, deterministic install health check.
//!
//! The first thing to run after installing on a fresh Termux device: it
//! exercises the whole stack end-to-end **without touching the network** and
//! prints a per-stage pass/fail report, so "did my install work?" is one
//! command — and if a stage fails, the reason (plus the always-on debug log)
//! tells Claude Code exactly what broke.
//!
//! Stages (each timed, each logged under the `hse::selftest` target):
//! 1. `storage` — open a throwaway SQLite DB + query (bundled rusqlite actually
//!    compiled and runs on this aarch64 device).
//! 2. `image` — PNG encode→decode→pHash round-trip (the pure-Rust `image`
//!    decoder works here).
//! 3. `metadata` — EXIF/XMP + PDF `/Info` parsers extract known fields.
//! 4. `engine` — a real, **offline** scan (`phone_intl`, no network) through
//!    dispatch → entity → persist → correlate → relations.
//! 5. `correlation` — the cross-correlation edge builders (stealer / image /
//!    co-location) produce edges from synthetic input.
//!
//! 100% local and deterministic — no external computation, no telemetry.
//! Exits non-zero if any stage fails (so it's CI/script friendly).

use std::sync::Arc;
use std::time::Instant;

use tracing::{info, warn};

use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::core::error::{Error, Result};
use crate::core::module::ModuleContext;
use crate::core::scan::{Scan, ScanOptions, Target, TargetKind};
use crate::storage::Store;
use crate::util::{http::build_client, keys, phash, uid::scan_id};

type StageResult = std::result::Result<String, String>;

pub(super) async fn cmd_selftest() -> Result<()> {
    println!(
        "HSE v{} — selftest (offline, deterministic)\n",
        crate::VERSION
    );

    let mut stages: Vec<(&str, StageResult, u128)> = Vec::new();
    macro_rules! stage {
        ($name:expr, $body:expr) => {{
            let t = Instant::now();
            let r: StageResult = $body;
            stages.push(($name, r, t.elapsed().as_millis()));
        }};
    }

    stage!("storage", stage_storage());
    stage!(
        "image",
        phash::self_test().map(|d| format!("PNG encode→decode→pHash ok (detail={d:.1})"))
    );
    stage!("metadata", stage_metadata());
    stage!("engine", stage_engine().await);
    stage!("correlation", stage_crosscorr());

    let mut pass = 0u32;
    for (name, res, ms) in &stages {
        match res {
            Ok(detail) => {
                pass += 1;
                println!("  [ok]   {name:<12} {detail}  ({ms} ms)");
                info!(target: "hse::selftest", stage = name, detail = %detail, "ok");
            }
            Err(e) => {
                println!("  [FAIL] {name:<12} {e}  ({ms} ms)");
                warn!(target: "hse::selftest", stage = name, error = %e, "stage failed");
            }
        }
    }

    let total = stages.len() as u32;
    println!();
    if pass == total {
        println!("selftest: PASS ({pass}/{total}) — install looks healthy");
        Ok(())
    } else {
        println!(
            "selftest: FAIL ({pass}/{total}) — paste this output and `hse doctor --bundle` to Claude Code"
        );
        Err(Error::Other(format!(
            "selftest failed: {pass}/{total} stages passed"
        )))
    }
}

/// Open a throwaway DB and query it — proves bundled SQLite built and runs on
/// this device (the write/persist path is covered by the `engine` stage).
fn stage_storage() -> StageResult {
    let path = std::env::temp_dir().join(format!("hse-selftest-{}.db", std::process::id()));
    let p = path.to_string_lossy().into_owned();
    let store = Store::open(&p).map_err(|e| format!("open temp DB: {e}"))?;
    let scans = store
        .list_scans(1)
        .map_err(|e| format!("query failed: {e}"))?;
    drop(store);
    cleanup_db(&p);
    Ok(format!(
        "bundled SQLite opens + queries ({} prior scans)",
        scans.len()
    ))
}

/// Drive the pure parsers with tiny in-memory fixtures.
fn stage_metadata() -> StageResult {
    use crate::util::metadata::{parse_image_xmp, parse_pdf};

    let xmp = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:Description tiff:Make="Canon"></rdf:Description></x:xmpmeta>"#;
    if parse_image_xmp(xmp).make.as_deref() != Some("Canon") {
        return Err("XMP parser did not extract tiff:Make".into());
    }
    let pdf = b"%PDF-1.7\n<< /Author (Selftest) >>";
    if parse_pdf(pdf).author.as_deref() != Some("Selftest") {
        return Err("PDF /Info parser did not extract /Author".into());
    }
    Ok("EXIF/XMP + PDF /Info parsers ok".into())
}

/// Run a real but fully offline scan through the engine. `phone_intl` parses
/// E.164 numbers from a built-in 175-prefix table — no network.
async fn stage_engine() -> StageResult {
    let path = std::env::temp_dir().join(format!("hse-selftest-engine-{}.db", std::process::id()));
    let p = path.to_string_lossy().into_owned();
    let store: Arc<dyn crate::core::port::StoragePort> =
        Arc::new(Store::open(&p).map_err(|e| format!("store: {e}"))?);
    let (bus, _rx) = tokio::sync::broadcast::channel(256);
    let engine = Arc::new(crate::core::engine::ScanEngine::new(
        crate::modules::registry(),
        Arc::clone(&store),
        bus.clone(),
    ));

    let target = Target::new(TargetKind::Phone, "+61400000000");
    let sid = scan_id(target.kind.canonical_str(), &target.value);
    let options = ScanOptions {
        // Allowlist a single offline module so the stage never touches the net.
        modules: Some(vec!["phone_intl".into()]),
        ..Default::default()
    };
    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus: bus.clone(),
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
    };

    let ran = engine.run(scan, target, ctx).await;
    let entities = store.entities_for_scan(&sid).unwrap_or_default();
    drop(engine);
    drop(store);
    cleanup_db(&p);

    ran.map_err(|e| format!("engine.run errored: {e}"))?;
    if entities.is_empty() {
        return Err("offline phone_intl scan produced no entity".into());
    }
    Ok(format!(
        "offline scan (phone_intl) → {} entities persisted",
        entities.len()
    ))
}

/// Confirm the cross-correlation edge builders run and produce edges from
/// synthetic, deterministic input (no engine, no I/O).
fn stage_crosscorr() -> StageResult {
    use crate::core::relation::{
        derive_colocation, derive_image_similarity, derive_stealer_cooccurrence,
    };

    let stealer_ent = |v: &str| {
        let mut e = Entity::new(EntityKind::Email, v, 0.6, "s");
        e.tag("stealer");
        e.add_evidence(Evidence::new("selftest", "x").with_attr("log_id", "L1"));
        e
    };
    let stealer =
        derive_stealer_cooccurrence(&[stealer_ent("a@x.com"), stealer_ent("b@x.com")], "s");

    let img_ent = |v: &str, h: &str| {
        let mut e = Entity::new(EntityKind::Url, v, 0.6, "s");
        e.add_evidence(Evidence::new("selftest", "x").with_attr("phash", h));
        e
    };
    let image = derive_image_similarity(
        &[
            img_ent("https://a/1.jpg", "0000000000000000"),
            img_ent("https://b/2.jpg", "0000000000000003"),
        ],
        "s",
    );

    let colo = derive_colocation(
        &[
            Entity::new(EntityKind::Coordinates, "-27.470000,153.020000", 0.9, "s"),
            Entity::new(EntityKind::Coordinates, "-27.470500,153.020500", 0.8, "s"),
        ],
        "s",
    );

    if stealer.is_empty() || image.is_empty() || colo.is_empty() {
        return Err(format!(
            "edge derivation produced too few edges (stealer={}, image={}, co-location={})",
            stealer.len(),
            image.len(),
            colo.len()
        ));
    }
    Ok(format!(
        "derived {} stealer + {} image + {} co-location edges",
        stealer.len(),
        image.len(),
        colo.len()
    ))
}

/// Remove a throwaway SQLite DB and its WAL/SHM sidecars.
fn cleanup_db(path: &str) {
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{path}{ext}"));
    }
}
