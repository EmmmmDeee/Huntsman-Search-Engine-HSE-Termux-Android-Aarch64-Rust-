//! One authority for "run a scan from a seed, in this process".
//!
//! Builds the application runtime (store, bus, engine composed with the real
//! module runtime and host), loads the operator's keys, wires Ctrl-C to the
//! engine's cooperative cancel flag, runs the scan, and hands back the
//! persisted result. `hse scan` and `hse sf` both go through here; `hse scan`
//! used to inline the sequence, and a second front end would have copied it.
//!
//! Ctrl-C matters: without the listener, SIGINT falls through to the OS
//! default (immediate kill), skipping `finalise_scan` — the scan row stays
//! `Running` forever and in-flight module tasks are abandoned mid-request.
//! Cancelling the flag the engine polls persists a clean `Aborted` scan with
//! everything collected so far.

use std::sync::Arc;

use crate::core::error::Result;
use crate::core::module::ModuleContext;
use crate::core::port::StoragePort;
use crate::core::scan::{Scan, ScanOptions, Target};
use crate::util::{keys, uid::scan_id};

/// What a completed (or cooperatively aborted) run left behind.
pub struct ScanRun {
    /// The stored scan's id.
    pub scan_id: String,
    /// The scan row as the engine finalised it.
    pub scan: Scan,
    /// The store the scan was persisted to — read entities, findings and
    /// relations from here.
    pub store: Arc<dyn StoragePort>,
}

/// Run one seed to completion and return what was persisted.
pub async fn run_seed(target: Target, options: ScanOptions) -> Result<ScanRun> {
    let sid = scan_id(target.kind.canonical_str(), &target.value);
    let crate::app::runtime::ApplicationRuntime { store, bus, engine } =
        crate::app::runtime::build_runtime(64)?;

    let scan = Scan::new(sid.clone(), target.clone()).with_options(options);
    let keys = keys::populate_and_load().await;
    let ctx = ModuleContext {
        scan_id: sid.clone(),
        bus,
        // Stamp outbound calls with this scan's id so a proxy/upstream access
        // log can be matched back to the scan (its NDJSON logs carry the same id).
        http: crate::util::http::build_client_with_trace(&sid),
        keys,
        cancel: crate::core::cancel::CancelHandle::new(),
    };

    let cancel_on_ctrl_c = ctx.cancel.clone();
    let ctrl_c_listener = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("\nstopping scan…");
            cancel_on_ctrl_c.cancel();
        }
    });
    let scan = engine.run(scan, target, ctx).await?;
    ctrl_c_listener.abort();

    Ok(ScanRun {
        scan_id: sid,
        scan,
        store,
    })
}

/// Per-correlation-rule result counts for a stored scan (`latest` allowed), as
/// `hse sf -C` reports them: the resolved scan ID and `(rule_id, count)` pairs
/// in rule-id order. The app layer owns the store access; the CLI formats it.
pub fn rule_result_counts(raw: &str) -> Result<(String, Vec<(String, usize)>)> {
    let store = crate::storage::Store::open(&crate::default_db_path())?;
    let sid = crate::app::runtime::resolve_scan_id(&store, raw)?;
    let findings = store.correlations_for_scan(&sid)?;
    let mut per_rule: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    for f in &findings {
        *per_rule.entry(f.rule_id.clone()).or_insert(0) += 1;
    }
    Ok((sid, per_rule.into_iter().collect()))
}
