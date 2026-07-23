//! `hse gaps` — discovery-gap analysis for a scan.
//!
//! Loads a scan's validated seeds and prints the ISOLATED ones (no evidence-backed link),
//! each classified by why it is isolated and with the corrective scan that would connect
//! it — the registered modules that accept its re-injection kind. Read-only over the
//! store; the analysis is pure synthesis ([`crate::core::gap::analyze`]). `--json` emits
//! the machine-readable report for the gap-resolution loop to drive automatically.

use crate::core::error::{Error, Result};
use crate::core::gap;
use crate::core::scan::{Target, TargetKind};
use crate::default_db_path;
use crate::storage::Store;

use super::resolve_scan_id;

/// `hse gaps [--scan-id <id|latest>] [--json]` — print the scan's discovery-gap report.
pub fn cmd_gaps(scan_id: Option<String>, json: bool) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let id = resolve_scan_id(&store, scan_id.as_deref().unwrap_or("latest"))?;
    let entities = store.entities_for_scan(&id)?;
    let relations = store.relations_for_scan(&id)?;
    let scan = store
        .get_scan(&id)?
        .ok_or_else(|| Error::Other(format!("scan {id} not found")))?;
    let min_expand = scan.options.min_expand_confidence;
    let report = gap::analyze_with_confidence(&entities, &relations, min_expand);

    if json {
        let out = serde_json::to_string_pretty(&report).map_err(|e| Error::Other(e.to_string()))?;
        println!("{out}");
        return Ok(());
    }

    if report.null_state {
        println!("Discovery gaps — scan {id}: null state (no validated seeds; keep monitoring).");
        return Ok(());
    }

    println!(
        "Discovery gaps — scan {id}: {}/{} seeds linked ({:.0}%), {} isolated",
        report.linked_seeds,
        report.total_seeds,
        report.linked_fraction * 100.0,
        report.isolated_seeds,
    );
    println!(
        "  isolation: {} unexpanded · {} below-floor · {} terminal",
        report.isolation.unexpanded, report.isolation.below_expand_floor, report.isolation.terminal,
    );

    if report.orphans.is_empty() {
        println!("  every validated seed is linked into the graph.");
        return Ok(());
    }

    // Per-orphan corrective modules: the additional data sources the gap-resolution loop
    // should run. The registry lives in the module layer, which the CLI can see.
    let reg = crate::modules::registry();
    let by_uid: std::collections::HashMap<&str, &crate::core::entity::Entity> =
        entities.iter().map(|e| (e.uid.as_str(), e)).collect();

    println!("  ── isolated seeds (most actionable first) ──");
    for o in report.orphans.iter().take(20) {
        let mods: Vec<&str> = by_uid
            .get(o.uid.as_str())
            .and_then(|e| {
                TargetKind::from_entity_kind(&e.kind).map(|tk| Target::new(tk, e.value.clone()))
            })
            .map(|t| {
                reg.iter()
                    .filter(|m| m.accepts(&t))
                    .map(|m| m.name())
                    .take(6)
                    .collect()
            })
            .unwrap_or_default();
        let run = if mods.is_empty() {
            String::new()
        } else {
            format!("  → run: {}", mods.join(", "))
        };
        println!(
            "  [{:?}] {} ({}) — {}{run}",
            o.isolation, o.value, o.kind, o.action
        );
    }
    if report.orphans.len() > 20 {
        println!("  …and {} more.", report.orphans.len() - 20);
    }
    Ok(())
}
