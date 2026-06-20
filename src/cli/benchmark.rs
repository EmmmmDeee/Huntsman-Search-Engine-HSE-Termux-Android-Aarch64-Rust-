//! `hse benchmark` — emit a consolidated, auditable benchmark report for a scan.
//!
//! Loads a completed scan and prints the measurable OSINT dimensions the directive
//! scores on — discovery depth, graph coverage, corroboration, density, throughput,
//! pivots — as a human scorecard, or as machine-readable JSON (`--json`) for a scripted,
//! reproducible A/B against another tool on the same seed. Read-only over the store; the
//! report itself is pure synthesis ([`crate::core::benchmark::report`]).

use crate::core::benchmark;
use crate::core::error::{Error, Result};
use crate::default_db_path;
use crate::storage::Store;

use super::resolve_scan_id;

/// `hse benchmark [--scan-id <id|latest>] [--json]` — print the scan's benchmark report.
pub fn cmd_benchmark(scan_id: Option<String>, json: bool) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let id = resolve_scan_id(&store, scan_id.as_deref().unwrap_or("latest"))?;
    let scan = store
        .get_scan(&id)?
        .ok_or_else(|| Error::Other(format!("scan {id} not found")))?;
    let entities = store.entities_for_scan(&id)?;
    let relations = store.relations_for_scan(&id)?;
    let report = benchmark::report(&scan, &entities, &relations);

    if json {
        let out = serde_json::to_string_pretty(&report).map_err(|e| Error::Other(e.to_string()))?;
        println!("{out}");
        return Ok(());
    }

    let sc = &report.scorecard;
    println!(
        "Benchmark — scan {} (seed: {} [{}], {})",
        report.scan_id, report.seed, report.seed_kind, report.status
    );
    match report.duration_secs {
        Some(d) => println!(
            "  duration          {d}s  ({:.2} entities/s)",
            report.entities_per_sec
        ),
        None => println!("  duration          (scan not finished)"),
    }
    println!(
        "  modules           {} run, {} errored, {} timed out",
        report.modules_run, report.modules_errored, report.modules_timed_out
    );
    println!("  ── scorecard ──────────────");
    println!("  entities          {}", sc.total_entities);
    println!("  relations         {}", sc.total_relations);
    println!("  multi-hop depth   {}", sc.multi_hop_depth);
    println!("  graph coverage    {:.0}%", sc.graph_coverage * 100.0);
    println!(
        "  corroborated      {:.0}%",
        sc.corroborated_fraction * 100.0
    );
    println!("  graph density     {:.0}%", sc.graph_density * 100.0);
    println!("  cut vertices      {}", sc.cut_vertex_count);
    println!("  bridges           {}", sc.bridge_count);
    println!("  cross-scan        {}", sc.cross_scan_bridges);
    println!("  pivot nodes       {}", report.pivot_count);
    Ok(())
}
