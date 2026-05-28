//! `hse export` — dump a previous scan's entities in JSON / CSV /
//! GEXF / pretty-JSON-report.
//!
//! Resolves the scan id (or `latest` → most-recent completed scan in
//! the store), renders the entities in the chosen format, and writes
//! to stdout or `--out <path>`.
//!
//! Mirrors the HTTP export surface so CLI operators and dashboard
//! users see the same outputs.

use std::fmt::Write as _;

use crate::core::error::{Error, Result};
use crate::core::scan::Scan;
use crate::default_db_path;
use crate::storage::Store;

/// Resolve the scan id requested by the user. `latest` → the most-
/// recent completed scan, ranked by `created_at` descending.
fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw != "latest" {
        return Ok(raw.to_string());
    }
    let mut scans: Vec<Scan> = store.list_scans(64)?;
    // list_scans returns newest-first already, but be defensive and
    // re-sort by started_at descending.
    scans.sort_by_key(|s| std::cmp::Reverse(s.started_at));
    scans
        .into_iter()
        .find(|s| matches!(s.status, crate::core::scan::ScanStatus::Complete))
        .map(|s| s.id)
        .ok_or_else(|| Error::Other("no completed scans in store".into()))
}

pub(super) async fn cmd_export(scan_id: String, format: String, out: Option<String>) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let sid = resolve_scan_id(&store, &scan_id)?;
    let body = match format.to_lowercase().as_str() {
        "json" => render_json(&store, &sid)?,
        "csv" => render_csv(&store, &sid)?,
        "gexf" => render_gexf(&store, &sid)?,
        "report" => render_report(&store, &sid)?,
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: json, csv, gexf, report"
            )));
        }
    };
    match out {
        Some(path) => {
            std::fs::write(&path, &body).map_err(|e| Error::Other(format!("write {path}: {e}")))?;
            eprintln!("exported {} bytes to {path}", body.len());
        }
        None => {
            // stdout — avoid println! to keep binary GEXF unmolested.
            use std::io::Write as _;
            std::io::stdout()
                .write_all(body.as_bytes())
                .map_err(|e| Error::Other(format!("stdout: {e}")))?;
        }
    }
    Ok(())
}

fn render_json(store: &Store, sid: &str) -> Result<String> {
    let entities = store.entities_for_scan(sid)?;
    serde_json::to_string_pretty(&entities)
        .map_err(|e| Error::Other(format!("json serialise: {e}")))
}

fn render_csv(store: &Store, sid: &str) -> Result<String> {
    let entities = store.entities_for_scan(sid)?;
    let mut body = String::with_capacity(192 + entities.len() * 128);
    body.push_str("kind,value,raw_value,confidence,c_effective,corroboration,classification,observed_at,sources,tags\n");
    for e in &entities {
        let eff = e.c_effective();
        let tier = e.classify().to_string();
        let mut sources: Vec<&str> = e.evidence_sources().into_iter().collect();
        sources.sort_unstable();
        let sources = sources.join("|");
        let tags = e.tags.join("|");
        let _ = writeln!(
            body,
            "{},{},{},{:.3},{:.3},{},{},{},{},{}",
            crate::api::scan_handlers::csv_escape(&e.kind.to_string()),
            crate::api::scan_handlers::csv_escape(&e.value),
            crate::api::scan_handlers::csv_escape(&e.raw_value),
            e.confidence,
            eff,
            e.corroboration,
            tier,
            e.observed_at,
            crate::api::scan_handlers::csv_escape(&sources),
            crate::api::scan_handlers::csv_escape(&tags),
        );
    }
    Ok(body)
}

fn render_gexf(store: &Store, sid: &str) -> Result<String> {
    let entities = store.entities_for_scan(sid)?;
    Ok(crate::core::gexf::entities_to_gexf(&entities, sid))
}

fn render_report(store: &Store, sid: &str) -> Result<String> {
    let scan = store
        .get_scan(sid)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    let entities = store.entities_for_scan(sid)?;
    let correlations = store.correlations_for_scan(sid)?;
    let report = serde_json::json!({
        "scan": scan,
        "entities": entities,
        "entity_count": entities.len(),
        "correlations": correlations,
        "correlation_count": correlations.len(),
        "exported_at": crate::core::entity::unix_now(),
    });
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}
