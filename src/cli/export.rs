//! `hse export` — dump a previous scan's entities in JSON / CSV /
//! GEXF / pretty-JSON-report.
//!
//! Resolves the scan id (or `latest` → most-recent completed scan in
//! the store), renders the entities in the chosen format, and writes
//! to stdout or `--out <path>`.
//!
//! Mirrors the HTTP export surface so CLI operators and dashboard
//! users see the same outputs.

use crate::core::error::{Error, Result};
use crate::default_db_path;
use crate::storage::Store;

/// Resolve the scan id requested by the user. `latest` → the most-
/// recent Complete scan, picked at the SQL layer so the 64-row
/// `list_scans` window can't shadow older Complete rows when many
/// recent scans failed.
fn resolve_scan_id(store: &Store, raw: &str) -> Result<String> {
    if raw != "latest" {
        return Ok(raw.to_string());
    }
    store
        .latest_completed_scan()?
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
    Ok(crate::api::scan_handlers::entities_to_csv(&entities))
}

fn render_gexf(store: &Store, sid: &str) -> Result<String> {
    let entities = store.entities_for_scan(sid)?;
    Ok(crate::core::gexf::entities_to_gexf(&entities, sid))
}

fn render_report(store: &Store, sid: &str) -> Result<String> {
    let report = crate::api::scan_handlers::build_scan_report(store as _, sid)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}
