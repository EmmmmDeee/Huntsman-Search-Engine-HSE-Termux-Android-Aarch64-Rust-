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

/// Fail loudly on a missing scan instead of emitting an empty CSV/JSON/GEXF.
/// `entities_for_scan` returns an empty Vec for an unknown id, which is
/// indistinguishable from a real scan that found nothing; the `report` format
/// already errors on a missing scan, so this makes all four formats consistent.
/// (The `latest` branch of `resolve_scan_id` already guarantees existence.)
fn require_scan(store: &Store, sid: &str) -> Result<()> {
    if store.get_scan(sid)?.is_none() {
        return Err(Error::Other(format!("scan {sid} not found")));
    }
    Ok(())
}

pub(super) async fn cmd_export(scan_id: String, format: String, out: Option<String>) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let sid = resolve_scan_id(&store, &scan_id)?;
    require_scan(&store, &sid)?;
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
    let relations = store.relations_for_scan(sid)?;
    Ok(crate::core::gexf::entities_to_gexf(
        &entities, &relations, sid,
    ))
}

fn render_report(store: &Store, sid: &str) -> Result<String> {
    // Default dossier hides quarantined `candidate` entities (non-target
    // breach-dump rows) — the confirmed-footprint view. They remain available
    // over HTTP via `report.json?include_candidates=1`.
    let report = crate::api::scan_handlers::build_scan_report(store as _, sid, false)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    serde_json::to_string_pretty(&report)
        .map_err(|e| Error::Other(format!("report serialise: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::{Scan, Target, TargetKind};

    #[test]
    fn require_scan_errors_on_missing_and_ok_on_present() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("export_test.db");
        let store = Store::open(db.to_str().unwrap()).unwrap();

        // Unknown id -> a clear "not found" error (no silent empty export).
        let err = require_scan(&store, "no-such-scan")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not found"),
            "expected not-found error, got: {err}"
        );

        // After the scan exists, the check passes.
        let target = Target::new(TargetKind::Email, "x@b.com");
        store
            .upsert_scan(&Scan::new("scan-present", target))
            .unwrap();
        assert!(require_scan(&store, "scan-present").is_ok());
    }
}
