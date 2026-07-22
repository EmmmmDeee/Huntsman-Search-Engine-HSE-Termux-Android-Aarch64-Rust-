//! `hse export` — dump a previous scan's entities in JSON / CSV /
//! GEXF / pretty-JSON-report.
//!
//! Resolves the scan id (or `latest` → most-recent completed scan in
//! the store), renders the entities in the chosen format, and writes
//! to stdout or `--out <path>`.
//!
//! Mirrors the HTTP export surface so CLI operators and dashboard
//! users see the same outputs.

mod dossier;
mod environment;
mod renderers;

#[cfg(test)]
mod tests;

pub(crate) use dossier::write_full_dossier;
pub(crate) use renderers::{
    KeyPoolSummary, SystemDebugInputs, render_debug_bundle, render_full, render_system_debug_bundle,
};

use crate::core::error::{Error, Result};
use crate::default_db_path;
use crate::storage::Store;

pub(super) async fn cmd_export(
    scan_id: String,
    format: String,
    out: Option<String>,
    include_infra: bool,
) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    // `latest` → most-recent Complete scan; an explicit id is existence-checked so
    // a typo fails loudly instead of emitting an empty CSV/JSON/GEXF (which is
    // indistinguishable from a real scan that found nothing). Shared with
    // `diff`/`audit` via `super::resolve_scan_id`.
    let sid = super::resolve_scan_id(&store, &scan_id)?;
    let body = match format.to_lowercase().as_str() {
        "json" => renderers::render_json(&store, &sid)?,
        "csv" => renderers::render_csv(&store, &sid)?,
        "gexf" => renderers::render_gexf(&store, &sid)?,
        "report" => renderers::render_report(&store, &sid, include_infra)?,
        // `full` always includes infra — it is the maximum-detail format.
        "full" => render_full(&store, &sid)?,
        "debug" => render_debug_bundle(&store, &sid)?,
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: json, csv, gexf, report, full, debug"
            )));
        }
    };
    // `full` / `debug` embed full PII *and* the raw API corpus — including any
    // third-party keys harvested during the scan — which is why the auto-saved
    // dossier writes them 0600 + atomically (`export/dossier.rs`). An explicit
    // `--out` for those formats must get the identical private guarantee, or it
    // silently drops the same secrets into a world-readable, umask-default file
    // (a real exposure on a shared Android device). The shareable scan exports
    // (json/csv/gexf/report) keep the plain write so an operator can hand them
    // off without first having to loosen 0600 perms.
    let sensitive = matches!(format.to_lowercase().as_str(), "full" | "debug");
    match out {
        Some(path) => {
            if sensitive {
                crate::util::atomic_file::write(std::path::Path::new(&path), body.as_bytes())
                    .map_err(|e| Error::Other(format!("write {path}: {e}")))?;
            } else {
                std::fs::write(&path, &body)
                    .map_err(|e| Error::Other(format!("write {path}: {e}")))?;
            }
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
