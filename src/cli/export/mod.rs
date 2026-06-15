//! `hse export` — dump a previous scan's entities in JSON / CSV /
//! GEXF / STIX 2.1 / MISP JSON / Maltego XML / SpiderFoot SQLite.
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
    render_debug_bundle, render_full, render_maltego, render_misp, render_stix,
};

use crate::core::error::{Error, Result};
use crate::default_db_path;
use crate::storage::Store;

pub(super) async fn cmd_export(scan_id: String, format: String, out: Option<String>) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    // `latest` → most-recent Complete scan; an explicit id is existence-checked so
    // a typo fails loudly instead of emitting an empty CSV/JSON/GEXF (which is
    // indistinguishable from a real scan that found nothing). Shared with
    // `diff`/`audit` via `super::resolve_scan_id`.
    let sid = super::resolve_scan_id(&store, &scan_id)?;
    // SpiderFoot exports a binary SQLite file — handled separately.
    if format.to_lowercase() == "spiderfoot" {
        let path =
            out.ok_or_else(|| Error::Other("--format spiderfoot requires --out <path.db>".into()))?;
        renderers::write_spiderfoot_db(&store, &sid, &path)?;
        eprintln!("SpiderFoot database written to {path}");
        return Ok(());
    }

    let body = match format.to_lowercase().as_str() {
        "json" => renderers::render_json(&store, &sid)?,
        "csv" => renderers::render_csv(&store, &sid)?,
        "gexf" => renderers::render_gexf(&store, &sid)?,
        "report" => renderers::render_report(&store, &sid)?,
        "full" => render_full(&store, &sid)?,
        "debug" => render_debug_bundle(&store, &sid)?,
        "stix" => renderers::render_stix(&store, &sid)?,
        "misp" => renderers::render_misp(&store, &sid)?,
        "maltego" => renderers::render_maltego(&store, &sid)?,
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: json, csv, gexf, report, full, debug, stix, misp, maltego, spiderfoot"
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
