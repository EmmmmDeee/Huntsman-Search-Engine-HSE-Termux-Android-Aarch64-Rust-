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
        "full" => render_full(&store, &sid)?,
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: json, csv, gexf, report, full"
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

/// The **full dossier** — Huntsman's standard of maximum output detail. Emits
/// EVERY entity (including quarantined `candidate` rows — nothing is hidden),
/// each with its confidence/corroboration/tags and its COMPLETE evidence chain:
/// every attribute verbatim — the full raw source record, the provenance
/// (`provider`, `api_key_origin`, `via_endpoint`), and the source website/db —
/// nothing hashed, masked, truncated, or omitted. A leading provenance summary
/// lists every provider, API-key origin, and source seen. This is the on-disk
/// counterpart to the live dossier and the raw archive: the contract is total
/// transparency for a professional interpreter.
fn render_full(store: &Store, sid: &str) -> Result<String> {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    let scan = store
        .get_scan(sid)?
        .ok_or_else(|| Error::Other(format!("scan {sid} not found")))?;
    let mut entities = store.entities_for_scan(sid)?;
    let relations = store.relations_for_scan(sid)?;
    // Stable, readable grouping: by kind, then value.
    entities.sort_by(|a, b| {
        a.kind
            .to_string()
            .cmp(&b.kind.to_string())
            .then_with(|| a.value.cmp(&b.value))
    });

    // Provenance roll-up across every evidence record.
    let mut providers: BTreeSet<String> = BTreeSet::new();
    let mut key_origins: BTreeSet<String> = BTreeSet::new();
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for e in &entities {
        for ev in &e.evidence {
            if let Some(p) = ev.attributes.get("provider") {
                providers.insert(p.clone());
            }
            if let Some(k) = ev.attributes.get("api_key_origin") {
                key_origins.insert(k.clone());
            }
            for sk in ["source", "source_db", "dbname"] {
                if let Some(v) = ev.attributes.get(sk).filter(|v| !v.is_empty()) {
                    sources.insert(v.clone());
                }
            }
        }
    }

    let mut s = String::new();
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let _ = writeln!(s, "HUNTSMAN FULL DOSSIER — complete, unredacted");
    let _ = writeln!(s, "═══════════════════════════════════════════════════════");
    let _ = writeln!(s, "scan id    : {}", scan.id);
    let _ = writeln!(
        s,
        "target     : {} = {}",
        scan.target.kind.canonical_str(),
        scan.target.value
    );
    let _ = writeln!(s, "status     : {:?}", scan.status);
    let _ = writeln!(s, "entities   : {}", entities.len());
    let _ = writeln!(s, "relations  : {}", relations.len());

    let _ = writeln!(s, "\n── PROVENANCE ──");
    let _ = writeln!(
        s,
        "providers      : {}",
        join_or_dash(providers.iter())
    );
    let _ = writeln!(
        s,
        "api key origins: {}",
        join_or_dash(key_origins.iter())
    );
    let _ = writeln!(
        s,
        "sources/sites  : {}",
        join_or_dash(sources.iter())
    );

    let _ = writeln!(s, "\n── ENTITIES (every field, fully unredacted) ──");
    for (i, e) in entities.iter().enumerate() {
        let _ = writeln!(
            s,
            "\n[{}] {} = {}",
            i + 1,
            e.kind,
            e.value
        );
        let _ = writeln!(
            s,
            "    confidence={:.2}  c_eff={:.2}  corroboration={}  class={}",
            e.confidence,
            e.c_effective(),
            e.corroboration,
            e.classify()
        );
        if !e.tags.is_empty() {
            let _ = writeln!(s, "    tags: {}", e.tags.join(", "));
        }
        for ev in &e.evidence {
            let _ = writeln!(s, "    ├─ [{}] {}", ev.source, ev.summary);
            for (k, v) in &ev.attributes {
                if !v.is_empty() {
                    let _ = writeln!(s, "    │    {k} = {v}");
                }
            }
        }
    }

    if !relations.is_empty() {
        let _ = writeln!(s, "\n── RELATIONS ──");
        for r in &relations {
            let _ = writeln!(
                s,
                "  {} ──{}──▶ {}  (conf={:.2})",
                r.from_uid, r.kind, r.to_uid, r.confidence
            );
        }
    }

    // ── RAW SOURCE RECORDS ──────────────────────────────────────────────────
    // Embed every paid API response this scan fetched, verbatim, recovered from
    // the on-disk archive. This guarantees the dossier leaves NOTHING out — even
    // thin records that produced no entity (e.g. a breach hit with only a
    // `source`, or a paste listing hundreds of unrelated addresses) appear here
    // in full. The archive files remain saved separately; this is an embedded
    // copy for a self-contained dossier.
    //
    // Responses are tied to THIS scan precisely: the time window [started_at,
    // finished_at] excludes earlier runs of the same target, and the query-set
    // (target value + every entity value) excludes a neighbouring back-to-back
    // scan whose second-granular window touches this one. (A loose ±margin window
    // bled adjacent scans together — unix timestamps are per-second.)
    let start = scan.started_at;
    let end = scan.finished_at.unwrap_or(u64::MAX);
    let mut queries: std::collections::HashSet<String> = std::collections::HashSet::new();
    queries.insert(scan.target.value.to_lowercase());
    for e in &entities {
        queries.insert(e.value.to_lowercase());
    }
    let raws = crate::util::raw_archive::records_for_queries(&queries, start, end);
    let _ = writeln!(
        s,
        "\n── RAW SOURCE RECORDS ({} response{}, verbatim) ──",
        raws.len(),
        if raws.len() == 1 { "" } else { "s" }
    );
    if raws.is_empty() {
        let _ = writeln!(
            s,
            "  (raw archive empty for this window — disabled, or run predates archiving)"
        );
    }
    for resp in &raws {
        let _ = writeln!(
            s,
            "\n  ▼ {} · endpoint={} · query={} · file={}",
            resp.provider, resp.endpoint, resp.query, resp.filename
        );
        // Pretty-print the verbatim body, indented, so the whole response —
        // every record, every field — is in the dossier with nothing elided.
        let pretty =
            serde_json::to_string_pretty(&resp.raw).unwrap_or_else(|_| resp.raw.to_string());
        for line in pretty.lines() {
            let _ = writeln!(s, "    {line}");
        }
    }

    Ok(s)
}

/// Comma-join an iterator of strings, or `(none)` when empty — so an empty
/// provenance line is explicit rather than a confusing blank.
fn join_or_dash<'a>(it: impl Iterator<Item = &'a String>) -> String {
    let joined = it.cloned().collect::<Vec<_>>().join(", ");
    if joined.is_empty() {
        "(none)".to_string()
    } else {
        joined
    }
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
    fn render_full_dumps_every_field_and_provenance() {
        use crate::core::entity::{Entity, EntityKind, Evidence};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("full_test.db");
        let store = Store::open(db.to_str().unwrap()).unwrap();

        let target = Target::new(TargetKind::Email, "vanamill@hotmail.com");
        let scan = Scan::new("scan-full", target);
        store.upsert_scan(&scan).unwrap();

        // A password entity carrying full provenance + a raw source field.
        let mut e = Entity::new(EntityKind::Password, "thelord", 0.75, "scan-full");
        e.tag("breach");
        e.add_evidence(
            Evidence::new("see_know", "SeekNow record from Snusbase")
                .with_attr("provider", "see-know.eu")
                .with_attr("api_key_origin", "see-know.eu:seek-62650f9a…0fd0a4")
                .with_attr("via_endpoint", "search")
                .with_attr("source", "Snusbase")
                .with_attr("username", "3toadsloth"),
        );
        store.upsert_entities_batch(&[e]).unwrap();

        let out = render_full(&store, "scan-full").unwrap();
        // Header + provenance roll-up.
        assert!(out.contains("HUNTSMAN FULL DOSSIER"));
        assert!(out.contains("providers      : see-know.eu"));
        assert!(out.contains("api key origins: see-know.eu:seek-62650f9a…0fd0a4"));
        assert!(out.contains("sources/sites  : Snusbase"));
        // The entity, its value, and EVERY evidence attribute verbatim.
        assert!(out.contains("password = thelord"));
        assert!(out.contains("api_key_origin = see-know.eu:seek-62650f9a…0fd0a4"));
        assert!(out.contains("via_endpoint = search"));
        assert!(out.contains("username = 3toadsloth"));
    }

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
