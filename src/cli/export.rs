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
        "debug" => render_debug_bundle(&store, &sid)?,
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: json, csv, gexf, report, full, debug"
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
pub(crate) fn render_full(store: &dyn crate::core::port::StoragePort, sid: &str) -> Result<String> {
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
    let _ = writeln!(s, "providers      : {}", join_or_dash(providers.iter()));
    let _ = writeln!(s, "api key origins: {}", join_or_dash(key_origins.iter()));
    let _ = writeln!(s, "sources/sites  : {}", join_or_dash(sources.iter()));

    // Foreign API keys retrieved from endpoint data — surfaced up front because
    // a leaked third-party credential is the highest-signal finding in a scan.
    // These are ApiKey entities tagged `foreign-key`: recognised VENDOR keys
    // (Stripe, AWS, GitHub, PEM blocks, …) identified in any module's response,
    // with our own auth keys excluded. Bare breach password hashes are NOT here
    // (they appear as their own entities below). Full evidence is in ENTITIES.
    let foreign: Vec<&crate::core::entity::Entity> = entities
        .iter()
        .filter(|e| e.has_tag("foreign-key"))
        .collect();
    let _ = writeln!(s, "\n── FOREIGN API KEYS RETRIEVED ({}) ──", foreign.len());
    if foreign.is_empty() {
        let _ = writeln!(s, "  (none identified in this scan's responses)");
    }
    for e in &foreign {
        let attr = |k: &str| {
            e.evidence
                .iter()
                .find_map(|ev| ev.attributes.get(k).cloned())
                .unwrap_or_default()
        };
        let _ = writeln!(
            s,
            "  • [{}] {}  (from {} · query={} · seen {}×)",
            attr("service"),
            e.value,
            attr("source_provider"),
            attr("source_query"),
            attr("occurrences"),
        );
    }

    let _ = writeln!(s, "\n── ENTITIES (every field, fully unredacted) ──");
    for (i, e) in entities.iter().enumerate() {
        let _ = writeln!(s, "\n[{}] {} = {}", i + 1, e.kind, e.value);
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

/// Environment fingerprint for the debug bundle: the build, host, module set,
/// and key-PRESENCE (names only — never values) under which a scan ran. This is
/// what makes "why did module X find nothing?" answerable from the artifact
/// alone — almost always an absent key or a missing `curl`, not a bug — and lets
/// configuration/environment drift between two bundles be diffed (Determinism
/// Requirement names config/env drift as a thing to detect and report).
///
/// Deliberately secret-free: only the NAMES of present `HUNTSMAN_*` keys are
/// listed, never their values. Per-process-stable (version, target, registry,
/// key presence don't change mid-process), so it does not break the bundle's
/// byte-determinism for a fixed host.
fn render_environment() -> String {
    use std::fmt::Write as _;
    let loaded = crate::util::keys::load();
    let mut present: Vec<&str> = loaded
        .keys()
        .filter(|k| k.starts_with("HUNTSMAN_"))
        .map(String::as_str)
        .collect();
    present.sort_unstable();
    let absent: Vec<&&str> = crate::util::keys::KNOWN_KEYS
        .iter()
        .filter(|k| !loaded.contains_key(**k))
        .collect();

    let mods = crate::modules::registry();
    let mut by_cost: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for m in &mods {
        *by_cost.entry(super::cost_label(m.cost())).or_default() += 1;
    }
    let cost_summary = by_cost
        .iter()
        .map(|(c, n)| format!("{c} {n}"))
        .collect::<Vec<_>>()
        .join(", ");

    let curl = std::process::Command::new("curl")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    let mut s = String::new();
    let _ = writeln!(s, "\n── ENVIRONMENT (reconstructable scan context) ──");
    let _ = writeln!(s, "  hse_version : {}", crate::VERSION);
    let _ = writeln!(
        s,
        "  build_target: {}-{}",
        std::env::consts::ARCH,
        std::env::consts::OS
    );
    let _ = writeln!(
        s,
        "  termux      : {}",
        if crate::is_termux() {
            "detected"
        } else {
            "not detected"
        }
    );
    let _ = writeln!(
        s,
        "  curl        : {} (search_engines/social_probe/oathnet shell out to it)",
        if curl {
            "present"
        } else {
            "MISSING — those modules return nothing"
        }
    );
    let _ = writeln!(
        s,
        "  modules     : {} registered ({cost_summary})",
        mods.len()
    );
    // The full module-file roster, so the bundle reflects EVERY module the binary
    // carries — including ones that never dispatched on this scan. Grouped by cost
    // tier and sorted, so a `grep 'module=<name>'` in the SCAN SEQUENCE / logs can
    // be cross-checked against the complete inventory.
    {
        let mut by_tier: std::collections::BTreeMap<&str, Vec<&str>> =
            std::collections::BTreeMap::new();
        for m in &mods {
            by_tier
                .entry(super::cost_label(m.cost()))
                .or_default()
                .push(m.name());
        }
        for names in by_tier.values_mut() {
            names.sort_unstable();
        }
        for (tier, names) in &by_tier {
            let _ = writeln!(s, "    {tier:<10} ({}) {}", names.len(), names.join(", "));
        }
    }
    let _ = writeln!(
        s,
        "  keys_present: {}",
        if present.is_empty() {
            "(none — all free modules still run)".to_string()
        } else {
            present.join(", ")
        }
    );
    let _ = writeln!(
        s,
        "  keys_absent : {} (modules needing these skip cleanly, not errors){}",
        absent.len(),
        if absent.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                absent.iter().map(|k| **k).collect::<Vec<_>>().join(", ")
            )
        }
    );
    s
}

/// The **one-file debug bundle** — everything needed to understand and improve a
/// scan from a single artifact, with no black boxes. It concatenates:
///   0. the environment fingerprint ([`render_environment`]) — build/host, module
///      set, and key-PRESENCE (names only) the scan ran under;
///   1. the full dossier ([`render_full`]) — every entity, every evidence field,
///      provenance, foreign keys, and the verbatim raw source records;
///   2. the typed relation graph and correlator hits;
///   3. the COMPLETE scan sequence — every event (module start/done/error,
///      entity found, every admission/expansion exclusion with its reason,
///      expansion ticks/stops) as loss-less JSONL plus a per-type histogram, so
///      the exact order of operations and every decision is reconstructable;
///   4. the scored self-audit — score, every weakness finding with its
///      recommendation, the exclusion ledger, and the geo-consistency summary.
///
/// One `hse export <id> --format debug` (or the web "Debug bundle" button) yields
/// a single text file from which the whole run — sequence, results, and every
/// flaw — is understandable via logs alone.
pub(crate) fn render_debug_bundle(
    store: &dyn crate::core::port::StoragePort,
    sid: &str,
) -> Result<String> {
    use std::collections::BTreeMap;
    use std::fmt::Write as _;

    let mut s = String::new();
    let _ = writeln!(
        s,
        "╔═══════════════════════════════════════════════════════╗"
    );
    let _ = writeln!(
        s,
        "║  HUNTSMAN DEBUG BUNDLE — complete scan snapshot         ║"
    );
    let _ = writeln!(
        s,
        "║  Self-contained: results, sequence, and every flaw.    ║"
    );
    let _ = writeln!(
        s,
        "╚═══════════════════════════════════════════════════════╝"
    );
    // DETERMINISM: the bundle body deliberately carries NO wall-clock generation
    // timestamp. For an immutable (completed) scan, two exports must be
    // byte-identical so the artifact can be `diff`ed across runs/tools/time —
    // the reproducibility the bundle exists to serve. The scan's own immutable
    // timestamps (event `ts`, entity `observed_at`) are already inside, and a
    // caller that needs the generation time can take it out-of-band (HTTP
    // `Date` header / shell). Guarded by `debug_bundle_is_deterministic`.

    // ── 0. Environment fingerprint (reconstructable scan context) ──
    s.push_str(&render_environment());

    // ── 1. Full dossier (entities/evidence/provenance/raw records) ──
    s.push_str(&render_full(store, sid)?);

    // ── 2. Correlator hits ──
    let correlations = store.correlations_for_scan(sid)?;
    let _ = writeln!(s, "\n── CORRELATIONS ({}) ──", correlations.len());
    if correlations.is_empty() {
        let _ = writeln!(s, "  (no correlator rules fired)");
    }
    for c in &correlations {
        let _ = writeln!(
            s,
            "  • [{}] {} ({}) — {}  · entities: {}",
            c.rule_id,
            c.rule_name,
            c.severity,
            c.description,
            c.entity_uids.len()
        );
    }

    // ── 3. Complete scan sequence (every event) ──
    let events = store.events_for_scan(sid)?;
    let mut histo: BTreeMap<String, usize> = BTreeMap::new();
    for ev in &events {
        *histo
            .entry(ev.kind.event_type_str().to_string())
            .or_default() += 1;
    }
    let _ = writeln!(s, "\n── SCAN SEQUENCE ({} events) ──", events.len());
    let _ = writeln!(s, "  event histogram:");
    for (typ, n) in &histo {
        let _ = writeln!(s, "    {typ:30} {n}");
    }
    let _ = writeln!(
        s,
        "\n  full timeline (JSONL — one loss-less event per line, in order):"
    );
    if events.is_empty() {
        let _ = writeln!(
            s,
            "  (no events recorded — event persistence disabled, or an import not a live scan)"
        );
    }
    for ev in &events {
        // Loss-less, greppable: timestamp + the entire serialised event.
        let json = serde_json::to_string(ev).unwrap_or_else(|_| "{}".into());
        let _ = writeln!(s, "  {} {}", ev.ts, json);
    }

    // ── 4. Scored self-audit (every weakness + recommendation) ──
    let entities = store.entities_for_scan(sid)?;
    let normalised: Vec<crate::audit::AuditEntity> = entities
        .iter()
        .map(crate::audit::AuditEntity::from_entity)
        .collect();
    let mut signals = crate::audit::LogSignals::default();
    crate::audit::fold_events(&mut signals, &events);
    let report = crate::audit::audit(&normalised, signals);

    let _ = writeln!(s, "\n── SELF-AUDIT ──");
    let _ = writeln!(
        s,
        "  score      : {}/100 ({})",
        report.score,
        report.grade()
    );
    let _ = writeln!(
        s,
        "  tiers      : {} verified · {} probable · {} candidate · {:.0}% noise",
        report.tiers.0,
        report.tiers.1,
        report.tiers.2,
        report.noise_ratio * 100.0
    );
    if report.geo.coord_count > 0 {
        let _ = writeln!(
            s,
            "  geo        : {} fix(es) / {} source(s) · spread {:.0} km · {}{}",
            report.geo.coord_count,
            report.geo.source_count,
            report.geo.max_spread_km,
            if report.geo.has_consensus {
                "consensus"
            } else {
                "NO consensus"
            },
            if report.geo.outliers > 0 {
                format!(" · {} outlier(s)", report.geo.outliers)
            } else {
                String::new()
            },
        );
    }
    if !report.log.excluded_reasons.is_empty() {
        let ledger: Vec<String> = report
            .log
            .excluded_reasons
            .iter()
            .map(|(r, n)| format!("{r}×{n}"))
            .collect();
        let _ = writeln!(s, "  exclusions : {}", ledger.join(", "));
    }
    let _ = writeln!(s, "\n  FINDINGS ({}):", report.findings.len());
    if report.findings.is_empty() {
        let _ = writeln!(s, "    ✓ no weaknesses detected");
    }
    for f in &report.findings {
        let _ = writeln!(
            s,
            "\n    [{}] {} — {}",
            f.severity.as_str(),
            f.category,
            f.message
        );
        for ex in &f.examples {
            let _ = writeln!(s, "        • {ex}");
        }
        let _ = writeln!(s, "        → {}", f.recommendation);
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

/// Default directory for auto-saved full dossiers: `$HOME/.huntsman/dossiers`.
pub(crate) fn dossier_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    std::path::PathBuf::from(home)
        .join(".huntsman")
        .join("dossiers")
}

/// Render and persist the full dossier for `sid` to
/// `$HOME/.huntsman/dossiers/<sid>.txt`, returning the path. Called at the end
/// of every `hse scan` so the maximum-detail dossier — every entity, full
/// provenance, and every raw API response embedded — is guaranteed to exist for
/// EVERY search, without the operator running a separate `export`. Best-effort
/// for the caller: a write failure is returned as an error to log, never fatal.
pub(crate) fn write_full_dossier(
    store: &dyn crate::core::port::StoragePort,
    sid: &str,
) -> Result<std::path::PathBuf> {
    let body = render_full(store, sid)?;
    let dir = dossier_dir();
    std::fs::create_dir_all(&dir).map_err(|e| Error::Other(format!("create {dir:?}: {e}")))?;
    let path = dir.join(format!("{sid}.txt"));
    std::fs::write(&path, &body).map_err(|e| Error::Other(format!("write {path:?}: {e}")))?;
    Ok(path)
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
    fn debug_bundle_includes_dossier_sequence_and_audit() {
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::event::{Event, EventKind};
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("debug_test.db");
        let store = Store::open(db.to_str().unwrap()).unwrap();

        let target = Target::new(TargetKind::Email, "isaac@example-real.com");
        let scan = Scan::new("scan-dbg", target);
        store.upsert_scan(&scan).unwrap();
        store
            .upsert_entities_batch(&[Entity::new(
                EntityKind::Email,
                "isaac@example-real.com",
                0.8,
                "scan-dbg",
            )])
            .unwrap();
        // A recorded sequence including an exclusion (so the audit ledger fires).
        store
            .insert_event(&Event::new(
                "scan-dbg",
                EventKind::ModuleStart {
                    module: "hibp".into(),
                },
            ))
            .unwrap();
        store
            .insert_event(&Event::new(
                "scan-dbg",
                EventKind::EntityExcluded {
                    kind: "username".into(),
                    value: "stranger".into(),
                    reason: "identity_mismatch".into(),
                },
            ))
            .unwrap();

        let out = render_debug_bundle(&store, "scan-dbg").unwrap();
        // The pillars are all present in the single artifact.
        assert!(out.contains("HUNTSMAN DEBUG BUNDLE"));
        // Environment fingerprint (secret-free) frames the run.
        assert!(out.contains("── ENVIRONMENT"));
        assert!(out.contains("hse_version :"));
        assert!(out.contains("keys_present:"));
        // The full module-file roster is present — every module-file the binary
        // carries is accounted for, named, even if it never dispatched here.
        assert!(out.contains("modules     :"));
        assert!(
            out.contains("hibp"),
            "ENVIRONMENT module roster must name every registered module"
        );
        assert!(out.contains("HUNTSMAN FULL DOSSIER")); // §1 embeds render_full
        assert!(out.contains("── CORRELATIONS")); // §2
        assert!(out.contains("── SCAN SEQUENCE (2 events)")); // §3
        assert!(out.contains("module_start")); // histogram + JSONL
        assert!(out.contains("\"reason\":\"identity_mismatch\"")); // loss-less event
        assert!(out.contains("── SELF-AUDIT")); // §4
        assert!(out.contains("score      :"));
        assert!(out.contains("exclusions : identity_mismatch×1")); // ledger folded in
    }

    #[test]
    fn debug_bundle_is_deterministic() {
        // DETERMINISM REQUIREMENT (evidence, not assertion): re-exporting the
        // same immutable stored scan must be byte-identical, so the artifact is
        // diffable across runs/time. This is the experiment that proves it.
        use crate::core::entity::{Entity, EntityKind};
        use crate::core::event::{Event, EventKind};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("det.db").to_str().unwrap()).unwrap();
        let scan = Scan::new(
            "scan-det",
            Target::new(TargetKind::Email, "a@example-real.com"),
        );
        store.upsert_scan(&scan).unwrap();
        // Several entities + events so any unstable iteration order would surface.
        store
            .upsert_entities_batch(&[
                Entity::new(EntityKind::Email, "a@example-real.com", 0.8, "scan-det"),
                Entity::new(EntityKind::Username, "alpha", 0.6, "scan-det"),
                Entity::new(EntityKind::Username, "bravo", 0.6, "scan-det"),
                Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-det"),
            ])
            .unwrap();
        for m in ["hibp", "gravatar", "crtsh"] {
            store
                .insert_event(&Event::new(
                    "scan-det",
                    EventKind::ModuleStart { module: m.into() },
                ))
                .unwrap();
        }
        let a = render_debug_bundle(&store, "scan-det").unwrap();
        let b = render_debug_bundle(&store, "scan-det").unwrap();
        assert_eq!(
            a, b,
            "debug bundle is not byte-deterministic across exports"
        );
        // And it carries no wall-clock generation timestamp that would break that.
        assert!(!a.contains("generated_at"));
    }

    #[test]
    fn export_formats_determinism_audit() {
        // DETERMINISM REQUIREMENT: evidence (not assertion) that every export
        // format is byte-reproducible for a fixed store — so exports are diffable
        // across runs/time — with `report.json`'s `exported_at` as the ONE
        // documented exception. If a future change adds non-determinism anywhere
        // else, this fails.
        use crate::core::entity::{Entity, EntityKind};
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("audit.db").to_str().unwrap()).unwrap();
        let scan = Scan::new(
            "scan-au",
            Target::new(TargetKind::Email, "z@example-real.com"),
        );
        store.upsert_scan(&scan).unwrap();
        store
            .upsert_entities_batch(&[
                Entity::new(EntityKind::Email, "z@example-real.com", 0.8, "scan-au"),
                Entity::new(EntityKind::Username, "zeta", 0.6, "scan-au"),
                Entity::new(EntityKind::Domain, "example-real.com", 0.5, "scan-au"),
            ])
            .unwrap();

        type StoreFmt = fn(&Store, &str) -> Result<String>;
        type PortFmt = fn(&dyn crate::core::port::StoragePort, &str) -> Result<String>;

        // Byte-reproducible formats (Store-typed).
        let store_fmts: &[(&str, StoreFmt)] = &[
            ("json", render_json),
            ("csv", render_csv),
            ("gexf", render_gexf),
        ];
        for (name, render) in store_fmts {
            let a = render(&store, "scan-au").unwrap();
            let b = render(&store, "scan-au").unwrap();
            assert_eq!(a, b, "format `{name}` is not byte-deterministic");
        }
        // full + debug take `&dyn StoragePort`.
        let port_fmts: &[(&str, PortFmt)] =
            &[("full", render_full), ("debug", render_debug_bundle)];
        for (name, render) in port_fmts {
            let a = render(&store, "scan-au").unwrap();
            let b = render(&store, "scan-au").unwrap();
            assert_eq!(a, b, "format `{name}` is not byte-deterministic");
        }

        // report.json: deterministic EXCEPT the documented `exported_at`. Compare
        // structurally with that one field removed — robust regardless of whether
        // the two renders happened to land in the same wall-clock second.
        let mut r1: serde_json::Value =
            serde_json::from_str(&render_report(&store, "scan-au").unwrap()).unwrap();
        let mut r2: serde_json::Value =
            serde_json::from_str(&render_report(&store, "scan-au").unwrap()).unwrap();
        assert!(
            r1.get("exported_at").is_some(),
            "exported_at must be present"
        );
        for r in [&mut r1, &mut r2] {
            r.as_object_mut().unwrap().remove("exported_at");
        }
        assert_eq!(
            r1, r2,
            "report.json varies in a field OTHER than the documented `exported_at`"
        );
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
