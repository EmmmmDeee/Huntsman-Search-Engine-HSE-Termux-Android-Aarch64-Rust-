//! `hse device-scan` — one-shot on-device sensor snapshot.
//!
//! The single-shot complement to `hse radar` (which loops). Runs the local
//! passive sensor modules — GPS, WiFi, cell towers, ARP/LAN, network
//! interfaces — exactly once against the device, prints every captured signal
//! entity, and exits. With `--depth > 0` each newly discovered signal is then
//! pivoted once through the full OSINT module graph (sharing radar's
//! quota-protecting pivot rules via [`super::sweep`]).
//!
//! This is a capability SpiderFoot structurally cannot offer (it has no access
//! to a handset's sensors). On a non-Termux host the sensor binaries are
//! absent; the modules fail safely (no panic) and the scan reports zero
//! signals — the command still runs end-to-end and exits cleanly.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::sync::Arc;

use crate::core::entity::Entity;
use crate::core::error::{Error, Result};
use crate::core::event::EventBus;
use crate::core::module::ModuleContext;
use crate::core::scan::{Scan, Target, TargetKind};
use crate::util::{http::build_client, keys, uid::scan_id};

use super::{build_runtime, color_confidence, sweep, truncate, use_color};

/// Rendered output format for the captured signal set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum OutputFmt {
    Table,
    Json,
    Dossier,
}

fn parse_output(s: &str) -> Result<OutputFmt> {
    match s.trim().to_lowercase().as_str() {
        "table" => Ok(OutputFmt::Table),
        "json" => Ok(OutputFmt::Json),
        "dossier" => Ok(OutputFmt::Dossier),
        other => Err(Error::Other(format!(
            "unknown output format '{other}'. Valid: table, json, dossier"
        ))),
    }
}

/// A flattened, render-ready view of one discovered signal entity. Decoupled
/// from `Entity` so rendering is pure and unit-testable without the engine.
struct SignalRow {
    kind: String,
    value: String,
    c_eff: f64,
    sources: usize,
    tags: Vec<String>,
}

/// Project entities to render rows, highest effective-confidence first
/// (deterministic: c_eff desc, then kind, then value).
fn rows_from(entities: &[Entity]) -> Vec<SignalRow> {
    let mut rows: Vec<SignalRow> = entities
        .iter()
        .map(|e| SignalRow {
            kind: e.kind.to_string(),
            value: e.value.clone(),
            c_eff: e.c_effective(),
            sources: e.evidence.len(),
            tags: e.tags.clone(),
        })
        .collect();
    rows.sort_by(|a, b| {
        b.c_eff
            .partial_cmp(&a.c_eff)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.kind.cmp(&b.kind))
            .then(a.value.cmp(&b.value))
    });
    rows
}

/// Machine-readable snapshot: `{ "signals": [ … ], "count": N }`.
fn render_json(rows: &[SignalRow]) -> String {
    let signals: Vec<_> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "kind": r.kind,
                "value": r.value,
                "c_eff": r.c_eff,
                "sources": r.sources,
                "tags": r.tags,
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "signals": signals,
        "count": rows.len(),
    }))
    .unwrap_or_else(|_| "{\"signals\":[],\"count\":0}".to_string())
}

/// Terse one-line-per-signal table.
fn render_table(rows: &[SignalRow], color: bool) -> String {
    if rows.is_empty() {
        return "  (no signals captured)".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(
        s,
        "{:<14} {:<40} {:>6} {:>4}  TAGS",
        "KIND", "VALUE", "C_EFF", "SRC"
    );
    let _ = writeln!(s, "{}", "-".repeat(78));
    for r in rows {
        let ceff = color_confidence(r.c_eff, &format!("{:.2}", r.c_eff), color);
        let _ = writeln!(
            s,
            "{:<14} {:<40} {:>6} {:>4}  {}",
            truncate(&r.kind, 14),
            truncate(&r.value, 40),
            ceff,
            r.sources,
            truncate(&r.tags.join(","), 30),
        );
    }
    let _ = write!(s, "\n{} signal(s) captured.", rows.len());
    s
}

/// Verbose per-signal dossier block.
fn render_dossier(rows: &[SignalRow], color: bool) -> String {
    if rows.is_empty() {
        return "No on-device signals captured.".to_string();
    }
    let mut s = String::new();
    let _ = writeln!(s, "═══ DEVICE SIGNALS ({}) ═══", rows.len());
    for (i, r) in rows.iter().enumerate() {
        let ceff = color_confidence(r.c_eff, &format!("{:.2}", r.c_eff), color);
        let _ = writeln!(s, "\n[{}] {} = {}", i + 1, r.kind, r.value);
        let _ = writeln!(s, "    c_eff: {ceff}  sources: {}", r.sources);
        if !r.tags.is_empty() {
            let _ = writeln!(s, "    tags: {}", r.tags.join(", "));
        }
    }
    s
}

fn make_ctx(sid: &str, bus: &EventBus) -> ModuleContext {
    ModuleContext {
        scan_id: sid.to_string(),
        bus: bus.clone(),
        http: build_client(),
        keys: keys::load(),
        cancel: crate::core::cancel::CancelHandle::new(),
        proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
    }
}

pub(super) async fn cmd_device_scan(depth: u32, free_only: bool, output: String) -> Result<()> {
    // Validate the format before any work so a typo fails fast and cheaply.
    let fmt = parse_output(&output)?;
    let color = use_color();
    eprintln!(
        "{}",
        color_confidence(0.85, "HSE device-scan — one-shot on-device sensor snapshot", color)
    );

    let (store, bus, engine) = build_runtime(1024)?;

    // ── One sensor sweep (no loop) ──────────────────────────────────────────
    let sweep_sid = scan_id("device-scan", "sweep");
    let sweep_target = Target::new(TargetKind::Domain, "device.local");
    let sweep_scan = Scan::new(sweep_sid.clone(), sweep_target.clone())
        .with_options(sweep::sensor_sweep_options());
    engine
        .run(sweep_scan, sweep_target, make_ctx(&sweep_sid, &bus))
        .await?;
    let mut discovered = store.entities_for_scan(&sweep_sid)?;
    eprintln!(
        "  {} {} signal(s) captured",
        color_confidence(0.85, "◉", color),
        discovered.len()
    );

    // ── Optional one-shot pivot on each new discovery ───────────────────────
    if depth > 0 {
        let mut seen: HashSet<String> = discovered.iter().map(|e| e.uid.clone()).collect();
        let targets = sweep::pivot_targets(&discovered);
        if !targets.is_empty() {
            eprintln!(
                "  {} pivoting {} signal(s) at depth {depth}",
                color_confidence(0.85, "▶", color),
                targets.len()
            );
        }
        for (tk, value) in targets {
            let psid = scan_id(tk.canonical_str(), &value);
            let ptarget = Target::new(tk, value.clone());
            let pscan = Scan::new(psid.clone(), ptarget.clone())
                .with_options(sweep::pivot_options(depth, free_only, tk));
            engine
                .run(pscan, ptarget, make_ctx(&psid, &bus))
                .await?;
            for e in store.entities_for_scan(&psid)? {
                if seen.insert(e.uid.clone()) {
                    discovered.push(e);
                }
            }
        }
    }

    // ── Render the snapshot to stdout (payload only; progress went to stderr)
    let rows = rows_from(&discovered);
    let payload = match fmt {
        OutputFmt::Json => render_json(&rows),
        OutputFmt::Table => render_table(&rows, color),
        OutputFmt::Dossier => render_dossier(&rows, color),
    };
    println!("{payload}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind, Evidence};

    fn sig(kind: EntityKind, value: &str, conf: f64) -> Entity {
        // With no evidence and default corroboration, c_effective() == conf
        // (both confidence models equal at n=1), so tests control c_eff via conf.
        Entity::new(kind, value, conf, "scan")
    }

    // ── parse_output ────────────────────────────────────────────────────────

    #[test]
    fn parse_output_accepts_known_formats_case_insensitively() {
        assert_eq!(parse_output("table").unwrap(), OutputFmt::Table);
        assert_eq!(parse_output(" JSON ").unwrap(), OutputFmt::Json);
        assert_eq!(parse_output("Dossier").unwrap(), OutputFmt::Dossier);
    }

    #[test]
    fn parse_output_rejects_unknown() {
        assert!(parse_output("xml").is_err());
        assert!(parse_output("").is_err());
    }

    // ── rows_from ─────────────────────────────────────────────────────────────

    #[test]
    fn rows_from_empty_is_empty() {
        assert!(rows_from(&[]).is_empty());
    }

    #[test]
    fn rows_from_orders_by_ceff_descending() {
        let ents = vec![
            sig(EntityKind::Coordinates, "low", 0.2),
            sig(EntityKind::Coordinates, "high", 0.9),
            sig(EntityKind::Coordinates, "mid", 0.5),
        ];
        let rows = rows_from(&ents);
        assert_eq!(rows.iter().map(|r| r.value.as_str()).collect::<Vec<_>>(), [
            "high", "mid", "low"
        ]);
    }

    #[test]
    fn rows_from_preserves_unicode_and_evidence_count() {
        let mut e = sig(EntityKind::Address, "São Paulo, Brasil", 0.6);
        e.add_evidence(Evidence::new("device_sensors", "x"));
        e.add_evidence(Evidence::new("wigle", "y"));
        let rows = rows_from(std::slice::from_ref(&e));
        assert_eq!(rows[0].value, "São Paulo, Brasil");
        assert_eq!(rows[0].sources, 2);
    }

    // ── render_json ───────────────────────────────────────────────────────────

    #[test]
    fn render_json_empty_is_valid_and_zero_count() {
        let v: serde_json::Value = serde_json::from_str(&render_json(&[])).unwrap();
        assert_eq!(v["count"], 0);
        assert_eq!(v["signals"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn render_json_round_trips_signals() {
        // Assert against the entity's own (post-normalisation) value/kind, not
        // the raw literal — Entity::new canonicalises some kinds (e.g. coords).
        let e = sig(EntityKind::Coordinates, "-27.55,152.27", 0.8);
        let rows = rows_from(std::slice::from_ref(&e));
        let v: serde_json::Value = serde_json::from_str(&render_json(&rows)).unwrap();
        assert_eq!(v["count"], 1);
        assert_eq!(v["signals"][0]["value"], e.value);
        assert_eq!(v["signals"][0]["kind"], e.kind.to_string());
    }

    // ── render_table / render_dossier ─────────────────────────────────────────

    #[test]
    fn render_table_empty_states_no_signals() {
        assert!(render_table(&[], false).contains("no signals"));
    }

    #[test]
    fn render_table_has_header_and_row_and_is_unicode_safe() {
        let rows = rows_from(&[sig(EntityKind::Address, "München, Deutschland", 0.7)]);
        let out = render_table(&rows, false);
        assert!(out.contains("KIND"));
        assert!(out.contains("address"));
        assert!(out.contains("München"));
        assert!(out.contains("1 signal(s) captured."));
    }

    #[test]
    fn render_dossier_lists_every_signal() {
        let coord = sig(EntityKind::Coordinates, "-27.55,152.27", 0.9);
        let mac = sig(EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff", 0.6);
        let (cval, mval) = (coord.value.clone(), mac.value.clone());
        let rows = rows_from(&[coord, mac]);
        let out = render_dossier(&rows, false);
        assert!(out.contains(&cval), "dossier must list the coordinate signal");
        assert!(out.contains(&mval), "dossier must list the MAC signal");
        assert!(out.contains("DEVICE SIGNALS (2)"));
    }

    #[test]
    fn render_dossier_empty_is_safe() {
        assert!(render_dossier(&[], false).contains("No on-device signals"));
    }
}
