//! `hse live` — re-run a scan on a fixed interval (v0.5+).
//!
//! Boots a `LiveScanner` against the runtime, kicks one initial scan
//! and streams events from the broadcast bus until Ctrl-C or the
//! iterations cap.

use std::collections::HashMap;
use std::sync::Arc;

use crate::core::error::Result;
use crate::core::scan::{ScanOptions, Target};

use super::{build_runtime, parse_target_kind, split_csv};

pub(super) struct LiveCmd {
    /// `None` (or `"auto"`) auto-detects the kind from `value` — the unified scan.
    pub kind: Option<String>,
    pub value: String,
    pub interval: u64,
    pub iterations: Option<u32>,
    pub depth: u32,
    pub free_only: bool,
    pub passive_only: bool,
    pub modules: Option<String>,
    /// Radar mode: persist the keyed-module dispatch ledger across iterations
    /// so paid APIs are never re-hit on already-covered seeds.
    pub radar: bool,
    /// Emit the raw NDJSON event stream instead of the human-readable view.
    pub json: bool,
    /// After each iteration, print a delta block showing new / moved / gone
    /// entities compared to the previous iteration.
    pub delta: bool,
}

/// Snapshot of entities from one scan iteration: maps `"kind\x1fvalue"` → confidence.
type EntitySnapshot = HashMap<String, (String, String, f64)>;

fn print_delta(prev: &EntitySnapshot, curr: &EntitySnapshot, iteration: u32, as_json: bool) {
    let mut new_entities: Vec<(&str, &str, f64)> = Vec::new();
    let mut moved: Vec<(&str, &str, f64, f64)> = Vec::new();
    let mut gone: Vec<(&str, &str, f64)> = Vec::new();

    for (key, (kind, value, conf)) in curr {
        match prev.get(key) {
            None => new_entities.push((kind.as_str(), value.as_str(), *conf)),
            Some((_, _, prev_conf)) => {
                if (conf - prev_conf).abs() > 0.001 {
                    moved.push((kind.as_str(), value.as_str(), *prev_conf, *conf));
                }
            }
        }
    }
    for (key, (kind, value, conf)) in prev {
        if !curr.contains_key(key) {
            gone.push((kind.as_str(), value.as_str(), *conf));
        }
    }

    if as_json {
        let obj = serde_json::json!({
            "type": "delta",
            "iteration": iteration,
            "new": new_entities.iter().map(|(k,v,c)| serde_json::json!({"kind":k,"value":v,"confidence":c})).collect::<Vec<_>>(),
            "moved": moved.iter().map(|(k,v,p,c)| serde_json::json!({"kind":k,"value":v,"prev_confidence":p,"confidence":c})).collect::<Vec<_>>(),
            "gone": gone.iter().map(|(k,v,c)| serde_json::json!({"kind":k,"value":v,"was_confidence":c})).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string(&obj).unwrap_or_default());
        return;
    }

    println!("\n=== DELTA [iter {iteration}] ===");
    if new_entities.is_empty() && moved.is_empty() && gone.is_empty() {
        println!("  (no changes)");
    } else {
        for (kind, value, conf) in &new_entities {
            println!("  + NEW    {kind}  {value}  ({conf:.2})");
        }
        for (kind, value, prev_conf, conf) in &moved {
            println!("  ~ MOVED  {kind}  {value}  ({prev_conf:.2}\u{2192}{conf:.2})");
        }
        for (kind, value, conf) in &gone {
            println!("  - GONE   {kind}  {value}  (was {conf:.2})");
        }
    }
}

pub(super) async fn cmd_live(cmd: LiveCmd) -> Result<()> {
    use crate::core::live::{LiveOptions, LiveScanner};
    use tokio_stream::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    // Unified live scan: omitted/`auto` --kind is inferred from the value.
    let kind_arg = cmd.kind.as_deref().map(str::trim).unwrap_or("");
    let target_kind = if kind_arg.is_empty() || kind_arg.eq_ignore_ascii_case("auto") {
        let detected = crate::core::scan::detect_kind(&cmd.value);
        eprintln!(
            "auto-detected target kind: {} (override with --kind)",
            detected.canonical_str()
        );
        detected
    } else {
        parse_target_kind(kind_arg)?
    };
    let target = Target::new(target_kind, cmd.value.clone());
    // Reject junk/placeholder seeds at the CLI boundary (mirrors `cmd_scan`
    // and the HTTP API's `validated_target`).
    if let Err(msg) = target.validate() {
        return Err(crate::core::error::Error::Other(format!(
            "invalid target '{}': {msg}",
            target.value
        )));
    }

    let scan_options = ScanOptions {
        modules: split_csv(cmd.modules),
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        ..Default::default()
    };
    let live_options = LiveOptions {
        interval_secs: cmd.interval,
        iterations: cmd.iterations,
        radar: cmd.radar,
    };

    let (store, response_sink, bus, engine) = build_runtime(1024)?;
    let scanner = LiveScanner::with_sink(
        Arc::clone(&engine),
        bus.clone(),
        crate::util::http::build_client(),
        crate::util::keys::populate_and_load().await,
        Some(response_sink),
    );

    let live_id = scanner.start(target, scan_options, live_options);
    eprintln!("live session {live_id} — Ctrl-C to stop");

    let rx = bus.subscribe();
    let scanner_clone = scanner.clone();
    let target_lid = live_id.clone();
    let as_json = cmd.json;
    let want_delta = cmd.delta;
    let mut stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event)
            if event.scan_id == target_lid
                || scanner_clone.session_owns_scan(&target_lid, &event.scan_id) =>
        {
            let is_terminator =
                matches!(event.kind, crate::core::event::EventKind::LiveStop { .. });
            let completed_scan_id =
                if let crate::core::event::EventKind::ScanComplete { scan_id, .. } = &event.kind {
                    if want_delta {
                        Some(scan_id.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
            // Default: human-readable, fully-unredacted structured view (every
            // entity with its complete evidence chain and every attribute).
            // `--json`: the raw NDJSON line for piping. Both carry identical
            // data — nothing is hidden, hashed, or summarised away in either.
            let line = if as_json {
                serde_json::to_string(&event.kind).unwrap_or_default()
            } else {
                render_event(&event.kind)
            };
            Some((line, is_terminator, completed_scan_id))
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            eprintln!("warning: event stream lagged, {n} event(s) dropped");
            None
        }
        _ => None,
    });

    let mut prev_snapshot: EntitySnapshot = HashMap::new();
    let mut delta_iteration: u32 = 0;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nstopping live session…");
                scanner.stop(&live_id);
            }
            line = stream.next() => match line {
                Some((s, is_terminator, completed_scan_id)) => {
                    // A renderer may intentionally yield "" for an event with no
                    // operator value in the human view; never print a blank line.
                    if !s.is_empty() {
                        println!("{s}");
                    }
                    if let Some(sid) = completed_scan_id {
                        delta_iteration += 1;
                        if let Ok(entities) = store.entities_for_scan(&sid) {
                            let curr_snapshot: EntitySnapshot = entities
                                .iter()
                                .map(|e| {
                                    let key = format!("{}\x1f{}", e.kind, e.value);
                                    (key, (e.kind.to_string(), e.value.clone(), e.confidence))
                                })
                                .collect();
                            print_delta(&prev_snapshot, &curr_snapshot, delta_iteration, as_json);
                            prev_snapshot = curr_snapshot;
                        }
                    }
                    if is_terminator {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    Ok(())
}

/// Render one live event as a human-readable, **fully unredacted** structured
/// block for a professional interpreter. The transparency contract: every
/// retrieved value is shown verbatim — passwords, hashes, raw stealer-record
/// fields, API keys, full bios — nothing is masked, hashed, truncated, or
/// omitted. This mirrors the post-scan dossier (`cli::scan`) so the live view
/// and the final report show identical, complete data.
///
/// Returns `""` for events that carry no operator-facing payload in this view
/// (the caller suppresses blank lines).
fn render_event(kind: &crate::core::event::EventKind) -> String {
    use crate::core::event::EventKind as E;

    match kind {
        E::LiveStart {
            target_kind,
            target_value,
            interval_secs,
            ..
        } => format!("◆ live start — {target_kind} {target_value} (every {interval_secs}s)"),
        E::LiveTick { iteration, .. } => format!("\n━━━ sweep #{iteration} ━━━"),
        E::ScanStart {
            target_kind,
            target_value,
        } => format!("▸ scan start — {target_kind} {target_value}"),
        E::ModuleStart { module } => format!("  · {module} …"),
        E::ModuleDone { module, found } => {
            if *found > 0 {
                format!("  ✓ {module} — {found} entit{}", plural(*found))
            } else {
                String::new()
            }
        }
        E::ModuleError { module, error } => format!("  ✗ {module} — error: {error}"),
        E::ModuleSkipped { module, reason } => format!("  – {module} — skipped: {reason}"),
        E::EntityFound { entity } => render_entity(entity),
        E::ExpansionTick {
            depth,
            queued,
            visited,
        } => format!("  ↻ expansion depth={depth} queued={queued} visited={visited}"),
        E::ExpansionStop { reason } => format!("  ◼ expansion stopped: {reason}"),
        E::EntityExcluded {
            kind,
            value,
            reason,
        } => {
            format!("  ⊘ not expanded [{kind}] {value} — {reason}")
        }
        E::CorrelationFound { correlation } => format!(
            "  ⚑ correlation [{}] {} — {}",
            correlation.severity, correlation.rule_name, correlation.description
        ),
        E::CorrelationsDone { count } => {
            if *count > 0 {
                format!("  ⚑ {count} correlation{} evaluated", plural2(*count))
            } else {
                String::new()
            }
        }
        E::ScanComplete { entity_count, .. } => {
            format!(
                "▪ scan complete — {entity_count} entit{}",
                plural(*entity_count)
            )
        }
        E::LiveStop { reason, .. } => format!("◆ live stop — {reason}"),
    }
}

/// Fully-unredacted, structured render of a single entity: its value, kind,
/// confidence/corroboration, tags, and the COMPLETE evidence chain with every
/// attribute printed verbatim (this is where raw stealer records, passwords,
/// and API-key context live — none of it is hidden).
fn render_entity(e: &crate::core::entity::Entity) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = write!(
        s,
        "  + {} [{}]  conf={:.2}  corr={}",
        e.value, e.kind, e.confidence, e.corroboration
    );
    if !e.tags.is_empty() {
        let _ = write!(s, "\n      tags: {}", e.tags.join(", "));
    }
    for ev in &e.evidence {
        let _ = write!(s, "\n      ├─ {} — {}", ev.source, ev.summary);
        // Every non-empty attribute, verbatim — no length cap, no masking.
        for (k, v) in &ev.attributes {
            if !v.is_empty() {
                let _ = write!(s, "\n      │  {k}: {v}");
            }
        }
    }
    s
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "y" } else { "ies" }
}

fn plural2(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
