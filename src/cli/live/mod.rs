//! `hse live` — re-run a scan on a fixed interval (v0.5+).
//!
//! Boots a `LiveScanner` against the runtime, kicks one initial scan
//! and streams events from the broadcast bus until Ctrl-C or the
//! iterations cap.

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
    pub exclude: Option<String>,
    pub throttle_ms: u64,
    pub min_confidence: Option<f64>,
    pub min_expand_confidence: f64,
    pub max_entities: Option<usize>,
    pub max_wall_time_secs: Option<u64>,
    pub max_concurrent: usize,
    pub max_roi: bool,
    pub convex_budget: bool,
    pub regional_search: bool,
    pub min_marginal_yield: Option<f64>,
    pub expansion_strategy: String,
    pub seeknow_scan_cap: Option<u32>,
    pub expand_all_identities: bool,
    pub gate_speculative: bool,
    /// Radar mode: persist the keyed-module dispatch ledger across iterations
    /// so paid APIs are never re-hit on already-covered seeds.
    pub radar: bool,
    /// Emit the raw NDJSON event stream instead of the human-readable view.
    pub json: bool,
}

pub(super) async fn cmd_live(cmd: LiveCmd) -> Result<()> {
    use crate::core::live::{LiveOptions, LiveScanner};
    use tokio_stream::StreamExt;
    use tokio_stream::wrappers::BroadcastStream;

    // Unified live scan: omitted/`auto` --kind is inferred from the value.
    let kind_arg = cmd.kind.as_deref().map_or("", str::trim);
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

    let scan_options = build_live_scan_options(&cmd)?;
    let live_options = LiveOptions {
        interval_secs: cmd.interval,
        iterations: cmd.iterations,
        radar: cmd.radar,
    };

    let (_store, bus, engine) = build_runtime(1024)?;
    let scanner = LiveScanner::new(
        Arc::clone(&engine),
        bus.clone(),
        crate::util::http::build_client(),
        crate::util::keys::populate_and_load().await,
    );

    let live_id = scanner.start(target, scan_options, live_options);
    eprintln!("live session {live_id} — Ctrl-C to stop");

    let rx = bus.subscribe();
    let scanner_clone = scanner.clone();
    let target_lid = live_id.clone();
    let as_json = cmd.json;
    let mut stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event)
            if event.scan_id == target_lid
                || scanner_clone.session_owns_scan(&target_lid, &event.scan_id) =>
        {
            let is_terminator =
                matches!(event.kind, crate::core::event::EventKind::LiveStop { .. });
            // Default: human-readable, fully-unredacted structured view (every
            // entity with its complete evidence chain and every attribute).
            // `--json`: the raw NDJSON line for piping. Both carry identical
            // data — nothing is hidden, hashed, or summarised away in either.
            let line = if as_json {
                serde_json::to_string(&event.kind).unwrap_or_default()
            } else {
                render_event(&event.kind)
            };
            Some((line, is_terminator))
        }
        Err(tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(n)) => {
            eprintln!("warning: event stream lagged, {n} event(s) dropped");
            None
        }
        _ => None,
    });

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nstopping live session…");
                scanner.stop(&live_id);
            }
            line = stream.next() => match line {
                Some((s, is_terminator)) => {
                    // A renderer may intentionally yield "" for an event with no
                    // operator value in the human view; never print a blank line.
                    if !s.is_empty() {
                        println!("{s}");
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

/// Build the per-iteration `ScanOptions` from a `LiveCmd`. Pulled out of
/// `cmd_live` so the full ScanOptions-surface mapping (the parity gap fixed
/// here — `hse live` used to build `ScanOptions { modules, free_only,
/// passive_only, depth, ..Default::default() }`, silently dropping every
/// other tuning flag `hse scan` and `POST /api/v1/live` both expose) is
/// directly testable without booting a runtime.
fn build_live_scan_options(cmd: &LiveCmd) -> Result<ScanOptions> {
    // Parse the strategy via `FromStr` on `ExpansionStrategy` so the variant
    // list lives in one place (core/scan.rs), same as `cmd_scan`.
    let expansion_strategy: crate::core::scan::ExpansionStrategy =
        cmd.expansion_strategy.parse().map_err(|e: String| {
            crate::core::error::Error::Other(format!("--expansion-strategy: {e}"))
        })?;
    Ok(ScanOptions {
        modules: split_csv(cmd.modules.clone()),
        exclude_modules: split_csv(cmd.exclude.clone()).unwrap_or_default(),
        throttle_ms: cmd.throttle_ms,
        max_concurrent: cmd.max_concurrent,
        min_confidence: cmd.min_confidence,
        free_only: cmd.free_only,
        passive_only: cmd.passive_only,
        depth: cmd.depth,
        min_expand_confidence: cmd.min_expand_confidence,
        // Comprehensive-but-bounded, matching `cmd_scan`: apply the product
        // entity ceiling when the operator gave none, so a long-running watch
        // can't fan a frontier out unbounded across iterations on a low-RAM
        // Termux device. `--max-entities` overrides.
        max_entities: cmd
            .max_entities
            .or(Some(crate::core::scan::DEFAULT_MAX_ENTITIES)),
        max_wall_time_secs: cmd.max_wall_time_secs,
        webhook_url: crate::core::webhook::webhook_url_from_env(),
        max_roi: cmd.max_roi,
        convex_budget: cmd.convex_budget,
        regional_search: cmd.regional_search,
        min_marginal_yield: cmd.min_marginal_yield,
        expansion_strategy,
        seeknow_scan_cap: cmd.seeknow_scan_cap,
        expand_all_identities: cmd.expand_all_identities,
        gate_speculative: cmd.gate_speculative,
        ..Default::default()
    }
    .sanitize())
}

/// Render one live event as a human-readable, **fully unredacted** structured
/// block for a professional interpreter. The transparency contract: every
/// retrieved value is shown verbatim — passwords, hashes, raw stealer-record
/// fields, API keys, full bios — nothing is masked, hashed, truncated, or
/// omitted. Same no-omission contract as the post-scan dossier
/// (`cli::scan::dossier`) — but NOT identical output: `hse live` has no
/// platform-infra filtering equivalent, so it shows every entity as it
/// arrives, including ones the dossier excludes by default (and discloses
/// when it does). The live view is a strict superset, not a mirror.
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
