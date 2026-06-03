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
    /// Radar mode: persist the keyed-module dispatch ledger across iterations
    /// so paid APIs are never re-hit on already-covered seeds.
    pub radar: bool,
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
    let mut stream = BroadcastStream::new(rx).filter_map(move |msg| match msg {
        Ok(event)
            if event.scan_id == target_lid
                || scanner_clone.session_owns_scan(&target_lid, &event.scan_id) =>
        {
            let is_terminator =
                matches!(event.kind, crate::core::event::EventKind::LiveStop { .. });
            let line = serde_json::to_string(&event.kind).unwrap_or_default();
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
                    println!("{s}");
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
