//! `hse engines` — the search-engine liveness panel.
//!
//! Probes every free, keyless search engine and reports up / blocked / down with
//! latency and result counts. The probe also emits structured `tracing` events
//! that the unified debug log captures, so a sweep is recorded for later
//! reference (see `modules::search_engines::health`).
//!
//! `probe_all` only probes *enabled* engines, so a disabled engine wouldn't
//! otherwise appear here. To match the web `#/engines` panel — and so an
//! operator can see (and, via `hse config engine.<name> on`, restore) a switched
//! off engine — the full engine roster is merged in and disabled engines are
//! listed with a `disabled` status.

use crate::core::error::Result;
use crate::modules::search_engines::engine_toggles;
use crate::modules::search_engines::health::{EngineHealth, EngineStatus, probe_all};

pub async fn cmd_engines(json: bool) -> Result<()> {
    // Probe results for the currently-enabled engines (fully populated — unlike
    // the web panel's cached snapshot, this sweep runs synchronously here).
    let health = probe_all().await;
    let by_name: std::collections::HashMap<&str, &EngineHealth> =
        health.iter().map(|h| (h.name, h)).collect();

    // Full roster (enabled + disabled), sorted by engine name so the listing is
    // a stable, predictable inventory rather than probe-completion order.
    let mut roster = engine_toggles();
    roster.sort_by(|a, b| a.0.cmp(&b.0));

    if json {
        let arr: Vec<serde_json::Value> = roster
            .iter()
            .map(|(key, enabled)| {
                let name = key.strip_prefix("engine.").unwrap_or(key);
                match by_name.get(name) {
                    Some(h) if *enabled => serde_json::json!({
                        "engine": name,
                        "status": h.status.as_str(),
                        "latency_ms": h.latency_ms,
                        "results": h.results,
                        "detail": h.detail,
                        "enabled": true,
                    }),
                    _ => serde_json::json!({
                        "engine": name,
                        "status": "disabled",
                        "latency_ms": serde_json::Value::Null,
                        "results": serde_json::Value::Null,
                        "enabled": false,
                    }),
                }
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap_or_default()
        );
        return Ok(());
    }

    // up/blocked/down are counted from the probe (enabled engines); disabled from
    // the roster. Their sum is the full roster — the same self-consistent tally
    // the web panel shows.
    let probed = |s: EngineStatus| health.iter().filter(|h| h.status == s).count();
    let disabled = roster.iter().filter(|(_, en)| !en).count();
    println!(
        "\nSearch-engine liveness — {} engines: {} up, {} blocked, {} down, {} disabled\n",
        roster.len(),
        probed(EngineStatus::Up),
        probed(EngineStatus::Blocked),
        probed(EngineStatus::Down),
        disabled,
    );
    println!("ENGINE           STATUS   LATENCY  RESULTS  DIAGNOSIS");
    println!("{}", "-".repeat(96));
    for (key, enabled) in &roster {
        let name = key.strip_prefix("engine.").unwrap_or(key);
        match by_name.get(name) {
            Some(h) if *enabled => {
                let mark = match h.status {
                    EngineStatus::Up => '●',
                    EngineStatus::Blocked => '◐',
                    EngineStatus::Down => '○',
                };
                println!(
                    "{name:<14} {mark} {:<8} {:>6}ms  {:>5}    {}",
                    h.status.as_str(),
                    h.latency_ms,
                    h.results,
                    h.detail,
                );
            }
            // Disabled (turned off in config); never queried by a scan or probe.
            _ => {
                let (status, dash) = ("disabled", "—");
                println!("{name:<14} · {status:<8} {dash:>9}  {dash}");
            }
        }
    }
    println!();
    Ok(())
}
