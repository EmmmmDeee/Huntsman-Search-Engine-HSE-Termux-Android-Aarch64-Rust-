//! `hse engines` — the search-engine liveness panel.
//!
//! Probes every free, keyless search engine and reports up / blocked / down with
//! latency and result counts. The probe also emits structured `tracing` events
//! that the unified debug log captures, so a sweep is recorded for later
//! reference (see `modules::search_engines::health`).

use crate::core::error::Result;
use crate::modules::search_engines::health::{EngineStatus, probe_all};

pub async fn cmd_engines(json: bool) -> Result<()> {
    let health = probe_all().await;

    if json {
        let arr: Vec<serde_json::Value> = health
            .iter()
            .map(|h| {
                serde_json::json!({
                    "engine": h.name,
                    "status": h.status.as_str(),
                    "latency_ms": h.latency_ms,
                    "results": h.results,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap_or_default()
        );
        return Ok(());
    }

    let count = |s: EngineStatus| health.iter().filter(|h| h.status == s).count();
    println!(
        "\nSearch-engine liveness — {} engines: {} up, {} blocked, {} down\n",
        health.len(),
        count(EngineStatus::Up),
        count(EngineStatus::Blocked),
        count(EngineStatus::Down),
    );
    println!("ENGINE           STATUS   LATENCY    RESULTS");
    println!("{}", "-".repeat(48));
    for h in &health {
        let mark = match h.status {
            EngineStatus::Up => '●',
            EngineStatus::Blocked => '◐',
            EngineStatus::Down => '○',
        };
        println!(
            "{:<14} {mark} {:<8} {:>7}ms  {}",
            h.name,
            h.status.as_str(),
            h.latency_ms,
            h.results
        );
    }
    println!();
    Ok(())
}
