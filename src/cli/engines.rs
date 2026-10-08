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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EngineFleetState {
    Healthy,
    Degraded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EngineHealthSummary {
    pub total: usize,
    pub enabled: usize,
    pub up: usize,
    pub blocked: usize,
    pub down: usize,
    pub disabled: usize,
}

impl EngineHealthSummary {
    pub fn state(self) -> EngineFleetState {
        // No enabled/usable engine is an obvious failure. A fleet with less
        // than 25% of its enabled engines usable is also operationally failed:
        // it has lost most of the independent retrieval paths diagnostics is
        // meant to verify. Exactly 25% remains degraded rather than failed.
        if self.enabled == 0 || self.up == 0 || self.up.saturating_mul(4) < self.enabled {
            EngineFleetState::Failed
        } else if self.up < self.enabled {
            EngineFleetState::Degraded
        } else {
            EngineFleetState::Healthy
        }
    }
}

pub async fn cmd_engines(json: bool) -> Result<()> {
    cmd_engines_with_summary(json).await.map(|_| ())
}

pub(super) async fn cmd_engines_with_summary(json: bool) -> Result<EngineHealthSummary> {
    // Probe results for the currently-enabled engines (fully populated — unlike
    // the web panel's cached snapshot, this sweep runs synchronously here).
    let health = probe_all().await;
    let by_name: std::collections::HashMap<&str, &EngineHealth> =
        health.iter().map(|h| (h.name, h)).collect();

    // Full roster (enabled + disabled), sorted by engine name so the listing is
    // a stable, predictable inventory rather than probe-completion order.
    let mut roster = engine_toggles();
    roster.sort_by(|a, b| a.0.cmp(&b.0));

    let probed = |s: EngineStatus| health.iter().filter(|h| h.status == s).count();
    let summary = EngineHealthSummary {
        total: roster.len(),
        enabled: roster.iter().filter(|(_, enabled)| *enabled).count(),
        up: probed(EngineStatus::Up),
        blocked: probed(EngineStatus::Blocked),
        down: probed(EngineStatus::Down),
        disabled: roster.iter().filter(|(_, enabled)| !*enabled).count(),
    };

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
        return Ok(summary);
    }

    println!(
        "\nSearch-engine liveness — {} engines: {} up, {} blocked, {} down, {} disabled\n",
        summary.total, summary.up, summary.blocked, summary.down, summary.disabled,
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
            _ => {
                let (status, dash) = ("disabled", "—");
                println!("{name:<14} · {status:<8} {dash:>9}  {dash}");
            }
        }
    }
    println!();
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(up: usize, blocked: usize, down: usize, disabled: usize) -> EngineHealthSummary {
        EngineHealthSummary {
            total: up + blocked + down + disabled,
            enabled: up + blocked + down,
            up,
            blocked,
            down,
            disabled,
        }
    }

    #[test]
    fn fleet_state_is_healthy_only_when_every_enabled_engine_is_up() {
        assert_eq!(summary(3, 0, 0, 2).state(), EngineFleetState::Healthy);
        assert_eq!(summary(3, 1, 0, 0).state(), EngineFleetState::Degraded);
        assert_eq!(summary(3, 0, 1, 0).state(), EngineFleetState::Degraded);
    }

    #[test]
    fn fleet_state_fails_when_usable_capacity_is_below_one_quarter() {
        assert_eq!(summary(0, 4, 2, 0).state(), EngineFleetState::Failed);
        assert_eq!(summary(0, 0, 0, 16).state(), EngineFleetState::Failed);
        assert_eq!(
            summary(3, 7, 6, 0).state(),
            EngineFleetState::Failed,
            "the observed 3/16 handset state must not pass diagnostics"
        );
        assert_eq!(
            summary(4, 7, 5, 0).state(),
            EngineFleetState::Degraded,
            "exactly 25% usable remains degraded, not failed"
        );
    }
}
