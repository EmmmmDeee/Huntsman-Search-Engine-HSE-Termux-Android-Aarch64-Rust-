//! `hse radar` — continuous-sensor + auto-pivot scanning loop.
//!
//! Each sweep runs the local-sensor modules (device_sensors, wifi_intel,
//! cell_intel, local_net) and pivots on any newly-discovered entity
//! through the full module graph. Designed for long-running situational
//! awareness on a device that's moving through space.
//!
//! `--interval` controls sweep cadence; `--depth` the per-pivot
//! recursion; `--sweeps` an optional iteration cap; `--free-only`
//! restricts pivots to keyless modules to preserve API quota.

use std::sync::Arc;

use crate::core::error::Result;
use crate::core::{
    module::ModuleContext,
    scan::{Scan, Target},
};
use crate::util::{http::build_client, keys, uid::scan_id};

use super::{build_runtime, color_confidence, truncate, use_color};

pub(super) async fn cmd_radar(
    interval: u64,
    depth: u32,
    sweeps: Option<u32>,
    free_only: bool,
) -> Result<()> {
    use std::collections::HashSet;

    let color = use_color();
    eprintln!(
        "{}",
        color_confidence(
            0.85,
            &format!("HSE radar — sweep every {interval}s, depth={depth}, Ctrl-C to stop"),
            color
        )
    );

    let (store, bus, engine) = build_runtime(1024)?;
    let mut seen_entities: HashSet<String> = HashSet::new();
    let mut sweep_num = 0u32;

    loop {
        sweep_num += 1;
        if let Some(max) = sweeps
            && sweep_num > max
        {
            break;
        }

        eprintln!(
            "\n{}",
            color_confidence(0.85, &format!("── sweep {sweep_num} ──"), color)
        );

        // Phase 1: Sensor sweep (passive modules only, any target, depth=0)
        let sweep_sid = scan_id("radar", &format!("sweep-{sweep_num}"));
        let sweep_target = Target::new(crate::core::scan::TargetKind::Domain, "radar.local");
        let sweep_scan = Scan::new(sweep_sid.clone(), sweep_target.clone())
            .with_options(super::sweep::sensor_sweep_options());
        let sweep_keys = keys::load();
        let sweep_ctx = ModuleContext {
            scan_id: sweep_sid.clone(),
            bus: bus.clone(),
            http: build_client(),
            keys: sweep_keys,
            cancel: crate::core::cancel::CancelHandle::new(),
            proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
        };

        let sweep_result = engine.run(sweep_scan, sweep_target, sweep_ctx).await?;
        let sweep_entities = store.entities_for_scan(&sweep_sid)?;

        // Phase 2: Identify NEW entities (not seen in previous sweeps)
        let mut new_targets: Vec<(crate::core::scan::TargetKind, String)> = Vec::new();
        for entity in &sweep_entities {
            if seen_entities.insert(entity.uid.clone())
                && let Some(tk) = crate::core::scan::TargetKind::from_entity_kind(&entity.kind)
            {
                eprintln!(
                    "  {} new: {} = {}",
                    color_confidence(0.85, "◉", color),
                    entity.kind,
                    entity.value
                );
                new_targets.push((tk, entity.value.clone()));
            }
        }

        if new_targets.is_empty() {
            eprintln!(
                "  {} no new signals ({} entities, {} known)",
                color_confidence(0.3, "○", color),
                sweep_result.entity_count,
                seen_entities.len()
            );
        } else {
            eprintln!(
                "  {} {} new signal(s) → pivoting at depth {depth}",
                color_confidence(0.85, "▶", color),
                new_targets.len()
            );

            // Phase 3: Pivot on each new discovery through the full pipeline
            for (tk, value) in &new_targets {
                let pivot_sid = scan_id(tk.canonical_str(), value);
                let pivot_target = Target::new(*tk, value.clone());
                // Sensor-discovered infra (IPs, domains, coords, MACs, ASNs)
                // sheds the paid identity modules so radar doesn't burn quota on
                // them; identity kinds keep the full module set. Shared with
                // `device-scan` via `super::sweep` so the two cannot drift.
                let pivot_scan = Scan::new(pivot_sid.clone(), pivot_target.clone())
                    .with_options(super::sweep::pivot_options(depth, free_only, *tk));
                let pivot_keys = keys::load();
                let pivot_ctx = ModuleContext {
                    scan_id: pivot_sid.clone(),
                    bus: bus.clone(),
                    http: build_client(),
                    keys: pivot_keys,
                    cancel: crate::core::cancel::CancelHandle::new(),
                    proxy_pool: Arc::new(crate::util::proxy::ProxyPool::new()),
                };

                let result = engine.run(pivot_scan, pivot_target, pivot_ctx).await?;
                let pivot_entities = store.entities_for_scan(&pivot_sid)?;

                // Add pivot results to seen set
                for e in &pivot_entities {
                    seen_entities.insert(e.uid.clone());
                }

                eprintln!(
                    "    {} {}={} → {} entities ({}run/{}err/{}to/{}dedup)",
                    color_confidence(0.7, "↳", color),
                    tk.canonical_str(),
                    truncate(value, 30),
                    result.entity_count,
                    result.modules_run,
                    result.modules_errored,
                    result.modules_timed_out,
                    result.modules_deduped,
                );

                // Stream key findings to stdout as JSON
                for e in &pivot_entities {
                    if e.c_effective() >= 0.50 {
                        let json = serde_json::json!({
                            "sweep": sweep_num,
                            "kind": e.kind.to_string(),
                            "value": e.value,
                            "confidence": e.confidence,
                            "c_eff": e.c_effective(),
                            "sources": e.evidence.len(),
                            "tags": e.tags,
                        });
                        println!("{}", serde_json::to_string(&json).unwrap_or_default());
                    }
                }
            }
        }

        // Wait for next sweep
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nradar stopped");
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {}
        }
    }

    eprintln!(
        "\n{} sweeps, {} unique entities discovered",
        sweep_num.min(sweeps.unwrap_or(sweep_num)),
        seen_entities.len()
    );
    Ok(())
}
