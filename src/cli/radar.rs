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
    scan::{Scan, ScanOptions, Target},
};
use crate::util::{http::build_client, keys, uid::scan_id};

use super::{build_runtime, color_confidence, truncate, use_color};

use crate::core::engine::LOCAL_PASSIVE_MODULES as SENSOR_MODULES;

/// Run one sub-scan (a sensor sweep or a pivot), racing an operator Ctrl-C
/// against it. A press signals the scan's OWN cooperative-cancel flag (so it
/// winds down promptly via `finalise_scan`'s clean `Aborted` path — the same
/// mechanism `--max-wall-time`'s watchdog uses — rather than running to its
/// own completion while the operator waits) AND sets `stop`, so the radar's
/// outer sweep loop breaks immediately afterwards instead of starting another
/// pivot/sweep. Without this, Ctrl-C during an in-flight sub-scan was only
/// observed once the engine returned on its own, silently deferring the
/// operator's stop request for however long that sub-scan took.
async fn run_sub_scan(
    engine: &crate::core::engine::ScanEngine,
    scan: Scan,
    target: Target,
    ctx: ModuleContext,
    stop: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<Scan> {
    let cancel = ctx.cancel.clone();
    let stop_flag = Arc::clone(stop);
    let listener = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            stop_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            cancel.cancel();
        }
    });
    let result = engine.run(scan, target, ctx).await;
    listener.abort();
    result
}

pub(super) async fn cmd_radar(
    interval: u64,
    depth: u32,
    sweeps: Option<u32>,
    free_only: bool,
) -> Result<()> {
    use std::collections::HashSet;

    // The radar is armed by default — running `hse radar` IS the deliberate
    // activation, so no prior opt-in is needed. The `feature.live_radar` toggle is
    // now a kill-switch: it only refuses here if the operator has explicitly set it
    // OFF. (Seed scans can never activate the sensors regardless — they hard-set
    // `allow_live_sensors:false`; this gate only governs the radar command itself.)
    if !crate::util::settings::live_radar_enabled() {
        return Err(crate::core::error::Error::Other(
            "live radar is switched OFF. It sweeps this device's own surroundings (WiFi / \
             Bluetooth / cell / GPS / LAN), not a seed target. It is armed by default; you have \
             disabled it. Re-arm it:\n    \
             hse config feature.live_radar on\nthen re-run `hse radar`."
                .to_string(),
        ));
    }

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
    // Set by `run_sub_scan` the moment Ctrl-C interrupts an in-flight sweep or
    // pivot, so the loop stops immediately rather than starting another one.
    let radar_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    'sweeps: loop {
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
        // The live sensors gate on a local-point seed (Coordinates/MAC) and ignore
        // its VALUE — they scan the device, not the point — so the sweep is seeded
        // with a sentinel coordinate. (A `Domain` seed is NOT accepted by the
        // sensors, so the sweep would dispatch nothing.) The seed is tagged `seed`
        // and excluded from the pivot phase below, so it contributes no noise.
        let sweep_target = Target::new(crate::core::scan::TargetKind::Coordinates, "0,0");
        let sweep_opts = ScanOptions {
            modules: Some(SENSOR_MODULES.iter().map(|s| (*s).to_string()).collect()),
            passive_only: true,
            depth: 0,
            max_concurrent: 4,
            // `hse radar` IS the dedicated, separate activation for the live
            // device sensors — the one place they are permitted to run.
            allow_live_sensors: true,
            // Carry the same entity ceiling every other scan entry point has, so a
            // long-running radar session can't accumulate entities unbounded → OOM
            // on the device (radar was the sole path missing this cap).
            max_entities: Some(crate::core::scan::DEFAULT_MAX_ENTITIES),
            ..Default::default()
        };
        let sweep_scan =
            Scan::new(sweep_sid.clone(), sweep_target.clone()).with_options(sweep_opts);
        let sweep_keys = keys::load();
        let sweep_ctx = ModuleContext {
            scan_id: sweep_sid.clone(),
            bus: bus.clone(),
            http: build_client(),
            keys: sweep_keys,
            cancel: crate::core::cancel::CancelHandle::new(),
        };

        let sweep_result =
            run_sub_scan(&engine, sweep_scan, sweep_target, sweep_ctx, &radar_stop).await?;
        if radar_stop.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("\nradar stopped");
            break 'sweeps;
        }
        let sweep_entities = store.entities_for_scan(&sweep_sid)?;

        // Phase 2: Identify NEW entities (not seen in previous sweeps)
        let mut new_targets: Vec<(crate::core::scan::TargetKind, String)> = Vec::new();
        for entity in &sweep_entities {
            // The synthetic sweep seed is not a real signal — never pivot it.
            if entity.has_tag("seed") {
                continue;
            }
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
                // Exclude oathnet_pro from radar pivots on infra/sensor entities
                // (IPs, domains, coords, MACs, ASNs). Sensor-discovered entities
                // rarely yield OathNet breach results and the quota is better
                // spent on identity-type entities discovered through other paths.
                let is_infra = matches!(
                    tk,
                    crate::core::scan::TargetKind::IpAddress
                        | crate::core::scan::TargetKind::Domain
                        | crate::core::scan::TargetKind::Coordinates
                        | crate::core::scan::TargetKind::MacAddress
                        | crate::core::scan::TargetKind::Asn
                );
                let mut exclude = Vec::new();
                if is_infra {
                    exclude.push("oathnet_pro".to_string());
                    exclude.push("see_know".to_string());
                }
                let pivot_opts = ScanOptions {
                    depth,
                    free_only,
                    exclude_modules: exclude,
                    max_concurrent: 4,
                    min_expand_confidence: 0.50,
                    // The pivot runs the full expansion pipeline; without the entity
                    // ceiling every one-shot `hse scan` carries, a fan-out pivot on
                    // the long-running radar loop grows the frontier unbounded in RAM
                    // and OOMs the phone. Match cli/scan's DEFAULT_MAX_ENTITIES and
                    // clamp the depth like every other entry point.
                    max_entities: Some(crate::core::scan::DEFAULT_MAX_ENTITIES),
                    ..Default::default()
                }
                .clamp_depth();
                let pivot_scan =
                    Scan::new(pivot_sid.clone(), pivot_target.clone()).with_options(pivot_opts);
                let pivot_keys = keys::load();
                let pivot_ctx = ModuleContext {
                    scan_id: pivot_sid.clone(),
                    bus: bus.clone(),
                    http: build_client(),
                    keys: pivot_keys,
                    cancel: crate::core::cancel::CancelHandle::new(),
                };

                let result =
                    run_sub_scan(&engine, pivot_scan, pivot_target, pivot_ctx, &radar_stop).await?;
                if radar_stop.load(std::sync::atomic::Ordering::Relaxed) {
                    eprintln!("\nradar stopped");
                    break 'sweeps;
                }
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
