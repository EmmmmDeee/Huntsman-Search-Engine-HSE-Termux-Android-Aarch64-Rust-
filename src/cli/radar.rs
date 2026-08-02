//! `hse radar` — continuous-sensor + auto-pivot scanning loop.
//!
//! **Running or stopped: there is nothing else to set.** `hse radar` starts it,
//! Ctrl-C stops it. Every input it needs comes from this device's own radios
//! via Termux — Wi-Fi and Bluetooth scans, GNSS fixes, the cell serving-cell,
//! and the local ARP table — so there is no seed to supply and no target to
//! name. Options were removed rather than defaulted: a knob on this command is
//! a way to run it wrong.
//!
//! Each sweep runs the local-sensor modules ([`SENSOR_MODULES`]) and hands
//! every newly-observed signal to the SAME pipeline a manually-initiated
//! `hse scan` uses — the full module graph, no module exclusions, no
//! free-only restriction, the standard expansion floor — so a MAC seen over
//! the air is enumerated exactly as thoroughly as one typed on the command
//! line. Pivots recurse [`RADAR_PIVOT_DEPTH`] hops, deep enough to carry an
//! observed signal through the identity chain SeekNow and the breach corpora
//! open up.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use crate::core::error::Result;
use crate::core::{
    module::ModuleContext,
    scan::{Scan, ScanOptions, Target},
};
use crate::util::{http::build_client, keys, uid::scan_id};

use super::{color_confidence, truncate, use_color};

use crate::core::engine::LOCAL_PASSIVE_MODULES as SENSOR_MODULES;

/// Seconds between sensor sweeps. Not operator-tunable: the radar has exactly
/// two states, and 10 s is fast enough to track a device moving on foot or in
/// traffic while leaving the radios idle most of the time.
const RADAR_SWEEP_INTERVAL_SECS: u64 = 10;

/// Expansion depth applied to every signal the sensors observe.
///
/// A radio observation starts further from an identity than a typed seed does:
/// a BSSID resolves to a location, the location to an address, the address to
/// a person, the person to their accounts and breach records — SeekNow and the
/// breach corpora only enter the chain several hops in. Five hops is the
/// shallowest depth that reaches them, and is why [`MAX_DEPTH`] was raised to
/// match.
///
/// [`MAX_DEPTH`]: crate::core::scan::MAX_DEPTH
const RADAR_PIVOT_DEPTH: u32 = 5;

/// Maximum number of already-seen entity uids the radar remembers across sweeps.
///
/// Generous enough that a stationary session (a location has at most a few
/// hundred APs/towers/BT devices, plus the entities its pivots discover) never
/// evicts, while bounding the memory a *moving* session accretes. `hse radar` is
/// explicitly built to track a device in motion, so without a cap its seen-set
/// grows with every signal passed en route for the whole session — the
/// per-scan `max_entities` ceilings bound one scan, never this cross-sweep set.
const SEEN_CAPACITY: usize = 50_000;

/// Bounded, insertion-ordered membership set for entity uids the radar has
/// already observed — the "have I seen this signal before?" check that makes
/// each sweep pivot only on genuinely NEW signals.
///
/// A plain [`HashSet`] answers that but grows without limit across a long or
/// moving session (see [`SEEN_CAPACITY`]). This caps the set and evicts
/// oldest-first when full. FIFO is the correct policy here, not merely the
/// simplest: the oldest uids are the signals left furthest behind as the device
/// moves — the least likely to recur — and if an evicted signal IS re-observed
/// later, treating it as new re-pivots it, which is bounded, correct rework, not
/// a lost observation.
struct SeenSet {
    set: HashSet<String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl SeenSet {
    fn with_capacity(capacity: usize) -> Self {
        debug_assert!(capacity >= 1, "a zero-capacity seen-set remembers nothing");
        Self {
            set: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record `uid`, returning `true` when it was NOT already present — the
    /// "this is a new signal, pivot it" answer, matching [`HashSet::insert`]'s
    /// return. When the set is at capacity, the oldest uid is evicted first so
    /// the size never exceeds `capacity`.
    fn insert(&mut self, uid: String) -> bool {
        if self.set.contains(&uid) {
            return false;
        }
        if self.set.len() >= self.capacity
            && let Some(oldest) = self.order.pop_front()
        {
            self.set.remove(&oldest);
        }
        self.order.push_back(uid.clone());
        self.set.insert(uid);
        true
    }

    /// Number of uids currently remembered (never exceeds `capacity`).
    fn len(&self) -> usize {
        self.set.len()
    }
}

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

pub(super) async fn cmd_radar() -> Result<()> {
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
            &format!(
                "HSE radar — device radios (WiFi/Bluetooth/GNSS/cell/LAN), \
                 sweep every {RADAR_SWEEP_INTERVAL_SECS}s, pivot depth \
                 {RADAR_PIVOT_DEPTH}, Ctrl-C to stop"
            ),
            color
        )
    );

    let crate::app::runtime::ApplicationRuntime { store, bus, engine } =
        crate::app::runtime::build_runtime(1024)?;
    let mut seen_entities = SeenSet::with_capacity(SEEN_CAPACITY);
    let mut sweep_num = 0u32;
    // Set by `run_sub_scan` the moment Ctrl-C interrupts an in-flight sweep or
    // pivot, so the loop stops immediately rather than starting another one.
    let radar_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    'sweeps: loop {
        sweep_num += 1;

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
        let sweep_target = Target::new(
            crate::core::scan::TargetKind::Coordinates,
            crate::core::scan::RADAR_SENTINEL_COORD_RAW,
        );
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

        // Bracket the sweep with the Termux bridge's activity counters, so an
        // empty sweep can say WHICH empty it is: radios read and quiet, or
        // radios never read. See the `no new signals` branch below.
        let sensors_before = crate::util::termux::activity();
        let sweep_result =
            run_sub_scan(&engine, sweep_scan, sweep_target, sweep_ctx, &radar_stop).await?;
        let sensors = crate::util::termux::activity().since(sensors_before);
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
            // "Nothing new" has two very different causes, and reporting the
            // second as the first is the radar telling the operator the area is
            // quiet when in truth it never listened. A sweep in which no Termux
            // sensor tool returned data observed nothing — it did not observe
            // nothing being there.
            if sensors.took_no_readings() {
                eprintln!(
                    "  {} no sensor readings this sweep — {} tool call(s) skipped, {} \
                     unanswered; the radios were NOT read, so this is not evidence that \
                     nothing is nearby",
                    color_confidence(0.3, "⚠", color),
                    sensors.skipped,
                    sensors.failed,
                );
            } else {
                eprintln!(
                    "  {} no new signals ({} entities, {} known)",
                    color_confidence(0.3, "○", color),
                    sweep_result.entity_count,
                    seen_entities.len()
                );
            }
        } else {
            eprintln!(
                "  {} {} new signal(s) → pivoting at depth {RADAR_PIVOT_DEPTH}",
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
                // No module exclusions and no free-only restriction: an
                // observed signal gets the SAME treatment as a manually
                // initiated scan. SeekNow and the breach corpora used to be
                // excluded for infrastructure-kind pivots to save quota, but
                // that severed the chain exactly where it starts paying off —
                // a BSSID becomes a location, an address, a person, and only
                // THEN an identity SeekNow can enumerate. Budgets already bound
                // the spend; suppressing the module bounded the findings.
                let pivot_opts = ScanOptions {
                    depth: RADAR_PIVOT_DEPTH,
                    max_concurrent: 4,
                    // The product expansion floor, as a manual scan uses. The
                    // old 0.50 discarded the derived identifiers (name →
                    // email/handle permutations, emitted at 0.20–0.30) that the
                    // deeper hops exist to confirm.
                    min_expand_confidence: crate::core::scan::DEFAULT_MIN_EXPAND_CONFIDENCE,
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
            _ = tokio::time::sleep(std::time::Duration::from_secs(RADAR_SWEEP_INTERVAL_SECS)) => {}
        }
    }

    eprintln!(
        "\n{} sweeps, {} unique entities discovered",
        sweep_num,
        seen_entities.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_reports_novelty_like_a_hashset() {
        let mut seen = SeenSet::with_capacity(8);
        assert!(seen.insert("a".to_string()), "first sighting is new");
        assert!(!seen.insert("a".to_string()), "second sighting is not new");
        assert!(seen.insert("b".to_string()));
        assert_eq!(seen.len(), 2);
    }

    #[test]
    fn size_never_exceeds_capacity() {
        // The whole point of the type: a long/moving session inserts far more
        // distinct signals than the cap, and the set must stay bounded.
        let cap = 16;
        let mut seen = SeenSet::with_capacity(cap);
        for i in 0..cap * 100 {
            seen.insert(format!("uid-{i}"));
            assert!(
                seen.len() <= cap,
                "size {} exceeded capacity {cap} after {i} inserts",
                seen.len()
            );
        }
        assert_eq!(seen.len(), cap, "a saturated set sits exactly at capacity");
    }

    #[test]
    fn eviction_is_oldest_first() {
        let mut seen = SeenSet::with_capacity(3);
        for u in ["a", "b", "c"] {
            assert!(seen.insert(u.to_string()));
        }
        // Inserting a 4th evicts the OLDEST ("a"), not "b"/"c".
        assert!(seen.insert("d".to_string()));
        assert_eq!(seen.len(), 3);
        // "b" and "c" are still remembered (re-insert returns false)...
        assert!(!seen.insert("b".to_string()), "b must still be present");
        assert!(!seen.insert("c".to_string()), "c must still be present");
        // ...while "a" was forgotten, so it reads as new again (a bounded,
        // acceptable re-pivot — never a lost observation).
        assert!(
            seen.insert("a".to_string()),
            "a was evicted, so it is new again"
        );
    }

    #[test]
    fn re_seeing_an_entry_does_not_change_its_eviction_age() {
        // Membership re-hits must NOT refresh recency (this is FIFO, not LRU):
        // re-observing "a" while it is present leaves it first in line to go.
        let mut seen = SeenSet::with_capacity(2);
        assert!(seen.insert("a".to_string()));
        assert!(seen.insert("b".to_string()));
        assert!(!seen.insert("a".to_string()), "a already present");
        // Insert "c": capacity 2, so the oldest ("a") is evicted despite the re-hit.
        assert!(seen.insert("c".to_string()));
        assert!(
            seen.insert("a".to_string()),
            "a was still the oldest and got evicted"
        );
        assert!(!seen.insert("c".to_string()), "c remains");
    }
}
