//! Per-target module dispatch — sequential and concurrent paths.
//!
//! `ScanEngine::dispatch_target` chooses between:
//!   * `dispatch_target_sequential` — `opts.max_concurrent == 0`,
//!     byte-identical to v0.1–v0.7 behaviour. Best on low-power Termux.
//!   * `dispatch_target_concurrent` — `opts.max_concurrent > 0`, up to N
//!     modules in flight via `tokio::sync::Semaphore + JoinSet`.
//!
//! Both paths share `module_skip_reason` for the
//! allowlist/exclude/free_only/passive_only filter so the event payloads
//! stay identical regardless of dispatch mode.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use super::ScanEngine;
use crate::core::{
    entity::Entity,
    error::Result,
    event::{Event, EventKind},
    module::{Module, ModuleContext, ModuleCost},
    scan::{ScanOptions, Target},
};

/// The output of one `module.process()` call after the engine wraps it
/// in `tokio::time::timeout` — either `Elapsed` (outer timeout fired),
/// `Err` (module returned an error), or `Ok(ModuleResult)` (success).
type TimeoutResult =
    std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>;

/// What a spawned per-module task returns to the consumer loop.
struct DispatchOutcome {
    name: &'static str,
    result: TimeoutResult,
}

impl super::ScanEngine {
    /// Translate one module's `process()` result into engine events
    /// (`ModuleError` / `EntityFound` / `ModuleDone`) and merge any
    /// emitted entities into the per-scan `entity_map`. Shared by
    /// `dispatch_target_sequential` and `dispatch_target_concurrent`
    /// so the event payload shape is identical between the two paths.
    pub(super) fn finalise_module_result(
        &self,
        scan_id: &str,
        name: &'static str,
        min_confidence: Option<f64>,
        entity_map: &mut HashMap<String, Entity>,
        result: TimeoutResult,
    ) {
        match result {
            Err(_) => {
                warn!(module = name, "timeout");
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: "timeout".into(),
                    },
                ));
            }
            Ok(Err(e)) => {
                warn!(module = name, error = %e, "module error");
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: e.to_string(),
                    },
                ));
            }
            Ok(Ok(mut mr)) => {
                let mut found = 0usize;
                for entity in mr.entities.drain(..) {
                    if let Some(min) = min_confidence
                        && entity.confidence < min
                    {
                        continue;
                    }
                    let _ = self.bus.send(Event::new(
                        scan_id,
                        EventKind::EntityFound {
                            entity: entity.clone(),
                        },
                    ));
                    let uid = entity.uid.clone();
                    if let Some(existing) = entity_map.get_mut(&uid) {
                        existing.merge(entity);
                    } else {
                        entity_map.insert(uid, entity);
                    }
                    found += 1;
                }
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleDone {
                        module: name.into(),
                        found,
                    },
                ));
                info!(module = name, found, "done");
            }
        }
    }
}

/// Per-module timeout: user override > module's declared max.
fn module_timeout_ms(module: &dyn Module, opts: &ScanOptions) -> u64 {
    opts.module_timeout_ms
        .unwrap_or_else(|| module.max_timeout_ms())
}

/// Returns `Some(reason)` if `module` should be skipped under `opts`.
/// `accepts(target)` is intentionally NOT checked here — that case skips
/// silently with no `ModuleSkipped` event, the others all emit one.
pub(super) fn module_skip_reason(module: &dyn Module, opts: &ScanOptions) -> Option<&'static str> {
    let name = module.name();
    if let Some(allow) = &opts.modules
        && !allow.iter().any(|n| n == name)
    {
        return Some("not in allowlist");
    }
    if opts.exclude_modules.iter().any(|n| n == name) {
        return Some("excluded");
    }
    if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
        return Some("requires key/payment");
    }
    if opts.passive_only && !module.is_passive() {
        return Some("not passive");
    }
    None
}

impl ScanEngine {
    /// Dispatch every accepting module against `target`. Picks the
    /// sequential or concurrent codepath based on `opts.max_concurrent`.
    pub(super) async fn dispatch_target(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        if opts.max_concurrent == 0 {
            self.dispatch_target_sequential(scan_id, target, ctx, opts, entity_map)
                .await
        } else {
            self.dispatch_target_concurrent(scan_id, target, ctx, opts, entity_map)
                .await
        }
    }

    /// v0.1 sequential dispatcher. Kept unchanged so the default scan
    /// behaviour (max_concurrent == 0) is byte-identical to pre-v0.8.
    async fn dispatch_target_sequential(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        for module in self.modules_for(target.kind) {
            let name = module.name();

            if let Some(reason) = module_skip_reason(&**module, opts) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                ));
                continue;
            }

            let _ = self.bus.send(Event::new(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            ));

            let result = timeout(
                Duration::from_millis(module_timeout_ms(&**module, opts)),
                module.process(target, ctx),
            )
            .await;

            self.finalise_module_result(scan_id, name, opts.min_confidence, entity_map, result);

            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }
        Ok(())
    }

    /// v0.8 concurrent dispatcher. Launches up to `opts.max_concurrent`
    /// modules at a time via a `tokio::sync::Semaphore`; collects results
    /// as tasks complete. Module-side filtering (allowlist, exclude,
    /// free_only, passive_only, accepts) is performed serially before
    /// spawning so the skip-events still emit in priority order; only the
    /// `process()` call itself parallelises.
    ///
    /// Event ordering caveat: `ModuleStart` events from concurrent tasks
    /// can interleave with each other and with `EntityFound` events from
    /// faster modules. SSE consumers handle this fine (each event is
    /// self-describing); CLI tracing logs will look interleaved.
    async fn dispatch_target_concurrent(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();

        for module in self.modules_for(target.kind) {
            let name = module.name();

            if let Some(reason) = module_skip_reason(&**module, opts) {
                let _ = self.bus.send(Event::new(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                ));
                continue;
            }

            // Acquire BEFORE spawning so dispatch *launches* respect the
            // concurrency cap (not just completions). The permit is held
            // for the duration of the spawned task.
            // semaphore closed — shouldn't happen
            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = ctx.clone();
            let bus = self.bus.clone();
            let scan_id_owned = scan_id.to_string();
            let throttle_ms = opts.throttle_ms;
            let timeout_ms = module_timeout_ms(&**module, opts);

            set.spawn(async move {
                let _permit = permit;
                let name = module_arc.name();

                let _ = bus.send(Event::new(
                    &scan_id_owned,
                    EventKind::ModuleStart {
                        module: name.into(),
                    },
                ));

                let result = timeout(
                    Duration::from_millis(timeout_ms),
                    module_arc.process(&target, &ctx),
                )
                .await;

                if throttle_ms > 0 {
                    sleep(Duration::from_millis(throttle_ms)).await;
                }

                DispatchOutcome { name, result }
            });
        }

        // Consume results as tasks finish. entity_map is single-owner
        // in this loop, so no Mutex needed.
        while let Some(joined) = set.join_next().await {
            let outcome = match joined {
                Ok(o) => o,
                Err(e) => {
                    warn!(error = %e, "concurrent module task panicked");
                    continue;
                }
            };
            self.finalise_module_result(
                scan_id,
                outcome.name,
                opts.min_confidence,
                entity_map,
                outcome.result,
            );
        }
        Ok(())
    }
}
