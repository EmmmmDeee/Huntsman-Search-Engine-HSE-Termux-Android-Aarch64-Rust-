use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use super::ScanEngine;
use crate::core::{
    entity::Entity,
    error::Result,
    event::EventKind,
    module::{Module, ModuleContext, ModuleCost},
    scan::{ScanOptions, Target},
};

type TimeoutResult =
    std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>;

struct DispatchOutcome {
    name: &'static str,
    result: TimeoutResult,
}

impl super::ScanEngine {
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
                self.emit(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: "timeout".into(),
                    },
                );
            }
            Ok(Err(e)) => {
                warn!(module = name, error = %e, "module error");
                self.emit(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: e.to_string(),
                    },
                );
            }
            Ok(Ok(mut mr)) => {
                let mut found = 0usize;
                for entity in mr.entities.drain(..) {
                    if !entity.confidence.is_finite() || !(0.0..=1.0).contains(&entity.confidence) {
                        warn!(
                            module = name,
                            "entity has invalid confidence {}, skipping", entity.confidence
                        );
                        continue;
                    }
                    if let Some(min) = min_confidence
                        && entity.confidence < min
                    {
                        continue;
                    }
                    self.emit(
                        scan_id,
                        EventKind::EntityFound {
                            entity: entity.clone(),
                        },
                    );
                    match entity_map.entry(entity.uid.clone()) {
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            e.get_mut().merge(entity);
                        }
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(entity);
                        }
                    }
                    found += 1;
                }
                self.emit(
                    scan_id,
                    EventKind::ModuleDone {
                        module: name.into(),
                        found,
                    },
                );
                info!(module = name, found, "done");
            }
        }
    }
}

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

    async fn dispatch_target_sequential(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
    ) -> Result<()> {
        for module in &self.modules {
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                return Ok(());
            }
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) = module_skip_reason(&**module, opts) {
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                );
                continue;
            }

            self.emit(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );

            let module_timeout_ms = opts
                .module_timeout_ms
                .unwrap_or_else(|| module.max_timeout_ms())
                .max(100);
            let result = timeout(
                Duration::from_millis(module_timeout_ms),
                module.process(target, ctx),
            )
            .await;

            self.finalise_module_result(scan_id, name, opts.min_confidence, entity_map, result);

            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }
        Ok(())
    }

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

        for module in &self.modules {
            if ctx.cancel.is_cancelled() {
                break;
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                break;
            }
            let name = module.name();

            if !module.accepts(target) {
                continue;
            }
            if let Some(reason) = module_skip_reason(&**module, opts) {
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: reason.into(),
                    },
                );
                continue;
            }

            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = ctx.clone();
            let bus = self.bus.clone();
            let store = Arc::clone(&self.store);
            let scan_id_owned = scan_id.to_string();
            let throttle_ms = opts.throttle_ms;
            let module_timeout_ms = opts
                .module_timeout_ms
                .unwrap_or_else(|| module_arc.max_timeout_ms())
                .max(100);

            set.spawn(async move {
                let _permit = permit;
                let name = module_arc.name();

                super::emit_event(
                    &store,
                    &bus,
                    &scan_id_owned,
                    EventKind::ModuleStart {
                        module: name.into(),
                    },
                );

                let result = timeout(
                    Duration::from_millis(module_timeout_ms),
                    module_arc.process(&target, &ctx),
                )
                .await;

                if throttle_ms > 0 {
                    sleep(Duration::from_millis(throttle_ms)).await;
                }

                DispatchOutcome { name, result }
            });
        }

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
