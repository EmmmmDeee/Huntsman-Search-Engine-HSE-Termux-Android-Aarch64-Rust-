//! Sequential scan engine — dispatches modules with per-module timeout.
//!
//! v0.1.0 behaviour:
//!   - Iterates modules in priority order (highest first)
//!   - Filters by `accepts()`, ScanOptions allowlist/denylist, free-only, passive-only
//!   - Per-module timeout (default `MODULE_TIMEOUT_MS`, overridable per scan)
//!   - GREATEST-semantics in-memory merge before persisting
//!   - Emits events for every lifecycle stage
//!   - `throttle_ms` sleeps between modules; `max_concurrent` is reserved for v0.3+

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::{info, warn};

use crate::{
    MODULE_TIMEOUT_MS,
    core::{
        entity::Entity,
        error::Result,
        event::{Event, EventBus, EventKind},
        module::{Module, ModuleContext, ModuleCost},
        scan::{Scan, ScanStatus, Target},
    },
    storage::store::Store,
};

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<Store>,
    bus: EventBus,
}

impl ScanEngine {
    pub fn new(mut modules: Vec<Arc<dyn Module>>, store: Arc<Store>, bus: EventBus) -> Self {
        modules.sort_by(|a, b| b.priority().cmp(&a.priority()));
        Self {
            modules,
            store,
            bus,
        }
    }

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Run a scan to completion. Honours every field of `scan.options`.
    pub async fn run(&self, mut scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        let _ = self.bus.send(Event::new(
            &scan.id,
            EventKind::ScanStart {
                target_kind: format!("{:?}", target.kind).to_lowercase(),
                target_value: target.value.clone(),
            },
        ));

        let opts = scan.options.clone();
        let module_timeout_ms = opts.module_timeout_ms.unwrap_or(MODULE_TIMEOUT_MS);
        let mut entity_map: HashMap<String, Entity> = HashMap::new();

        for module in &self.modules {
            let name = module.name();

            // Filter: target kind acceptance
            if !module.accepts(&target) {
                continue;
            }

            // Filter: explicit allowlist
            if let Some(allow) = &opts.modules {
                if !allow.iter().any(|n| n == name) {
                    let _ = self.bus.send(Event::new(
                        &scan.id,
                        EventKind::ModuleSkipped {
                            module: name.into(),
                            reason: "not in allowlist".into(),
                        },
                    ));
                    continue;
                }
            }

            // Filter: explicit denylist
            if opts.exclude_modules.iter().any(|n| n == name) {
                let _ = self.bus.send(Event::new(
                    &scan.id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "excluded".into(),
                    },
                ));
                continue;
            }

            // Filter: free-only
            if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
                let _ = self.bus.send(Event::new(
                    &scan.id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "requires key/payment".into(),
                    },
                ));
                continue;
            }

            // Filter: passive-only
            if opts.passive_only && !module.is_passive() {
                let _ = self.bus.send(Event::new(
                    &scan.id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason: "not passive".into(),
                    },
                ));
                continue;
            }

            let _ = self.bus.send(Event::new(
                &scan.id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            ));

            let result = timeout(
                Duration::from_millis(module_timeout_ms),
                module.process(&target, &ctx),
            )
            .await;

            match result {
                Err(_) => {
                    warn!(module = name, "timeout");
                    let _ = self.bus.send(Event::new(
                        &scan.id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: "timeout".into(),
                        },
                    ));
                }
                Ok(Err(e)) => {
                    warn!(module = name, error = %e, "module error");
                    let _ = self.bus.send(Event::new(
                        &scan.id,
                        EventKind::ModuleError {
                            module: name.into(),
                            error: e.to_string(),
                        },
                    ));
                }
                Ok(Ok(mut mr)) => {
                    let mut found = 0usize;
                    for entity in mr.entities.drain(..) {
                        if let Some(min) = opts.min_confidence
                            && entity.confidence < min
                        {
                            continue;
                        }

                        let _ = self.bus.send(Event::new(
                            &scan.id,
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
                        &scan.id,
                        EventKind::ModuleDone {
                            module: name.into(),
                            found,
                        },
                    ));
                    info!(module = name, found, "done");
                }
            }

            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }

        let entity_count = entity_map.len();
        for entity in entity_map.into_values() {
            self.store.upsert_entity(&entity)?;
        }

        scan.status = ScanStatus::Complete;
        scan.entity_count = entity_count;
        scan.finished_at = Some(crate::core::entity::unix_now());
        self.store.upsert_scan(&scan)?;

        let _ = self.bus.send(Event::new(
            &scan.id,
            EventKind::ScanComplete {
                scan_id: scan.id.clone(),
                entity_count,
            },
        ));

        Ok(scan)
    }
}
