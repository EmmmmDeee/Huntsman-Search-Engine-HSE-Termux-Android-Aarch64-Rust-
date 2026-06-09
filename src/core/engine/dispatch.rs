//! Per-target module dispatch: the sequential and concurrent loops that run a
//! target's accepting modules, the gate that decides whether each module runs,
//! the panic/timeout-guarded module runner, and the per-result finalize step.
//! Split out of `engine` so the round loop (in `mod.rs`) reads as orchestration —
//! it just calls `self.dispatch_target(..)` — while all the per-module dispatch
//! mechanics live here. The `impl super::ScanEngine` block carries the methods;
//! sibling engine methods (`emit`, `emit_skipped`) and free helpers are reached
//! via `self`/`super::`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::{sleep, timeout};
use tracing::{debug, info, warn};

use super::{DispatchLog, ModuleStats};
use crate::core::entity::{Entity, normalise};
use crate::core::error::{Error, Result};
use crate::core::event::EventKind;
use crate::core::module::{Module, ModuleContext, ModuleCost, ModuleResult};
use crate::core::scan::{ScanOptions, Target, TargetKind};

/// Dispatch-dedup key: a module is invoked at most once per `(module, normalised
/// target)` across the whole scan. The value is normalised the same way
/// `Entity::new` does, so the same target reached two ways dedups to one run.
pub(super) fn dispatch_key(
    module_name: &'static str,
    target: &Target,
) -> (&'static str, TargetKind, String) {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    (module_name, target.kind, normalised)
}

/// Emit the uniform per-module dispatch trace, paired with the `ModuleStart` bus
/// event at every dispatch site (sequential + both concurrent phases). Without it
/// the raw debug log showed a module's outcome (done/skipped/errored/timeout) but
/// never its *start*, so a module that hung or vanished mid-flight left no trace.
/// Keyed by `module=<name>` (+ the target) so `grep module=hibp` reconstructs that
/// one module's entire lifecycle from the logs alone.
#[inline]
pub(super) fn log_module_dispatch(name: &str, target: &Target) {
    debug!(
        module = name,
        kind = ?target.kind,
        value = %target.value,
        "dispatch"
    );
}

/// Run one module's `process()` under both a timeout AND a panic guard.
///
/// A panicking module (an `unwrap`/slice on a hostile/drifted upstream response,
/// or a panic deep in a dependency) would otherwise unwind into the sequential
/// loop or a `JoinSet` task and, under `panic = "abort"`, take down a long-lived
/// `hse serve`. Wrapping the timed future in `catch_unwind` maps a caught panic to
/// `Ok(Err(Error::module(name, "panicked: …")))`, so it flows through
/// `finalise_module_result`'s `errored` arm exactly like a returned error —
/// counted, named, and non-fatal to the scan.
pub(super) async fn run_module_guarded(
    timeout_ms: u64,
    name: &'static str,
    fut: impl std::future::Future<Output = Result<ModuleResult>>,
) -> TimeoutResult {
    use futures::FutureExt;
    match std::panic::AssertUnwindSafe(timeout(Duration::from_millis(timeout_ms), fut))
        .catch_unwind()
        .await
    {
        Ok(timeout_result) => timeout_result,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "module panicked".to_string());
            warn!(module = name, %msg, "module panic contained");
            Ok(Err(Error::module(name, format!("panicked: {msg}"))))
        }
    }
}

/// What a spawned per-module task returns to the consumer loop.
pub(super) struct DispatchOutcome {
    pub(super) name: &'static str,
    pub(super) result: TimeoutResult,
}

/// Distinct corroborating evidence-source count for the entity a `target`
/// resolves to (0 if it isn't in the working set yet). Drives the high-value-API
/// gate: a discovered entity must reach real cross-correlation, not just a bumped
/// corroboration counter, before the heaviest paid modules fire on it.
pub(super) fn target_distinct_sources(
    entity_map: &HashMap<String, Entity>,
    target: &Target,
) -> usize {
    let entity_kind = target.kind.to_entity_kind();
    let normalised = normalise(&entity_kind, &target.value);
    let uid = crate::core::entity::derive_uid(&entity_kind, &normalised);
    entity_map
        .get(&uid)
        .map_or(0, |e| e.evidence_sources().len())
}

pub(super) fn module_skip_reason(
    module: &dyn Module,
    target: &Target,
    opts: &ScanOptions,
    is_expansion: bool,
    target_distinct_sources: usize,
) -> Option<&'static str> {
    let name = module.name();
    // The allowlist means "ONLY these modules run" (docs/USAGE.md) — and that
    // must hold on EVERY round, not just the seed. Gating it with `!is_expansion`
    // let every non-allowlisted module run on discovered entities during
    // expansion, contradicting the documented contract and (on the Termux target)
    // turning a focused `--modules name_intel` scan into a full network sweep the
    // moment it expanded. `--exclude` already applies in all rounds; the allowlist
    // now matches.
    if let Some(allow) = &opts.modules
        && !allow.iter().any(|n| n == name)
    {
        return Some("not in allowlist");
    }
    if opts.exclude_modules.iter().any(|n| n == name) {
        return Some("excluded");
    }
    // Circuit breaker: a module that already hit a rate-limit/quota wall or
    // failed repeatedly this run is skipped until its cooldown elapses. Retrying
    // a 429'd or quota-exhausted provider on the next target is guaranteed waste
    // (and extends the ban); skipping it hands that dispatch slot to a source
    // that still works — the budget the alias scan needs to find more. Checked
    // here (not as a hard exclusion) so it auto-recovers when the window passes.
    if super::circuit::is_open(name) {
        return Some("circuit-open — rate-limited/quota/repeated failure (cooling down)");
    }
    // Persistent per-module toggle (universal toggleability): `hse config
    // module.<name> off` disables a module across ALL scans until re-enabled.
    // Default on, so an unset module behaves exactly as before.
    if !crate::util::settings::get_bool(&format!("module.{name}"), true) {
        return Some("disabled in config");
    }
    if opts.free_only && !matches!(module.cost(), ModuleCost::Free) {
        return Some("requires key/payment");
    }
    if opts.passive_only && !module.is_passive() {
        return Some("not passive");
    }
    if is_expansion && module.is_passive() && super::LOCAL_PASSIVE_MODULES.contains(&name) {
        return Some("sensor (already ran on seed round)");
    }
    // High-value-only modules: the heaviest paid API (oathnet_pro, priority
    // 127, Paid, 30s) burns one query per target and a low-specificity seed
    // fans out into a large unrelated corpus — a live `name="Onur Ada"` scan
    // pulled 172 unrelated US-banking breach records that buried the real
    // findings. Per the operator's rule, such a module may fire when the
    // target is EITHER the initial seed query OR a discovered entity that has
    // reached *sufficient cross-correlation* — i.e. corroborated by at least
    // `CROSS_CORRELATION_MIN_SOURCES` DISTINCT evidence sources, not just a
    // bumped corroboration counter. On the live scan this admits the genuinely
    // on-target pivots (the breach email at 4 sources, the person at 3, the
    // employer domain at 2) while excluding the 97 single-source banking
    // emails that would otherwise trigger fresh fan-out. SeekNow (`see_know`)
    // is intentionally NOT gated here: its own per-scan budget in
    // `util::see_know` bounds the quota while letting it pivot freely.
    const HIGH_VALUE_ONLY_MODULES: &[&str] = &["oathnet_pro"];
    const CROSS_CORRELATION_MIN_SOURCES: usize = 2;
    if is_expansion
        && HIGH_VALUE_ONLY_MODULES.contains(&name)
        && target_distinct_sources < CROSS_CORRELATION_MIN_SOURCES
    {
        return Some("high-value API — awaiting cross-correlation (>=2 sources)");
    }
    // ── Universal preflight: reject private IPs / local domains for
    // modules that talk to external APIs. Sensor modules opt out via
    // LOCAL_PASSIVE_MODULES — they legitimately scan the local
    // network. Every other module is treated as "may reach an external
    // service" so we save its quota / suppress its "HTTP 400 invalid
    // IP" responses before the dispatch even fires.
    //
    // Modules with non-IP/Domain accepts (Email, Phone, Username, etc.)
    // fall through the `_` arm and run normally — there's no concept
    // of a "private email".
    if !super::LOCAL_PASSIVE_MODULES.contains(&name) {
        use crate::util::preflight;
        match target.kind {
            // Use the v6-tolerant gate — public IPv6 must pass through
            // (shodan, censys, RDAP, abuseipdb, etc. all support v6).
            // `should_skip_external_ipv4` rejects ANY `:`-containing
            // string and is reserved for the small set of IPv4-only
            // modules (ipapi, ip-api.com, ipinfo.io, ipquery.io)
            // that route through it inside their own `process`.
            TargetKind::IpAddress if preflight::should_skip_external_ip(&target.value) => {
                return Some("private/reserved IP — external API would reject");
            }
            TargetKind::Domain if preflight::is_local_domain(&target.value) => {
                return Some("local/reserved domain — external API would reject");
            }
            // SSRF gate: a URL whose host is a private IP or local
            // domain must not reach a URL-accepting external module
            // (dns_intel, doh_resolver, exif_geo, geo_domain_classifier,
            // web_crawler). Without this, an autonomously-discovered
            // `http://192.168.1.1/admin` would coerce HSE into
            // hitting the operator's internal network.
            TargetKind::Url if crate::util::preflight::url_host_is_private(&target.value) => {
                return Some("URL with private host — external API would reject (SSRF gate)");
            }
            _ => {}
        }
    }
    None
}

/// The output of one `module.process()` call after the engine wraps it
/// in `tokio::time::timeout` — either `Elapsed` (outer timeout fired),
/// `Err` (module returned an error), or `Ok(ModuleResult)` (success).
pub(super) type TimeoutResult =
    std::result::Result<Result<crate::core::module::ModuleResult>, tokio::time::error::Elapsed>;

impl super::ScanEngine {
    /// Translate one module's `process()` result into engine events
    /// (`ModuleError` / `EntityFound` / `ModuleDone`) and merge any
    /// emitted entities into the per-scan `entity_map`. Shared by
    /// `dispatch_target_sequential` and `dispatch_target_concurrent`
    /// so the event payload shape is identical between the two paths.
    fn finalise_module_result(
        &self,
        scan_id: &str,
        name: &'static str,
        min_confidence: Option<f64>,
        entity_map: &mut HashMap<String, Entity>,
        result: TimeoutResult,
        stats: &mut ModuleStats,
    ) {
        stats.run += 1;
        match result {
            Err(_) => {
                stats.timed_out += 1;
                // A timeout carries no message to classify, so it's a soft
                // failure: trips only after a streak (one slow round is transient).
                super::circuit::record_soft_failure(name);
                warn!(module = name, "timeout");
                self.emit(
                    scan_id,
                    EventKind::ModuleError {
                        module: name.into(),
                        error: "timeout".into(),
                    },
                );
            }
            Ok(Err(Error::MissingKey(key))) => {
                // An unconfigured optional provider is NOT a failure. Surface it
                // as a clean "needs key" skip (with a free-signup hint where
                // known) instead of a scary module error, and count it under
                // `skipped` rather than `errored`.
                stats.skipped += 1;
                let reason = match crate::util::keys::signup_hint(&key) {
                    Some(hint) => format!("needs API key {key} — {hint}"),
                    None => format!("needs API key {key}"),
                };
                debug!(module = name, %key, "skipped — needs key");
                self.emit(
                    scan_id,
                    EventKind::ModuleSkipped {
                        module: name.into(),
                        reason,
                    },
                );
            }
            Ok(Err(e)) => {
                stats.errored += 1;
                // Feed the breaker: a rate-limit/quota message trips immediately;
                // any other hard error counts toward the soft streak.
                super::circuit::record_error(name, &e.to_string());
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
                // A completed dispatch (even an empty one) proves the provider is
                // reachable — clear any failure streak so a recovered source is
                // trusted again immediately.
                super::circuit::record_success(name);
                let mut found = 0usize;
                for entity in mr.entities.drain(..) {
                    if let Some(min) = min_confidence
                        && entity.confidence < min
                    {
                        continue;
                    }
                    // Drop guaranteed-bogus IPs (documentation / reserved /
                    // benchmark ranges, e.g. 192.0.2.1 scraped off a tutorial
                    // page) at admission so they never enter the graph, fire
                    // correlations, or appear as findings. RFC1918 private and
                    // loopback are intentionally kept — local sensors surface
                    // those legitimately on-device.
                    if entity.kind == crate::core::entity::EntityKind::IpAddress
                        && crate::core::validation::is_bogus_ip(&entity.value)
                    {
                        self.emit_excluded(scan_id, &entity, "bogus_ip");
                        continue;
                    }
                    // Drop documentation / placeholder artifacts (example.com,
                    // jordan@example.com, http://example.com, the `example`
                    // username, "John Doe", …) at admission so they never enter
                    // the graph, expand into whole infrastructure rounds, or
                    // fire correlations. Inherently-unique secrets (passwords /
                    // API keys / credentials) are exempt — see
                    // `validation::is_placeholder_entity`.
                    if crate::core::validation::is_placeholder_entity(&entity.kind, &entity.value) {
                        self.emit_excluded(scan_id, &entity, "placeholder_artifact");
                        continue;
                    }
                    // Drop truncated / incomplete values (`@gmail`, a domain-less
                    // email, a bare dotless host, a `@`-prefixed handle that
                    // failed to normalise) at admission so the user never sees an
                    // unverifiable fragment. The auditor independently flags any
                    // that somehow slip through (`fragment-values`).
                    if crate::core::validation::is_fragment_value(&entity.kind, &entity.value) {
                        self.emit_excluded(scan_id, &entity, "fragment_value");
                        continue;
                    }
                    self.emit(
                        scan_id,
                        EventKind::EntityFound {
                            entity: entity.clone(),
                        },
                    );
                    super::scan_entity_for_keys(&entity);
                    let mut entity = entity;
                    super::enrich_geospatial(&mut entity);
                    if let Some(existing) = entity_map.get_mut(&entity.uid) {
                        existing.merge(entity);
                    } else {
                        entity_map.insert(entity.uid.clone(), entity);
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

    /// Dispatch every accepting module against `target`. Picks the
    /// sequential or concurrent codepath based on `opts.max_concurrent`.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn dispatch_target(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        if opts.max_concurrent == 0 {
            self.dispatch_target_sequential(
                scan_id,
                target,
                ctx,
                opts,
                entity_map,
                is_expansion,
                stats,
                dispatched,
            )
            .await
        } else {
            self.dispatch_target_concurrent(
                scan_id,
                target,
                ctx,
                opts,
                entity_map,
                is_expansion,
                stats,
                dispatched,
            )
            .await
        }
    }

    /// Gate check shared by the sequential path and both concurrent phases: if
    /// `module` is filtered out for this `target` (excluded / disabled-in-config /
    /// not-in-allowlist / free-only / passive-only / sensor / insufficient
    /// cross-correlation), count it in `modules_skipped`, emit the `ModuleSkipped`
    /// event, and return `true` so the caller skips to the next module.
    ///
    /// One definition keeps the skip tally faithful and identical across all
    /// three dispatch loops — toggling a module off is observable in the scan
    /// summary, not just the event stream, and the counting can't drift between
    /// the sequential and the two concurrent phases.
    #[allow(clippy::too_many_arguments)]
    fn gate_skips(
        &self,
        scan_id: &str,
        module: &dyn Module,
        name: &'static str,
        target: &Target,
        opts: &ScanOptions,
        is_expansion: bool,
        target_sources: usize,
        stats: &mut ModuleStats,
    ) -> bool {
        if let Some(reason) = module_skip_reason(module, target, opts, is_expansion, target_sources)
        {
            stats.skipped += 1;
            self.emit_skipped(scan_id, name, reason);
            true
        } else {
            false
        }
    }

    /// Sequential dispatcher (max_concurrent == 0).
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_target_sequential(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        // O(1) dispatch-index lookup replaces the O(M) accepts() scan.
        // Modules are already priority-sorted within each bucket so we
        // walk them in the same order the legacy `for module in &self.modules`
        // loop did. Iterating index-by-index (instead of pre-allocating
        // a `Vec<Arc<dyn Module>>` and Arc-cloning per target) avoids
        // a heap allocation + N atomic increments per dispatch — meaningful
        // on the hot path that runs once per expansion candidate.
        // Distinct-source count of the target entity (for the high-value-API
        // cross-correlation gate); computed once per target, not per module.
        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.max_entities.is_some_and(|cap| entity_map.len() >= cap) {
                return Ok(());
            }
            let name = module.name();

            // Belt-and-braces: a module whose `consumes()` declaration
            // diverges from its runtime `accepts()` would otherwise
            // slip through. Cheap re-check on the hit path.
            if !module.accepts(target) {
                continue;
            }
            if self.gate_skips(
                scan_id,
                &**module,
                name,
                target,
                opts,
                is_expansion,
                target_sources,
                stats,
            ) {
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }

            log_module_dispatch(name, target);
            self.emit(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );

            let result = run_module_guarded(
                super::resolve_timeout(opts, &**module),
                name,
                module.process(target, ctx),
            )
            .await;

            self.finalise_module_result(
                scan_id,
                name,
                opts.min_confidence,
                entity_map,
                result,
                stats,
            );

            super::hot_inject_keys(&mut ctx.keys);

            // Re-check the cancel flag before the throttle sleep so an
            // operator cancel between modules doesn't pay the full
            // `throttle_ms` latency before the next gate at the top of
            // the loop is reached. The throttle exists to be polite to
            // upstreams; once the operator has asked us to stop there's
            // nothing left to be polite about.
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            if opts.throttle_ms > 0 {
                sleep(Duration::from_millis(opts.throttle_ms)).await;
            }
        }
        Ok(())
    }

    /// Concurrent dispatcher (max_concurrent > 0). Launches up to `opts.max_concurrent`
    /// modules at a time via a Semaphore; collects results as tasks complete.
    ///
    /// Paid modules run synchronously first (key-discovery-first pattern):
    /// oathnet_pro, dehashed, intelx discover API keys that hot-inject into
    /// ctx before the remaining modules are spawned concurrently. Without this,
    /// all modules launch with a cloned ctx that lacks discovered keys.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_target_concurrent(
        &self,
        scan_id: &str,
        target: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        entity_map: &mut HashMap<String, Entity>,
        is_expansion: bool,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
    ) -> Result<()> {
        use tokio::sync::Semaphore;
        use tokio::task::JoinSet;

        // O(1) dispatch-index lookup — only modules accepting `target.kind`
        // are even considered. Phase 1 then filters to Paid. We iterate
        // indices directly rather than allocating a `Vec<Arc<dyn Module>>`
        // and Arc-cloning per target; on the hot path this saves a heap
        // allocation + N atomic increments per dispatch.

        // Phase 1: Run Paid modules synchronously so discovered keys are
        // available via hot-inject before the concurrent phase begins.
        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if !matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
            if ctx.cancel.is_cancelled() {
                break;
            }
            let name = module.name();
            if !module.accepts(target) {
                continue;
            }
            if self.gate_skips(
                scan_id,
                &**module,
                name,
                target,
                opts,
                is_expansion,
                target_sources,
                stats,
            ) {
                continue;
            }
            if !dispatched.insert(dispatch_key(name, target)) {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }
            log_module_dispatch(name, target);
            self.emit(
                scan_id,
                EventKind::ModuleStart {
                    module: name.into(),
                },
            );
            let result = run_module_guarded(
                super::resolve_timeout(opts, &**module),
                name,
                module.process(target, ctx),
            )
            .await;
            self.finalise_module_result(
                scan_id,
                name,
                opts.min_confidence,
                entity_map,
                result,
                stats,
            );
            // Hot-inject discovered keys so Phase 2 modules can use them.
            // Multiplier-tier keys (Shodan, Censys, Hunter, Proxycurl etc.)
            // cascade — their outputs feed web_crawler/search_engines, which
            // discover MORE keys.
            super::hot_inject_keys(&mut ctx.keys);
        }

        // Phase 2: Spawn remaining (Free + KeyGated) modules concurrently.
        // ctx now contains any keys discovered in Phase 1. Same
        // index-iteration pattern as Phase 1 — Arc::clone moves to the
        // single spawn site below, instead of being paid for every
        // candidate during candidate-list construction.
        let sem = Arc::new(Semaphore::new(opts.max_concurrent));
        let mut set: JoinSet<DispatchOutcome> = JoinSet::new();
        let scan_id_arc: Arc<str> = scan_id.into();
        // Share one context across all spawned modules in this round instead of
        // deep-cloning the keys map + scan_id per dispatch. Modules take
        // `&ModuleContext` (read-only) and ctx is stable within a round, so an
        // Arc bump per spawn replaces N HashMap/String clones — a real win on a
        // low-RAM phone with ~80 modules/round.
        let ctx_shared: Arc<ModuleContext> = Arc::new(ctx.clone());

        let target_sources = target_distinct_sources(entity_map, target);
        for &idx in self.graph.modules_for(target.kind) {
            let Some(module) = self.modules.get(idx) else {
                continue;
            };
            if matches!(module.cost(), ModuleCost::Paid) {
                continue;
            }
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
            if self.gate_skips(
                scan_id,
                &**module,
                name,
                target,
                opts,
                is_expansion,
                target_sources,
                stats,
            ) {
                continue;
            }
            if !matches!(module.cost(), ModuleCost::Free)
                && !dispatched.insert(dispatch_key(name, target))
            {
                stats.deduped += 1;
                self.emit_skipped(scan_id, name, "already dispatched for this target");
                continue;
            }

            let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
                break;
            };

            let module_arc: Arc<dyn Module> = Arc::clone(module);
            let target = target.clone();
            let ctx = Arc::clone(&ctx_shared);
            let emitter = self.emitter.clone();
            let sid = Arc::clone(&scan_id_arc);
            let throttle_ms = opts.throttle_ms;
            let module_timeout_ms = super::resolve_timeout(opts, &*module_arc);

            set.spawn(async move {
                let _permit = permit;

                log_module_dispatch(name, &target);
                emitter.emit(
                    &sid,
                    EventKind::ModuleStart {
                        module: name.into(),
                    },
                );

                let result =
                    run_module_guarded(module_timeout_ms, name, module_arc.process(&target, &ctx))
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
                Err(e) if e.is_cancelled() => {
                    tracing::debug!("concurrent module task cancelled");
                    continue;
                }
                Err(e) => {
                    warn!(error = %e, "concurrent module task panicked");
                    self.emit(
                        scan_id,
                        EventKind::ModuleError {
                            module: "unknown (panicked)".into(),
                            error: e.to_string(),
                        },
                    );
                    continue;
                }
            };
            self.finalise_module_result(
                scan_id,
                outcome.name,
                opts.min_confidence,
                entity_map,
                outcome.result,
                stats,
            );
        }
        Ok(())
    }
}
