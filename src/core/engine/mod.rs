//! Scan engine — module dispatcher + autonomous expansion + parallel dispatch
//! + per-scan dispatch deduplication.
//!
//! Each scan has two phases:
//!   1. Seed dispatch — every accepting module runs against the seed target.
//!   2. Expansion (when `ScanOptions::depth > 0`) — entities produced so far
//!      with `c_effective() ≥ min_expand_confidence` are converted to new
//!      targets and re-dispatched, up to `depth` rounds. Already-visited
//!      (kind, normalised-value) pairs are skipped, so cycles terminate
//!      naturally. Budgets (`max_entities`, `max_wall_time_secs`) short-circuit
//!      if exceeded.
//!
//! API deduplication: a per-scan `DispatchLog` tracks every
//! (module_name, target_kind, normalised_value) triple dispatched during the
//! scan. Non-free modules (KeyGated, Paid) are skipped if the same triple
//! was already dispatched — this ensures each API key/service is utilised at
//! most once per target in the pivot pipeline. Free modules are exempt since
//! re-running them can corroborate entities with independent evidence.
//!
//! Dispatch mode is selected by `ScanOptions::max_concurrent`:
//!   * `0` (default) → sequential. Best for low-power Termux devices.
//!   * `N > 0` → up to N modules in flight concurrently via
//!     `tokio::sync::Semaphore`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

mod circuit;
mod dispatch;
mod enrich;
mod expansion;
mod history;
mod ledger;
mod passes;
mod ranking;
mod timeout;
mod writer;
pub use ledger::DispatchLog;
// Out-of-scan-loop APIs (leverage / autonomous-target ranking, offline geo
// enrichment) live in `ranking`; re-exported so existing
// `crate::core::engine::…` call sites in the CLI / API / dossier are unchanged.
use passes::{
    consolidate_address_localities, flag_geo_discordant_namesakes, hot_inject_keys,
    promote_breach_candidate_geo_corroborated, promote_cross_scan_corroborated,
    promote_geo_corroborated_family, promote_multipath_corroborated,
};
pub use ranking::{
    AutonomousPlan, AutonomousTarget, ClusteredTarget, DEFAULT_SWEEP_DIVERSITY, LeverageRanked,
    autonomous_target_score, enrich_offline_geo, kind_pivot_value, plan_autonomous_sweep,
    rank_enrichment_leverage, rank_identity_aware_targets,
};
use writer::DbWriter;
// The per-target dispatch context (`DispatchCx`) and the mutable accumulator
// bundle (`DispatchState`) are constructed here — at the seed-round and
// expansion call sites — and threaded into the loops that live in `dispatch`.
use dispatch::{DispatchCx, DispatchState};
// The dispatch loops now live in `dispatch`; these items are referenced only by
// the tests that stayed in this file, so the bridge is test-only.
#[cfg(test)]
use dispatch::{
    admission_rejection, dispatch_key, log_module_dispatch, module_skip_reason, run_module_guarded,
    target_distinct_sources,
};
use enrich::{
    address_to_coords_pass, enrich_geospatial, scan_entity_for_keys, seed_anchor_entity,
    tag_breach_sector, tag_platform_infra,
};
use expansion::{
    apply_roi_cutoff, budget_check, cmp_expansion_candidates, correlation_key, visit_key,
};
use timeout::resolve_timeout;
// Used only by the dispatch-related tests retained in this file.
#[cfg(test)]
use crate::core::{error::Error, module::ModuleCost};

use crate::core::{
    dependency::ModuleGraph,
    entity::Entity,
    error::Result,
    event::{Event, EventBus, EventKind},
    module::{Module, ModuleContext},
    port::StoragePort,
    relation::{Relation, RelationKind},
    scan::{Scan, ScanOptions, ScanStatus, Target, TargetKind},
};

pub struct ScanEngine {
    modules: Vec<Arc<dyn Module>>,
    store: Arc<dyn StoragePort>,
    bus: EventBus,
    emitter: EventEmitter,
    /// Pre-computed dispatch index + richness scoring. Built once at
    /// engine construction so the per-target dispatch loop can skip
    /// the O(M) `accepts()` scan and so the expansion ranker can pull
    /// the richness factor in constant time.
    graph: Arc<ModuleGraph>,
    /// Handle to the DB-writer actor; used to flush pending events at scan
    /// completion before returning the finished scan to the caller.
    writer: DbWriter,
}

/// Reason an expansion round stopped before depth was exhausted.
enum StopReason {
    NoMoreCandidates,
    DepthExhausted,
    MaxEntities(usize),
    MaxWallTime(u64),
    Cancelled,
}

/// Accumulator for per-scan module execution statistics.
/// Created in `run()`, threaded through the dispatch chain, and applied
/// to the `Scan` record in `finalise_scan`.
#[derive(Debug, Default)]
pub(crate) struct ModuleStats {
    pub run: usize,
    pub errored: usize,
    pub timed_out: usize,
    pub deduped: usize,
    /// Modules skipped rather than run: gate-skips (excluded, disabled in
    /// config, not in the allowlist, filtered by free-only/passive-only, or a
    /// sensor that already ran) plus modules that dispatched then cleanly opted
    /// out because a required API key is absent. Counted separately from
    /// `errored` so an unconfigured optional provider is never a failure.
    pub skipped: usize,
    /// Modules whose result was replayed from the inter-scan entity cache
    /// (C9 / SOL-CACHE-INTERSCAN). Not counted in `run`.
    pub cached: usize,
}

/// Mutable scan-wide accumulators threaded through the expansion loop: the
/// working entity set, the visited-target set (the cycle guard), the run
/// tallies, the paid-dedup ledger, the lineage (`DerivedFrom`) edges, and the
/// set of already-emitted correlation ids. Bundled so [`ScanEngine::run_expansion`]
/// takes one borrow instead of six always-together out-parameters; passed *by
/// value* and destructured at the top of the loop, so the body keeps using the
/// fields by their plain names and only the borrow lifetime is bundled. The
/// `entity_map`/`stats`/`dispatched` trio is re-borrowed into a [`DispatchState`]
/// for each `dispatch_target` call.
struct ExpansionState<'a> {
    entity_map: &'a mut HashMap<String, Entity>,
    visited: &'a mut HashSet<(TargetKind, String)>,
    stats: &'a mut ModuleStats,
    dispatched: &'a mut DispatchLog,
    relations: &'a mut Vec<Relation>,
    emitted_corr: &'a mut HashSet<String>,
}

impl StopReason {
    fn label(&self) -> String {
        match self {
            Self::NoMoreCandidates => "no more high-confidence candidates".into(),
            Self::DepthExhausted => "maximum expansion depth reached".into(),
            Self::MaxEntities(n) => format!("max_entities={n} reached"),
            Self::MaxWallTime(s) => format!("max_wall_time_secs={s} exceeded"),
            Self::Cancelled => "cancelled by operator".into(),
        }
    }
}

/// Cheaply-cloneable event emitter. Enqueues to the DB-writer actor, then
/// broadcasts on the in-process SSE bus. Spawned tasks clone this instead of
/// re-cloning store + bus separately.
#[derive(Clone)]
struct EventEmitter {
    writer: DbWriter,
    bus: EventBus,
}

impl EventEmitter {
    fn new(writer: DbWriter, bus: EventBus) -> Self {
        Self { writer, bus }
    }

    fn emit(&self, scan_id: &str, kind: EventKind) {
        let event = Event::new(scan_id, kind);
        // Non-blocking enqueue to the DB-writer actor; persisted asynchronously.
        self.writer.submit(event.clone());
        // Best-effort live fan-out to SSE subscribers. `broadcast::send` errors
        // ONLY when there are zero active receivers — the normal case for a CLI
        // scan with no `/events` client attached. Drop silently (see previous
        // rationale: per-event logging floods the terminal on breach-heavy scans).
        let _ = self.bus.send(event);
    }
}

impl ScanEngine {
    pub fn new(
        mut modules: Vec<Arc<dyn Module>>,
        store: Arc<dyn StoragePort>,
        bus: EventBus,
    ) -> Self {
        modules.sort_by_key(|m| std::cmp::Reverse(m.priority()));
        let writer = DbWriter::spawn(Arc::clone(&store));
        let emitter = EventEmitter::new(writer.clone(), bus.clone());
        let graph = Arc::new(ModuleGraph::build(&modules));
        Self {
            modules,
            store,
            bus,
            emitter,
            graph,
            writer,
        }
    }

    /// Read-only access to the pre-computed module dependency graph.
    /// Used by the HTTP API to surface `/api/v1/modules/graph` and by
    /// integration tests that need to introspect dispatch counts.
    pub fn graph(&self) -> &ModuleGraph {
        &self.graph
    }

    fn emit(&self, scan_id: &str, kind: EventKind) {
        self.emitter.emit(scan_id, kind);
    }

    /// Emit a `ModuleSkipped` event — the gate-rejection path shared by
    /// `run_expansion` and both dispatchers (cancel/quota/cost-dedup/skip-rule).
    fn emit_skipped(&self, scan_id: &str, module: &str, reason: &str) {
        self.emit(
            scan_id,
            EventKind::ModuleSkipped {
                module: module.into(),
                reason: reason.into(),
            },
        );
    }

    /// Emit an `EntityExcluded` event — an expansion-pruning OR admission-drop
    /// decision made visible so the pipeline is never a black box (the reason
    /// names exactly why the entity was not pivoted on, or was rejected before
    /// ever entering the graph: `bogus_ip`, `placeholder_artifact`,
    /// `fragment_value`, …).
    fn emit_excluded(&self, scan_id: &str, entity: &Entity, reason: &str) {
        self.emit(
            scan_id,
            EventKind::EntityExcluded {
                kind: entity.kind.to_string(),
                value: entity.value.clone(),
                reason: reason.into(),
            },
        );
    }

    /// The registered modules, in dispatch order — the set the engine runs each
    /// applicable one of against every target.
    #[must_use]
    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

    /// The engine's [`EventBus`] — subscribe to it to stream scan progress
    /// (module start/done, entities found, correlations) as the graph grows.
    #[must_use]
    pub fn bus(&self) -> &EventBus {
        &self.bus
    }

    /// Run a scan to completion, including any expansion rounds.
    /// Run one scan with a fresh dispatch ledger (the normal one-shot path).
    pub async fn run(&self, scan: Scan, target: Target, ctx: ModuleContext) -> Result<Scan> {
        let mut dispatched: DispatchLog = DispatchLog::new();
        self.run_with_ledger(scan, target, ctx, &mut dispatched)
            .await
    }

    /// Run one scan against a caller-owned dispatch ledger.
    ///
    /// Identical to [`run`](Self::run) except the keyed/paid-module
    /// deduplication set is supplied by the caller, so a continuous mode
    /// (radar) can persist ONE ledger across iterations: a keyed module that
    /// already queried a given seed in an earlier sweep is skipped on every
    /// later sweep, so the APIs are never re-hit on already-covered seeds.
    /// Free modules still re-run each sweep (they corroborate with fresh
    /// evidence and cost nothing), so the radar keeps surfacing new leads.
    ///
    /// Wraps the work in the foreign-key scan-scope ambient
    /// ([`crate::util::found_keys::with_scan`]) so the per-response key scanner
    /// attributes discoveries to THIS `scan_id` even under concurrent `serve`
    /// scans (PROBLEM_TREE T2.11); the logic lives in `run_with_ledger_inner`.
    pub async fn run_with_ledger(
        &self,
        scan: Scan,
        target: Target,
        ctx: ModuleContext,
        dispatched: &mut DispatchLog,
    ) -> Result<Scan> {
        let sid = scan.id.clone();
        crate::util::found_keys::with_scan(
            sid,
            self.run_with_ledger_inner(scan, target, ctx, dispatched),
        )
        .await
    }

    async fn run_with_ledger_inner(
        &self,
        mut scan: Scan,
        target: Target,
        mut ctx: ModuleContext,
        dispatched: &mut DispatchLog,
    ) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        // Reset every module's per-scan state — rate budgets + the foreign-API-key
        // sink — so long-lived processes (`hse serve` / `hse live`) get a fresh
        // budget per scan, and this scan reports only the keys IT retrieves.
        // Driven through the module-hook registry so core stays module-agnostic
        // (see `core::hooks`).
        crate::core::hooks::reset_per_scan(&scan.id);
        // Apply the regional-search toggle for this scan. Regional augmentation
        // is on when EITHER the per-scan flag (`--regional`) is set OR the
        // persistent default `feature.regional` is on (universal toggleability;
        // default off ⇒ geolocation-neutral queries). The per-scan flag only
        // adds regional — set the standing baseline via `hse config
        // feature.regional <on|off>`. Mirrors the see_know per-scan global.
        crate::core::hooks::set_regional(
            scan.options.regional_search
                || crate::util::settings::get_bool("feature.regional", false),
        );

        // Apply per-scan SeekNow budget override if the operator asked
        // for one. Capped at 500 so a single scan cannot blow the
        // per-session ceiling. `reset_budget` above cleared any prior
        // override; this re-installs it for the current scan only.
        if let Some(cap) = scan.options.seeknow_scan_cap {
            let clamped = cap.min(500);
            crate::util::see_know::set_scan_cap_override(clamped);
        }

        self.emit(
            &scan.id,
            EventKind::ScanStart {
                target_kind: target.kind.canonical_str().to_string(),
                target_value: target.value.clone(),
            },
        );

        let opts = scan.options.clone();
        let started = Instant::now();

        // Wall-time watchdog. `budget_check` only enforces the wall budget
        // BETWEEN expansion candidates, so the seed round (all accepting
        // modules fan out at once) and any long in-flight concurrent batch
        // could blow far past `max_wall_time_secs` — observed: a
        // `--max-wall-time 5` scan ran until an external SIGKILL because no
        // deadline was checked during the seed round. This watchdog fires the
        // engine-wide cancel flag at the deadline; every dispatch loop already
        // polls `ctx.cancel`, and finalise treats cancellation as a clean
        // `Aborted` with all collected entities persisted — so the scan stops
        // promptly AND still prints/streams what it found (the "always display
        // results" + "fallback bound that actually bounds" requirements).
        let wall_watchdog = opts.max_wall_time_secs.map(|secs| {
            let cancel = ctx.cancel.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(secs)).await;
                cancel.cancel();
            })
        });

        let mut entity_map: HashMap<String, Entity> =
            HashMap::with_capacity(opts.max_entities.unwrap_or(256).min(4096));
        let mut visited: HashSet<(TargetKind, String)> = HashSet::new();
        let mut stats = ModuleStats::default();
        // Lineage `DerivedFrom` edges (child → the parent it was expanded
        // from), accumulated across expansion rounds and persisted in
        // finalise_scan.
        let mut lineage: Vec<Relation> = Vec::new();
        // Live cross-correlation dedup set: the stable identity (rule_id +
        // sorted entity uids) of every correlation already streamed during
        // ingestion. Shared across the seed round, every expansion round, and
        // the authoritative finalise pass so each correlation is emitted at
        // most once even though the rules are re-evaluated continuously.
        let mut emitted_corr: HashSet<String> = HashSet::new();

        visited.insert(visit_key(&target));
        // Anchor the queried subject as a root entity BEFORE dispatch, so the
        // result graph always has a node for what the operator searched for —
        // the hub every relation/correlation hangs off. Pre-inserting (rather
        // than appending) means a module that re-emits the seed merges its
        // evidence onto this anchor by uid instead of duplicating it. `FullName`
        // is delegated to name_intel's Person anchor (see seed_anchor_entity).
        // Guard on cancellation: a scan cancelled before it starts does no work
        // and persists nothing — not even the anchor — so the "pre-cancel is a
        // clean no-op" invariant holds. A live scan inserts the anchor, then
        // dispatch may still abort mid-flight, leaving the subject node present
        // (we always show what was queried), consistent with finalise persisting
        // collected entities on a clean Aborted.
        if !ctx.cancel.is_cancelled()
            && let Some(anchor) = seed_anchor_entity(&target, &scan.id)
        {
            entity_map.insert(anchor.uid.clone(), anchor);
        }

        // ─── Recall: the persistent database as a source (opt-in) ───────────
        // When enabled, pre-populate the working set with everything prior scans
        // of this target already discovered, so the local store feeds the seed
        // round and every expansion round. Universal toggle `feature.recall`,
        // **default OFF**: every scan is a fresh start showing only what THIS run
        // found — no archaic prior-scan entities injected (which also keeps the
        // per-round correlation pass small). The store still RETAINS everything
        // and cross-scan corroboration still runs at finalise; recall only
        // controls pre-loading. `hse config feature.recall on` to opt in. Skipped
        // on a pre-cancelled scan (clean no-op invariant).
        if !ctx.cancel.is_cancelled() && crate::util::settings::get_bool("feature.recall", false) {
            let recalled =
                self.recall_prior_entities(&target, &scan.id, scan.options.allow_live_sensors);
            let n = recalled.len();
            for entity in recalled {
                if let Some(existing) = entity_map.get_mut(&entity.uid) {
                    existing.merge(entity);
                } else {
                    entity_map.insert(entity.uid.clone(), entity);
                }
            }
            if n > 0 {
                info!(scan_id = %scan.id, recalled = n, "recall: injected prior-scan entities from the local database");
                self.emit(
                    &scan.id,
                    EventKind::ModuleDone {
                        module: "recall".to_string(),
                        found: n,
                    },
                );
            }
        }
        // Seed-dispatch errors are warn-and-continue, exactly like
        // expansion-round dispatch below: propagating here returned before
        // finalise_scan (losing every collected entity and leaving the scan
        // row stuck `Running`) AND leaked the wall-time watchdog, which then
        // fired `cancel()` on the caller's context long after this scan was
        // gone — poisoning the shared token under a long-lived serve/radar.
        // Per-module failures are already surfaced as ModuleError events.
        {
            // Seed-round plan visibility: the operator sees exactly how many
            // modules will run for this target kind and at what concurrency —
            // dispelling the "APIs aren't executing" perception when a wide scan
            // is simply working through a long module list.
            info!(
                scan_id = %scan.id,
                kind = target.kind.canonical_str(),
                modules = self.graph.modules_for(target.kind).len(),
                concurrency = opts.effective_max_concurrent(),
                "seed round: dispatching modules"
            );
            let cx = DispatchCx {
                scan_id: &scan.id,
                target: &target,
                opts: &opts,
                is_expansion: false,
                seed_kind: target.kind,
            };
            let mut dstate = DispatchState {
                entity_map: &mut entity_map,
                stats: &mut stats,
                dispatched: &mut *dispatched,
            };
            if let Err(e) = self.dispatch_target(&cx, &mut ctx, &mut dstate).await {
                warn!(scan_id = %scan.id, error = %e, "seed dispatch failed (continuing to finalise)");
            }
            // Seed-round tally: `stats` starts at default() and neither the anchor
            // nor recall touch it before here, so these ARE the seed-round counts.
            info!(
                scan_id = %scan.id,
                run = stats.run,
                skipped = stats.skipped,
                cached = stats.cached,
                deduped = stats.deduped,
                errored = stats.errored,
                timed_out = stats.timed_out,
                entities = entity_map.len(),
                elapsed_ms = started.elapsed().as_millis() as u64,
                "seed round complete"
            );
        }

        // Convert Address entities to Coordinates (offline city lookup) so they
        // feed AU-052/053 geo correlation rules.  Run before the snapshot so
        // derived Coordinates are checkpointed and correlated in the same pass.
        for mut derived in address_to_coords_pass(&entity_map, &scan.id) {
            enrich_geospatial(&mut derived);
            if let Some(existing) = entity_map.get_mut(&derived.uid) {
                existing.merge(derived);
            } else {
                entity_map.insert(derived.uid.clone(), derived);
            }
        }

        // Checkpoint + correlate the seed round from a single snapshot: the
        // entities are made durable before expansion begins (crash-safety) and
        // single-round (depth=0) scans stream correlations live rather than
        // waiting for finalise.
        let seed_snapshot: Vec<Entity> = entity_map.values().cloned().collect();
        self.checkpoint_entities(&scan.id, &seed_snapshot);
        self.correlate_incremental(&scan.id, &seed_snapshot, &mut emitted_corr);

        if opts.depth > 0 {
            let est = ExpansionState {
                entity_map: &mut entity_map,
                visited: &mut visited,
                stats: &mut stats,
                dispatched: &mut *dispatched,
                relations: &mut lineage,
                emitted_corr: &mut emitted_corr,
            };
            // Capture the terminal stop reason so it reaches the log: the normal
            // `DepthExhausted` outcome is emitted as no event anywhere, so this is
            // the only place the operator learns how expansion ended.
            let stop = self
                .run_expansion(&scan.id, &target, &mut ctx, &opts, started, est)
                .await;
            info!(scan_id = %scan.id, reason = %stop.label(), "expansion finished");

            // Active gap-fill (last leg of the recursive-linking program): for any
            // single-route link the expansion gates left fragile, run the missing
            // orthogonal family's modules on the gap endpoints to pursue the
            // corroborating pathway AU-063 names. Bounded + toggle-gated; any new
            // entities flow into finalise below.
            let _ = self
                .run_gap_fill(
                    &scan.id,
                    &target,
                    &mut ctx,
                    &opts,
                    started,
                    &mut entity_map,
                    &mut visited,
                    &mut stats,
                    &mut *dispatched,
                    &mut lineage,
                )
                .await;
        }

        // Scan body done — stop the wall-time watchdog so it can't fire after
        // we've already finished (and is reaped promptly rather than sleeping
        // out its full deadline in the background on a long-lived `serve`).
        if let Some(handle) = wall_watchdog {
            handle.abort();
        }

        let outcome = self
            .finalise_scan(scan, entity_map, &ctx, stats, lineage, emitted_corr)
            .await;
        // Drain the DB-writer actor so the ScanComplete event (and all events
        // before it) are persisted before we hand the scan back to the caller.
        self.writer.flush().await;
        outcome
    }

    /// Persist entities, run the correlator, and mark the scan terminal.
    /// Runs on a dedicated blocking thread (`tokio::task::spawn_blocking`) so
    /// the four synchronous rusqlite round-trips never stall the async worker
    /// pool — critical on low-core aarch64 where the pool is typically 4–8
    /// threads and a single blocked worker visibly degrades concurrency.
    async fn finalise_scan(
        &self,
        mut scan: Scan,
        entity_map: HashMap<String, Entity>,
        ctx: &ModuleContext,
        stats: ModuleStats,
        lineage_relations: Vec<Relation>,
        mut emitted_corr: HashSet<String>,
    ) -> Result<Scan> {
        let store = Arc::clone(&self.store);
        let emitter = self.emitter.clone();
        // Snapshot the cancellation state before crossing into the blocking
        // thread: CancellationToken is not 'static and cannot be moved.
        let cancelled = ctx.cancel.is_cancelled();
        tokio::task::spawn_blocking(move || -> Result<Scan> {
            // Persist the scan's entities in a single transaction. On the common
            // path (every entity is new or a clean GREATEST-merge) this collapses
            // N per-entity commits into one WAL fsync — a material win on
            // low-power aarch64 where each commit is the dominant cost. The batch
            // is all-or-nothing, so on any error we fall back to per-entity
            // upserts: this salvages whatever is persistable and recovers the
            // granular `first_err`, preserving the prior continue-on-error
            // resilience semantics (partial persist → Complete-with-error;
            // nothing persisted → Failed).
            // Mint ApiKey entities for every FOREIGN key identified in this scan's
            // endpoint responses (deduped by value across all modules; our own auth
            // keys already excluded by the sink). This guarantees leaked third-party
            // keys land in the graph + dossier no matter which module surfaced the
            // data — not only the breach pools that scan their own record fields.
            // They are merged THROUGH `entity_map` by UID (not appended to the batch)
            // so a key a specialised module already emitted with richer
            // tags/evidence is GREATEST-merged, never duplicated or blindly
            // overwritten.
            let mut entity_map = entity_map;
            for e in crate::core::hooks::drain_found_keys(&scan.id) {
                match entity_map.get_mut(&e.uid) {
                    Some(existing) => existing.merge(e),
                    None => {
                        entity_map.insert(e.uid.clone(), e);
                    }
                }
            }
            let mut entities: Vec<Entity> = entity_map.into_values().collect();
            // Codebase-wide address-locality consolidation. The UID merge above
            // dedups by exact normalised value, so "X, NSW" and "X, NSW 2582" (one
            // place at two granularities) survive as two Address entities — which
            // double-counts the location in the geo correlations. This runs once,
            // AFTER every module (APIs included) and every expansion round has
            // contributed, folding such variants into the most-specific one. It is
            // the engine-level backstop to the per-module dedup in `search_engines`.
            let folded_locality_uids = consolidate_address_localities(&mut entities);
            // Free, offline cross-angle confirmation: a shared-surname
            // family-candidate whose postcode resolves into the subject's confirmed
            // area is corroborated by a SECOND independent signal (the subject's
            // own GPS fix) and promoted from a lone candidate to a reliable
            // relative — so every scan's geo-confirmed family reads as reliable,
            // not 0.3 noise. Runs after consolidation so it sees the final set.
            promote_geo_corroborated_family(&mut entities);
            // People-centric companion (free, offline): a SAME-NAME breach/stealer
            // candidate whose locality resolves to the subject's confirmed metro is
            // the subject's own record (same name AND same place), so it is lifted
            // out of namesake quarantine into the graded, correlatable set — the
            // finalise application of the per-round reconsideration pass.
            promote_breach_candidate_geo_corroborated(&mut entities);
            // Precision complement (free, offline): a same-surname family-candidate
            // a whole region away from the subject's confirmed fix shares only the
            // name, so it is tagged `geo-discordant` to demote it in the leads —
            // telling the real local family from interstate look-alikes. Tag-only,
            // so it never inflates confidence; runs after promotion (the two bands
            // are disjoint, but a corroborated relative is then never re-examined).
            flag_geo_discordant_namesakes(&mut entities);
            // Cross-scan history flywheel — OPT-IN (`feature.cross_scan`, default
            // off). These three passes fold data from PRIOR scans of the same
            // subject into this scan's output (tags, evidence, and — for relations
            // — links to entities not even present this scan). They never inflate
            // confidence, but they DO incorporate local prior-scan intelligence, so
            // per the "local data not incorporated unless purposely added" contract
            // they only run when the operator opts in. The learning SINK
            // (`record_pathway_template`, below) stays always-on — HSE keeps
            // learning route shapes; it just doesn't inject them back by default.
            if crate::util::settings::get_bool("feature.cross_scan", false) {
                // Tag any specific personal identifier (phone/email/handle/named
                // person/precise address) that ALSO appears in an earlier scan — a
                // cross-investigation bridge a seed-centric recall never makes.
                history::link_cross_scan_history(store.as_ref(), &mut entities, &scan.id);
                // When two identifiers that appeared TOGETHER in an earlier scan
                // both reappear now, tag the recurring association.
                history::link_cross_scan_cooccurrence(store.as_ref(), &mut entities, &scan.id);
                // When a reappearing identifier was SEMANTICALLY linked in a prior
                // scan (located_at / identified_by / alias_of / …), surface that
                // known connection now.
                history::link_cross_scan_relations(store.as_ref(), &mut entities, &scan.id);
            }
            // Determinism: normalise each entity's evidence/tags ordering before
            // persist, so concurrent dispatch's completion-order merging can't leak
            // into the stored/exported result (see `Entity::canonicalize_order`).
            for e in &mut entities {
                e.canonicalize_order();
            }
            let total = entities.len();
            let (persisted, first_err): (usize, Option<String>) = match store
                .upsert_entities_batch(&entities)
            {
                Ok(n) => (n, None),
                Err(batch_err) => {
                    warn!(scan_id = %scan.id, error = %batch_err, "batch entity persist rolled back; falling back to per-entity upserts");
                    let mut persisted = 0usize;
                    let mut first_err: Option<String> = None;
                    for entity in &entities {
                        match store.upsert_entity(entity) {
                            Ok(()) => persisted += 1,
                            Err(e) => {
                                warn!(scan_id = %scan.id, entity_uid = %entity.uid, error = %e, "entity persist failed");
                                if first_err.is_none() {
                                    first_err = Some(e.to_string());
                                }
                            }
                        }
                    }
                    (persisted, first_err)
                }
            };
            let entity_count = persisted;
            let failed = total - persisted;

            scan.modules_run = stats.run;
            scan.modules_errored = stats.errored;
            scan.modules_timed_out = stats.timed_out;
            scan.modules_deduped = stats.deduped;
            scan.modules_skipped = stats.skipped;
            scan.modules_cached = stats.cached;

            if persisted == 0 && first_err.is_some() {
                scan.status = ScanStatus::Failed;
                scan.entity_count = 0;
                scan.error = first_err;
                scan.finished_at = Some(crate::core::entity::unix_now());
                // Persist the failed-scan record. Best-effort like the WAL
                // checkpoint below — we still return the failed scan to the
                // caller — but log on error rather than discarding it silently,
                // matching the success path's `upsert_scan(scan)?` and the
                // "no silent failures" invariant.
                if let Err(e) = store.upsert_scan(&scan) {
                    warn!(scan_id = %scan.id, error = %e, "failed to persist failed-scan record");
                }
                emitter.emit(
                    &scan.id,
                    EventKind::ScanComplete {
                        scan_id: scan.id.clone(),
                        entity_count: 0,
                    },
                );
                return Ok(scan);
            }

            scan.status = if cancelled {
                ScanStatus::Aborted
            } else {
                ScanStatus::Complete
            };
            scan.entity_count = entity_count;
            if failed > 0 {
                scan.error = Some(format!(
                    "{failed}/{total} entities failed to persist: {}",
                    first_err.as_deref().unwrap_or("unknown")
                ));
            }
            scan.finished_at = Some(crate::core::entity::unix_now());
            store.upsert_scan(&scan)?;

            // Purge the address-locality variants that `consolidate_address_localities`
            // folded away in-memory but that earlier round checkpoints already
            // persisted. The finalise correlator (below) reads the persisted scan,
            // so without this the stale variant double-counts the locality in the
            // geo rules and duplicates it in the dossier. Best-effort: a failure
            // here degrades to the pre-fix behaviour, never fails the scan.
            if !folded_locality_uids.is_empty()
                && let Err(e) = store.delete_scan_entities(&scan.id, &folded_locality_uids)
            {
                warn!(scan_id = %scan.id, error = %e, "failed to purge folded address-locality variants");
            }

            // Derive + persist the typed entity-relation edges (attribution
            // graph): the lineage edges captured during expansion plus the
            // structural edges derived from the persisted entity set. The
            // lineage-free structural set (structural/colocation/resolution/
            // registration/name-lineage) is derived identically here and on the
            // import paths via `derive_all`, so a live scan and an imported
            // dossier can't drift on which edges a finished scan carries.
            // Best-effort: a relation that fails to persist is logged, never
            // fatal to the scan.
            {
                // Bounded derivation: stop starting new passes past the budget
                // so a pathological (max_entities-filled) graph can't run the
                // super-linear pass chain for minutes and get SIGKILLed before
                // the dossier is written. Partial relations still persist.
                let derive_deadline =
                    Some(Instant::now() + crate::core::relation::DERIVE_BUDGET);
                let derived =
                    crate::core::relation::derive_all_within(&entities, &scan.id, derive_deadline);
                if !lineage_relations.is_empty() || !derived.is_empty() {
                    let mut rel_persisted = 0usize;
                    for r in lineage_relations.iter().chain(derived.iter()) {
                        match store.upsert_relation(r) {
                            Ok(()) => rel_persisted += 1,
                            Err(e) => warn!(scan_id = %scan.id, relation = %r.id, error = %e, "relation persist failed"),
                        }
                    }
                    info!(
                        scan_id = %scan.id,
                        lineage = lineage_relations.len(),
                        derived = derived.len(),
                        persisted = rel_persisted,
                        "entity relations persisted"
                    );
                }
            }

            // Authoritative finalise-time correlation pass. Runs the full rule
            // set (entity + graph-aware relation rules) over the persisted scan,
            // persists every firing, and emits `CorrelationFound` only for
            // correlations not already streamed live during ingestion (deduped
            // via `emitted_corr`). The `CorrelationsDone` count is the
            // authoritative total for the scan.
            // Guarded against a rule panicking on adversarial persisted data: a
            // panic here would otherwise unwind the whole finalise block, losing
            // the terminal `ScanComplete` event and the harvested key pool. A
            // caught panic (or a returned error) degrades to "no finalise
            // correlations," exactly as the live incremental pass does.
            if let Some(firings) = guarded_finalise_correlation(&scan.id, || {
                crate::core::correlator::Correlator::new(Arc::clone(&store)).run(&scan.id)
            }) {
                for c in &firings {
                    if emitted_corr.insert(correlation_key(c)) {
                        emitter.emit(
                            &scan.id,
                            EventKind::CorrelationFound {
                                correlation: c.clone(),
                            },
                        );
                    }
                }
                emitter.emit(
                    &scan.id,
                    EventKind::CorrelationsDone {
                        count: firings.len(),
                    },
                );
            }

            // ── Cross-scan pathway-template learning (C1 universal linking) ──
            // Generalise this scan's confirmed connections into direction-
            // canonical routes. A route a *prior* scan already proved is credited
            // here as historically corroborated (the engine-level AU-065 finding —
            // it is storage-dependent, so it can't be a pure correlator rule);
            // then every route this scan produced is recorded, so a link learned
            // once lifts every later scan. A *fragile* single-pathway link (the
            // AU-063 gap) whose route shape is proven in ≥2 prior scans is the
            // engine-level AU-066 finding: accumulated cross-scan knowledge is the
            // orthogonal pathway that fills the gap, and its endpoints are queued
            // (`xscan_boost`) for the conservative boost below. Best-effort: a
            // storage hiccup never aborts a finalised scan.
            let mut xscan_boost: HashMap<String, String> = HashMap::new();
            // The learning SINK (recording this scan's route shapes) stays
            // always-on so HSE keeps accumulating cross-scan knowledge; but
            // CONSULTING that prior-scan history to emit AU-065/066 findings and
            // boost this scan's leads is OPT-IN (`feature.cross_scan`, default off)
            // — it incorporates local prior-scan data into the output, which the
            // "local data not incorporated unless purposely added" contract gates.
            let feature_cross_scan = crate::util::settings::get_bool("feature.cross_scan", false);
            if let (Ok(ents), Ok(rels)) = (
                store.entities_for_scan(&scan.id),
                store.relations_for_scan(&scan.id),
            ) {
                // The fragile single-route identity pairs (a<b) — exactly AU-063's
                // notion of an uncorroborated link, via the shared detector so the
                // gap the lead flags is the gap the engine fills. Only needed by the
                // (opt-in) AU-066 gap-fill.
                let fragile: HashSet<(String, String)> = if feature_cross_scan {
                    crate::core::correlator::single_route_identity_links(&ents, &rels)
                        .into_iter()
                        .map(|l| (l.a_uid, l.b_uid))
                        .collect()
                } else {
                    HashSet::new()
                };
                for ct in crate::core::relation::connection_templates(&ents, &rels, 4) {
                    // Consult prior-scan history + emit corroboration findings only
                    // when opted in; the record_pathway_template sink below is
                    // unconditional so learning never stops.
                    if feature_cross_scan {
                    let prior = store.pathway_template_count(&ct.template).unwrap_or(0);
                    if prior >= 1 {
                        let mut uids: std::collections::BTreeSet<String> =
                            std::collections::BTreeSet::new();
                        for (f, t) in &ct.pairs {
                            uids.insert(f.clone());
                            uids.insert(t.clone());
                        }
                        let c = crate::core::correlator::Correlation::new(
                            "AU-065",
                            "Cross-scan corroborated route",
                            crate::core::correlator::Severity::Medium,
                            format!(
                                "the route [{}] connecting {} identity pair(s) here was \
                                 confirmed in {} prior scan(s) — a historically proven \
                                 attribution pattern, not a one-off",
                                ct.template,
                                ct.pairs.len(),
                                prior,
                            ),
                            uids.into_iter().collect::<Vec<_>>(),
                            scan.id.as_str(),
                            crate::core::entity::unix_now(),
                        );
                        if store.upsert_correlation(&c).is_ok()
                            && emitted_corr.insert(correlation_key(&c))
                        {
                            emitter.emit(
                                &scan.id,
                                EventKind::CorrelationFound { correlation: c },
                            );
                        }
                    }
                    // AU-066 — cross-scan route fills a single-pathway gap. A
                    // fragile link whose route shape is proven in ≥2 PRIOR scans
                    // (stricter than AU-065's ≥1, to keep the gap-fill conservative)
                    // is corroborated by the proven attribution method itself: the
                    // accumulated cross-scan pathway is the orthogonal route the
                    // AU-063 gap was missing. Its endpoints are queued for the boost.
                    if prior >= 2 {
                        for (f, t) in &ct.pairs {
                            if !fragile.contains(&(f.clone(), t.clone())) {
                                continue; // only fragile (single-route) links are gaps to fill
                            }
                            let reason = format!(
                                "the single-pathway link's route shape [{}] was independently \
                                 confirmed in {prior} prior scans — the proven attribution method \
                                 is the orthogonal pathway that fills the single-route gap",
                                ct.template,
                            );
                            let c = crate::core::correlator::Correlation::new(
                                "AU-066",
                                "Cross-scan route fills single-pathway gap",
                                crate::core::correlator::Severity::Medium,
                                reason.clone(),
                                vec![f.clone(), t.clone()],
                                scan.id.as_str(),
                                crate::core::entity::unix_now(),
                            );
                            if store.upsert_correlation(&c).is_ok()
                                && emitted_corr.insert(correlation_key(&c))
                            {
                                emitter.emit(
                                    &scan.id,
                                    EventKind::CorrelationFound { correlation: c },
                                );
                            }
                            xscan_boost
                                .entry(f.clone())
                                .or_insert_with(|| reason.clone());
                            xscan_boost.entry(t.clone()).or_insert(reason);
                        }
                    }
                    } // end `if feature_cross_scan` — the sink below stays always-on
                    let _ = store.record_pathway_template(&ct.template);
                }
            }

            // ── Corroboration boosts: confirmed links strengthen the entities ──
            // Two orthogonal corroboration signals feed back into the entity set so
            // the scan's OUTPUT reflects what its own analysis established:
            //   • multipath (C2): a link AU-062 proved via ≥2 edge-disjoint,
            //     source-orthogonal IN-SCAN routes — robust to any one source going
            //     dark (built on the SAME detector the rule uses).
            //   • cross-scan (AU-066): a fragile single-route link whose route shape
            //     is proven in ≥2 PRIOR scans — accumulated knowledge fills the gap.
            // Both tag + evidence-stamp only the identity ENDPOINTS, are idempotent
            // via their tags, and use unscored ("other") evidence sources so they
            // never feed back to inflate the in-scan orthogonality measure.
            // Best-effort and conditional: the single re-persist runs only when a
            // boost actually fires and never aborts a finalised scan.
            {
                let mut boosted_any = false;
                if let Ok(rels) = store.relations_for_scan(&scan.id) {
                    boosted_any |= promote_multipath_corroborated(&mut entities, &rels) > 0;
                }
                boosted_any |= promote_cross_scan_corroborated(&mut entities, &xscan_boost) > 0;
                if boosted_any {
                    let boosted: Vec<Entity> = entities
                        .iter_mut()
                        .filter(|e| {
                            e.has_tag("multipath-corroborated")
                                || e.has_tag("cross-scan-corroborated")
                        })
                        .map(|e| {
                            e.canonicalize_order();
                            e.clone()
                        })
                        .collect();
                    match store.upsert_entities_batch(&boosted) {
                        Ok(n) => info!(
                            scan_id = %scan.id,
                            boosted = n,
                            "corroboration-boosted identities re-persisted (confirmed links strengthened the scan)"
                        ),
                        Err(e) => warn!(
                            scan_id = %scan.id,
                            error = %e,
                            "corroboration boost re-persist failed (non-fatal)"
                        ),
                    }
                }
            }

            // Persist the key pool to disk after every scan. Keys discovered
            // during this scan (from breach data, page bodies, entity values)
            // are permanently stored with full provenance metadata.
            let pool = crate::util::key_pool::global_pool();
            if let Err(e) = crate::util::key_pool::save_pool(&pool) {
                warn!("failed to save key pool after scan: {e}");
            }

            // Scan-boundary WAL checkpoint: fold the WAL into the main DB and
            // truncate the -wal file back to zero. Bounds the on-disk/mmap WAL
            // footprint between scans under a long-lived `serve`/`live` process
            // (the 'everything bounded' invariant). Best-effort — a busy
            // checkpoint just defers to the next scan boundary.
            if let Err(e) = store.checkpoint_truncate() {
                warn!(scan_id = %scan.id, error = %e, "WAL checkpoint deferred (busy)");
            }

            // Bound the events table during long-lived serve/live/radar processes
            // (otherwise pruned only at startup). Best-effort + same retention
            // policy as the startup prune — a busy prune just defers to the next
            // scan boundary.
            if let Err(e) = store.prune_events(
                crate::core::port::EVENTS_RETENTION_SECS,
                crate::core::port::EVENTS_MAX_ROWS,
            ) {
                warn!(scan_id = %scan.id, error = %e, "events prune deferred");
            }
            // Same bound for the inter-scan cache — a long-lived process scanning
            // many distinct targets would otherwise grow `raw_archive` unbounded.
            if let Err(e) = store.prune_raw_archive(crate::core::port::RAW_ARCHIVE_MAX_ROWS) {
                warn!(scan_id = %scan.id, error = %e, "raw_archive prune deferred");
            }

            // Closing scan summary in the standard log — for EVERY output format
            // (the CLI table prints a tally, but json/dossier and the log ring had
            // none). One line that says how the scan ended and what it produced.
            info!(
                scan_id = %scan.id,
                status = scan.status.as_str(),
                entities = entity_count,
                run = scan.modules_run,
                errored = scan.modules_errored,
                timed_out = scan.modules_timed_out,
                deduped = scan.modules_deduped,
                skipped = scan.modules_skipped,
                cached = scan.modules_cached,
                "scan complete"
            );
            emitter.emit(
                &scan.id,
                EventKind::ScanComplete {
                    scan_id: scan.id.clone(),
                    entity_count,
                },
            );

            Ok(scan)
        })
        .await
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))?
    }

    /// Working-set ceiling for the LIVE incremental correlation pass. Above this,
    /// the per-round streaming pass is deferred to the authoritative finalise pass
    /// (which is wall-clock-bounded) so a large recalled / breach-heavy graph can't
    /// make a single round run for seconds and present as a frozen scan. Generous:
    /// a normal scan stays well under it and streams correlations live every round;
    /// only a pathologically large set defers. Larger than a typical scan's entity
    /// count so live streaming is the norm, not the exception.
    const INCREMENTAL_CORRELATE_MAX_ENTITIES: usize = 400;

    /// Live cross-correlation during ingestion. Evaluates the entity rules
    /// against an in-memory snapshot of the working set (no store round-trip)
    /// and streams any newly-fired correlation immediately, persisting it as it
    /// appears. Idempotent across rounds: a correlation's stable identity
    /// (`rule_id` + sorted entity uids) is recorded in `emitted` so it fires
    /// exactly once even though the rules are re-run every round.
    fn correlate_incremental(
        &self,
        scan_id: &str,
        entities: &[Entity],
        emitted: &mut HashSet<String>,
    ) {
        // Rank live-streamed correlations with the same severity × max-child-
        // C_eff score the finalize pass uses, so a scan that is killed at its
        // wall/entity budget (and never reaches finalize) still persists ranked
        // correlations — not rank=0.0 rows. Build the C_eff map once per call.
        let ceff: HashMap<String, f64> = entities
            .iter()
            .map(|e| (e.uid.clone(), e.c_effective()))
            .collect();
        // Contain a correlator panic exactly as module dispatch does
        // (`run_module_guarded`): the 34 AU-rules run index/parse-heavy logic over
        // entity data, so a single malformed value in one rule must degrade to "no
        // new correlations this round" rather than unwind through finalize and lose
        // the scan. Entities are already checkpointed and persisted, so nothing
        // discovered is lost — only this round's correlation pass is skipped.
        // Bound the per-round live pass by working-set size. It is UNBUDGETED on
        // the assumption the set is "small" (the streaming correlations must be
        // reproducible, so a wall-clock cut-off is avoided here), but
        // `feature.recall` (or a deep breach sweep) can make it large, and the
        // unbounded entity-rule pass then runs for seconds EVERY round — between
        // the seed round and the first expansion round — which reads to the
        // operator as the scan freezing right where it should start enumerating.
        // Above the threshold, defer this round's streaming pass; the
        // authoritative, complete, `CORRELATOR_BUDGET`-bounded pass still runs at
        // finalise, so nothing is lost — only the live preview is deferred.
        if entities.len() > Self::INCREMENTAL_CORRELATE_MAX_ENTITIES {
            debug!(
                scan_id,
                entities = entities.len(),
                "live correlation deferred to finalise (working set above the live-pass threshold)"
            );
            return;
        }
        let produced = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::core::correlator::correlate_entities(entities, scan_id)
        }))
        .unwrap_or_else(|_| {
            warn!(
                scan_id,
                "correlation pass panicked — entities preserved, correlations skipped this round"
            );
            Vec::new()
        });
        let mut fresh: Vec<crate::core::correlator::Correlation> = produced
            .into_iter()
            .filter(|c| emitted.insert(correlation_key(c)))
            .collect();
        crate::core::correlator::rank_and_sort(&mut fresh, &ceff);
        for c in fresh {
            if let Err(e) = self.store.upsert_correlation(&c) {
                warn!(scan_id, error = %e, "live correlation persist failed");
            }
            self.emit(scan_id, EventKind::CorrelationFound { correlation: c });
        }
    }

    /// Checkpoint the working entity set to durable storage mid-scan so a crash
    /// or kill preserves discovered intel instead of losing everything until
    /// `finalise_scan`. Runs at every productive round boundary. The upsert is
    /// idempotent GREATEST-merge — replaying the same entities only ever raises
    /// confidence/corroboration, so a resumed or re-run scan never regresses.
    /// Best-effort: a checkpoint failure is logged and retried at finalise.
    fn checkpoint_entities(&self, scan_id: &str, entities: &[Entity]) {
        if entities.is_empty() {
            return;
        }
        if let Err(e) = self.store.upsert_entities_batch(entities) {
            warn!(scan_id, error = %e, "entity checkpoint failed (will retry at finalise)");
        }
    }

    /// Recall everything the local database already knows about this target, for
    /// injection into the working set — so the persistent store is a SOURCE for
    /// every scan, not just a sink. A target ever scanned before re-enters the
    /// graph pre-populated with the entities prior runs (and their expansion
    /// rounds) discovered, ready to corroborate live findings and seed
    /// expansion. This is what makes the database "utilised as a source for all
    /// recursion and future scans".
    ///
    /// The store is content-addressed (same kind+value ⇒ same uid) with a
    /// per-entity observation history, so the relevant prior scans are those
    /// that observed the exact seed identity, plus any that observed an entity
    /// whose value equals the target (robust to `FullName` re-formatting, and
    /// catching scans where the target surfaced as a *discovered* node rather
    /// than the seed). Each recalled entity is stamped with the current scan id
    /// (a first-class member of this scan's graph — so it counts as observed now
    /// and chains into future recalls), tagged
    /// [`RECALLED`](crate::core::tags::RECALLED), and carries its stored
    /// confidence; live modules merge onto it by uid.
    ///
    /// Bounded (`MAX_PRIOR_SCANS` scans, `MAX_ENTITIES` nodes, confidence-sorted
    /// so the caps drop the weakest leads first) to keep the working set sane on
    /// a 4 GB device. Best-effort: storage errors log and yield nothing rather
    /// than failing the scan.
    fn recall_prior_entities(
        &self,
        target: &Target,
        scan_id: &str,
        allow_live_sensors: bool,
    ) -> Vec<Entity> {
        use crate::core::entity::{EntityKind, Evidence, derive_uid, normalise};
        const MAX_PRIOR_SCANS: usize = 8;
        const MAX_ENTITIES: usize = 300;
        const VALUE_MATCH_CAP: usize = 64;

        // Order/case/punctuation-insensitive token-set key (pure-digit tokens
        // dropped) so a FullName seed survives the reformatting name parsing
        // applies to the stored Person anchor — case ("jordan meyers" vs the
        // stored title-cased "Jordan Meyers"), comma order ("Meyers, Jordan"),
        // and a trailing year ("Jordan Meyers 1987" → "Jordan Meyers"). Exact
        // equality on the sorted alphabetic tokens stays conservative: it never
        // conflates "John Smith" with "John A Smith" or a different name.
        fn token_set_key(s: &str) -> String {
            let lower = s.to_lowercase();
            let mut toks: Vec<&str> = lower
                .split(|c: char| !c.is_alphanumeric())
                .filter(|t| !t.is_empty() && !t.bytes().all(|b| b.is_ascii_digit()))
                .collect();
            toks.sort_unstable();
            toks.join(" ")
        }

        // Gather candidate scan-id lists from both recall paths, then flatten
        // into a recency-ordered, de-duplicated list (excluding this scan).
        let kind = target.kind.to_entity_kind();
        let seed_uid = derive_uid(&kind, &normalise(&kind, &target.value));
        let mut id_lists: Vec<Vec<String>> = Vec::new();
        match self.store.scan_ids_for_entity(&seed_uid) {
            Ok(ids) => id_lists.push(ids),
            Err(e) => warn!(scan_id, error = %e, "recall: seed history lookup failed"),
        }
        // Value-match fallback — catches scans where the target surfaced as a
        // discovered node, and rescues the FullName seed whose stored anchor was
        // reformatted (the seed_uid above derives from the raw, un-title-cased
        // input, so it misses for names). A Person seed matches on the token-set
        // key; exact-valued kinds keep strict case-insensitive equality (their
        // seed_uid path is already exact, and a looser key could mis-pull a
        // structurally-different value, e.g. reorder an email's tokens).
        let is_name = matches!(kind, EntityKind::Person);
        let key = |v: &str| -> String {
            if is_name {
                token_set_key(v)
            } else {
                v.trim().to_lowercase()
            }
        };
        let target_key = key(&target.value);
        // Search the digit-stripped token form for a name so a trailing year
        // can't defeat the all-tokens-required FTS match; the raw value otherwise.
        let search_q = if is_name {
            token_set_key(&target.value)
        } else {
            target.value.trim().to_string()
        };
        if !target_key.is_empty()
            && !search_q.is_empty()
            && let Ok(matches) = self.store.search_entities(&search_q, VALUE_MATCH_CAP)
        {
            for m in matches {
                if key(&m.value) == target_key
                    && let Ok(ids) = self.store.scan_ids_for_entity(&m.uid)
                {
                    id_lists.push(ids);
                }
            }
        }
        let mut prior: Vec<String> = Vec::new();
        let mut seen_scan: HashSet<String> = HashSet::new();
        for id in id_lists.into_iter().flatten() {
            if id != scan_id && seen_scan.insert(id.clone()) {
                prior.push(id);
            }
        }
        if prior.is_empty() {
            return Vec::new();
        }

        // Pull each relevant prior scan's entity graph, dedup-merging across
        // scans, then stamp/tag every node for this scan. `entities_filtered` with
        // an explicit `Some(MAX_ENTITIES)` limit bounds the pull to the top-N by
        // confidence IN SQL, so a heavily-scanned prior target can't make scan
        // start deserialise its entire historical graph on a 4 GB device. This is
        // lossless for the final result: the merged set is truncated to
        // `MAX_ENTITIES` anyway, and since the per-scan pull limit equals that cap
        // and the merge takes the MAX per-uid confidence, any entity below every
        // prior scan's top-N is provably below the merged top-N too. (The bound
        // was previously an internal `LIMIT` inside `entities_filtered`, removed
        // when that function's UI caller needed the unbounded set — this restores
        // it explicitly for recall.)
        let mut merged: HashMap<String, Entity> = HashMap::new();
        for pid in prior.into_iter().take(MAX_PRIOR_SCANS) {
            let ents = match self.store.entities_filtered(
                &pid,
                None,
                None,
                None,
                Some(MAX_ENTITIES),
            ) {
                Ok(e) => e,
                Err(e) => {
                    warn!(scan_id, prior = %pid, error = %e, "recall: prior entities load failed");
                    continue;
                }
            };
            for mut e in ents {
                // Noise gate: a purely live-sensor-derived entity (the operator's
                // own RF/network environment — Wi-Fi APs, ARP hosts, the device
                // GPS fix) must not be recalled into a scan that hasn't activated
                // the sensors. That would re-inject, from cache, exactly the
                // contamination the dispatch gate keeps out of fresh runs. A prior
                // recall may have stamped its own `recall` source onto the stored
                // node, so that pseudo-source is ignored: the entity is dropped
                // when EVERY remaining (real) source is a live-sensor module.
                if !allow_live_sensors {
                    let mut real = e
                        .evidence
                        .iter()
                        .map(|ev| ev.source.as_str())
                        .filter(|s| *s != "recall")
                        .peekable();
                    if real.peek().is_some() && real.all(|s| LOCAL_PASSIVE_MODULES.contains(&s)) {
                        continue;
                    }
                }
                e.scan_id = scan_id.to_string();
                e.tag(crate::core::tags::RECALLED);
                e.add_evidence(Evidence::new(
                    "recall",
                    "Recalled from the local intelligence database (prior scan)",
                ));
                if let Some(existing) = merged.get_mut(&e.uid) {
                    existing.merge(e);
                } else {
                    merged.insert(e.uid.clone(), e);
                }
            }
        }

        let mut out: Vec<Entity> = merged.into_values().collect();
        // A recalled node contributes ZERO corroboration. Recall re-injects
        // STORED data the database already counts, so re-persisting it must be
        // idempotent: with corroboration 0 the GREATEST-merge keeps the DB's
        // true count (`absorb` sums then floors at 1) instead of compounding it
        // every re-scan. A live module that re-discovers the entity this scan
        // still adds its own +1 on top. Applied AFTER the cross-scan dedup merge
        // above (which would otherwise floor a duplicate back up to 1).
        for e in &mut out {
            e.corroboration = 0;
        }
        // Confidence desc, then uid asc as a total, deterministic tie-break: `out`
        // comes from a HashMap (`merged.into_values()`, randomised order) and the
        // stable sort would otherwise leave equal-confidence entities — hence WHICH
        // survive the `truncate(MAX_ENTITIES)` boundary cut — in HashMap-iteration
        // order, leaking non-determinism into the persisted working set. This is the
        // same tie-break cmp_expansion_candidates / rank_enrichment_leverage use.
        out.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.uid.cmp(&b.uid))
        });
        out.truncate(MAX_ENTITIES);
        out
    }

    /// Active gap-fill — pursue the corroborating pathway AU-063 only names.
    ///
    /// After expansion, a single-route (fragile) identity link is a connection no
    /// independent pathway corroborates. AU-063 reports *which* orthogonal source
    /// family would confirm it; this runs the modules of that family on the gap
    /// endpoints to actually go and find the link. Confined to the missing
    /// families (not the endpoint's whole module graph), it seeks corroboration of
    /// an already-confirmed connection rather than chasing a graph-adjacent
    /// stranger's footprint — and it is bounded (a small probe cap, budget- and
    /// cancel-gated) and honours passive/free/exclude exactly as expansion does.
    /// New entities flow into finalise normally. Toggle: `feature.gap_fill` (ON).
    /// Returns the number of endpoints probed.
    #[allow(clippy::too_many_arguments)]
    async fn run_gap_fill(
        &self,
        scan_id: &str,
        seed: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        started: Instant,
        entity_map: &mut HashMap<String, Entity>,
        visited: &mut HashSet<(TargetKind, String)>,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
        relations: &mut Vec<Relation>,
    ) -> usize {
        const MAX_PROBES: usize = 8;

        if !crate::util::settings::get_bool(crate::util::settings::GAP_FILL_FEATURE, true) {
            return 0;
        }

        // A cancelled scan (operator stop OR the wall-time watchdog) must do NO
        // further collection — return before the snapshot + `derive_all` below,
        // which is itself super-linear on a large graph. Without this guard a
        // wall-timed-out `--full` scan paid a full gap-analysis derivation pass
        // AFTER its deadline, pushing finalise past any external timeout. The
        // per-probe loop already checks cancel, but the costly setup ran first.
        if ctx.cancel.is_cancelled() {
            return 0;
        }

        // The gap analysis needs the full relation graph the finaliser will build:
        // the in-flight lineage edges plus the structural edges derivable from the
        // current entity set. Derive once, off a snapshot.
        let ents: Vec<Entity> = entity_map.values().cloned().collect();
        let mut rels = relations.clone();
        rels.extend(crate::core::relation::derive_all(&ents, scan_id));

        let probes = crate::core::correlator::gap_fill_probes(&ents, &rels);
        if probes.is_empty() {
            return 0;
        }

        let by_uid: HashMap<&str, &Entity> = ents.iter().map(|e| (e.uid.as_str(), e)).collect();
        let mut before: HashSet<String> = HashSet::new();
        let mut probed = 0usize;

        for probe in probes {
            if probed >= MAX_PROBES
                || ctx.cancel.is_cancelled()
                || budget_check(opts, started, entity_map.len()).is_some()
            {
                break;
            }
            let Some(&ep) = by_uid.get(probe.endpoint_uid.as_str()) else {
                continue;
            };
            let Some(tk) = TargetKind::from_entity_kind(&ep.kind) else {
                continue;
            };
            let target = Target::new(tk, ep.value.clone());
            // Endpoints already expanded ran their whole module graph; the value is
            // in the gap endpoints the expansion gates held back.
            if visited.contains(&visit_key(&target)) {
                continue;
            }
            // Only the modules in the MISSING orthogonal families the operator
            // hasn't excluded — the corroboration-seeking set, classified by the
            // same `source_family` the gap analysis uses.
            let mut allow: Vec<String> = self
                .modules
                .iter()
                .filter(|m| {
                    let fam = crate::core::correlator::source_family(m.name());
                    probe.missing_families.contains(&fam)
                })
                .map(|m| m.name().to_string())
                .collect();
            if let Some(user_allow) = &opts.modules {
                allow.retain(|m| user_allow.contains(m));
            }
            if allow.is_empty() {
                continue;
            }

            let gap_opts = ScanOptions {
                modules: Some(allow),
                ..opts.clone()
            };

            before.clear();
            before.extend(entity_map.keys().cloned());
            {
                let cx = DispatchCx {
                    scan_id,
                    target: &target,
                    opts: &gap_opts,
                    is_expansion: true,
                    seed_kind: seed.kind,
                };
                let mut dstate = DispatchState {
                    entity_map: &mut *entity_map,
                    stats: &mut *stats,
                    dispatched: &mut *dispatched,
                };
                if let Err(e) = self.dispatch_target(&cx, ctx, &mut dstate).await {
                    warn!(scan_id, error = %e, "gap-fill dispatch failed (continuing)");
                }
            }
            // New entities this probe surfaced are derived from the gap endpoint.
            for (uid, child) in entity_map.iter() {
                if !before.contains(uid) {
                    relations.push(Relation::new(
                        uid.as_str(),
                        probe.endpoint_uid.as_str(),
                        RelationKind::DerivedFrom,
                        child.confidence,
                        scan_id,
                    ));
                }
            }
            visited.insert(visit_key(&target));
            probed += 1;
        }

        if probed > 0 {
            info!(
                scan_id,
                probed, "active gap-fill: probed gap endpoints for missing-family corroboration"
            );
        }
        probed
    }

    /// Drive the expansion loop. Returns the stop reason for diagnostics.
    ///
    /// Takes the mutable scan-wide accumulators as one [`ExpansionState`] *by
    /// value* and destructures it immediately, so the loop body below reads and
    /// mutates `entity_map`/`visited`/`stats`/`dispatched`/`relations`/
    /// `emitted_corr` by their plain names exactly as before — only the call
    /// signature is bundled. The `&mut` borrows are released to the caller when
    /// this returns.
    async fn run_expansion(
        &self,
        scan_id: &str,
        seed: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        started: Instant,
        state: ExpansionState<'_>,
    ) -> StopReason {
        let ExpansionState {
            entity_map,
            visited,
            stats,
            dispatched,
            relations,
            emitted_corr,
        } = state;
        // Reused across candidates to capture lineage: the set of entity UIDs
        // present *before* a candidate's dispatch, so new UIDs afterward are
        // children that candidate surfaced. Reusing the buffer avoids a
        // per-candidate allocation; the key clones are bounded by max_entities.
        let mut before: HashSet<String> = HashSet::new();
        for depth in 1..=opts.depth {
            // Refresh keys from the pool at the start of each round. Keys
            // discovered during the previous round (oathnet_pro breach data,
            // api_key_probe validation, web_crawler scraping) become available
            // to this round's modules automatically.
            hot_inject_keys(&mut ctx.keys);

            // Refresh SeekNow's per-round budget so it is utilised in EVERY
            // iteration (not just until a wide first round drains it). The
            // per-session ceiling still bounds total volume across all rounds.
            crate::core::hooks::refresh_round_budget();

            if ctx.cancel.is_cancelled() {
                let stop = StopReason::Cancelled;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                );
                return stop;
            }
            // ── Reconsideration: "return to old data when downstream adds
            // credibility" ──────────────────────────────────────────────────
            // Before selecting this round's candidates, re-run the free/offline
            // promotion passes over the WHOLE accumulated working set, so any
            // prior entity that the evidence gathered since now corroborates is
            // lifted in place (a corroboration tag + evidence → higher
            // `c_effective`) ABOVE the expansion floor and is therefore picked up
            // as a candidate THIS round — instead of that re-promotion only
            // happening at finalise (too late to expand it). This is the
            // autonomous mechanism that lets the scan come back to a lead it had
            // set aside once later rounds make it credible. Idempotent
            // (tag-guarded — a promotion never double-stamps across rounds) and
            // bounded by working-set size exactly like the live correlation pass,
            // so it can never itself stall a round.
            if entity_map.len() <= Self::INCREMENTAL_CORRELATE_MAX_ENTITIES {
                let mut snapshot: Vec<Entity> = entity_map.values().cloned().collect();
                // Multipath corroboration (AU-062) needs the STRUCTURAL relation
                // graph (BelongsToDomain / RegisteredBy / CoLocatedWith / …), not
                // just the lineage `DerivedFrom` edges accumulated so far — two
                // orthogonal, source-diverse pathways can't form from lineage
                // alone, so feeding only `relations` here left this promotion a
                // no-op until finalise (too late to expand the lead). Derive the
                // structural edges over the current snapshot and union with lineage
                // — the same in-flight full-graph build the gap-analysis pass uses
                // — so a lead corroborated by multiple independent routes is
                // actually re-promoted and expanded THIS round. Bounded: this arm
                // only runs at ≤ INCREMENTAL_CORRELATE_MAX_ENTITIES (400) entities.
                let mut round_relations = relations.clone();
                round_relations.extend(crate::core::relation::derive_all(&snapshot, scan_id));
                let promoted = promote_geo_corroborated_family(&mut snapshot)
                    + promote_multipath_corroborated(&mut snapshot, &round_relations)
                    + promote_breach_candidate_geo_corroborated(&mut snapshot);
                if promoted > 0 {
                    for e in snapshot {
                        entity_map.insert(e.uid.clone(), e);
                    }
                    debug!(
                        scan_id,
                        promoted,
                        round = depth,
                        "reconsidered prior data — re-promoted candidates on new downstream corroboration"
                    );
                }
            }
            // Snapshot the entity set at round start — entities discovered
            // during this round will be expansion candidates in the next round,
            // not this one.
            let entities_at_round_start = entity_map.len();
            // Round-start visibility: makes recursion legible in the standard log
            // (expansion decisions are otherwise emitted only as events).
            info!(
                scan_id,
                depth,
                working_set = entities_at_round_start,
                "expansion round started"
            );
            let has_paid = ctx.keys.contains_key("HUNTSMAN_OATHNET_KEY");
            // Each candidate carries the UID of the parent entity it was
            // derived from, so a `DerivedFrom` lineage edge can be recorded
            // for whatever new entities its dispatch surfaces.
            // Subject identity fingerprints for wrong-identity gating: the seed
            // itself plus every VERIFIED identity entity confirmed so far. A
            // discovered Username/Person that shares no name/handle overlap with
            // ANY of these — and is uncorroborated — is almost certainly a
            // different person, and pivoting on it pulls a stranger's whole
            // footprint into the scan (a real run chased `arizonambb` —
            // Arizona basketball — off an `jordanavery` seed). Rebuilt each
            // round so confirmed aliases widen the identity as the scan learns.
            // Only the wrong-identity gate consumes this, and that gate is
            // bypassed entirely under `--expand-all-identities`; skip the
            // per-round allocation + scan when it can't be read.
            let subject_identities: Vec<String> = if opts.expand_all_identities {
                Vec::new()
            } else {
                std::iter::once(seed.value.clone())
                    .chain(entity_map.values().filter_map(|e| {
                        use crate::core::entity::{Classification, EntityKind};
                        let is_identity = matches!(
                            e.kind,
                            EntityKind::Username | EntityKind::Person | EntityKind::Email
                        );
                        (is_identity && e.c_effective() >= Classification::VERIFIED_MIN)
                            .then(|| e.value.clone())
                    }))
                    .collect()
            };

            // At most one candidate per working-set entity survives the gates;
            // reserve up front so the push loop never re-grows on a large round.
            let mut next: Vec<(Target, f64, String)> = Vec::with_capacity(entity_map.len());
            // Seed identity normalised ONCE for the incidental-infra
            // candidate-is-seed check below; it is invariant across the whole
            // candidate loop, so computing `strip(&seed.value)` (a trim +
            // lowercasing allocation) per entity was pure repeated work.
            let strip = |s: &str| s.trim().trim_start_matches("www.").to_ascii_lowercase();
            let seed_stripped = strip(&seed.value);
            for entity in entity_map.values() {
                // Hoist the two pure-but-repeated scores: `c_effective()` is read
                // up to four times below (the floor check, the wrong-identity gate,
                // the strategy weight, the convex premium) and `source_count()`
                // twice. Computing each once per candidate trims redundant work in
                // the hottest expansion loop on the constrained target.
                let c_eff = entity.c_effective();
                if c_eff < opts.effective_min_expand_confidence() {
                    self.emit_excluded(scan_id, entity, "below_min_expand_confidence");
                    continue;
                }
                let source_count = entity.source_count();
                // Search-snippet recycling is the lowest-reliability discovery
                // path: a value scraped from the *text* of whatever page a search
                // engine returned for a recycled query — a Subway-directory
                // "Austin, Texas", an unrelated contact email on a scraped page.
                // At the relaxed deep/`--full` expansion floor these clear
                // `min_expand_confidence` on a single source, so without this gate
                // the recursion budget gets burned pivoting on strangers. The
                // wrong-identity gate below can't catch them: it only covers
                // Username/Person and is lifted entirely by
                // `--expand-all-identities`. Record the lead, but don't pivot
                // until a second, independent source corroborates it —
                // corroboration lifts `source_count` past 1 and the entity
                // expands normally on a later round.
                if entity.is_uncorroborated_recycled() {
                    self.emit_excluded(scan_id, entity, "uncorroborated_recycled");
                    continue;
                }
                // ROI bundle: convergence-pruning. Once an entity has 2+
                // corroborating sources at high confidence, further dispatch
                // only re-confirms what we already know. Skip it.
                if opts.max_roi && crate::core::roi::is_saturated(entity) {
                    self.emit_excluded(scan_id, entity, "roi_saturated");
                    continue;
                }
                // A kind with no external search target (Credential, Password,
                // DeviceId, TrackingId, Other) cannot be pivoted on. Previously
                // this was a silent `continue` — a black box. Record it so the
                // logs show exactly why the entity was not expanded.
                let Some(tk) = TargetKind::from_entity_kind(&entity.kind) else {
                    self.emit_excluded(scan_id, entity, "non_pivotable_kind");
                    continue;
                };
                // Speculative name-permutation gate — OPT-IN (`--gate-speculative`),
                // OFF by default. name_intel's `firstname.lastname@provider` /
                // handle guesses are frequently the subject's REAL identifiers, so
                // by default the scan EXPANDS and validates them (the whole point of
                // a name scan) — pivoting confirms which guesses are real. Only when
                // the operator opts in (expecting heavy namesake collision and
                // wanting a faster, tighter sweep) does an uncorroborated permutation
                // stay a recorded-but-not-pivoted candidate until a reliable source
                // confirms it. `--expand-all-identities` / `--full` force the
                // exhaustive sweep regardless.
                if opts.gate_speculative
                    && !opts.expand_all_identities
                    && entity.is_uncorroborated_name_permutation()
                {
                    self.emit_excluded(scan_id, entity, "uncorroborated_speculative");
                    continue;
                }
                // Wrong-identity gate: an uncorroborated, non-verified
                // Username/Person whose handle shares no overlap with the
                // subject's confirmed identity is a different person. Recording it
                // as a candidate is fine, but pivoting on it would search the web
                // for a stranger and import their footprint. Verified or
                // multi-source identities, and anything overlapping the subject,
                // still expand — so genuine aliases are never lost.
                if !opts.expand_all_identities
                    && crate::core::scan::is_wrong_identity_pivot(
                        &entity.kind,
                        c_eff,
                        source_count,
                        &entity.value,
                        &subject_identities,
                    )
                {
                    self.emit_excluded(scan_id, entity, "identity_mismatch");
                    continue;
                }
                // Never pivot on a non-routable / reserved / documentation IP
                // (e.g. 192.0.2.1 scraped from a tutorial page, or a private
                // 192.168.x surfaced by local sensors). No external OSINT source
                // can resolve these, so expanding them only burns whole rounds
                // on guaranteed-empty lookups and pollutes the graph with noise.
                if tk == TargetKind::IpAddress
                    && crate::core::validation::is_non_routable_ip(&entity.value)
                {
                    self.emit_excluded(scan_id, entity, "non_routable_ip");
                    continue;
                }
                // Don't deep-expand *incidentally-discovered* haystack
                // infrastructure — it maps a platform/CDN/provider's own estate,
                // not the subject, and burns the round budget that should go to
                // target-specific enrichment:
                //   • a non-central DOMAIN — a mega/social platform
                //     (twitter.com, …) or shared mail/DNS/registrar infra
                //     (sendgrid.net, secureserver.net, ns*.dnsmadeeasy.com), whose
                //     NS/MX/SOA fan out into dozens of generic provider domains;
                //   • a CDN-edge IP — a Cloudflare/Fastly anycast address whose
                //     reverse-IP lookup returns thousands of co-tenant strangers
                //     (a real scan pulled 480+ co-hosted domains through two).
                // Still expand when the candidate IS the seed (you're
                // investigating that property itself).
                {
                    let candidate_is_seed =
                        seed.kind == tk && seed_stripped == strip(&entity.value);
                    let is_incidental_infra = match tk {
                        // Freemail / social / shared CDN-DNS-registrar infra is
                        // never the subject's own estate — expanding it maps the
                        // provider, not the target. All consolidated in the
                        // core-side `is_noncentral_domain` (mega + infra lists,
                        // incl. freemail and ISP webmail) so the engine stays free
                        // of any `util` import (core → modules → util only).
                        TargetKind::Domain => {
                            crate::core::scan::is_noncentral_domain(&entity.value)
                        }
                        TargetKind::IpAddress => {
                            crate::core::validation::is_cdn_edge_ip(&entity.value)
                        }
                        _ => false,
                    };
                    if is_incidental_infra && !candidate_is_seed {
                        self.emit_excluded(scan_id, entity, "incidental_infra");
                        continue;
                    }
                }
                let new_target = Target::new(tk, entity.value.clone());
                let key = visit_key(&new_target);
                if visited.insert(key) {
                    let richness = self.graph.richness_for(tk);
                    // Strategy weight × a non-saturating corroboration prior.
                    // c_effective() clamps at 1.0, erasing the cross-correlation
                    // signal for confident pivots; re-apply it on the ranking so
                    // a lead confirmed by N independent sources is dispatched
                    // ahead of an equally-confident single-source lead (its
                    // dispatch is likelier to yield genuine children).
                    let mut weight = crate::core::scan::expansion_weight_for_strategy(
                        opts.expansion_strategy,
                        tk,
                        c_eff,
                        &entity.value,
                        has_paid,
                        richness,
                    ) * crate::core::scan::corroboration_prior(source_count);
                    // Convex (optionality / barbell) budget allocation, opt-in:
                    // multiply by a convexity premium for heavy-tailed upside over
                    // per-kind dispatch cost, so the bounded budget favours cheap,
                    // high-optionality identity leads over saturated infrastructure.
                    // Neutral (×≈1) for the confident cheap core, so it only
                    // re-sorts the uncertain tail and the expensive infra.
                    if opts.convex_budget {
                        weight *= crate::core::convex::optionality_multiplier(
                            tk,
                            source_count,
                            c_eff,
                            richness,
                        );
                    }
                    // Geo-corroboration bonus: entities confirmed by anchoring
                    // geo sources (self-reported address, photo GPS, registry
                    // address, person-enrichment location) rank slightly ahead
                    // of equal-weight entities with no person-anchored geo
                    // signal. Each anchoring geo source contributes +2%, capped
                    // at +10%, keeping the bonus sub-dominant to the confidence
                    // and corroboration factors.
                    let anchoring_geo_count = entity
                        .corroborating_sources()
                        .into_iter()
                        .filter(|s| crate::core::correlator::is_anchoring_geo_source(s))
                        .count();
                    if anchoring_geo_count > 0 {
                        weight *= 1.0 + (anchoring_geo_count as f64 * 0.02).min(0.10);
                    }
                    // Social-profile URL priority boost: a confirmed social-profile
                    // URL crawl can complete the tracking-ID co-ownership pivot.
                    // +15% nudges these above generic domain/IP targets at equal
                    // confidence so the crawl fires within the wall-clock budget.
                    // Sub-dominant to confidence and corroboration factors.
                    if tk == TargetKind::Url && entity.has_tag("social-profile") {
                        weight *= 1.15;
                    }
                    next.push((new_target, weight, entity.uid.clone()));
                } else {
                    // This exact target was already dispatched (or queued) this
                    // scan. Skipping it prevents an infinite pivot cycle, but the
                    // decision must be visible rather than a silent drop.
                    self.emit_excluded(scan_id, entity, "already_dispatched_this_scan");
                }
            }

            // Sort expansion candidates by weighted score (descending), with a
            // DETERMINISTIC total tie-break. The weight combines geo_npv with
            // entity confidence and dampens generic mega-domains. `next` is built
            // by iterating a HashMap (random per-process seed), so without a
            // tie-break two equal-weight candidates sorted Equal would keep that
            // non-deterministic input order — and the ROI `truncate(keep)` below
            // would then drop a DIFFERENT candidate run-to-run, making the very
            // results non-reproducible (Determinism Requirement). Breaking ties by
            // (kind, value) gives identical inputs an identical dispatch order.
            next.sort_by(cmp_expansion_candidates);

            // ROI bundle: top-K gate + relative knee. Keep the leading
            // candidates by weight (budget-bounded via top-K, scaled with
            // concurrency) AND drop the long tail that sorts far below this
            // round's best lead (quality-bounded via the knee). Stops both
            // a flood of low-weight domains from a single SERP and the
            // dampened mega-domain noise that survives top-K on a thin round.
            if opts.max_roi {
                apply_roi_cutoff(&mut next, visited, opts.max_concurrent);
            }
            let dispatched_this_round = next.len();
            // Round-selection digest: how many working-set entities were weighed vs
            // how many survived the gates and will actually be re-dispatched. The
            // gap is the pruning (below-floor / wrong-identity / already-dispatched
            // / ROI-cut), so a round that dispatches 0 of N is visibly a pruned
            // round, not a stalled one. Counts only (PII-free).
            info!(
                scan_id,
                depth,
                considered = entities_at_round_start,
                dispatched = dispatched_this_round,
                "expansion round selection"
            );
            let next: Vec<(Target, String)> = next.into_iter().map(|(t, _, p)| (t, p)).collect();

            if next.is_empty() {
                let stop = StopReason::NoMoreCandidates;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: stop.label(),
                    },
                );
                return stop;
            }

            self.emit(
                scan_id,
                EventKind::ExpansionTick {
                    depth,
                    queued: next.len(),
                    visited: visited.len(),
                },
            );

            for (nt, parent_uid) in &next {
                if ctx.cancel.is_cancelled() {
                    let stop = StopReason::Cancelled;
                    self.emit(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    );
                    return stop;
                }
                if let Some(stop) = budget_check(opts, started, entity_map.len()) {
                    self.emit(
                        scan_id,
                        EventKind::ExpansionStop {
                            reason: stop.label(),
                        },
                    );
                    return stop;
                }
                // Snapshot UIDs before dispatch so we can attribute the
                // entities this candidate surfaces back to its parent.
                before.clear();
                before.extend(entity_map.keys().cloned());
                {
                    // Re-borrow the mutable accumulator trio into a
                    // `DispatchState` for this candidate; the block scopes the
                    // borrows so the lineage attribution below is free to read
                    // `entity_map` again.
                    let cx = DispatchCx {
                        scan_id,
                        target: nt,
                        opts,
                        is_expansion: true,
                        seed_kind: seed.kind,
                    };
                    let mut dstate = DispatchState {
                        entity_map: &mut *entity_map,
                        stats: &mut *stats,
                        dispatched: &mut *dispatched,
                    };
                    if let Err(e) = self.dispatch_target(&cx, ctx, &mut dstate).await {
                        // Per-target dispatch errors are already surfaced as
                        // ModuleError events; we keep going through the round.
                        warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
                    }
                }
                // Record a DerivedFrom edge for every entity newly created by
                // this candidate's dispatch (merges into existing entities are
                // not "new" and are skipped, avoiding cross-round edge spam).
                // Direction is child -> parent: the new entity (`uid`) was
                // *derived from* the parent it was expanded out of (`parent_uid`),
                // matching the `DerivedFrom` edge name.
                for (uid, child) in entity_map.iter() {
                    if !before.contains(uid) {
                        relations.push(Relation::new(
                            uid.as_str(),
                            parent_uid.as_str(),
                            RelationKind::DerivedFrom,
                            child.confidence,
                            scan_id,
                        ));
                    }
                }
            }

            // ROI bundle: adaptive-depth termination. After the round,
            // measure new-entities-per-dispatched-target; if below floor,
            // stop early. Marginal yield collapses near convergence.
            let new_this_round = entity_map.len().saturating_sub(entities_at_round_start);

            // Round-boundary durability + live correlation from one snapshot:
            // checkpoint the freshly-grown graph to storage so a crash here
            // preserves everything through this round, then re-evaluate the
            // entity rules and stream any newly-fired correlations. Gated on
            // dispatch activity — a round that dispatched nothing cannot have
            // changed the graph, so we skip both passes (backpressure).
            if dispatched_this_round > 0 {
                // Address→Coords pass: any new Address entities this round may
                // name a known city; derive Coordinates before the snapshot so
                // AU-052/053 can correlate them immediately.
                for derived in address_to_coords_pass(entity_map, scan_id) {
                    let mut d = derived;
                    enrich_geospatial(&mut d);
                    if let Some(existing) = entity_map.get_mut(&d.uid) {
                        existing.merge(d);
                    } else {
                        entity_map.insert(d.uid.clone(), d);
                    }
                }
                let snapshot: Vec<Entity> = entity_map.values().cloned().collect();
                self.checkpoint_entities(scan_id, &snapshot);
                self.correlate_incremental(scan_id, &snapshot, emitted_corr);
            }

            let floor = opts
                .effective_min_marginal_yield()
                .unwrap_or(crate::core::roi::DEFAULT_MIN_MARGINAL_YIELD);
            if crate::core::roi::should_terminate_adaptive(
                opts.max_roi,
                new_this_round,
                dispatched_this_round,
                floor,
            ) {
                let stop = StopReason::NoMoreCandidates;
                self.emit(
                    scan_id,
                    EventKind::ExpansionStop {
                        reason: format!(
                            "adaptive-depth: marginal yield {:.2} < floor {:.2}",
                            crate::core::roi::marginal_yield(new_this_round, dispatched_this_round),
                            floor
                        ),
                    },
                );
                return stop;
            }
        }
        StopReason::DepthExhausted
    }
}

// ---------------------------------------------------------------------------
// Per-target module dispatch — sequential and concurrent paths.
//
// `ScanEngine::dispatch_target` chooses between:
//   * `dispatch_target_sequential` — `opts.max_concurrent == 0`,
//     Best on low-power Termux devices.
//   * `dispatch_target_concurrent` — `opts.max_concurrent > 0`, up to N
//     modules in flight via `tokio::sync::Semaphore + JoinSet`.
//
// Both paths share `module_skip_reason` for the
// allowlist/exclude/free_only/passive_only filter so the event payloads
// stay identical regardless of dispatch mode.
// ---------------------------------------------------------------------------

/// Modules that legitimately consume private IPs / local domains —
/// sensor modules that run against the local network. Universal
/// preflight (private-IP / local-domain rejection) skips these.
///
/// Re-exposed at `pub(crate)` because `hse radar` drives the same
/// set on every sweep — single source of truth, so adding a new
/// sensor module here both bypasses preflight AND joins the radar
/// loop in one edit.
pub(crate) const LOCAL_PASSIVE_MODULES: &[&str] = &[
    "device_sensors",
    "wifi_intel",
    "cell_intel",
    "local_net",
    "signal_radar",
];

/// Run the authoritative finalise-time correlation pass under a panic guard.
///
/// Returns `Some(firings)` on success (the caller emits `CorrelationFound` +
/// `CorrelationsDone`), or `None` when the pass returned an error OR **panicked**
/// — in which case the caller skips emission but `finalise_scan` still proceeds
/// to `ScanComplete` and the key-pool restoration that follow.
///
/// The live incremental pass already wraps `correlate_entities` in `catch_unwind`
/// (`correlate_incremental`), but the finalise pass ran `Correlator::run`
/// unguarded: a rule panicking on adversarial persisted data (a slice-index bug
/// over a crafted entity) would unwind the entire finalise block, losing the
/// terminal `ScanComplete` event AND the API-key pool the scan harvested. This
/// closes that asymmetry — a caught panic degrades to "no finalise correlations,"
/// exactly as the live pass does. Pure control-flow wrapper; unit-tested with a
/// deliberately panicking closure.
fn guarded_finalise_correlation(
    scan_id: &str,
    run: impl FnOnce() -> crate::core::error::Result<Vec<crate::core::correlator::Correlation>>,
) -> Option<Vec<crate::core::correlator::Correlation>> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(run)) {
        Ok(Ok(firings)) => Some(firings),
        Ok(Err(e)) => {
            warn!(scan_id, error = %e, "correlator failed");
            None
        }
        Err(_) => {
            warn!(
                scan_id,
                "finalise correlation pass panicked — scan still completes, finalise correlations skipped"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests;
