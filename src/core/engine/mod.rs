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
mod health;
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
    rank_autonomous_targets, rank_enrichment_leverage, rank_identity_aware_targets,
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
    apply_roi_cutoff, budget_check, cmp_expansion_candidates, correlation_key,
    expansion_confidence, visit_key,
};
use timeout::resolve_timeout;
// Used only by the dispatch-related tests retained in this file.
#[cfg(test)]
use crate::core::module::ModuleCost;

use crate::core::{
    dependency::ModuleGraph,
    entity::Entity,
    error::{Error, Result},
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

/// The scan-wide working entity set, wrapping `HashMap<String, Entity>` to
/// track which UIDs were inserted or mutated since the last
/// [`take_dirty`](Self::take_dirty) call.
///
/// Every expansion round used to checkpoint the WHOLE accumulated entity set
/// to storage, every round with dispatch activity — round 50 re-persisted
/// round 1's untouched entities all over again, making the per-round
/// checkpoint cost grow with total accumulated entities, not with what that
/// round actually changed. `take_dirty()` lets the round loop persist only
/// what changed since the last checkpoint instead.
///
/// Only the two mutating operations the engine actually performs on the
/// working set (`insert`, `get_mut`) are wrapped, so dirty-tracking can never
/// be forgotten at a call site — every existing `get_mut` in this engine
/// already writes through the returned reference (verified: none are used
/// read-only), so marking dirty unconditionally on a successful lookup is
/// exactly right for the current call sites, and merely conservative (never
/// incorrect) for a hypothetical future read-only one. Read-only access
/// (`.values()`, `.len()`, `.get()`, `.contains_key()`, iteration, …) goes
/// through [`Deref`](std::ops::Deref) to the inner map, unrestricted — live correlation
/// (`correlate_incremental`) still reads the FULL working set every round,
/// which is correct: a correlation rule can legitimately relate an entity
/// from round 1 to one from round 5, so narrowing correlation's input to
/// only the dirty subset would silently miss cross-round correlations. Only
/// the checkpoint's PERSISTENCE volume is narrowed here, never correlation's
/// input, and never what any reader sees.
struct TrackedEntityMap {
    map: HashMap<String, Entity>,
    dirty: HashSet<String>,
}

impl TrackedEntityMap {
    #[cfg(test)]
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            dirty: HashSet::new(),
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            dirty: HashSet::new(),
        }
    }

    fn insert(&mut self, uid: String, entity: Entity) -> Option<Entity> {
        self.dirty.insert(uid.clone());
        self.map.insert(uid, entity)
    }

    fn get_mut(&mut self, uid: &str) -> Option<&mut Entity> {
        // Single lookup (previously `contains_key` + `get_mut`, hashing the
        // key twice on this hot path): only mark dirty on an actual hit.
        let entity = self.map.get_mut(uid)?;
        self.dirty.insert(uid.to_string());
        Some(entity)
    }

    /// Snapshot every entity inserted or mutated since the last call (or
    /// since construction), clearing dirty-tracking. Empty if nothing
    /// changed — the caller should skip an empty-result checkpoint exactly
    /// as it already skips one on a round with no dispatch activity.
    fn take_dirty(&mut self) -> Vec<Entity> {
        // `drain()`, not `mem::take()`: this runs once per round, and
        // `mem::take` would drop the HashSet's backing allocation and force
        // a fresh one on every round's subsequent inserts. `drain()` clears
        // the set while keeping its capacity for reuse.
        self.dirty
            .drain()
            .filter_map(|uid| self.map.get(&uid).cloned())
            .collect()
    }

    /// Unwrap into the plain map for the one-time final flush
    /// (`finalise_scan` persists everything unconditionally, dirty or not,
    /// so it has no use for dirty-tracking).
    fn into_inner(self) -> HashMap<String, Entity> {
        self.map
    }
}

impl std::ops::Deref for TrackedEntityMap {
    type Target = HashMap<String, Entity>;

    fn deref(&self) -> &HashMap<String, Entity> {
        &self.map
    }
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
    entity_map: &'a mut TrackedEntityMap,
    visited: &'a mut HashSet<(TargetKind, String)>,
    stats: &'a mut ModuleStats,
    dispatched: &'a mut DispatchLog,
    relations: &'a mut Vec<Relation>,
    emitted_corr: &'a mut HashSet<String>,
    /// Modules quarantined for this scan by capability-aware dispatch (empty
    /// unless enabled on the comprehensive fan-out) — carried here so every
    /// expansion round's `DispatchCx` borrows the one set computed at scan start,
    /// without widening `run_expansion`'s argument list.
    quarantined: &'a HashSet<String>,
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
        // Regional augmentation is on when EITHER the per-scan flag
        // (`--regional`) is set OR the persistent default `feature.regional`
        // is on (universal toggleability; default off ⇒ geolocation-neutral
        // queries). Computed here, before `scan` moves into the inner call, so
        // it can be captured into the `with_regional` ambient below — a per-
        // scan task-local (PROBLEM_TREE T2.11), not the process-global
        // `search_engines` used to read, which `hse serve`'s concurrent scans
        // could silently flip for each other.
        let regional_on = scan.options.regional_search
            || crate::util::settings::get_bool("feature.regional", false);
        crate::util::found_keys::with_scan(
            sid,
            crate::util::regional::with_regional(
                regional_on,
                self.run_with_ledger_inner(scan, target, ctx, dispatched),
            ),
        )
        .await
    }

    /// Panic-safe wrapper around [`run`](Self::run): a panic anywhere in the
    /// scan-dispatch path (not just inside a module's `process()`, which
    /// `run_module_guarded` already contains — see `dispatch::run_module_guarded`)
    /// is caught here, the scan is force-marked `Failed` and persisted, and the
    /// panic is surfaced as an `Err` instead of unwinding into the caller's
    /// spawned task and leaving the scan permanently stuck `Running`.
    ///
    /// Wrapping at this single top-level choke point (rather than each of the
    /// three separate dispatch call sites — `dispatch_target_sequential`,
    /// `run_paid_phase`/`spawn_free_phase` inside `dispatch_target_concurrent`)
    /// avoids whack-a-mole: every path through the engine funnels through `run`/
    /// `run_with_ledger`, so this guarantees no detached scan is ever left stuck
    /// regardless of where inside the engine a panic originates. CLI callers
    /// (`hse scan`/`hse radar`/`hse provision`) deliberately keep using the plain
    /// `run`/`run_with_ledger` methods — a panic there gives the operator direct
    /// terminal feedback already, so the extra persistence work is unnecessary.
    pub async fn run_panic_safe(
        &self,
        scan: Scan,
        target: Target,
        ctx: ModuleContext,
    ) -> Result<Scan> {
        use futures::FutureExt;
        let scan_id = scan.id.clone();
        match std::panic::AssertUnwindSafe(self.run(scan, target, ctx))
            .catch_unwind()
            .await
        {
            Ok(result) => result,
            Err(payload) => Err(self.force_fail_panicked_scan(&scan_id, &payload)),
        }
    }

    /// Panic-safe wrapper around [`run_with_ledger`](Self::run_with_ledger) —
    /// see [`run_panic_safe`](Self::run_panic_safe) for the rationale. Used by
    /// `LiveScanner`'s detached poll loop, which owns a persistent ledger across
    /// iterations.
    pub async fn run_with_ledger_panic_safe(
        &self,
        scan: Scan,
        target: Target,
        ctx: ModuleContext,
        dispatched: &mut DispatchLog,
    ) -> Result<Scan> {
        use futures::FutureExt;
        let scan_id = scan.id.clone();
        match std::panic::AssertUnwindSafe(self.run_with_ledger(scan, target, ctx, dispatched))
            .catch_unwind()
            .await
        {
            Ok(result) => result,
            Err(payload) => Err(self.force_fail_panicked_scan(&scan_id, &payload)),
        }
    }

    /// Force-marks `scan_id` `Failed` and persists it, then returns an `Error`
    /// carrying the panic message. Best-effort: if the store read/write itself
    /// fails, the scan record is left as-is (still better than panicking again
    /// inside a panic handler) and only a warning is logged.
    fn force_fail_panicked_scan(
        &self,
        scan_id: &str,
        payload: &Box<dyn std::any::Any + Send>,
    ) -> Error {
        let msg = dispatch::panic_payload_to_string(payload);
        warn!(scan_id = %scan_id, %msg, "scan dispatch panic contained — force-marking scan Failed");
        if let Ok(Some(mut persisted)) = self.store.get_scan(scan_id) {
            persisted.status = ScanStatus::Failed;
            persisted.error = Some(format!("panicked: {msg}"));
            persisted.finished_at = Some(crate::core::entity::unix_now());
            if let Err(e) = self.store.upsert_scan(&persisted) {
                warn!(scan_id = %scan_id, error = %e, "failed to persist panic-failed scan record");
            }
        }
        Error::module("engine", format!("scan panicked: {msg}"))
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
        // The regional-search ambient is already established by
        // `run_with_ledger` (the caller), which wraps this whole function's
        // future in `util::regional::with_regional` — nothing to do here.

        // Keep the validated egress proxy pool healthy: pull operator-configured
        // published feeds and re-probe due proxies so a dead proxy is evicted
        // before it can make a resource unreachable. Detached (never blocks the
        // scan) and internally throttled; not spawned at all when no proxy/feed
        // is configured, so a proxy-less deployment pays nothing.
        if crate::util::egress::pool_is_configured()
            || std::env::var(crate::util::egress::PROXY_FEEDS_ENV).is_ok()
        {
            tokio::spawn(async {
                let (fed, ok) = crate::util::egress::refresh_pool().await;
                if fed > 0 || ok > 0 {
                    tracing::debug!(fed, validated_ok = ok, "egress proxy pool refreshed");
                }
            });
        }

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

        // ─── Capability-aware dispatch: quarantine provably-dead modules ────
        // Skip modules whose parser has gone dead (persistent hard failures or
        // silent zero-yield drift, from the cross-scan health log — see
        // `util::scraper_health`) so the comprehensive fan-out spends its
        // bounded budget on sources that still work. Gated so it only culls the
        // AUTOMATIC sweep: a scan that pinned an explicit module allowlist, or
        // `hse scan --full` (both clear `skip_dead_modules`), runs exactly what
        // the operator asked for. Computed once per scan and borrowed by every
        // round's `DispatchCx`. Self-recovering — a module drops out the instant
        // it emits one healthy result. A health-read error never fails the scan
        // (falls back to an empty set = no quarantine). On a fresh DB the event
        // log is empty, so the set is empty and dispatch is unchanged.
        let quarantined: HashSet<String> = if opts.skip_dead_modules && opts.modules.is_none() {
            use crate::util::scraper_health::{
                RECENT_EVENTS_WINDOW, aggregate_source_health, quarantined_modules,
            };
            self.store
                .recent_module_outcome_events(RECENT_EVENTS_WINDOW)
                .map(|evs| quarantined_modules(&aggregate_source_health(&evs)))
                .unwrap_or_default()
        } else {
            HashSet::new()
        };
        if !quarantined.is_empty() {
            info!(
                scan_id = %scan.id,
                quarantined = quarantined.len(),
                "capability-aware dispatch: skipping modules with persistent drift this scan"
            );
        }

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

        let mut entity_map: TrackedEntityMap =
            TrackedEntityMap::with_capacity(opts.max_entities.unwrap_or(256).min(4096));
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
            let cx = DispatchCx {
                scan_id: &scan.id,
                target: &target,
                opts: &opts,
                is_expansion: false,
                seed_kind: target.kind,
                quarantined: &quarantined,
            };
            // Seed dispatch has no parent to attribute lineage to, so the
            // new-uid buffer is write-only here and discarded.
            let mut seed_newly_inserted: Vec<String> = Vec::new();
            let mut dstate = DispatchState {
                entity_map: &mut entity_map,
                stats: &mut stats,
                dispatched: &mut *dispatched,
                newly_inserted: &mut seed_newly_inserted,
            };
            if let Err(e) = self.dispatch_target(&cx, &mut ctx, &mut dstate).await {
                warn!(scan_id = %scan.id, error = %e, "seed dispatch failed (continuing to finalise)");
            }
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

        // Checkpoint the seed round's dirty entities (everything inserted so
        // far — nothing has been checkpointed yet, so this is every entity
        // the seed round produced) and correlate from a full snapshot: the
        // entities are made durable before expansion begins (crash-safety) and
        // single-round (depth=0) scans stream correlations live rather than
        // waiting for finalise. Correlation reads the FULL working set (not
        // just the dirty subset) — see [`TrackedEntityMap`]'s doc for why.
        let mut seed_dirty: Vec<Entity> = entity_map.take_dirty();
        self.checkpoint_entities(&scan.id, &mut seed_dirty);
        let seed_snapshot: Vec<Entity> = entity_map.values().cloned().collect();
        self.correlate_incremental(&scan.id, &seed_snapshot, &mut emitted_corr);

        if opts.depth > 0 {
            let est = ExpansionState {
                entity_map: &mut entity_map,
                visited: &mut visited,
                stats: &mut stats,
                dispatched: &mut *dispatched,
                relations: &mut lineage,
                emitted_corr: &mut emitted_corr,
                quarantined: &quarantined,
            };
            let _ = self
                .run_expansion(&scan.id, &target, &mut ctx, &opts, started, est)
                .await;

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
                    &quarantined,
                )
                .await;

            // Final bulk breach query — the last leg. Everything above has run,
            // so the plan is compiled from the whole graph the recursion built
            // rather than from the seed alone. Bounded, cancel-aware, toggle-
            // gated, and restricted to the breach corpora; any new entities flow
            // into finalise below.
            let _ = self
                .run_breach_sweep(
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
                    &quarantined,
                )
                .await;
        }

        // Grade the breach corpus and record the autonomous verdict. Outside the
        // depth gate on purpose: the sweep is collection and needs the recursion
        // to have run, but the audit is pure grading of evidence already held —
        // a depth-0 scan whose seed round hit two corpora with contradictory
        // dates of birth needs that verdict just as much as a deep one.
        self.run_consensus_audit(&scan.id, &mut entity_map);

        // Scan body done — stop the wall-time watchdog so it can't fire after
        // we've already finished (and is reaped promptly rather than sleeping
        // out its full deadline in the background on a long-lived `serve`).
        if let Some(handle) = wall_watchdog {
            handle.abort();
        }

        let outcome = self
            .finalise_scan(
                scan,
                entity_map.into_inner(),
                &ctx,
                stats,
                lineage,
                emitted_corr,
            )
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
        let scan = tokio::task::spawn_blocking(move || -> Result<Scan> {
            // Mint ApiKey entities for every FOREIGN key identified in this scan's
            // endpoint responses, run the finalise-time offline enrichment passes,
            // then persist the batch (falling back to per-entity upserts on a
            // rolled-back transaction) — see each phase helper's own doc comment.
            let mut entities = merge_found_keys_and_flatten(&scan.id, entity_map);
            apply_finalise_enrichment_passes(store.as_ref(), &scan.id, &mut entities);
            let total = entities.len();
            let (persisted, first_err) =
                persist_entities_with_fallback(store.as_ref(), &scan.id, &entities);
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

            // Derive + persist the typed entity-relation edges (attribution
            // graph), then run the authoritative finalise-time correlation pass
            // over the persisted scan — see each phase helper's own doc comment.
            derive_and_persist_relations(store.as_ref(), &scan.id, &entities, &lineage_relations);
            run_finalise_correlation_and_emit(&store, &emitter, &scan.id, &mut emitted_corr);

            // Cross-scan pathway-template learning (C1 universal linking), then
            // the corroboration-boost feedback pass, then end-of-scan
            // housekeeping — see each phase helper's own doc comment.
            let xscan_boost = learn_cross_scan_pathway_templates(
                store.as_ref(),
                &emitter,
                &scan.id,
                &mut emitted_corr,
            );
            apply_corroboration_boosts(store.as_ref(), &scan.id, &mut entities, &xscan_boost);
            run_finalise_housekeeping(store.as_ref(), &scan.id);

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
        .map_err(|e| crate::core::error::Error::Other(e.to_string()))??;

        // Fire the operator's completion webhook, if one was configured via
        // `HUNTSMAN_WEBHOOK_URL` / `ScanOptions`. The URL was already threaded into
        // `scan.options.webhook_url` by the CLI/live paths, but the POST itself was
        // never wired — so a configured webhook silently never fired. This closes
        // that gap. It must run HERE (in the async context after the blocking
        // finalise), because `notify_scan_complete` is async and the finalise above
        // runs inside `spawn_blocking`. Fire-and-forget: the helper is bounded to a
        // 10 s timeout and never returns an error, so a slow or dead endpoint can't
        // stall or fail the scan. Fires for every terminal state (complete /
        // aborted / failed); the `status` field distinguishes them.
        if let Some(url) = scan.options.webhook_url.as_deref() {
            let correlations_count = self
                .store
                .correlations_for_scan(&scan.id)
                .map_or(0, |c| c.len());
            crate::core::webhook::notify_scan_complete(
                &ctx.http,
                url,
                &crate::core::webhook::WebhookPayload {
                    scan_id: &scan.id,
                    target_kind: scan.target.kind.canonical_str(),
                    target_value: &scan.target.value,
                    entity_count: scan.entity_count,
                    status: scan.status.as_str(),
                    correlations_count,
                },
            )
            .await;
        }
        Ok(scan)
    }

    /// Working-set ceiling for the LIVE incremental correlation pass. Above this,
    /// the per-round streaming pass is deferred to the authoritative finalise pass
    /// (which is wall-clock-bounded) so a large recalled / breach-heavy graph can't
    /// make a single round run for seconds and present as a frozen scan. Generous:
    /// a normal scan stays well under it and streams correlations live every round;
    /// only a pathologically large set defers. Larger than a typical scan's entity
    /// count so live streaming is the norm, not the exception.
    const INCREMENTAL_CORRELATE_MAX_ENTITIES: usize = 400;

    /// Expansion depth-decay base (see `feature.depth_decay`): each generation
    /// away from the seed multiplies an entity's *expansion* confidence by this
    /// factor — gen 1 ×0.75, gen 2 ×0.56, gen 3 ×0.42. Combined with the default
    /// 0.20 expansion floor this sets a genuine depth horizon: a gen-3 lead
    /// needs raw c_eff ≥ 0.20/0.75³ ≈ 0.47 to keep expanding, so a deep chain
    /// must be well-corroborated to continue while seed-adjacent leads are
    /// untouched (gen 0 ×0.75⁰ = ×1). Only consulted when the opt-in policy is
    /// on; the stored/displayed confidence and every correlation/gate that reads
    /// plain `c_effective` are never touched.
    const DEPTH_DECAY_BASE: f64 = 0.75;

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
    ///
    /// Determinism: normalises each entity's evidence/tags ordering before
    /// persist, same as the finalise path (see `Entity::canonicalize_order`).
    /// Without this, a scan interrupted after reaching a checkpoint — routine
    /// on Termux/Android — reads back through `entities_for_scan`'s normal
    /// table path, which (unlike the empty-table event-log recovery path)
    /// never canonicalises, so concurrent dispatch's completion-order merging
    /// would otherwise leak into the checkpointed/exported result.
    fn checkpoint_entities(&self, scan_id: &str, entities: &mut [Entity]) {
        if entities.is_empty() {
            return;
        }
        for e in entities.iter_mut() {
            e.canonicalize_order();
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
        // scans, then stamp/tag every node for this scan. `entities_filtered`
        // (not `entities_for_scan`) bounds the pull: it applies a SQL `LIMIT` on
        // the confidence-DESC preorder and skips the Rust relevance re-sort —
        // both wasted here, since recall confidence-sorts and caps the merged
        // set anyway. So a heavily-scanned prior target can't make scan start
        // deserialise its entire historical graph on a 4 GB device.
        let mut merged: HashMap<String, Entity> = HashMap::new();
        for pid in prior.into_iter().take(MAX_PRIOR_SCANS) {
            let ents = match self.store.entities_filtered(&pid, None, None, None) {
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
                // Stale-admission gate: a role/provider mailbox (`dns@cloudflare.com`,
                // `abuse@jomax.net`, …) is never minted as a first-class Email entity
                // by a FRESH scan — every emitter (dns_intel's SOA-admin path, whois,
                // ripestat, search_engines) already refuses it at admission, because
                // the address is a shared registrar/DNS/CDN desk, not the subject's
                // identity. But recall bypasses that admission gate entirely: it
                // replays whatever the database already holds, so a role mailbox
                // admitted under an OLDER/laxer version of the code (or discovered by
                // a since-removed module) is resurrected forever, and — because the
                // SAME literal address is shared across millions of unrelated
                // domains — accumulates "Zone admin for X" evidence from every
                // unrelated domain this project has ever scanned, ballooning into a
                // VERIFIED, breach-tagged phantom (a live `see-know.xyz` scan
                // recalled `dns@cloudflare.com` at corroboration=396, sourced from 90+
                // domains with no connection to the scan target). A fresh scan will
                // re-discover the CURRENT domain's own admin contact anyway with a
                // clean single evidence bullet, so nothing is lost by refusing to
                // recall the polluted historical node.
                if e.kind == EntityKind::Email && crate::core::validation::is_role_mailbox(&e.value)
                {
                    continue;
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
            // Recalled prior-scan knowledge is injected BEFORE the seed round —
            // it is pre-existing background context, generation 0 of this scan,
            // not something this scan's expansion reached. (The stored value was
            // relative to a DIFFERENT scan's seed, so it is meaningless here.) A
            // live module that re-discovers the entity deeper this scan still
            // keeps 0, since merge preserves the earliest generation.
            e.generation = 0;
        }
        // Confidence desc, then uid asc as a total, deterministic tie-break: `out`
        // comes from a HashMap (`merged.into_values()`, randomised order) and the
        // stable sort would otherwise leave equal-confidence entities — hence WHICH
        // survive the `truncate(MAX_ENTITIES)` boundary cut — in HashMap-iteration
        // order, leaking non-determinism into the persisted working set. This is the
        // same tie-break cmp_expansion_candidates / rank_enrichment_leverage use.
        rank_recalled_and_cap(out, MAX_ENTITIES)
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
        entity_map: &mut TrackedEntityMap,
        visited: &mut HashSet<(TargetKind, String)>,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
        relations: &mut Vec<Relation>,
        quarantined: &HashSet<String>,
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
        let mut newly_inserted: Vec<String> = Vec::new();
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

            newly_inserted.clear();
            {
                let cx = DispatchCx {
                    scan_id,
                    target: &target,
                    opts: &gap_opts,
                    is_expansion: true,
                    seed_kind: seed.kind,
                    quarantined,
                };
                let mut dstate = DispatchState {
                    entity_map: &mut *entity_map,
                    stats: &mut *stats,
                    dispatched: &mut *dispatched,
                    newly_inserted: &mut newly_inserted,
                };
                if let Err(e) = self.dispatch_target(&cx, ctx, &mut dstate).await {
                    warn!(scan_id, error = %e, "gap-fill dispatch failed (continuing)");
                }
            }
            // New entities this probe surfaced are derived from the gap endpoint.
            // Gap-fill runs AFTER the planned expansion rounds, so its finds sit
            // one generation beyond the last round in the derivation trail.
            let gap_generation = opts.depth.saturating_add(1);
            for uid in newly_inserted.drain(..) {
                if let Some(child) = entity_map.get_mut(&uid) {
                    child.generation = gap_generation;
                    let child_conf = child.confidence;
                    relations.push(Relation::new(
                        uid.as_str(),
                        probe.endpoint_uid.as_str(),
                        RelationKind::DerivedFrom,
                        child_conf,
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

    /// The registered modules that query a breach/stealer/paste corpus, as the
    /// dispatch allow-list for the final sweep.
    ///
    /// Classified by [`crate::core::correlator::is_breach_source`] — the SAME
    /// predicate the consensus pass uses to decide which evidence sources attest
    /// a finding. Sharing it is the point: a module dispatched here whose source
    /// the grader does not recognise would produce findings that are never
    /// graded, and the sweep would report an audit that silently skipped them.
    ///
    /// A module that self-declares [`ModuleCategory::Breach`] but is not
    /// recognised is exactly that hole, so it is named in a warning rather than
    /// quietly dispatched — `core` cannot import the module registry, so this
    /// call site is the only place the two classifications are both visible.
    fn breach_sweep_modules(&self, scan_id: &str) -> Vec<String> {
        let mut allow = Vec::new();
        let mut ungraded: Vec<&str> = Vec::new();
        for m in &self.modules {
            let name = m.name();
            let recognised = crate::core::correlator::is_breach_source(name);
            if recognised {
                allow.push(name.to_string());
            } else if m.info().category == crate::core::ModuleCategory::Breach {
                ungraded.push(name);
            }
        }
        if !ungraded.is_empty() {
            warn!(
                scan_id,
                modules = ungraded.join(","),
                "breach-category modules unknown to the corpus classifier — their findings would \
                 not be graded by the consensus audit, so they are excluded from the sweep; add \
                 them to `source_family`'s breach set"
            );
        }
        allow
    }

    /// The final bulk breach query: compile every confident identity the scan
    /// has accumulated into one plan and put it to the breach corpora.
    ///
    /// Runs LAST, after expansion and gap-fill, because that is what makes it
    /// worth running: the plan is compiled from the full graph the recursive
    /// search built, not from the seed, so an alias discovered at depth 3 is
    /// swept with the same standing as the address the operator typed. The
    /// compiler ([`crate::core::breach_sweep`]) is pure and deterministic; this
    /// function is only the dispatch half.
    ///
    /// Returns the number of probes actually dispatched.
    #[allow(clippy::too_many_arguments)]
    async fn run_breach_sweep(
        &self,
        scan_id: &str,
        seed: &Target,
        ctx: &mut ModuleContext,
        opts: &ScanOptions,
        started: Instant,
        entity_map: &mut TrackedEntityMap,
        visited: &mut HashSet<(TargetKind, String)>,
        stats: &mut ModuleStats,
        dispatched: &mut DispatchLog,
        relations: &mut Vec<Relation>,
        quarantined: &HashSet<String>,
    ) -> usize {
        if !crate::util::settings::get_bool(crate::util::settings::BREACH_SWEEP_FEATURE, true) {
            return 0;
        }
        // Same ordering as gap-fill: bail BEFORE the snapshot + compile, not just
        // before the dispatch loop. A cancelled scan must do no further work, and
        // the compile walks the whole entity set.
        if ctx.cancel.is_cancelled() {
            return 0;
        }

        let allow: Vec<String> = {
            let mut a = self.breach_sweep_modules(scan_id);
            if let Some(user_allow) = &opts.modules {
                a.retain(|m| user_allow.contains(m));
            }
            a
        };
        if allow.is_empty() {
            return 0;
        }

        let ents: Vec<Entity> = entity_map.values().cloned().collect();
        let plan = crate::core::breach_sweep::compile(
            &ents,
            crate::core::breach_sweep::SweepInputs {
                already_probed: visited,
                quarantined,
                // Whichever floor is stricter — see `MIN_ANCHOR_CONFIDENCE`.
                min_confidence: opts
                    .effective_min_expand_confidence()
                    .max(crate::core::breach_sweep::MIN_ANCHOR_CONFIDENCE),
            },
        );

        // Emit the plan's shape BEFORE dispatching, and emit it even when empty:
        // "the sweep ran and had nothing to ask" and "the sweep never ran" are
        // different outcomes and must not look the same in the event log.
        self.emit(
            scan_id,
            EventKind::BreachSweep {
                anchors: plan.anchors_used,
                probes: plan.len(),
                dropped: plan.dropped_over_cap,
            },
        );
        if plan.dropped_over_cap > 0 {
            warn!(
                scan_id,
                dropped = plan.dropped_over_cap,
                cap = crate::core::breach_sweep::MAX_PROBES,
                "breach sweep hit its probe cap — the plan is a bounded sample, not exhaustive"
            );
        }
        if plan.is_empty() {
            return 0;
        }

        let sweep_opts = ScanOptions {
            modules: Some(allow),
            ..opts.clone()
        };
        // One generation beyond gap-fill's `+1`: the sweep is the last leg, so
        // its finds are the furthest point of the derivation trail.
        let sweep_generation = opts.depth.saturating_add(2);

        let mut newly_inserted: Vec<String> = Vec::new();
        let mut probed = 0usize;

        for probe in &plan.probes {
            if ctx.cancel.is_cancelled() || budget_check(opts, started, entity_map.len()).is_some() {
                // Not a silent stop: the operator must be able to tell a sweep
                // that finished from one the budget cut short.
                warn!(
                    scan_id,
                    dispatched = probed,
                    planned = plan.len(),
                    "breach sweep stopped early (cancelled or over budget)"
                );
                break;
            }
            let target = probe.target();

            newly_inserted.clear();
            {
                let cx = DispatchCx {
                    scan_id,
                    target: &target,
                    opts: &sweep_opts,
                    is_expansion: true,
                    seed_kind: seed.kind,
                    quarantined,
                };
                let mut dstate = DispatchState {
                    entity_map: &mut *entity_map,
                    stats: &mut *stats,
                    dispatched: &mut *dispatched,
                    newly_inserted: &mut newly_inserted,
                };
                if let Err(e) = self.dispatch_target(&cx, ctx, &mut dstate).await {
                    warn!(scan_id, error = %e, "breach-sweep dispatch failed (continuing)");
                }
            }
            for uid in newly_inserted.drain(..) {
                if let Some(child) = entity_map.get_mut(&uid) {
                    child.generation = sweep_generation;
                    child.tag(crate::core::breach_consensus::SWEEP_TAG);
                    let child_conf = child.confidence;
                    relations.push(Relation::new(
                        uid.as_str(),
                        probe.anchor_uid.as_str(),
                        RelationKind::DerivedFrom,
                        child_conf,
                        scan_id,
                    ));
                }
            }
            visited.insert(visit_key(&target));
            probed += 1;
        }

        info!(
            scan_id,
            probed,
            planned = plan.len(),
            anchors = plan.anchors_used,
            skipped_already_probed = plan.skipped_already_probed,
            skipped_free_text = plan.skipped_free_text,
            dropped_over_cap = plan.dropped_over_cap,
            "final breach sweep dispatched"
        );
        probed
    }

    /// Grade the scan's breach findings and record the autonomous audit verdict.
    ///
    /// Runs unconditionally at the end of every scan, not only when the sweep
    /// dispatched something. The audit's job is to answer "do the corpora agree
    /// about this person?", and a depth-0 scan whose seed round hit two corpora
    /// with contradictory dates of birth needs that answer just as much as a
    /// deep one. Costs no network I/O — it reads evidence already collected.
    ///
    /// The pass never raises confidence (see [`crate::core::breach_consensus`]);
    /// it only attaches its summary and its flags, so this is safe to run after
    /// every gate the scan has already applied.
    fn run_consensus_audit(&self, scan_id: &str, entity_map: &mut TrackedEntityMap) {
        let mut ents: Vec<Entity> = entity_map.values().cloned().collect();
        let report = crate::core::breach_consensus::run_consensus_pass(&mut ents, scan_id);
        if report.entities_examined == 0 {
            return;
        }

        // Write back ONLY the entities the pass graded — the rest are untouched
        // clones, and overwriting them would clobber nothing today but would
        // silently discard any concurrent mutation if this ever moved.
        let graded: HashSet<String> = report
            .results
            .iter()
            .map(|r| r.entity_uid.clone())
            .collect();
        for e in ents {
            if graded.contains(&e.uid)
                && let Some(slot) = entity_map.get_mut(&e.uid)
            {
                *slot = e;
            }
        }

        let flags = report.flags().count();
        self.emit(
            scan_id,
            EventKind::ConsensusAudit {
                verdict: report.verdict.as_str().to_string(),
                examined: report.entities_examined,
                corroborated: report.entities_corroborated,
                flags,
            },
        );
        if report.verdict.can_use_for_correlation() {
            info!(
                scan_id,
                verdict = report.verdict.as_str(),
                examined = report.entities_examined,
                corroborated = report.entities_corroborated,
                new_findings = report.new_findings,
                flags,
                "autonomous breach audit complete"
            );
        } else {
            // A failed audit means two corpora contradict each other on a
            // single-valued attribute. That is a finding in its own right, and
            // must be loud rather than buried in an info line.
            warn!(
                scan_id,
                verdict = report.verdict.as_str(),
                examined = report.entities_examined,
                flag_counts = ?report.flag_counts(),
                "autonomous breach audit did not pass — corpora disagree"
            );
        }
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
            quarantined,
        } = state;
        // Reused across candidates to capture lineage: the UIDs a candidate's
        // dispatch genuinely inserted (never merged into an existing entity),
        // populated directly by `DispatchState::newly_inserted` — no snapshot
        // of the whole (up to `max_entities`-sized) entity_map needed per
        // candidate. Reusing the buffer avoids a per-candidate allocation.
        let mut newly_inserted: Vec<String> = Vec::new();
        // Expansion depth-decay (opt-in `feature.depth_decay`, default off): when
        // on, an entity's confidence FOR EXPANSION is discounted by its
        // generation, so the recursion favours seed-adjacent leads and deep chains
        // need more corroboration to keep expanding. Read once per scan; `None` ⇒
        // the expansion is byte-identical to today (plain `c_effective`).
        let decay_base: Option<f64> =
            crate::util::settings::get_bool(crate::util::settings::DEPTH_DECAY_FEATURE, false)
                .then_some(Self::DEPTH_DECAY_BASE);
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
                let promoted = promote_geo_corroborated_family(&mut snapshot)
                    + promote_multipath_corroborated(&mut snapshot, relations.as_slice())
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
                // the hottest expansion loop on the constrained target. When the
                // depth-decay policy is on, this single value is
                // generation-discounted, so every downstream expansion decision
                // (floor / rank / gate) sees the decayed confidence consistently.
                let c_eff = expansion_confidence(entity, decay_base);
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
                // Never recursively pivot a COARSE-tagged Coordinates OR Address
                // entity — a country/region-level fix a module explicitly flagged
                // as non-specific (e.g. `geo_intel`'s phone-prefix-to-country-
                // centroid fallback, `phone_geo`'s carrier-country Address pass).
                // Dispatching it to further geo-consuming modules (offline ASGS/
                // gazetteer lookups, reverse/forward geocoders, registries) snaps
                // it to "the nearest locality" or geocodes it outright, manufacturing
                // a fresh, precise-looking named suburb/street from an admittedly
                // imprecise input — a live phone scan reproduced exactly this for
                // the Coordinates case: a country-centroid fix (tagged `coarse`)
                // got ASGS-snapped to "Ghan, NT", then forward-geocoded into a
                // VERIFIED-tier street address the subject has no connection to.
                // Both kinds carry the identical risk (a bare "Australia" Address
                // re-dispatched to a geocoder is the same laundering shape one hop
                // earlier), and `relation::builders::COARSE_ADDRESS_TAGS` already
                // treats a COARSE Address with the same suspicion for household
                // linking — this extends that established judgement to recursion.
                // A module can't self-guard against this: it only ever sees the
                // bare (kind, value) Target, never the originating entity's tags,
                // so the gate has to live here, at the one point that still has
                // both. The entity itself is unaffected (its own confidence and
                // the correlator's admissibility gates already decide whether it
                // counts as evidence) — only further recursive expansion is
                // stopped. The SAME discipline the codebase already applies to
                // co-residence linking and cross-scan history bridging
                // (`engine::history::is_cross_scan_candidate`); this closes the
                // third, most consequential place a coarse geo fix was still
                // treated as precise.
                if matches!(tk, TargetKind::Coordinates | TargetKind::Address)
                    && entity.has_tag(crate::core::tags::COARSE)
                {
                    self.emit_excluded(scan_id, entity, "coarse_geo_not_pivoted");
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
                newly_inserted.clear();
                {
                    // Re-borrow the mutable accumulator quartet into a
                    // `DispatchState` for this candidate; the block scopes the
                    // borrows so the lineage attribution below is free to read
                    // `entity_map` again.
                    let cx = DispatchCx {
                        scan_id,
                        target: nt,
                        opts,
                        is_expansion: true,
                        seed_kind: seed.kind,
                        quarantined,
                    };
                    let mut dstate = DispatchState {
                        entity_map: &mut *entity_map,
                        stats: &mut *stats,
                        dispatched: &mut *dispatched,
                        newly_inserted: &mut newly_inserted,
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
                for uid in newly_inserted.drain(..) {
                    if let Some(child) = entity_map.get_mut(&uid) {
                        // Stamp the expansion generation: this entity was first
                        // surfaced in round `depth`, i.e. `depth` pivots out from
                        // the seed along its derivation trail. Only genuinely-new
                        // UIDs reach here (merges into an existing, earlier entity
                        // are excluded), so this never overwrites an earlier
                        // generation.
                        child.generation = depth;
                        let child_conf = child.confidence;
                        relations.push(Relation::new(
                            uid.as_str(),
                            parent_uid.as_str(),
                            RelationKind::DerivedFrom,
                            child_conf,
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
                    // A Coordinates entity derived from a round-`depth` Address
                    // belongs to that same expansion generation (a merge into an
                    // earlier-generation entity still keeps that earlier value).
                    d.generation = depth;
                    if let Some(existing) = entity_map.get_mut(&d.uid) {
                        existing.merge(d);
                    } else {
                        entity_map.insert(d.uid.clone(), d);
                    }
                }
                // Checkpoint only what changed since the last checkpoint — not
                // the whole accumulated working set (see `TrackedEntityMap`'s
                // doc). Correlation still reads the full current set: a rule
                // can legitimately relate an entity from an earlier round to
                // one from this round, so narrowing its input would silently
                // miss cross-round correlations.
                let mut dirty: Vec<Entity> = entity_map.take_dirty();
                self.checkpoint_entities(scan_id, &mut dirty);
                let snapshot: Vec<Entity> = entity_map.values().cloned().collect();
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

// ── `finalise_scan` phase helpers ───────────────────────────────────────────
// Pure code motion out of `ScanEngine::finalise_scan`'s `spawn_blocking`
// closure: each function is one of that pipeline's cohesive, sequentially-run
// phases, given exactly the state it reads/mutates. No behaviour changes —
// same statements, same order, just named and independently navigable/
// testable instead of inlined in one ~460-line closure.

/// Phase 1: fold any `ApiKey` entities harvested during this scan's endpoint
/// responses (deduped by value across all modules; own auth keys already
/// excluded by the sink) into `entity_map` by UID — so a key a specialised
/// module already emitted with richer tags/evidence is GREATEST-merged, never
/// duplicated or blindly overwritten — then flatten to the working `Vec`.
fn merge_found_keys_and_flatten(scan_id: &str, entity_map: HashMap<String, Entity>) -> Vec<Entity> {
    let mut entity_map = entity_map;
    for e in crate::core::hooks::drain_found_keys(scan_id) {
        match entity_map.get_mut(&e.uid) {
            Some(existing) => existing.merge(e),
            None => {
                entity_map.insert(e.uid.clone(), e);
            }
        }
    }
    entity_map.into_values().collect()
}

/// Phase 2: the sequential offline enrichment passes that run once, after
/// every module and expansion round has contributed, before persist —
/// address-locality consolidation (the engine-level backstop to the
/// per-module dedup in `search_engines`), geo/breach-candidate corroboration
/// promotion, geo-discordant namesake tagging, and the three cross-scan
/// history/co-occurrence/relation-recall bridges — finishing with
/// `canonicalize_order` so concurrent dispatch's completion-order merging
/// can't leak into the stored/exported result.
fn apply_finalise_enrichment_passes(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &mut Vec<Entity>,
) {
    consolidate_address_localities(entities);
    promote_geo_corroborated_family(entities);
    promote_breach_candidate_geo_corroborated(entities);
    flag_geo_discordant_namesakes(entities);
    history::link_cross_scan_history(store, entities, scan_id);
    // After same-kind recurrence, so an entity the stronger pass already bridged
    // isn't also tagged with the weaker cross-kind alias.
    history::link_cross_scan_kind_aliases(store, entities, scan_id);
    history::link_cross_scan_cooccurrence(store, entities, scan_id);
    history::link_cross_scan_relations(store, entities, scan_id);
    for e in entities.iter_mut() {
        e.canonicalize_order();
    }
}

/// Phase 3: persist the scan's entities in a single transaction (collapsing N
/// per-entity commits into one WAL fsync — a material win on low-power
/// aarch64). All-or-nothing: on any error, fall back to per-entity upserts so
/// whatever is persistable is salvaged and the granular `first_err` recovered.
/// Returns `(persisted, first_err)`; the caller derives `failed` from
/// `entities.len() - persisted`.
fn persist_entities_with_fallback(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &[Entity],
) -> (usize, Option<String>) {
    match store.upsert_entities_batch(entities) {
        Ok(n) => (n, None),
        Err(batch_err) => {
            warn!(scan_id, error = %batch_err, "batch entity persist rolled back; falling back to per-entity upserts");
            let mut persisted = 0usize;
            let mut first_err: Option<String> = None;
            for entity in entities {
                match store.upsert_entity(entity) {
                    Ok(()) => persisted += 1,
                    Err(e) => {
                        warn!(scan_id, entity_uid = %entity.uid, error = %e, "entity persist failed");
                        if first_err.is_none() {
                            first_err = Some(e.to_string());
                        }
                    }
                }
            }
            (persisted, first_err)
        }
    }
}

/// Phase 4: derive the typed entity-relation edges (attribution graph) — the
/// lineage edges captured during expansion plus the structural edges derived
/// from the persisted entity set, identically to the import paths' `derive_all`
/// so a live scan and an imported dossier can't drift on which edges a
/// finished scan carries — and persist them. Bounded: derivation stops
/// starting new passes past `DERIVE_BUDGET` so a pathological graph can't run
/// the super-linear pass chain for minutes; partial relations still persist.
/// Best-effort: a relation that fails to persist is logged, never fatal.
fn derive_and_persist_relations(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &[Entity],
    lineage_relations: &[Relation],
) {
    let derive_deadline = Some(Instant::now() + crate::core::relation::DERIVE_BUDGET);
    let derived = crate::core::relation::derive_all_within(entities, scan_id, derive_deadline);
    if !lineage_relations.is_empty() || !derived.is_empty() {
        let lineage_n = lineage_relations.len();
        let derived_n = derived.len();
        // Persist the whole edge set in ONE transaction (one fsync at finalise
        // instead of one autocommit per edge). `derived` is consumed to avoid a
        // clone; only the small lineage set is cloned into the combined batch.
        let all: Vec<Relation> = lineage_relations.iter().cloned().chain(derived).collect();
        let rel_persisted = match store.upsert_relations_batch(&all) {
            Ok(n) => n,
            Err(e) => {
                warn!(scan_id, error = %e, "relation batch persist failed — falling back to per-relation");
                let mut n = 0usize;
                for r in &all {
                    match store.upsert_relation(r) {
                        Ok(()) => n += 1,
                        Err(e) => {
                            warn!(scan_id, relation = %r.id, error = %e, "relation persist failed");
                        }
                    }
                }
                n
            }
        };
        info!(
            scan_id,
            lineage = lineage_n,
            derived = derived_n,
            persisted = rel_persisted,
            "entity relations persisted"
        );
    }
}

/// Phase 5: the authoritative finalise-time correlation pass — runs the full
/// rule set over the persisted scan, persists every firing, and emits
/// `CorrelationFound` only for correlations not already streamed live during
/// ingestion (deduped via `emitted_corr`); `CorrelationsDone`'s count is the
/// authoritative total. Guarded against a rule panicking on adversarial
/// persisted data — see [`guarded_finalise_correlation`]'s own doc comment.
fn run_finalise_correlation_and_emit(
    store: &Arc<dyn StoragePort>,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
) {
    if let Some(firings) = guarded_finalise_correlation(scan_id, || {
        crate::core::correlator::Correlator::new(Arc::clone(store)).run(scan_id)
    }) {
        for c in &firings {
            if emitted_corr.insert(correlation_key(c)) {
                emitter.emit(
                    scan_id,
                    EventKind::CorrelationFound {
                        correlation: c.clone(),
                    },
                );
            }
        }
        emitter.emit(
            scan_id,
            EventKind::CorrelationsDone {
                count: firings.len(),
            },
        );
    }
}

/// Phase 6 (C1 universal linking): generalise this scan's confirmed
/// connections into direction-canonical routes. A route a *prior* scan already
/// proved is credited as historically corroborated (AU-065 — storage-
/// dependent, so it can't be a pure correlator rule); a *fragile*
/// single-pathway link (the AU-063 gap) whose route shape is proven in ≥2
/// prior scans is AU-066: accumulated cross-scan knowledge fills the gap, and
/// its endpoints are returned in `xscan_boost` for the caller's corroboration
/// boost pass. Best-effort: a storage hiccup never aborts a finalised scan.
fn learn_cross_scan_pathway_templates(
    store: &dyn StoragePort,
    emitter: &EventEmitter,
    scan_id: &str,
    emitted_corr: &mut HashSet<String>,
) -> HashMap<String, String> {
    let mut xscan_boost: HashMap<String, String> = HashMap::new();
    if let (Ok(ents), Ok(rels)) = (
        store.entities_for_scan(scan_id),
        store.relations_for_scan(scan_id),
    ) {
        // The fragile single-route identity pairs (a<b) — exactly AU-063's
        // notion of an uncorroborated link, via the shared detector so the
        // gap the lead flags is the gap the engine fills.
        let fragile: HashSet<(String, String)> =
            crate::core::correlator::single_route_identity_links(&ents, &rels)
                .into_iter()
                .map(|l| (l.a_uid, l.b_uid))
                .collect();
        for ct in crate::core::relation::connection_templates(&ents, &rels, 4) {
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
                    scan_id,
                    crate::core::entity::unix_now(),
                );
                if store.upsert_correlation(&c).is_ok() && emitted_corr.insert(correlation_key(&c))
                {
                    emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
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
                        scan_id,
                        crate::core::entity::unix_now(),
                    );
                    if store.upsert_correlation(&c).is_ok()
                        && emitted_corr.insert(correlation_key(&c))
                    {
                        emitter.emit(scan_id, EventKind::CorrelationFound { correlation: c });
                    }
                    xscan_boost
                        .entry(f.clone())
                        .or_insert_with(|| reason.clone());
                    xscan_boost.entry(t.clone()).or_insert(reason);
                }
            }
            let _ = store.record_pathway_template(&ct.template);
        }
    }
    xscan_boost
}

/// Phase 7: two orthogonal corroboration signals feed back into the entity set
/// so the scan's OUTPUT reflects what its own analysis established — multipath
/// (C2: a link AU-062 proved via ≥2 edge-disjoint, source-orthogonal IN-SCAN
/// routes) and cross-scan (AU-066: a fragile single-route link whose route
/// shape is proven in ≥2 PRIOR scans). Both tag + evidence-stamp only the
/// identity ENDPOINTS, are idempotent via their tags, and use unscored
/// ("other") evidence sources so they never feed back to inflate the in-scan
/// orthogonality measure. Best-effort and conditional: the single re-persist
/// runs only when a boost actually fires.
fn apply_corroboration_boosts(
    store: &dyn StoragePort,
    scan_id: &str,
    entities: &mut [Entity],
    xscan_boost: &HashMap<String, String>,
) {
    let mut boosted_any = false;
    if let Ok(rels) = store.relations_for_scan(scan_id) {
        boosted_any |= promote_multipath_corroborated(entities, &rels) > 0;
    }
    boosted_any |= promote_cross_scan_corroborated(entities, xscan_boost) > 0;
    if boosted_any {
        let boosted: Vec<Entity> = entities
            .iter_mut()
            .filter(|e| e.has_tag("multipath-corroborated") || e.has_tag("cross-scan-corroborated"))
            .map(|e| {
                e.canonicalize_order();
                e.clone()
            })
            .collect();
        match store.upsert_entities_batch(&boosted) {
            Ok(n) => info!(
                scan_id,
                boosted = n,
                "corroboration-boosted identities re-persisted (confirmed links strengthened the scan)"
            ),
            Err(e) => warn!(
                scan_id,
                error = %e,
                "corroboration boost re-persist failed (non-fatal)"
            ),
        }
    }
}

/// Phase 8: end-of-scan housekeeping, all best-effort and non-fatal — persist
/// the key pool discovered during this scan to disk, checkpoint the WAL (fold
/// it into the main DB and truncate, bounding the on-disk/mmap footprint
/// between scans under a long-lived `serve`/`live` process), and bound the
/// events table and inter-scan raw-response cache so a long-lived process
/// scanning many targets doesn't grow either unbounded.
fn run_finalise_housekeeping(store: &dyn StoragePort, scan_id: &str) {
    let pool = crate::util::key_pool::global_pool();
    if let Err(e) = crate::util::key_pool::save_pool(&pool) {
        warn!("failed to save key pool after scan: {e}");
    }
    if let Err(e) = store.checkpoint_truncate() {
        warn!(scan_id, error = %e, "WAL checkpoint deferred (busy)");
    }
    if let Err(e) = store.prune_events(
        crate::core::port::EVENTS_RETENTION_SECS,
        crate::core::port::EVENTS_MAX_ROWS,
    ) {
        warn!(scan_id, error = %e, "events prune deferred");
    }
    if let Err(e) = store.prune_raw_archive(crate::core::port::RAW_ARCHIVE_MAX_ROWS) {
        warn!(scan_id, error = %e, "raw_archive prune deferred");
    }
}

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

pub(crate) use health::ModuleHealth;

/// Every module currently showing a failure streak this process, worst-first
/// (PROBLEM_TREE T2.7 / SOLUTION_TREE SOL-HEALTH-SIGNAL). Empty on a
/// freshly-started or fully healthy process — the common case.
#[must_use]
pub(crate) fn module_health_report() -> Vec<ModuleHealth> {
    health::unhealthy_modules()
}

/// Rank recalled entities strongest-first and cap to `max` (`recall_prior_entities`'s
/// sort+truncate step, split out so it's directly testable). Deterministic uid
/// tie-break (CONVENTIONS.md §5): the incoming `Vec`'s order inherits a `HashMap`'s
/// randomised-per-process iteration order, and modules routinely stamp flat
/// literal confidences (0.6, 0.7, 0.8, …), so exact ties at the cutoff are
/// realistic, not contrived — without a tiebreak, two otherwise-identical
/// recalls of the same target could truncate to a DIFFERENT set of surviving
/// entities, not just a different display order. Mirrors the uid tiebreak
/// `ranking::rank_enrichment_leverage`/`rank_autonomous_targets` also use.
fn rank_recalled_and_cap(mut out: Vec<Entity>, max: usize) -> Vec<Entity> {
    out.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.uid.cmp(&b.uid))
    });
    out.truncate(max);
    out
}
#[cfg(test)]
mod tests;
