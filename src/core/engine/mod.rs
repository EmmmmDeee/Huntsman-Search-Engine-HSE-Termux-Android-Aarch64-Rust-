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

use tracing::{info, warn};

mod circuit;
mod dispatch;
mod enrich;
mod expansion;
mod ledger;
mod passes;
mod persist;
mod recall;
mod timeout;
pub use ledger::DispatchLog;
use passes::hot_inject_keys;
use recall::recall_prior_entities;
// Re-exported into the engine module's namespace so the `use super::*` tests
// (which exercise the locality-consolidation pass directly) keep resolving it
// after the persist split moved its sole non-test caller into `persist`.
#[cfg(test)]
use passes::consolidate_address_localities;
// The dispatch loops now live in `dispatch`; these items are referenced only by
// the tests that stayed in this file, so the bridge is test-only.
#[cfg(test)]
use dispatch::{
    dispatch_key, log_module_dispatch, module_skip_reason, run_module_guarded,
    target_distinct_sources,
};
use enrich::{address_to_coords_pass, enrich_geospatial, scan_entity_for_keys, seed_anchor_entity};
use expansion::{apply_roi_cutoff, budget_check, cmp_expansion_candidates, visit_key};
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
}

#[cfg(test)]
impl ScanEngine {
    /// Test-only shim onto [`recall::recall_prior_entities`] so the recall unit
    /// tests can drive it through an engine instance without reaching into the
    /// private `store` handle. Production code calls the free function directly.
    fn recall_prior_entities(
        &self,
        target: &crate::core::scan::Target,
        scan_id: &str,
    ) -> Vec<crate::core::entity::Entity> {
        recall::recall_prior_entities(self.store.as_ref(), target, scan_id)
    }
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

/// Cheaply-cloneable event emitter. Persist-first, then broadcast.
/// Spawned tasks clone this instead of cloning store + bus separately.
#[derive(Clone)]
struct EventEmitter {
    store: Arc<dyn StoragePort>,
    bus: EventBus,
}

impl EventEmitter {
    fn new(store: Arc<dyn StoragePort>, bus: EventBus) -> Self {
        Self { store, bus }
    }

    fn emit(&self, scan_id: &str, kind: EventKind) {
        let event = Event::new(scan_id, kind);
        if let Err(e) = self.store.insert_event(&event) {
            warn!(scan_id = %event.scan_id, error = %e, "failed to persist event to store");
        }
        // Best-effort live fan-out to SSE subscribers. `broadcast::send` errors
        // ONLY when there are zero active receivers — the normal case for a CLI
        // scan with no `/events` client attached. The event is already durably
        // persisted above (and the CLI/report reads from the store, not the
        // bus), so a missing subscriber is a no-op, NOT a condition worth
        // logging: at the default TRACE verbosity a per-event log here floods
        // the terminal with one line per entity — hundreds on a breach-heavy
        // scan — burying the real output. Drop silently.
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
        let emitter = EventEmitter::new(Arc::clone(&store), bus.clone());
        let graph = Arc::new(ModuleGraph::build(&modules));
        Self {
            modules,
            store,
            bus,
            emitter,
            graph,
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

    pub fn modules(&self) -> &[Arc<dyn Module>] {
        &self.modules
    }

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
    pub async fn run_with_ledger(
        &self,
        mut scan: Scan,
        target: Target,
        mut ctx: ModuleContext,
        dispatched: &mut DispatchLog,
    ) -> Result<Scan> {
        scan.status = ScanStatus::Running;
        self.store.upsert_scan(&scan)?;

        // Reset per-scan budget counters so long-lived processes
        // (`hse serve` / `hse live`) get a fresh budget per scan.
        crate::modules::oathnet_pro::reset_budget();
        crate::modules::see_know::reset_budget();
        crate::modules::wigle::reset_budget();
        // Clear the foreign-API-key sink so this scan reports only the keys IT
        // retrieves from endpoint responses (and refresh the own-key exclusion).
        // Via the module-layer shim — core must not import util directly.
        crate::modules::reset_found_keys();
        // Apply the regional-search toggle for this scan. Regional augmentation
        // is on when EITHER the per-scan flag (`--regional`) is set OR the
        // persistent default `feature.regional` is on (universal toggleability;
        // default off ⇒ geolocation-neutral queries). The per-scan flag only
        // adds regional — set the standing baseline via `hse config
        // feature.regional <on|off>`. Mirrors the see_know per-scan global.
        crate::modules::search_engines::set_regional(
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

        // ─── Recall: the persistent database as a source ────────────────────
        // Pre-populate the working set with everything prior scans of this
        // target already discovered, so the local store feeds the seed round,
        // every expansion round, and cross-scan corroboration — the database is
        // a SOURCE, not just a sink. Recalled nodes merge by uid with whatever
        // live modules re-discover this scan. Universal toggle `feature.recall`
        // (default on); `hse config feature.recall off` for a leave-no-memory
        // session. Skipped on a pre-cancelled scan (clean no-op invariant).
        if !ctx.cancel.is_cancelled() && crate::util::settings::get_bool("feature.recall", true) {
            let recalled = recall_prior_entities(self.store.as_ref(), &target, &scan.id);
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
        if let Err(e) = self
            .dispatch_target(
                &scan.id,
                &target,
                &mut ctx,
                &opts,
                &mut entity_map,
                false,
                &mut stats,
                dispatched,
            )
            .await
        {
            warn!(scan_id = %scan.id, error = %e, "seed dispatch failed (continuing to finalise)");
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
            let _ = self
                .run_expansion(
                    &scan.id,
                    &target,
                    &mut ctx,
                    &opts,
                    started,
                    &mut entity_map,
                    &mut visited,
                    &mut stats,
                    dispatched,
                    &mut lineage,
                    &mut emitted_corr,
                )
                .await;
        }

        // Scan body done — stop the wall-time watchdog so it can't fire after
        // we've already finished (and is reaped promptly rather than sleeping
        // out its full deadline in the background on a long-lived `serve`).
        if let Some(handle) = wall_watchdog {
            handle.abort();
        }

        self.finalise_scan(&mut scan, entity_map, &ctx, stats, lineage, emitted_corr)
    }

    /// Drive the expansion loop. Returns the stop reason for diagnostics.
    #[allow(clippy::too_many_arguments)]
    async fn run_expansion(
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
        emitted_corr: &mut HashSet<String>,
    ) -> StopReason {
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
            crate::modules::see_know::refresh_round_budget();

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
                // the hottest expansion loop on the constrained target.
                let c_eff = entity.c_effective();
                if c_eff < opts.min_expand_confidence {
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
                // Snapshot UIDs before dispatch so we can attribute the
                // entities this candidate surfaces back to its parent.
                before.clear();
                before.extend(entity_map.keys().cloned());
                if let Err(e) = self
                    .dispatch_target(scan_id, nt, ctx, opts, entity_map, true, stats, dispatched)
                    .await
                {
                    // Per-target dispatch errors are already surfaced as
                    // ModuleError events; we keep going through the round.
                    warn!(scan_id, error = %e, "dispatch_target failed (continuing)");
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
                .min_marginal_yield
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
pub(crate) const LOCAL_PASSIVE_MODULES: &[&str] =
    &["device_sensors", "wifi_intel", "cell_intel", "local_net"];

#[cfg(test)]
mod tests;
