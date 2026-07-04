//! Live mode — re-run a scan on a fixed interval.
//!
//! A live session wraps the existing [`ScanEngine`] and invokes
//! [`ScanEngine::run`] in a loop with the same `Target` and `ScanOptions`
//! on every tick. Each iteration is a normal scan — events flow through
//! the existing [`EventBus`] and entities/correlations persist to the
//! store via [`crate::storage::Store`] exactly as one-shot scans do.
//!
//! Why this design choice:
//! - Reuses every piece of the engine (correlator, expansion, throttle,
//!   ScanOptions filters) without an "if live" branch anywhere in core.
//! - The SSE endpoint at `/api/v1/live/{id}/events` simply demultiplexes
//!   events tagged with this session's live-id (live-level) plus any
//!   scan-id the session has spawned (scan-level), so observers see
//!   the same module/entity/correlation events as for a static scan.
//! - Per-session cancellation via the same `CancelHandle` the engine
//!   polls, so `DELETE /api/v1/live/{id}` aborts the currently-running
//!   iteration at the next module boundary rather than waiting for it
//!   to run to completion before the outer loop's next check (issue #23).
//! - Sessions are in-memory only. Restart → cleared. Persistence is a
//!   v0.7+ concern.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::core::{
    cancel::CancelHandle,
    engine::{DispatchLog, ScanEngine},
    entity::unix_now,
    event::{Event, EventBus, EventKind},
    module::ModuleContext,
    scan::{Scan, ScanOptions, Target},
};

/// User-tunable knobs for a live session, on top of [`ScanOptions`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveOptions {
    /// Seconds between iteration starts. Default 30; minimum enforced is 1.
    #[serde(default = "default_interval_secs")]
    pub interval_secs: u64,

    /// Stop after this many iterations. `None` = run forever (until
    /// explicit stop or process exit).
    #[serde(default)]
    pub iterations: Option<u32>,

    /// Radar mode: persist ONE dispatch ledger across all iterations so a
    /// keyed/paid module never re-queries a seed it has already covered in an
    /// earlier sweep. Each sweep then spends API budget only on genuinely NEW
    /// seeds (surfaced by the free modules, which still re-run), so a
    /// long-running radar is not aggressive with the APIs. `false` (default)
    /// keeps classic live behaviour: every iteration is an independent re-scan
    /// that re-queries everything (catches fresh data on the same seed).
    #[serde(default)]
    pub radar: bool,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            interval_secs: default_interval_secs(),
            iterations: None,
            radar: false,
        }
    }
}

fn default_interval_secs() -> u64 {
    crate::LIVE_DEFAULT_INTERVAL_SECS
}

/// Status of a live session at a moment in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStatus {
    Running,
    Completed,
    Stopped,
}

/// The public view of a live session. Returned by list/get endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveSession {
    pub id: String,
    pub target: Target,
    pub scan_options: ScanOptions,
    pub live_options: LiveOptions,
    pub status: LiveStatus,
    pub started_at: u64,
    pub last_iteration_at: Option<u64>,
    pub iteration: u32,
    /// scan_ids spawned by this session, for the SSE handler's per-event
    /// `session_owns_scan` check (O(1) via the `HashSet`). Bounded with FIFO
    /// eviction (see [`LiveSession::record_scan`]) so a multi-day radar session
    /// — which spawns a distinct scan per discovered target — can't grow it
    /// without limit; only ids spawned long ago are evicted, so recent/active
    /// scans always route their events.
    pub scan_ids: std::collections::HashSet<String>,
    /// Insertion order for `scan_ids`, enabling FIFO eviction at
    /// [`SCAN_ID_CAP`]. Internal bookkeeping — not serialised (the API exposes
    /// only the `scan_ids` set), and defaults to empty on deserialize.
    #[serde(default, skip_serializing)]
    scan_id_order: VecDeque<String>,
}

/// Upper bound on a session's retained `scan_ids` (FIFO-evicted). A radar
/// session can spawn one distinct scan per discovered target over days; 10k
/// recent ids is far more than the SSE owner-check needs (active scans finish
/// in seconds–minutes) while bounding memory to a few hundred KB.
const SCAN_ID_CAP: usize = 10_000;

impl LiveSession {
    /// Register a spawned scan id for SSE ownership, FIFO-evicting the oldest
    /// once [`SCAN_ID_CAP`] is exceeded so a long-lived radar session stays
    /// bounded. A duplicate id is a no-op; recent (hence active) scans are
    /// always retained.
    fn record_scan(&mut self, scan_id: String) {
        if self.scan_ids.insert(scan_id.clone()) {
            self.scan_id_order.push_back(scan_id);
            if self.scan_id_order.len() > SCAN_ID_CAP
                && let Some(evicted) = self.scan_id_order.pop_front()
            {
                self.scan_ids.remove(&evicted);
            }
        }
    }
}

/// The request payload for starting a live session via API or CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveRequest {
    /// Target kind. `None` (omitted) auto-detects from `value` via
    /// [`crate::core::scan::TargetKind::detect`] — the unified-scan path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<crate::core::scan::TargetKind>,
    pub value: String,
    /// Per-iteration scan options. Defaults to the same product defaults a
    /// [`crate::core::scan::ScanRequest`] gets (depth 2, gentle concurrency) —
    /// a bare `#[serde(default)]` here used `ScanOptions::default()` (depth 0)
    /// instead, so `{"value":"x"}` ran zero-expansion iterations while the
    /// identical request with an empty `"options": {}` object recursed two
    /// hops (field-level serde defaults). Two spellings of "no preference"
    /// must mean the same thing, and live must match scan.
    #[serde(default = "crate::core::scan::default_scan_options")]
    pub options: ScanOptions,
    #[serde(default)]
    pub live: LiveOptions,
}

impl LiveRequest {
    /// Resolve the kind: explicit if supplied, else auto-detected from `value`.
    pub fn resolved_kind(&self) -> crate::core::scan::TargetKind {
        self.kind
            .unwrap_or_else(|| crate::core::scan::detect_kind(&self.value))
    }
}

// ─── Scanner ─────────────────────────────────────────────────────────────────

/// Owns the set of in-flight live sessions. Cheap to clone (single `Arc`).
#[derive(Clone)]
pub struct LiveScanner {
    inner: Arc<LiveInner>,
}

struct LiveInner {
    sessions: RwLock<HashMap<String, LiveSession>>,
    cancels: RwLock<HashMap<String, CancelHandle>>,
    engine: Arc<ScanEngine>,
    bus: EventBus,
    http: reqwest::Client,
    keys: std::collections::HashMap<String, String>,
}

impl LiveScanner {
    pub fn new(
        engine: Arc<ScanEngine>,
        bus: EventBus,
        http: reqwest::Client,
        keys: std::collections::HashMap<String, String>,
    ) -> Self {
        Self {
            inner: Arc::new(LiveInner {
                sessions: RwLock::new(HashMap::new()),
                cancels: RwLock::new(HashMap::new()),
                engine,
                bus,
                http,
                keys,
            }),
        }
    }

    /// Maximum concurrent live sessions to prevent resource exhaustion.
    const MAX_SESSIONS: usize = 10;

    /// Spawn a new live session. Returns the new `live_id`. Sessions run
    /// detached on the tokio runtime; cancellation is via [`stop`](Self::stop).
    pub fn start(&self, target: Target, scan_options: ScanOptions, live: LiveOptions) -> String {
        // Live sessions re-scan on a loop; cap depth at the operator boundary too.
        let scan_options = scan_options.clamp_depth();
        {
            let sessions = self.inner.sessions.read();
            let active = sessions
                .values()
                .filter(|s| s.status == LiveStatus::Running)
                .count();
            if active >= Self::MAX_SESSIONS {
                // Evict the oldest running session. `sessions` is a HashMap, so
                // its `values()` order is randomised; break started_at ties by
                // session id so that *which* of two same-second sessions is
                // dropped is predictable (and logged-then-reproducible), not a
                // coin flip on HashMap iteration order.
                let oldest_id = sessions
                    .values()
                    .filter(|s| s.status == LiveStatus::Running)
                    .min_by(|a, b| {
                        a.started_at
                            .cmp(&b.started_at)
                            .then_with(|| a.id.cmp(&b.id))
                    })
                    .map(|s| s.id.clone());
                if let Some(id) = oldest_id {
                    drop(sessions);
                    self.stop(&id);
                }
            }
        }
        let live_id = new_live_id(&target);
        let session = LiveSession {
            id: live_id.clone(),
            target: target.clone(),
            scan_options: scan_options.clone(),
            live_options: live.clone(),
            status: LiveStatus::Running,
            started_at: unix_now(),
            last_iteration_at: None,
            iteration: 0,
            scan_ids: std::collections::HashSet::new(),
            scan_id_order: VecDeque::new(),
        };

        let cancel = CancelHandle::new();
        self.inner.sessions.write().insert(live_id.clone(), session);
        self.inner
            .cancels
            .write()
            .insert(live_id.clone(), cancel.clone());

        let inner = Arc::clone(&self.inner);
        let live_id_for_task = live_id.clone();
        let cancel_for_task = cancel;

        // The JoinHandle is intentionally dropped — we don't need it for
        // shutdown (the tokio runtime cleans up tasks when it stops) or
        // for cancellation (the CancelHandle covers that). Storing it would
        // grow `LiveInner` unboundedly with completed handles.
        tokio::spawn(async move {
            session_loop(
                inner,
                live_id_for_task,
                target,
                scan_options,
                live,
                cancel_for_task,
            )
            .await;
        });

        info!(live_id = %live_id, "live session started");
        live_id
    }

    /// Request a session to stop. The same handle is plumbed into the
    /// in-flight iteration's `ModuleContext.cancel`, so flipping it
    /// aborts the running scan at the engine's next module-boundary
    /// gate (~3–8 s p99 under typical `max_timeout_ms` budgets), AND
    /// the outer loop's pre-iteration check sees it and exits before
    /// starting the next iteration. Returns `true` if a matching
    /// session was found.
    pub fn stop(&self, live_id: &str) -> bool {
        self.inner.cancels.read().get(live_id).is_some_and(|c| {
            c.cancel();
            true
        })
    }

    pub fn get(&self, live_id: &str) -> Option<LiveSession> {
        self.inner.sessions.read().get(live_id).cloned()
    }

    pub fn list(&self) -> Vec<LiveSession> {
        let mut sessions: Vec<LiveSession> = self.inner.sessions.read().values().cloned().collect();
        // Deterministic order (HashMap iteration is randomised): oldest-first,
        // ties broken by session id — mirrors the eviction comparator in `start`.
        sessions.sort_by(|a, b| {
            a.started_at
                .cmp(&b.started_at)
                .then_with(|| a.id.cmp(&b.id))
        });
        sessions
    }

    /// True if the given `scan_id` was spawned by `live_id`. Used by the
    /// SSE handler to forward scan-level events to live-session
    /// subscribers. O(1) thanks to `scan_ids` being a `HashSet`.
    pub fn session_owns_scan(&self, live_id: &str, scan_id: &str) -> bool {
        self.inner
            .sessions
            .read()
            .get(live_id)
            .is_some_and(|s| s.scan_ids.contains(scan_id))
    }
}

// ─── Loop ────────────────────────────────────────────────────────────────────

async fn session_loop(
    inner: Arc<LiveInner>,
    live_id: String,
    target: Target,
    scan_options: ScanOptions,
    live: LiveOptions,
    cancel: CancelHandle,
) {
    let interval = Duration::from_secs(live.interval_secs.max(1));
    let max_iter = live.iterations;
    let http = inner.http.clone();
    let loaded_keys = inner.keys.clone();

    // Radar mode persists ONE keyed-module dispatch ledger across every
    // iteration, so a paid API is never re-hit on a seed an earlier sweep
    // already covered. Classic live mode leaves it `None` → each iteration
    // gets a fresh ledger and re-queries everything (to catch fresh data on
    // the same seed).
    let mut radar_ledger: Option<DispatchLog> = live.radar.then(DispatchLog::new);

    let _ = inner.bus.send(Event::new(
        &live_id,
        EventKind::LiveStart {
            live_id: live_id.clone(),
            target_kind: target.kind.canonical_str().to_string(),
            target_value: target.value.clone(),
            interval_secs: live.interval_secs,
        },
    ));

    loop {
        if cancel.is_cancelled() {
            break;
        }

        let current = {
            let mut s = inner.sessions.write();
            if let Some(sess) = s.get_mut(&live_id) {
                sess.iteration += 1;
                sess.last_iteration_at = Some(unix_now());
                sess.iteration
            } else {
                // Session was removed externally — bail.
                break;
            }
        };

        // Spawn a fresh scan for this iteration. `scan_id` is collision-free per
        // call (a process-wide monotonic counter + sub-second nanos, NOT just
        // `unix_now()` at one-second resolution — see its doc), so back-to-back
        // ticks and fast radar iterations within the same second still get
        // distinct ids instead of overwriting each other. Canonical snake_case
        // form matches CLI/API scan_id derivation.
        let sid = crate::core::entity::scan_id(target.kind.canonical_str(), &target.value);

        // Register the scan_id with the session BEFORE running, so the SSE
        // handler can forward its events the moment they fire.
        if let Some(s) = inner.sessions.write().get_mut(&live_id) {
            s.record_scan(sid.clone());
        }

        let _ = inner.bus.send(Event::new(
            &live_id,
            EventKind::LiveTick {
                live_id: live_id.clone(),
                iteration: current,
                scan_id: sid.clone(),
            },
        ));

        let scan = Scan::new(sid.clone(), target.clone()).with_options(scan_options.clone());
        let ctx = ModuleContext {
            scan_id: sid.clone(),
            bus: inner.bus.clone(),
            http: http.clone(),
            keys: loaded_keys.clone(),
            // A per-iteration CHILD of the live-session cancel handle. An operator
            // stop (`DELETE /api/v1/live/{id}`) cancels the PARENT and still aborts
            // the in-flight iteration at the next module boundary (the iteration's
            // scan completes `ScanStatus::Aborted`, partial entities preserved).
            // But the engine's per-iteration wall-time watchdog cancels only this
            // CHILD — so a single sweep that overruns `max_wall_time_secs` (routine
            // at depth on a flaky mobile link) aborts just that iteration instead
            // of tripping the shared session handle and permanently ending the
            // whole continuous session.
            cancel: cancel.child(),
            proxy_pool: std::sync::Arc::new(crate::util::proxy::ProxyPool::new()),
        };

        // Radar mode threads the persistent ledger so keyed modules skip
        // already-covered seeds; classic live mode runs with a fresh ledger.
        let iteration_result = match radar_ledger.as_mut() {
            Some(ledger) => {
                inner
                    .engine
                    .run_with_ledger(scan, target.clone(), ctx, ledger)
                    .await
            }
            None => inner.engine.run(scan, target.clone(), ctx).await,
        };
        if let Err(e) = iteration_result {
            warn!(live_id = %live_id, scan_id = %sid, error = %e, "iteration failed");
        }

        if let Some(max) = max_iter
            && current >= max
        {
            mark_completed(&inner, &live_id, "iterations reached");
            return;
        }

        // Wait the configured interval, but check cancellation periodically
        // so a long interval doesn't delay a Stop request.
        let mut remaining = interval;
        let tick = Duration::from_millis(250);
        while remaining > Duration::ZERO {
            if cancel.is_cancelled() {
                break;
            }
            let step = remaining.min(tick);
            sleep(step).await;
            remaining = remaining.saturating_sub(step);
        }
    }

    mark_stopped(&inner, &live_id);
}

/// Terminal (Completed/Stopped) sessions retained for `GET /api/v1/live/{id}`
/// lookups after a session ends. Unlike `cancels` (pruned on completion, see
/// below), `sessions` had no bound at all: every live invocation that ever
/// finished left a permanent record — each carrying its own
/// `scan_ids`/`scan_id_order`, up to [`SCAN_ID_CAP`] entries apiece — so a
/// long-running `hse serve` process accumulated megabytes of dead session
/// history over weeks of uptime with no way to reclaim it short of a
/// restart. 100 keeps a generous recent history (`list()`/lookups stay
/// useful) while bounding total growth.
const MAX_TERMINAL_SESSIONS: usize = 100;

/// Drop the oldest terminal sessions once their count exceeds
/// [`MAX_TERMINAL_SESSIONS`]. Running sessions are never evicted here — that
/// eviction (by active-session count, not history) is `start`'s
/// `MAX_SESSIONS` job. Ties broken by id, matching `start`/`list`'s ordering
/// convention so the choice of which same-second session survives is
/// deterministic, not a `HashMap`-iteration coin flip. Takes the bare map
/// (not `&LiveInner`) so it's testable without constructing an engine/bus/
/// http client.
fn prune_terminal_sessions(sessions: &RwLock<HashMap<String, LiveSession>>) {
    let mut sessions = sessions.write();
    let mut terminal: Vec<(String, u64)> = sessions
        .iter()
        .filter(|(_, s)| s.status != LiveStatus::Running)
        .map(|(id, s)| (id.clone(), s.started_at))
        .collect();
    if terminal.len() <= MAX_TERMINAL_SESSIONS {
        return;
    }
    terminal.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    let excess = terminal.len() - MAX_TERMINAL_SESSIONS;
    for (id, _) in terminal.into_iter().take(excess) {
        sessions.remove(&id);
    }
}

fn mark_completed(inner: &LiveInner, live_id: &str, reason: &'static str) {
    if let Some(s) = inner.sessions.write().get_mut(live_id) {
        s.status = LiveStatus::Completed;
    }
    // Session has ended — no further `stop()` calls can meaningfully act on
    // it, so drop the AtomicBool entry to bound `cancels` map growth in
    // long-running `hse serve` processes. The `sessions` entry stays so
    // GET /api/v1/live/{id} keeps returning the completed record (bounded by
    // `prune_terminal_sessions`, below).
    inner.cancels.write().remove(live_id);
    prune_terminal_sessions(&inner.sessions);
    let _ = inner.bus.send(Event::new(
        live_id,
        EventKind::LiveStop {
            live_id: live_id.into(),
            reason: reason.into(),
        },
    ));
}

fn mark_stopped(inner: &LiveInner, live_id: &str) {
    let mut emit_event = true;
    if let Some(s) = inner.sessions.write().get_mut(live_id) {
        // Don't overwrite Completed → Stopped if iterations naturally ended.
        if matches!(s.status, LiveStatus::Completed) {
            emit_event = false;
        } else {
            s.status = LiveStatus::Stopped;
        }
    }
    // Same cleanup as `mark_completed` — drop the cancel flag and bound
    // session-history growth once the session is terminal. See notes there.
    inner.cancels.write().remove(live_id);
    prune_terminal_sessions(&inner.sessions);
    if emit_event {
        let _ = inner.bus.send(Event::new(
            live_id,
            EventKind::LiveStop {
                live_id: live_id.into(),
                reason: "stopped".into(),
            },
        ));
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// `live-<16 hex>` — collision-resistant per-target+timestamp identifier.
fn new_live_id(target: &Target) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    h.update(format!("live-{ns}-{:?}-{}", target.kind, target.value).as_bytes());
    let full = hex::encode(h.finalize());
    format!("live-{}", &full[..16])
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
