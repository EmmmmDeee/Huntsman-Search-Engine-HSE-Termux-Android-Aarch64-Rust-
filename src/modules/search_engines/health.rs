//! Search-engine liveness probing.
//!
//! Tests each keyless search engine with a benign, geolocation-neutral probe
//! query, classifies the outcome (up / blocked / down) with a latency, and emits
//! a structured `tracing` event per engine. Those events are captured by the
//! unified [`crate::util::log_capture`] ring alongside every other component's
//! logs, so the liveness data feeds the same downloadable debug log
//! (`GET /api/v1/logs` / Settings → "Download debug log") for future reference
//! and troubleshooting. Surfaced to operators via `hse engines` (and, next, a
//! web liveness panel + periodic in-`serve` sweeps). Probes run concurrently so
//! the whole sweep finishes in roughly one engine's timeout.

use std::sync::{LazyLock, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use futures::future::join_all;

use super::engines::{ENGINES, EngineSpec};
use super::fetch::{parse_results, try_fetch};
use super::helpers::FetchOutcome;

/// Benign, region-neutral probe query — a reserved example domain, so a probe
/// never targets a real person and the query is comparable across engines.
const PROBE_QUERY: &str = "example.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EngineStatus {
    /// Reachable and returning parseable results.
    Up,
    /// Reachable but CAPTCHA/anti-bot challenged, or a 200 with no usable
    /// results (an empty / soft-blocked page).
    Blocked,
    /// Unreachable — network failure or no response.
    Down,
}

impl EngineStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Blocked => "blocked",
            Self::Down => "down",
        }
    }
}

/// One engine's liveness result.
#[derive(Clone, Copy)]
pub(crate) struct EngineHealth {
    pub(crate) name: &'static str,
    pub(crate) status: EngineStatus,
    pub(crate) latency_ms: u64,
    pub(crate) results: usize,
}

/// A timestamped result of one full liveness sweep.
#[derive(Clone)]
pub(crate) struct HealthSnapshot {
    /// Unix seconds when the sweep completed.
    pub(crate) checked_at: u64,
    pub(crate) engines: Vec<EngineHealth>,
}

/// Process-global cache of the latest sweep, populated by the periodic +
/// startup background task in `hse serve` (and lazily on first read). The web
/// liveness panel / `GET /api/v1/engines/health` serve this snapshot so a panel
/// refresh is instant and never triggers 17 live fetches per page view.
static CACHE: LazyLock<RwLock<Option<HealthSnapshot>>> = LazyLock::new(|| RwLock::new(None));

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Run a full sweep, store it in the cache, and return the fresh snapshot.
pub(crate) async fn refresh_cache() -> HealthSnapshot {
    let snap = HealthSnapshot {
        engines: probe_all().await,
        checked_at: unix_now(),
    };
    if let Ok(mut w) = CACHE.write() {
        *w = Some(snap.clone());
    }
    snap
}

/// The most recent cached sweep, if any has run yet.
pub(crate) fn cached() -> Option<HealthSnapshot> {
    CACHE.read().ok().and_then(|r| r.clone())
}

/// Pure classification of a probe outcome — split out so it's unit-testable
/// without a live fetch.
fn classify(outcome: &FetchOutcome, results: usize) -> EngineStatus {
    match outcome {
        FetchOutcome::Unreachable => EngineStatus::Down,
        FetchOutcome::Blocked => EngineStatus::Blocked,
        // Reachable: "up" only if it actually yielded parseable results; a 200
        // carrying zero results is an empty / soft-blocked page.
        FetchOutcome::Body(_) => {
            if results > 0 {
                EngineStatus::Up
            } else {
                EngineStatus::Blocked
            }
        }
    }
}

async fn probe_one(engine: &'static EngineSpec) -> EngineHealth {
    let url = (engine.build_url)(PROBE_QUERY);
    let post = engine.build_post.map(|f| f(PROBE_QUERY));
    let start = Instant::now();
    let outcome = try_fetch(&url, engine.ua, post.as_deref()).await;
    let latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let results = match &outcome {
        FetchOutcome::Body(b) => parse_results(b, engine.name, PROBE_QUERY).len(),
        _ => 0,
    };
    let status = classify(&outcome, results);
    // Structured event → captured by util::log_capture into the unified debug
    // log, tagged with a stable target so engine-health lines are greppable
    // among other components' output.
    tracing::info!(
        target: "huntsman::engine_health",
        engine = engine.name,
        status = status.as_str(),
        latency_ms,
        results,
        "search engine liveness probe"
    );
    EngineHealth {
        name: engine.name,
        status,
        latency_ms,
        results,
    }
}

/// Probe every engine concurrently, sorted by name for stable display. Emits a
/// structured summary line so a sweep is one greppable record in the debug log.
pub(crate) async fn probe_all() -> Vec<EngineHealth> {
    let mut out = join_all(ENGINES.iter().map(probe_one)).await;
    out.sort_by_key(|h| h.name);
    tracing::info!(
        target: "huntsman::engine_health",
        total = out.len(),
        up = out.iter().filter(|h| h.status == EngineStatus::Up).count(),
        blocked = out.iter().filter(|h| h.status == EngineStatus::Blocked).count(),
        down = out.iter().filter(|h| h.status == EngineStatus::Down).count(),
        "search engine liveness sweep complete"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_maps_every_outcome() {
        assert_eq!(classify(&FetchOutcome::Unreachable, 0), EngineStatus::Down);
        assert_eq!(classify(&FetchOutcome::Blocked, 0), EngineStatus::Blocked);
        assert_eq!(
            classify(&FetchOutcome::Body("x".into()), 5),
            EngineStatus::Up
        );
        // Reachable but empty → blocked, not up.
        assert_eq!(
            classify(&FetchOutcome::Body("x".into()), 0),
            EngineStatus::Blocked
        );
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(EngineStatus::Up.as_str(), "up");
        assert_eq!(EngineStatus::Blocked.as_str(), "blocked");
        assert_eq!(EngineStatus::Down.as_str(), "down");
    }
}
