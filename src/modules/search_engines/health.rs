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
#[derive(Clone)]
pub(crate) struct EngineHealth {
    pub(crate) name: &'static str,
    pub(crate) status: EngineStatus,
    pub(crate) latency_ms: u64,
    pub(crate) results: usize,
    /// Actionable, human-readable reason naming the likely failing layer
    /// (network / anti-bot / parser). The manifesto's "no black-box": every
    /// failure explains itself so the operator knows where to look.
    pub(crate) detail: String,
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

/// The cached sweep, or an empty (never-probed) snapshot. Used by the HTTP
/// handler so a panel fetch is instant and hermetic — it never triggers a live
/// 17-engine probe on the request path; the periodic/startup sweep in
/// `hse serve` (or `hse engines`) is what populates the cache.
pub(crate) fn cached_or_empty() -> HealthSnapshot {
    cached().unwrap_or(HealthSnapshot {
        checked_at: 0,
        engines: Vec::new(),
    })
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

/// Actionable diagnosis of a probe outcome — names the LIKELY failing layer so a
/// failure is never opaque. `link_hint` is a cheap count of result-like anchors
/// in the body (only meaningful for the reachable-but-empty case): a page that
/// returned many links yet parsed to zero results points at a PARSER defect /
/// markup change rather than a block. **Pure**, so it's unit-tested without a
/// live fetch.
fn diagnose(outcome: &FetchOutcome, results: usize, link_hint: usize) -> String {
    match outcome {
        FetchOutcome::Unreachable => {
            "no usable response — network/TLS failure, timeout, or body < 500B".to_string()
        }
        FetchOutcome::Blocked => {
            "anti-bot/CAPTCHA interstitial — needs a residential IP or HUNTSMAN_SEARCH_PROXY"
                .to_string()
        }
        FetchOutcome::Body(_) if results > 0 => format!("{results} result(s) parsed"),
        FetchOutcome::Body(_) => {
            if link_hint >= 10 {
                format!(
                    "page carried ~{link_hint} links but the parser extracted 0 results — \
                     likely a PARSER defect or markup change for this engine"
                )
            } else {
                "reachable but empty (0 results, sparse markup) — soft-block / IP throttling"
                    .to_string()
            }
        }
    }
}

/// Cheap heuristic count of result-bearing anchors in an HTML body: occurrences
/// of `href="http`. Used only to tell a parser failure (many links, 0 parsed)
/// apart from a genuine empty/soft-block page (few links).
fn link_hint(body: &str) -> usize {
    body.matches("href=\"http").count() + body.matches("href='http").count()
}

async fn probe_one(engine: &'static EngineSpec) -> EngineHealth {
    let url = (engine.build_url)(PROBE_QUERY);
    let post = engine.build_post.map(|f| f(PROBE_QUERY));
    let start = Instant::now();
    let outcome = try_fetch(&url, engine.ua, post.as_deref()).await;
    let latency_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let (results, links) = match &outcome {
        FetchOutcome::Body(b) => (parse_results(b, engine.name, PROBE_QUERY).len(), link_hint(b)),
        _ => (0, 0),
    };
    let status = classify(&outcome, results);
    let detail = diagnose(&outcome, results, links);
    // Structured event → captured by util::log_capture into the unified debug
    // log, tagged with a stable target so engine-health lines are greppable
    // among other components' output. `detail` makes every failure self-explain.
    tracing::info!(
        target: "huntsman::engine_health",
        engine = engine.name,
        status = status.as_str(),
        latency_ms,
        results,
        detail = %detail,
        "search engine liveness probe"
    );
    EngineHealth {
        name: engine.name,
        status,
        latency_ms,
        results,
        detail,
    }
}

/// Probe every engine concurrently, sorted by name for stable display. Emits a
/// structured summary line so a sweep is one greppable record in the debug log.
pub(crate) async fn probe_all() -> Vec<EngineHealth> {
    // Only probe engines that are enabled (universal toggleability) — a disabled
    // engine is never queried, so the panel reflects the active set.
    let mut out = join_all(
        ENGINES
            .iter()
            .filter(|e| super::engine_enabled(e.name))
            .map(probe_one),
    )
    .await;
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
    fn diagnose_distinguishes_parser_failure_from_block() {
        // Reachable page with many links but 0 parsed results → parser defect.
        let body = FetchOutcome::Body("x".into());
        let d = diagnose(&body, 0, 25);
        assert!(d.contains("PARSER"), "got: {d}");
        // Reachable but sparse → soft-block/throttle, NOT a parser blame.
        let d = diagnose(&body, 0, 1);
        assert!(d.contains("soft-block") || d.contains("throttling"), "got: {d}");
        assert!(!d.contains("PARSER"), "got: {d}");
        // Up case names the count.
        assert!(diagnose(&body, 7, 30).contains('7'));
        // Network + anti-bot cases name their layer.
        assert!(diagnose(&FetchOutcome::Unreachable, 0, 0).contains("network"));
        assert!(diagnose(&FetchOutcome::Blocked, 0, 0).contains("anti-bot"));
    }

    #[test]
    fn link_hint_counts_http_anchors() {
        let html = r#"<a href="http://a.com">a</a><a href='https://b.com'>b</a><a href="/rel">c</a>"#;
        assert_eq!(link_hint(html), 2);
    }

    #[test]
    fn status_strings_are_stable() {
        assert_eq!(EngineStatus::Up.as_str(), "up");
        assert_eq!(EngineStatus::Blocked.as_str(), "blocked");
        assert_eq!(EngineStatus::Down.as_str(), "down");
    }
}
