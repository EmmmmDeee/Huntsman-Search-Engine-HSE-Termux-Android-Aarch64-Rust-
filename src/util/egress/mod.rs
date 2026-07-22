//! Validated, self-healing egress rotation — the live layer over the pure
//! [`pool`] logic.
//!
//! HSE's OSINT collection must never fail because one proxy or DNS resolver
//! went dark. This module keeps a **continuously-validated pool** of egress
//! proxies: entries are health-scored, dead ones drop out of rotation and are
//! evicted, a request that fails through one proxy transparently fails over to
//! the next healthy one, and the pool **self-refills** from operator-configured
//! published proxy-list feeds (`HUNTSMAN_PROXY_FEEDS`) — every fed entry is
//! probe-validated before it can carry traffic.
//!
//! Sourcing is deliberately limited to what the operator points HSE at (an
//! explicit proxy list or feed URLs they supply): HSE validates and rotates
//! over *provided/published* sources, it does **not** scan IP ranges to
//! discover open proxies. The [`crate::util::netrotate`] never-scan guard still
//! ensures a proxy HSE routes through is never itself a scan target.
//!
//! Termux aarch64 / no-root: the validation probe spawns the same `curl` the
//! paid-client transport already uses (no new deps, no raw sockets, no root),
//! and every probe is time-bounded so a hung proxy can't freeze a scan.

mod pool;

pub use pool::{DEAD_THRESHOLD, EgressEntry, EgressPool, EgressState, parse_feed_body};

use std::sync::OnceLock;

use parking_lot::Mutex;

/// Env var: comma-separated proxy list the operator supplies directly
/// (mirrors the existing `HUNTSMAN_SEARCH_PROXY`, whose value is folded in too).
pub const PROXY_ENV: &str = "HUNTSMAN_SEARCH_PROXY";
/// Env var: comma-separated URLs of published proxy-list feeds HSE self-refills
/// from. Each fetched entry is probe-validated before entering rotation.
pub const PROXY_FEEDS_ENV: &str = "HUNTSMAN_PROXY_FEEDS";

/// A validated proxy is re-probed once its last success is older than this.
const PROBE_STALE_SECS: u64 = 600;
/// Never validate more than this many candidates in one refresh pass (bounds a
/// large feed so a refresh can't fan out into thousands of curl spawns).
const MAX_VALIDATE_PER_PASS: usize = 64;
/// Keep at least this many usable proxies before eviction may prune Dead ones.
const KEEP_MIN: usize = 1;
/// Per-proxy validation-probe budget (ms). Tight: a proxy that can't answer a
/// 204 check this fast is not worth carrying.
const PROBE_TIMEOUT_MS: u64 = 6_000;
/// Neutral, stable connectivity endpoint that returns an empty `204 No Content`
/// — the canonical captive-portal / reachability check, chosen so a probe
/// transfers almost nothing and doesn't hit any scan target.
const PROBE_URL: &str = "http://www.gstatic.com/generate_204";

/// The process-wide validated proxy pool, seeded lazily from [`PROXY_ENV`].
fn proxy_pool() -> &'static Mutex<EgressPool> {
    static POOL: OnceLock<Mutex<EgressPool>> = OnceLock::new();
    POOL.get_or_init(|| {
        let seed = std::env::var(PROXY_ENV)
            .ok()
            .map(|raw| crate::util::netrotate::parse_proxy_list(&raw))
            .unwrap_or_default();
        Mutex::new(EgressPool::from_specs(seed))
    })
}

/// The next validated proxy to route through, or `None` for a direct
/// connection. Health-ranked + round-robin; skips dead proxies.
#[must_use]
pub fn next_proxy() -> Option<String> {
    proxy_pool().lock().select()
}

/// The next validated proxy excluding `exclude` — the failover call: after a
/// request fails through one proxy, retry with it excluded so a single dead
/// path never renders a resource unreachable.
#[must_use]
pub fn next_proxy_excluding(exclude: &[String]) -> Option<String> {
    proxy_pool().lock().next_excluding(exclude)
}

/// Record a real request outcome for `spec` so the pool's health tracks live
/// behaviour, not just probe results. `latency_ms` is ignored on failure.
pub fn report_proxy(spec: &str, ok: bool, latency_ms: u32) {
    proxy_pool()
        .lock()
        .report(spec, ok, latency_ms, crate::core::entity::unix_now());
}

/// Operator-facing snapshot `(spec, state, latency_ms, health)` for the
/// diagnostic bundle. Contains only specs the operator configured/fed.
#[must_use]
pub fn proxy_pool_snapshot() -> Vec<(String, EgressState, u32, f64)> {
    proxy_pool().lock().snapshot()
}

/// Usable-vs-total proxy counts for a one-line health summary.
#[must_use]
pub fn proxy_pool_counts() -> (usize, usize) {
    let p = proxy_pool().lock();
    (p.usable_count(), p.len())
}

/// True when the operator has asserted an intent to proxy — i.e. the pool holds
/// at least one entry (seeded from [`PROXY_ENV`] or fed from a feed). The curl
/// path reads this to decide whether exhaustion means "give up" (configured, so
/// never leak a direct connection) or "connect directly" (no proxy configured
/// at all). A pool whose every entry is currently Dead still counts as
/// configured — that's precisely when we must NOT fall back to direct.
#[must_use]
pub fn pool_is_configured() -> bool {
    !proxy_pool().lock().is_empty()
}

/// Validate one proxy: spawn `curl` to fetch the neutral 204 check through it,
/// measuring success + latency. Bounded by [`PROBE_TIMEOUT_MS`]. `None` return
/// from the spawn is treated as failure. Pure-ish: no pool mutation (the caller
/// folds the result in), so it's driveable from a test with a fake proxy.
async fn validate_proxy(spec: &str) -> (bool, u32) {
    let secs = (PROBE_TIMEOUT_MS / 1000).max(1).to_string();
    // Start the clock BEFORE the spawn so the measured latency covers the whole
    // proxied round-trip, not just the post-completion bookkeeping.
    let started = std::time::Instant::now();
    // `-o /dev/null` discards the (empty) body; `-w %{http_code}` prints the
    // status; `--max-time` bounds the whole attempt; `-x` routes via the proxy.
    let out = tokio::process::Command::new("curl")
        .args(["-s", "-o", "/dev/null", "-w", "%{http_code}"])
        .args(["--max-time", &secs, "-x", spec, PROBE_URL])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            let code = String::from_utf8_lossy(&o.stdout);
            let code = code.trim();
            // Any 2xx/3xx means the proxy carried the request; gstatic answers
            // 204. A 000 (curl couldn't connect) or 4xx/5xx ⇒ unusable.
            let ok = code.starts_with('2') || code.starts_with('3');
            #[allow(clippy::cast_possible_truncation)]
            let latency = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
            (ok, if ok { latency } else { 0 })
        }
        _ => (false, 0),
    }
}

/// Concurrently validate `specs`, returning `(spec, ok, latency_ms)` for each.
/// Bounded concurrency so a big feed doesn't spawn a curl storm on a phone.
async fn validate_many(specs: Vec<String>) -> Vec<(String, bool, u32)> {
    use futures::stream::{self, StreamExt};
    stream::iter(specs)
        .map(|spec| async move {
            let (ok, lat) = validate_proxy(&spec).await;
            (spec, ok, lat)
        })
        .buffer_unordered(8)
        .collect()
        .await
}

/// Minimum seconds between two actual refreshes — so calling [`refresh_pool`]
/// once per scan on a busy `hse serve` throttles to occasional work rather than
/// re-fetching feeds + re-probing on every single scan.
const MIN_REFRESH_INTERVAL_SECS: u64 = 300;

/// Last unix-secs a refresh actually ran (0 = never), for the throttle above.
static LAST_REFRESH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// One self-healing pass: fetch every configured feed, parse candidate proxies,
/// merge the new ones into the pool, then probe-validate a bounded batch of the
/// pool's due-for-probe entries and fold the results into their health. Returns
/// `(fed, validated_ok)` for logging. Safe to call periodically or on demand;
/// throttled to [`MIN_REFRESH_INTERVAL_SECS`] and a no-op (empty feeds + nothing
/// due) costs nothing.
pub async fn refresh_pool() -> (usize, usize) {
    use std::sync::atomic::Ordering;
    // Throttle: skip if a refresh ran within the interval. A single relaxed
    // load/store race at worst runs one extra refresh — harmless and bounded.
    let now = crate::core::entity::unix_now();
    if now.saturating_sub(LAST_REFRESH.load(Ordering::Relaxed)) < MIN_REFRESH_INTERVAL_SECS {
        return (0, 0);
    }
    LAST_REFRESH.store(now, Ordering::Relaxed);

    // 1. Pull candidate specs from published feeds (operator-configured URLs).
    let mut fed = 0usize;
    if let Ok(raw) = std::env::var(PROXY_FEEDS_ENV) {
        for url in crate::util::netrotate::parse_proxy_list(&raw) {
            if let Some(body) = fetch_feed(&url).await {
                let specs = parse_feed_body(&body);
                fed += proxy_pool().lock().merge_specs(specs);
            }
        }
    }
    // 2. Validate a bounded batch of due entries (never-probed + stale).
    let now = crate::core::entity::unix_now();
    let due = proxy_pool()
        .lock()
        .due_for_probe(now, PROBE_STALE_SECS, MAX_VALIDATE_PER_PASS);
    if due.is_empty() {
        return (fed, 0);
    }
    let results = validate_many(due).await;
    let mut ok_count = 0usize;
    {
        let mut pool = proxy_pool().lock();
        let now = crate::core::entity::unix_now();
        for (spec, ok, lat) in results {
            if ok {
                ok_count += 1;
            }
            pool.report(&spec, ok, lat, now);
        }
        // 3. Evict corpses, but never strand the pool.
        pool.prune_dead(KEEP_MIN);
    }
    (fed, ok_count)
}

/// Fetch a feed URL's body with a bounded timeout via `curl` (no proxy — the
/// feed host is a plain HTTPS endpoint the operator chose). `None` on any error.
async fn fetch_feed(url: &str) -> Option<String> {
    let out = tokio::process::Command::new("curl")
        .args(["-s", "--max-time", "15", "-A", "hse-egress/1", url])
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    (!body.trim().is_empty()).then_some(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_counts_reflect_seeded_specs() {
        // The live singleton reads the process env once; rather than mutate
        // globals we exercise the pool type directly here (the singleton wiring
        // is a thin OnceLock seed). The pure pool is covered in pool_tests.rs.
        let mut p = EgressPool::from_specs(["http://a:3128", "socks5://b:1080"]);
        assert_eq!(p.usable_count(), 2);
        p.report("http://a:3128", false, 0, 1);
        p.report("http://a:3128", false, 0, 2);
        p.report("http://a:3128", false, 0, 3);
        assert_eq!(p.usable_count(), 1, "dead proxy drops from usable");
    }

    #[tokio::test]
    async fn validate_proxy_reports_failure_for_a_dead_local_proxy() {
        // A proxy pointing at a closed local port must validate as unusable,
        // fast (bounded by --max-time). No network dependency: 127.0.0.1:1 is
        // reliably refused. Proves the probe classifies a dead proxy correctly.
        let (ok, _lat) = validate_proxy("http://127.0.0.1:1").await;
        assert!(!ok, "a refused local port must validate as a dead proxy");
    }
}
