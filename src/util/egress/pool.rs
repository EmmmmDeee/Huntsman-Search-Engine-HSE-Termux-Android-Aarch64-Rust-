//! The validated, self-healing egress pool — pure health/selection/failover
//! logic (no I/O), mirroring the proven [`crate::secrets::key_pool`] health model
//! so the rotation is fully unit-testable without a live network. The async
//! validation probe and feed fetch live in the sibling `validate` module; this
//! file owns *which endpoint to use next* and *how an endpoint's health
//! evolves*.
//!
//! An "endpoint" is either a proxy spec (`socks5://h:1080`,
//! `http://u:p@h:3128`) or a DNS-resolver identity — the pool is generic over
//! the opaque `spec` string; the caller interprets it.

/// Operational state of one egress endpoint. A lower state is never selected
/// ahead of a higher one of equal latency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressState {
    /// Never probed — optimistically eligible (a fresh feed entry), but ranked
    /// below a proven-Healthy peer so we lean on known-good paths first.
    Untested,
    /// Last probe/use succeeded — the preferred tier.
    Healthy,
    /// Recent failures but not yet dead — de-prioritised behind Healthy peers,
    /// NOT starved (still used when every healthier peer is unavailable), so a
    /// transiently-flaky proxy recovers instead of being permanently benched.
    Degraded,
    /// Failed [`DEAD_THRESHOLD`] times in a row — never selected; kept for a
    /// possible later re-probe (so a temporarily-blocked egress can return)
    /// until `prune_dead` evicts it once healthy alternatives exist.
    Dead,
}

impl EgressState {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Untested => "untested",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Dead => "dead",
        }
    }
}

/// Consecutive failures at which an endpoint is declared Dead. Small, because a
/// dead proxy/resolver should drop out of rotation fast — the whole point is
/// "no resource inaccessible because we kept routing through a corpse".
pub const DEAD_THRESHOLD: u32 = 3;

/// One egress endpoint with its rolling health.
#[derive(Debug, Clone)]
pub struct EgressEntry {
    pub spec: String,
    pub state: EgressState,
    /// Unix secs of the last success (0 = never).
    pub last_ok: u64,
    /// Last measured round-trip latency in ms (0 = unknown).
    pub latency_ms: u32,
    pub consecutive_failures: u32,
    pub successes: u64,
    pub failures: u64,
}

impl EgressEntry {
    #[must_use]
    pub fn new(spec: impl Into<String>) -> Self {
        Self {
            spec: spec.into(),
            state: EgressState::Untested,
            last_ok: 0,
            latency_ms: 0,
            consecutive_failures: 0,
            successes: 0,
            failures: 0,
        }
    }

    /// Fold one probe/use outcome into the entry's health. `latency_ms` is
    /// ignored on failure. Pure over `now` so the state machine is testable.
    pub fn record(&mut self, ok: bool, latency_ms: u32, now: u64) {
        if ok {
            self.successes += 1;
            self.consecutive_failures = 0;
            self.last_ok = now;
            self.latency_ms = latency_ms;
            self.state = EgressState::Healthy;
        } else {
            self.failures += 1;
            self.consecutive_failures += 1;
            self.state = if self.consecutive_failures >= DEAD_THRESHOLD {
                EgressState::Dead
            } else {
                EgressState::Degraded
            };
        }
    }

    /// Selectable at all (anything but Dead).
    #[must_use]
    pub fn is_usable(&self) -> bool {
        self.state != EgressState::Dead
    }

    #[must_use]
    pub fn total_uses(&self) -> u64 {
        self.successes + self.failures
    }

    /// Success rate in `0.0..=1.0`; optimistic `1.0` prior when never used, so a
    /// fresh feed entry is tried rather than pre-judged.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.total_uses();
        if total == 0 {
            return 1.0;
        }
        self.successes as f64 / total as f64
    }

    /// Quantified health in `0.0..=1.0`: success rate dominates, a mild latency
    /// bonus breaks ties toward faster egress. Dead → 0.0. Used for the operator
    /// health roll-up, not selection (selection uses [`Self::selection_rank`]).
    #[must_use]
    pub fn health_score(&self) -> f64 {
        if self.state == EgressState::Dead {
            return 0.0;
        }
        let sr = self.success_rate();
        // Latency bonus: 1.0 at 0ms falling to 0.0 by 2000ms, weighted lightly.
        let lat = if self.latency_ms == 0 {
            0.5 // unknown latency: neutral
        } else {
            (1.0 - (f64::from(self.latency_ms) / 2000.0)).clamp(0.0, 1.0)
        };
        (sr * 0.85 + lat * 0.15).clamp(0.0, 1.0)
    }

    /// Coarse health band for selection: Healthy=2, Untested=1, Degraded=0.
    /// Dead is filtered before ranking.
    fn band(&self) -> u8 {
        match self.state {
            EgressState::Healthy => 2,
            EgressState::Untested => 1,
            EgressState::Degraded | EgressState::Dead => 0,
        }
    }

    /// Sort key (descending preference): higher band first, then lower latency
    /// (unknown latency treated as mid so a fresh entry isn't pushed to the back
    /// purely for lacking a measurement). Deterministic.
    #[must_use]
    pub fn selection_rank(&self) -> (u8, std::cmp::Reverse<u32>) {
        let lat = if self.latency_ms == 0 {
            1000
        } else {
            self.latency_ms
        };
        (self.band(), std::cmp::Reverse(lat))
    }
}

/// The validated, self-healing pool. Selection is rank-then-round-robin over
/// usable entries; failover is the caller re-calling [`Self::next_excluding`]
/// after a failed attempt. Not thread-safe by itself — the live singleton wraps
/// it in a `parking_lot::Mutex` (mirrors `key_pool`).
#[derive(Debug, Default)]
pub struct EgressPool {
    entries: Vec<EgressEntry>,
    cursor: usize,
}

impl EgressPool {
    #[must_use]
    pub fn from_specs<I, S>(specs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut pool = Self::default();
        for s in specs {
            pool.merge_one(s.into());
        }
        pool
    }

    /// Add a spec if absent, preserving the health of any existing entry — the
    /// feed-refill path calls this so re-seeing a known-bad proxy doesn't reset
    /// its Dead state. Returns true if newly added.
    pub fn merge_one(&mut self, spec: String) -> bool {
        if spec.trim().is_empty() || self.entries.iter().any(|e| e.spec == spec) {
            return false;
        }
        self.entries.push(EgressEntry::new(spec));
        true
    }

    /// Merge many specs (feed refill). Returns the count newly added.
    pub fn merge_specs<I: IntoIterator<Item = String>>(&mut self, specs: I) -> usize {
        specs
            .into_iter()
            .filter(|s| self.merge_one(s.clone()))
            .count()
    }

    /// Highest-ranked usable spec, rotating the cursor so repeated calls spread
    /// load across equally-ranked peers. `None` when every entry is Dead (the
    /// caller then falls back to a direct connection / system resolver). Does
    /// NOT mutate health — the caller reports the outcome via [`Self::report`].
    pub fn select(&mut self) -> Option<String> {
        self.next_excluding(&[])
    }

    /// Like [`Self::select`] but skips any spec in `exclude` — the failover
    /// primitive: after a spec fails mid-request, the caller retries with that
    /// spec excluded so one dead path never makes the resource unreachable.
    pub fn next_excluding(&mut self, exclude: &[String]) -> Option<String> {
        let mut idxs: Vec<usize> = (0..self.entries.len())
            .filter(|&i| self.entries[i].is_usable() && !exclude.contains(&self.entries[i].spec))
            .collect();
        if idxs.is_empty() {
            return None;
        }
        // Descending selection rank; ties keep insertion order so the cursor
        // produces a deterministic rotation.
        idxs.sort_by(|&a, &b| {
            self.entries[b]
                .selection_rank()
                .cmp(&self.entries[a].selection_rank())
        });
        let top = self.entries[idxs[0]].selection_rank();
        let top_run: Vec<usize> = idxs
            .iter()
            .copied()
            .take_while(|&i| self.entries[i].selection_rank() == top)
            .collect();
        let pick = top_run[self.cursor % top_run.len()];
        self.cursor = self.cursor.wrapping_add(1);
        Some(self.entries[pick].spec.clone())
    }

    /// Fold an outcome for `spec` into its health. No-op if the spec isn't in
    /// the pool (it may have been pruned between select and report).
    pub fn report(&mut self, spec: &str, ok: bool, latency_ms: u32, now: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.spec == spec) {
            e.record(ok, latency_ms, now);
        }
    }

    /// Evict Dead entries, but only while at least `keep_min` usable entries
    /// remain — so we never prune the pool to empty just because everything is
    /// transiently failing (that would strand the whole scan). Returns evicted
    /// count. Kept-Dead entries stay eligible for a later re-probe.
    pub fn prune_dead(&mut self, keep_min: usize) -> usize {
        if self.usable_count() < keep_min {
            return 0;
        }
        let before = self.entries.len();
        // Removing only Dead entries never lowers usable_count, so the keep_min
        // invariant checked above still holds afterward.
        self.entries.retain(|e| e.state != EgressState::Dead);
        before - self.entries.len()
    }

    #[must_use]
    pub fn usable_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_usable()).count()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Mean health across usable entries in `0.0..=1.0` (0 when none usable) —
    /// the operator-facing pool health for the diagnostic bundle.
    #[must_use]
    pub fn avg_health(&self) -> f64 {
        let usable: Vec<&EgressEntry> = self.entries.iter().filter(|e| e.is_usable()).collect();
        if usable.is_empty() {
            return 0.0;
        }
        usable.iter().map(|e| e.health_score()).sum::<f64>() / usable.len() as f64
    }

    /// Specs due for a (re-)validation probe: never-probed, or last-ok older
    /// than `stale_secs`. Bounded to `max` so a background revalidation sweep
    /// can't fan out unboundedly. Read-only.
    #[must_use]
    pub fn due_for_probe(&self, now: u64, stale_secs: u64, max: usize) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| {
                e.state == EgressState::Untested || now.saturating_sub(e.last_ok) >= stale_secs
            })
            .take(max)
            .map(|e| e.spec.clone())
            .collect()
    }

    /// Read-only snapshot for diagnostics: `(spec, state, latency_ms, health)`
    /// per entry, so the debug bundle can render the pool without exposing the
    /// mutable pool or leaking proxy credentials beyond the spec the operator
    /// themselves configured.
    #[must_use]
    pub fn snapshot(&self) -> Vec<(String, EgressState, u32, f64)> {
        self.entries
            .iter()
            .map(|e| (e.spec.clone(), e.state, e.latency_ms, e.health_score()))
            .collect()
    }
}

/// Parse a published proxy-list feed body into specs. Feeds publish one proxy
/// per line as `ip:port`, `scheme://ip:port`, or with creds; comments (`#`) and
/// blanks are skipped. A bare `ip:port` defaults to `http://` (the common feed
/// convention). Pure.
#[must_use]
pub fn parse_feed_body(body: &str) -> Vec<String> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(normalise_feed_line)
        .collect()
}

fn normalise_feed_line(line: &str) -> Option<String> {
    let line = line.split_whitespace().next()?; // first token only
    if line.contains("://") {
        return Some(line.to_string());
    }
    let (host, port) = line.rsplit_once(':')?;
    if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("http://{host}:{port}"))
}

#[cfg(test)]
mod tests {
    include!("pool_tests.rs");
}
