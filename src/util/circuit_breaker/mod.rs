//! Per-host circuit breaker for volatile external HTTP endpoints.
//!
//! A flaky or dead upstream that fails every request still costs a full
//! connect/read budget on each attempt. Under the wide fan-outs HSE runs
//! (`username_search` alone probes dozens of sites), one wedged host can burn a
//! large slice of a low-power Termux scan's time for no possible result. This
//! breaker makes a host that has crossed a consecutive-failure threshold
//! **fail fast**: further requests to it are short-circuited (no socket opened)
//! until a cooldown elapses, after which a single probe (half-open) decides
//! whether to recover (close) or back off again (re-open).
//!
//! Distinct from the engine's per-module circuit breaker
//! (`core::engine::circuit`), which trips a whole *module* by name from the
//! dispatch layer on a classified error message. This one is keyed by *host* and
//! lives at the shared HTTP fetch choke point
//! ([`crate::util::http`]): a single module can touch many hosts and many
//! modules can share one host, so a dead host is skipped regardless of which
//! module reaches for it, and a 429 one scan sees backs every other scan off
//! the same host too.
//!
//! ## Determinism
//!
//! The state machine takes the current time **explicitly** as a Unix-epoch
//! second (`now`) on every method, so the transitions are pure and the tests
//! drive time by passing values rather than sleeping. Callers pass
//! [`crate::core::entity::unix_now`]. Epoch seconds (not [`std::time::Instant`])
//! are used so the time base matches the rest of `util`'s wall-clock state and
//! stays trivially injectable.

use std::collections::HashMap;
use std::sync::LazyLock;

use parking_lot::Mutex;

/// Consecutive transport/server failures to one host before its breaker opens.
///
/// Five tolerates an isolated blip or a couple of unlucky timeouts on a slow
/// mobile link, while still cutting a genuinely dead host loose well within a
/// single deep scan (whose many targets would otherwise each re-pay the wedged
/// host's full timeout). A normal 404 (or any definitive client answer) is a
/// valid result and is *not* counted — only transport errors and server-side
/// faults (5xx / 429) move the counter.
pub const FAILURE_THRESHOLD: u32 = 5;

/// How long an open breaker short-circuits a host before it allows one probe.
///
/// Sixty seconds far outlasts a transient hiccup yet is short enough that a host
/// which recovers mid-run is retried during a long `hse serve`. It auto-clears,
/// so a spike never disables a host permanently. Kept under the common per-host
/// rate-limit reset windows on purpose: the goal is to stop *burning budget*
/// re-hitting a wall, not to model the exact reset of every upstream.
pub const COOLDOWN_SECS: u64 = 60;

/// The three states of a single host's breaker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    /// Healthy: requests flow normally and failures are being counted.
    Closed,
    /// Tripped: requests are short-circuited until `retry_at` (see [`Breaker`]).
    Open,
    /// One probe is permitted to test recovery; its outcome closes or re-opens.
    HalfOpen,
}

/// One host's breaker: a consecutive-failure count, the current [`BreakerState`],
/// and — while [`BreakerState::Open`] — the epoch second at which a probe is next
/// allowed.
#[derive(Debug, Clone, Copy)]
pub struct Breaker {
    state: BreakerState,
    /// Consecutive failures since the last success; drives the trip to
    /// [`BreakerState::Open`] at [`FAILURE_THRESHOLD`].
    consecutive_failures: u32,
    /// Epoch second at which an [`BreakerState::Open`] breaker may probe. Unused
    /// (`0`) in any other state.
    retry_at: u64,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            retry_at: 0,
        }
    }
}

impl Breaker {
    /// A fresh, closed breaker with no recorded failures.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The current state. `Open` here is the *stored* state; it may be eligible
    /// to transition to `HalfOpen` — call [`Breaker::allow`] to act on that.
    #[must_use]
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// Decide whether a request may proceed at epoch second `now`, mutating the
    /// breaker as the state machine requires:
    ///
    /// * `Closed` ⇒ `true` (healthy; let it through).
    /// * `Open` ⇒ `true` **only** once `now` has reached `retry_at`, and in that
    ///   case the breaker transitions to `HalfOpen` so exactly one probe is
    ///   admitted; otherwise `false` (short-circuit, still cooling down).
    /// * `HalfOpen` ⇒ `false` — a probe is already in flight, so concurrent
    ///   callers are denied and the recovering host gets exactly ONE trial
    ///   request, not a thundering herd. (Previously every concurrent caller was
    ///   admitted, defeating the single-probe design and hammering a host that is
    ///   very likely still down.) `retry_at` doubles as the probe *deadline*: if
    ///   the probe's outcome is never recorded — a dropped/cancelled request would
    ///   otherwise wedge the breaker `HalfOpen` forever — a fresh probe is
    ///   admitted one [`COOLDOWN_SECS`] later.
    pub fn allow(&mut self, now: u64) -> bool {
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open => {
                if now >= self.retry_at {
                    self.enter_half_open(now);
                    true
                } else {
                    false
                }
            }
            BreakerState::HalfOpen => {
                // A probe is in flight → deny others. If its outcome was never
                // recorded and the deadline has passed, admit one fresh probe.
                if now >= self.retry_at {
                    self.enter_half_open(now);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Admit a single probe: enter `HalfOpen` and arm the probe deadline one
    /// cooldown out, so a probe whose outcome is never recorded self-heals into a
    /// fresh probe rather than wedging the breaker.
    fn enter_half_open(&mut self, now: u64) {
        self.state = BreakerState::HalfOpen;
        self.retry_at = now.saturating_add(COOLDOWN_SECS);
    }

    /// Record a successful request: the host is healthy, so reset to `Closed`
    /// with a zero failure count (this also closes a `HalfOpen` probe that
    /// succeeded).
    pub fn on_success(&mut self) {
        self.state = BreakerState::Closed;
        self.consecutive_failures = 0;
        self.retry_at = 0;
    }

    /// Record a failed request at epoch second `now`.
    ///
    /// A failure during a `HalfOpen` probe immediately re-opens the breaker for
    /// another [`COOLDOWN_SECS`] (the host is still bad). Otherwise the
    /// consecutive-failure count increments and, at or above
    /// [`FAILURE_THRESHOLD`], the breaker opens with `retry_at = now +
    /// COOLDOWN_SECS`.
    pub fn on_failure(&mut self, now: u64) {
        if self.state == BreakerState::HalfOpen {
            // The lone probe failed → straight back to Open for a fresh cooldown.
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.open_from(now);
            return;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            self.open_from(now);
        }
    }

    /// Record a request the host **explicitly refused as rate-limited** (429)
    /// at epoch second `now`, honouring the cooldown it asked for.
    ///
    /// Distinct from [`on_failure`](Self::on_failure) in both triggers and
    /// timing, because a 429 is a different kind of evidence. A 5xx or a
    /// transport error is a guess about health — one bad node, one unlucky
    /// socket — so it takes [`FAILURE_THRESHOLD`] of them before we conclude
    /// the host is down. A 429 is the server stating its own contract: further
    /// requests *will* be refused, and `Retry-After` says for how long. There
    /// is nothing to accumulate evidence about, so this opens the breaker on
    /// the first one and uses the server's window rather than the local
    /// [`COOLDOWN_SECS`] guess.
    ///
    /// `retry_after_secs` is the caller's already-parsed and already-clamped
    /// hint (see [`crate::util::http::retry_after_secs`], which applies both a
    /// default and a ceiling), floored at one second so a `Retry-After: 0` —
    /// or a caller that passes zero — cannot produce an open breaker that
    /// admits traffic immediately, which would defeat the whole point.
    pub fn on_rate_limited(&mut self, now: u64, retry_after_secs: u64) {
        self.state = BreakerState::Open;
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        self.retry_at = now.saturating_add(retry_after_secs.max(1));
    }

    /// Trip to `Open`, scheduling the next probe one cooldown from `now`.
    fn open_from(&mut self, now: u64) {
        self.state = BreakerState::Open;
        self.retry_at = now.saturating_add(COOLDOWN_SECS);
    }
}

/// Process-global per-host breaker registry.
///
/// Keyed by host string, mirroring the locking idiom of other process-global
/// `util` state (`util::termux`'s unavailable-tool map, `util::key_pool`'s
/// indices): a [`LazyLock`] over a [`parking_lot::Mutex`]. Process-global on
/// purpose — a host's health is a property of the endpoint, not of one scan, so
/// every concurrent scan shares (and benefits from) the same view.
static REGISTRY: LazyLock<Mutex<HashMap<String, Breaker>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Whether a request to `host` may proceed at epoch second `now`.
///
/// Returns `true` for an unknown (never-failed) or closed host — the
/// overwhelmingly common path, costing only a map lookup. An open host returns
/// `false` until its cooldown elapses, then `true` once (transitioning to
/// half-open). See [`Breaker::allow`].
#[must_use]
pub fn allow_host(host: &str, now: u64) -> bool {
    let mut reg = REGISTRY.lock();
    // Entry API: a never-seen host is inserted closed and immediately allowed,
    // with no extra clone or double lookup.
    reg.entry(host.to_owned()).or_default().allow(now)
}

/// Record that a request to `host` succeeded → close and reset its breaker.
pub fn record_success(host: &str) {
    let mut reg = REGISTRY.lock();
    reg.entry(host.to_owned()).or_default().on_success();
}

/// Record that a request to `host` failed (transport error or 5xx / 429) at
/// epoch second `now` → advance its breaker toward / into the open state.
pub fn record_failure(host: &str, now: u64) {
    let mut reg = REGISTRY.lock();
    reg.entry(host.to_owned()).or_default().on_failure(now);
}

/// Record that `host` refused a request as rate-limited (429) at epoch second
/// `now`, backing every caller off for the `retry_after_secs` the server itself
/// asked for. Opens the breaker immediately — see [`Breaker::on_rate_limited`]
/// for why a 429 is not counted toward [`FAILURE_THRESHOLD`] like a 5xx is.
pub fn record_rate_limited(host: &str, now: u64, retry_after_secs: u64) {
    let mut reg = REGISTRY.lock();
    reg.entry(host.to_owned())
        .or_default()
        .on_rate_limited(now, retry_after_secs);
}

/// Snapshot of `host`'s current stored [`BreakerState`], or `None` if the host
/// has no breaker yet. For diagnostics/telemetry; does not mutate or probe.
#[must_use]
pub fn host_state(host: &str) -> Option<BreakerState> {
    REGISTRY.lock().get(host).map(Breaker::state)
}

/// Extract the host component of `url` for keying the breaker.
///
/// Returns the lower-cased host (IPv6 literals keep their brackets, as
/// [`url::Url::host_str`] yields them) so `https://Example.COM/a` and
/// `http://example.com/b` share one breaker. `None` for an unparseable URL or
/// one without a host (e.g. a bare path), in which case the caller leaves the
/// request un-instrumented rather than inventing a key.
#[must_use]
pub fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url.trim())
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
