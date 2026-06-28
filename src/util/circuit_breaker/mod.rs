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
///
/// This is the *base* cooldown for the first open cycle. A host that re-opens
/// repeatedly (its probe keeps failing) backs off exponentially up to
/// [`MAX_COOLDOWN_SECS`] — see [`Breaker::cooldown_for_cycle`] — so a genuinely
/// dead host stops being re-probed every minute for the life of an `hse serve`.
pub const COOLDOWN_SECS: u64 = 60;

/// Ceiling on the exponential backoff applied to a host that re-opens
/// repeatedly.
///
/// Sixteen minutes (`60 · 2⁴`) caps the doubling so even a host that has been
/// dead for hours is still re-probed a few times an hour — enough to notice a
/// recovery during a long-running `hse serve` without re-paying its full
/// timeout every minute. Past this the cooldown stays flat.
pub const MAX_COOLDOWN_SECS: u64 = COOLDOWN_SECS << 4;

/// Soft ceiling on the number of live per-host breaker entries.
///
/// A wide scan (`username_search` alone fans out across dozens of sites) plus
/// every transient/typo host a long `hse serve` ever touches would otherwise
/// accumulate one permanent entry each. When an *insert of a new host* would
/// push the map past this, idle healthy entries are pruned first (see
/// [`prune_idle`]). Closed-and-clean entries carry no state worth keeping, so
/// dropping them is lossless: the host simply re-defaults to closed next touch.
/// Chosen generously so a normal scan's working set never triggers a prune,
/// while still bounding memory on a 4 GB Termux device to a few hundred small
/// entries.
pub const MAX_ENTRIES: usize = 4096;

/// How long a `Closed` breaker may sit untouched before it is eligible for
/// eviction once the registry is over [`MAX_ENTRIES`].
///
/// Ten minutes outlasts any single scan's fan-out, so an entry pruned here is
/// genuinely cold — re-creating it costs one default insert. Only `Closed`
/// entries are ever pruned; an `Open` / `HalfOpen` host still carries live
/// cooldown state and is kept regardless of idle time.
pub const IDLE_TTL_SECS: u64 = 600;

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
    /// Number of times this breaker has opened without an intervening success.
    /// Drives the exponential backoff in [`Breaker::cooldown_for_cycle`] and lets
    /// telemetry tell a briefly-flaky host (1 cycle) from a long-dead one (many).
    /// Reset to `0` on success, alongside [`Breaker::consecutive_failures`].
    open_cycles: u32,
    /// Epoch second at which an [`BreakerState::Open`] breaker may probe. Unused
    /// (`0`) in any other state.
    retry_at: u64,
    /// Epoch second of the most recent state-affecting touch (allow / success /
    /// failure). Used only by the registry's idle-eviction pass ([`prune_idle`])
    /// to age out cold `Closed` entries; never affects the state machine.
    last_touch: u64,
}

impl Default for Breaker {
    fn default() -> Self {
        Self {
            state: BreakerState::Closed,
            consecutive_failures: 0,
            open_cycles: 0,
            retry_at: 0,
            last_touch: 0,
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

    /// Whether this breaker is in its quiescent ground state — `Closed`, with no
    /// recorded failures and no remembered open cycles.
    ///
    /// Such an entry is byte-for-byte a freshly defaulted [`Breaker`] (modulo
    /// `last_touch`), so it carries no information: dropping it from the registry
    /// and re-defaulting it on the next touch is lossless. The registry uses this
    /// to keep the map bounded (see [`prune_idle`] and [`record_success`]).
    #[must_use]
    pub fn is_clean_closed(&self) -> bool {
        self.state == BreakerState::Closed
            && self.consecutive_failures == 0
            && self.open_cycles == 0
    }

    /// Consecutive open cycles without an intervening success (`0` for a host
    /// that has never tripped). Exposed for telemetry so a long-dead host — many
    /// cycles, each backing off further per [`Breaker::cooldown_for_cycle`] — is
    /// distinguishable from a host that blipped open once and recovered.
    #[must_use]
    pub fn open_cycles(&self) -> u32 {
        self.open_cycles
    }

    /// Decide whether a request may proceed at epoch second `now`, mutating the
    /// breaker as the state machine requires:
    ///
    /// * `Closed` / `HalfOpen` ⇒ `true` (let it through; `HalfOpen` already
    ///   represents the one in-flight probe).
    /// * `Open` ⇒ `true` **only** once `now` has reached `retry_at`, and in that
    ///   case the breaker transitions to `HalfOpen` so exactly one probe is
    ///   admitted; otherwise `false` (short-circuit, still cooling down).
    pub fn allow(&mut self, now: u64) -> bool {
        self.last_touch = now;
        match self.state {
            BreakerState::Closed | BreakerState::HalfOpen => true,
            BreakerState::Open => {
                if now >= self.retry_at {
                    self.state = BreakerState::HalfOpen;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Record a successful request at epoch second `now`: the host is healthy, so
    /// reset to `Closed` with a zero failure count and a cleared backoff (this
    /// also closes a `HalfOpen` probe that succeeded).
    pub fn on_success(&mut self, now: u64) {
        self.state = BreakerState::Closed;
        self.consecutive_failures = 0;
        self.open_cycles = 0;
        self.retry_at = 0;
        self.last_touch = now;
    }

    /// Record a failed request at epoch second `now`.
    ///
    /// A failure during a `HalfOpen` probe immediately re-opens the breaker for a
    /// fresh — and, after repeated re-opens, progressively longer — cooldown (the
    /// host is still bad). Otherwise the consecutive-failure count increments and,
    /// at or above [`FAILURE_THRESHOLD`], the breaker opens with `retry_at = now +
    /// cooldown_for_cycle()`.
    pub fn on_failure(&mut self, now: u64) {
        self.last_touch = now;
        if self.state == BreakerState::HalfOpen {
            // The lone probe failed → straight back to Open for a fresh (longer)
            // cooldown.
            self.consecutive_failures = self.consecutive_failures.saturating_add(1);
            self.open_from(now);
            return;
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        if self.consecutive_failures >= FAILURE_THRESHOLD {
            self.open_from(now);
        }
    }

    /// Cooldown, in seconds, for the *next* open cycle: [`COOLDOWN_SECS`] doubled
    /// once per prior open cycle, clamped to [`MAX_COOLDOWN_SECS`].
    ///
    /// Cycle 0 (the first trip) → `COOLDOWN_SECS`; cycle 1 → `2·`; cycle 2 →
    /// `4·`; … flattening at [`MAX_COOLDOWN_SECS`]. A flat 60 s wastes budget
    /// re-probing a permanently-dead host every minute; doubling lets a genuinely
    /// dead host back off while a host that recovers (success ⇒ `open_cycles = 0`)
    /// pays the short cooldown again next time.
    #[must_use]
    fn cooldown_for_cycle(&self) -> u64 {
        // Shift caps at 6 because `COOLDOWN_SECS << 6` already exceeds
        // MAX_COOLDOWN_SECS; clamping the shift keeps the `<<` well-defined and
        // the result is min'd to the ceiling regardless.
        let shift = self.open_cycles.min(6);
        COOLDOWN_SECS
            .saturating_mul(1u64 << shift)
            .min(MAX_COOLDOWN_SECS)
    }

    /// Trip to `Open`, counting the cycle and scheduling the next probe one
    /// (backoff-scaled) cooldown from `now`.
    fn open_from(&mut self, now: u64) {
        self.retry_at = now.saturating_add(self.cooldown_for_cycle());
        self.state = BreakerState::Open;
        self.open_cycles = self.open_cycles.saturating_add(1);
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

/// Drop cold `Closed`-and-clean entries from `reg` to keep it bounded.
///
/// Called from the *cold* insert branch (a host with no entry yet) only when the
/// map is already at [`MAX_ENTRIES`]: an `Open` / `HalfOpen` host, or a `Closed`
/// host still carrying a failure streak / open-cycle history, holds live state
/// and is **never** pruned. A clean `Closed` entry is retained only while it is
/// fresh — within [`IDLE_TTL_SECS`] of its `last_touch` at `now` — so an active
/// scan's working set survives while genuinely cold entries age out. Re-creating
/// a pruned host is a single default insert, so the prune is lossless.
///
/// If nothing is idle enough to drop (every entry is live or recently touched),
/// the map is allowed to exceed the soft cap rather than evict useful state —
/// [`MAX_ENTRIES`] is a target, not a hard wall, and the next idle pass reclaims
/// the space.
fn prune_idle(reg: &mut HashMap<String, Breaker>, now: u64) {
    reg.retain(|_host, b| {
        if !b.is_clean_closed() {
            return true; // live cooldown / failure state — keep.
        }
        // Clean Closed: keep only if touched within the idle TTL. `saturating_sub`
        // guards a `last_touch` somehow ahead of `now` (clock skew) → treated as
        // freshly touched (age 0), so it is retained.
        now.saturating_sub(b.last_touch) < IDLE_TTL_SECS
    });
}

/// Look up `host`'s breaker for a mutation, inserting a fresh `Closed` one if
/// absent, and apply `f` to it.
///
/// The hot path is a host that already has an entry: a borrow-keyed
/// [`HashMap::get_mut`] with `&str` touches it with **no** allocation. Only the
/// cold "first time we've seen this host" branch pays a `to_owned()` for the
/// owned `String` key — and that branch first runs [`prune_idle`] if the map is
/// at its soft cap, so the registry stays bounded under HSE's wide fan-outs and
/// a long-running `hse serve`'s endless parade of transient hosts.
fn with_breaker<R>(host: &str, now: u64, f: impl FnOnce(&mut Breaker) -> R) -> R {
    let mut reg = REGISTRY.lock();
    if let Some(b) = reg.get_mut(host) {
        return f(b);
    }
    // Cold branch: unknown host. Keep the map bounded before inserting.
    if reg.len() >= MAX_ENTRIES {
        prune_idle(&mut reg, now);
    }
    f(reg.entry(host.to_owned()).or_default())
}

/// Whether a request to `host` may proceed at epoch second `now`.
///
/// Returns `true` for an unknown (never-failed) or closed host — the
/// overwhelmingly common path, costing only a borrow-keyed map lookup (no
/// allocation when the host is already known). An open host returns `false`
/// until its cooldown elapses, then `true` once (transitioning to half-open).
/// See [`Breaker::allow`].
#[must_use]
pub fn allow_host(host: &str, now: u64) -> bool {
    with_breaker(host, now, |b| b.allow(now))
}

/// Record that a request to `host` succeeded → close and reset its breaker.
///
/// If the success leaves the breaker in its clean ground state (the common
/// case — a healthy host that never tripped), its entry is dropped outright
/// rather than left as a permanent zero-information row: it would re-default
/// identically on the next touch. This is the primary bound on registry growth
/// for the healthy-host majority.
pub fn record_success(host: &str, now: u64) {
    let mut reg = REGISTRY.lock();
    let Some(b) = reg.get_mut(host) else {
        // Unknown host succeeding is already the ground state — nothing to store.
        return;
    };
    b.on_success(now);
    if b.is_clean_closed() {
        reg.remove(host);
    }
}

/// Record that a request to `host` failed (transport error or 5xx / 429) at
/// epoch second `now` → advance its breaker toward / into the open state.
pub fn record_failure(host: &str, now: u64) {
    with_breaker(host, now, |b| b.on_failure(now));
}

/// Snapshot of `host`'s current stored [`BreakerState`], or `None` if the host
/// has no breaker yet. For diagnostics/telemetry; does not mutate or probe.
#[must_use]
pub fn host_state(host: &str) -> Option<BreakerState> {
    REGISTRY.lock().get(host).map(Breaker::state)
}

/// Snapshot of `host`'s open-cycle count — how many times its breaker has
/// tripped without an intervening success — or `None` if the host has no breaker
/// yet. `0` means healthy / never-tripped; a high value flags a long-dead host
/// (each cycle backs off further per [`Breaker::cooldown_for_cycle`]). For
/// diagnostics/telemetry; does not mutate or probe.
#[must_use]
pub fn host_open_cycles(host: &str) -> Option<u32> {
    REGISTRY.lock().get(host).map(Breaker::open_cycles)
}

/// Number of live per-host breaker entries currently retained. For diagnostics
/// and the eviction tests; the value drifts as hosts are touched and pruned.
#[must_use]
pub fn registry_len() -> usize {
    REGISTRY.lock().len()
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
