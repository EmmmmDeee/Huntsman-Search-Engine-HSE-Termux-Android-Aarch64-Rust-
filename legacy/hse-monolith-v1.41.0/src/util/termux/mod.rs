//! Bridge to the on-device **Termux `termux-*` API tools** — the primary
//! deployment target's sensor/telephony surface (`termux-location`,
//! `termux-wifi-scaninfo`, `termux-telephony-cellinfo`, …).
//!
//! Every call goes through [`termux_cmd`], which runs the helper under a hard
//! timeout and caches a failure so a dead sensor never costs its full timeout
//! once per scan — the single biggest per-scan time sink on a phone. Two kinds
//! of failure are cached, and **the distinction between them is load-bearing**:
//!
//! * **The tool would not spawn** (ENOENT: `termux-api` isn't installed, or
//!   this isn't Termux at all). That is a definitive property of the *binary*,
//!   so it is cached for [`ABSENT_TTL`] against the binary name and suppresses
//!   every invocation of it.
//! * **The tool ran but did not answer in time.** That is a property of one
//!   *invocation at one moment* — a GNSS receiver that hasn't locked yet, an OS
//!   Wi-Fi-scan throttle, a busy radio — and it is transient. It is cached
//!   against the exact argv, for [`TIMEOUT_BACKOFF`]'s initial delay, doubling
//!   per consecutive timeout up to its ceiling.
//!
//! Conflating the two is what silently blinded a running radar. Observed over
//! an eight-sweep `hse radar` session: `termux-wifi-scaninfo` returned 12
//! access points on sweep 1, timed out once on sweep 2, and was then skipped
//! for the remaining six sweeps — which reported "no new signals" while no
//! radio had been read at all. A tool that answered a moment ago is not absent.
//!
//! Keying on the argv rather than the binary also un-breaks `signal_radar`'s
//! GNSS ladder ([`crate::modules::signal_radar`]), whose documented design is
//! to fall back from a fresh lock to the OS's near-instant last-known-position
//! cache. Under binary-wide keying the 12 s fresh-lock timeout suppressed the
//! three cheap fallbacks behind it, so the fallback that exists precisely for
//! "no fresh lock available" could never run. The cost of this correctness is
//! explicit: when location is genuinely unavailable, the first sweep now pays
//! each ladder stage's timeout (26 s) instead of only the first (12 s), after
//! which every stage is independently backed off and the steady-state cost
//! converges on the old one.
//!
//! A *prompt* non-zero exit (the tool ran, it just had no data) is NOT
//! penalised, so a responsive-but-empty sensor stays live. The caches are
//! process-global, so a skip is shared across the concurrent sensor modules
//! that call the same tools and persists across scans on a long-running
//! `hse serve` or `hse radar`. Non-Termux platforms simply fail to spawn the
//! tools and degrade cleanly to `None` (cross-platform safe — the sensor
//! modules treat absence as "no signal").
//!
//! [`activity`] reports what the bridge actually did, so a caller can tell
//! "the sensors answered and there was nothing out there" from "the sensors
//! were never consulted" instead of printing the former when it means the
//! latter.

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::timeout;

use crate::util::backoff::BackoffPolicy;

/// How long a `termux-*` binary that would not spawn is skipped before we
/// re-probe it. ENOENT means the `termux-api` package is absent, which the
/// operator can fix mid-session (`pkg install termux-api`), so this expires
/// rather than latching: five minutes costs one wasted spawn per sensor per
/// five minutes while never permanently disabling a tool.
const ABSENT_TTL: Duration = Duration::from_secs(300);

/// Re-probe schedule for an invocation that *timed out*, as a delay ladder:
/// 30 s, then 60 / 120 / 240, capped at 300 s.
///
/// A timeout is transient by nature, so the first backoff is short — short
/// enough that a Wi-Fi scan the OS throttled, or a GNSS fix that had not landed
/// yet, is retried within a sweep or two rather than being written off for five
/// minutes. Escalation is what keeps the original win: a permission that is
/// genuinely ungranted keeps timing out and reaches the same 300 s ceiling
/// within a couple of minutes, so the pathological case still costs its full
/// timeout only rarely.
///
/// Only the delay ladder is used here — this is a re-probe schedule, not a
/// retry loop, so [`BackoffPolicy::max_attempts`] bounds nothing; it is set to
/// the number of steps the ladder takes to reach its ceiling.
const TIMEOUT_BACKOFF: BackoffPolicy = BackoffPolicy::new(5, 30_000, 300_000, false);

/// Everything the bridge remembers, behind one lock so a call's skip decision
/// and its activity accounting can't interleave.
#[derive(Default)]
struct State {
    /// `binary name -> instant after which it may be re-probed`. Populated only
    /// by a spawn failure, which is a property of the binary itself.
    absent: HashMap<String, Instant>,
    /// `full argv -> backoff`. Populated only by a timeout, which is a property
    /// of the individual invocation.
    timed_out: HashMap<String, Backoff>,
    activity: Activity,
    /// The same tally, split per `termux-*` binary.
    ///
    /// The aggregate above answers "did this sweep read ANY radio?", which is
    /// too coarse for a caller that speaks for ONE of them: a successful
    /// `termux-wifi-scaninfo` makes `reads > 0`, masking a Bluetooth tool that
    /// was skipped or failed in the same window. A per-radio display that
    /// trusted the aggregate would then report "nothing nearby" for a radio it
    /// never actually read — asserting an observation of absence from an absence
    /// of observation, the one thing this accounting exists to prevent.
    by_tool: HashMap<String, Activity>,
}

/// One invocation's timeout backoff: when it may next be attempted, and how
/// many consecutive timeouts have escalated it to that point.
#[derive(Clone, Copy)]
struct Backoff {
    until: Instant,
    consecutive: u32,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| Mutex::new(State::default()));

fn state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the Termux bridge actually did, as monotonic process-wide counters.
///
/// The three outcomes are kept apart because collapsing them loses the only
/// thing a caller needs to report honestly: whether an empty result means the
/// radios were read and were quiet, or that they were never read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Activity {
    /// Calls that ran the tool and got usable output back.
    pub reads: u64,
    /// Calls short-circuited by the skip caches — the tool was never run.
    pub skipped: u64,
    /// Calls that ran the tool and got nothing usable back (timed out, would
    /// not spawn, or exited non-zero).
    pub failed: u64,
}

impl Activity {
    /// This snapshot minus an `earlier` one: what happened in between. Saturating,
    /// so a caller that mixes up the operand order gets zeroes rather than a panic.
    #[must_use]
    pub const fn since(self, earlier: Self) -> Self {
        Self {
            reads: self.reads.saturating_sub(earlier.reads),
            skipped: self.skipped.saturating_sub(earlier.skipped),
            failed: self.failed.saturating_sub(earlier.failed),
        }
    }

    /// True when the tools were called for but nothing was read: no successful
    /// read, and at least one call skipped or failed. An empty result over this
    /// window is an absence of *observation*, not an observation of absence —
    /// the two must not be reported the same way.
    #[must_use]
    pub const fn took_no_readings(self) -> bool {
        self.reads == 0 && (self.skipped > 0 || self.failed > 0)
    }

    /// True when nothing happened at all — no call was made in this window.
    #[must_use]
    pub const fn is_idle(self) -> bool {
        self.reads == 0 && self.skipped == 0 && self.failed == 0
    }
}

/// A snapshot of the process-wide [`Activity`] counters. Take one before a
/// sweep and one after, then [`Activity::since`] to get that sweep's tally.
#[must_use]
pub fn activity() -> Activity {
    state().activity
}

/// The [`Activity`] tally for ONE `termux-*` binary (e.g.
/// `"termux-bluetooth-scaninfo"`), or an all-zero tally if it was never called.
///
/// Use this instead of [`activity`] whenever the caller speaks for a single
/// radio. The aggregate cannot answer "was *Bluetooth* read?" — a successful
/// Wi-Fi scan in the same window sets `reads > 0` and masks a Bluetooth tool
/// that was skipped or failed, so a per-radio display trusting it would report
/// "nothing nearby" for a radio it never read.
///
/// Snapshot before and after a sweep and use [`Activity::since`], exactly as
/// with the aggregate.
#[must_use]
pub fn activity_for(tool: &str) -> Activity {
    state().by_tool.get(tool).copied().unwrap_or_default()
}

/// The skip-cache key for a timeout: the exact invocation, not the binary.
///
/// `termux-location -p gps -r once` (a 12 s wait for a fresh satellite lock)
/// and `termux-location -p network -r last` (an instant read of the OS position
/// cache) are different questions with different costs and different failure
/// modes. The first timing out says nothing whatsoever about the second.
fn invocation_key(cmd: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return cmd.to_string();
    }
    let mut key =
        String::with_capacity(cmd.len() + args.iter().map(|a| a.len() + 1).sum::<usize>());
    key.push_str(cmd);
    for arg in args {
        key.push(' ');
        key.push_str(arg);
    }
    key
}

/// Why this invocation must be short-circuited, if it must be. Counts the skip
/// under the same lock that decides it.
fn check_skip(cmd: &str, args: &[&str], now: Instant) -> Option<&'static str> {
    let mut st = state();
    let reason = if st.absent.get(cmd).is_some_and(|&until| now < until) {
        "tool absent (would not spawn)"
    } else if st
        .timed_out
        .get(&invocation_key(cmd, args))
        .is_some_and(|b| now < b.until)
    {
        "backing off after timeout"
    } else {
        return None;
    };
    st.activity.skipped += 1;
    st.by_tool.entry(cmd.to_string()).or_default().skipped += 1;
    Some(reason)
}

/// Record that `cmd` would not spawn: the binary is absent, so suppress every
/// invocation of it for [`ABSENT_TTL`].
fn record_absent(cmd: &str, now: Instant) {
    let mut st = state();
    st.absent.insert(cmd.to_string(), now + ABSENT_TTL);
    st.activity.failed += 1;
    st.by_tool.entry(cmd.to_string()).or_default().failed += 1;
}

/// Record that this exact invocation timed out, escalating its backoff one step
/// along [`TIMEOUT_BACKOFF`]'s ladder. Returns the delay applied, for the log.
fn record_timeout(cmd: &str, args: &[&str], now: Instant) -> Duration {
    let mut st = state();
    let entry = st
        .timed_out
        .entry(invocation_key(cmd, args))
        .or_insert(Backoff {
            until: now,
            consecutive: 0,
        });
    entry.consecutive = entry.consecutive.saturating_add(1);
    // `consecutive` is 1-based (this is the first timeout) and the ladder is
    // 0-indexed, so the first timeout draws the initial delay.
    let delay = TIMEOUT_BACKOFF.delay(entry.consecutive - 1);
    entry.until = now + delay;
    st.activity.failed += 1;
    st.by_tool.entry(cmd.to_string()).or_default().failed += 1;
    delay
}

/// Record that the tool ran and answered promptly, whatever it answered. That
/// proves the binary exists (clearing any absence mark) and that *this*
/// invocation is responsive (clearing its timeout backoff, so the ladder starts
/// from the bottom next time). It deliberately does not clear a sibling
/// invocation's backoff — a fast cache read succeeding says nothing about a
/// slow fresh lock.
fn record_responsive(cmd: &str, args: &[&str], read: bool) {
    let mut st = state();
    st.absent.remove(cmd);
    st.timed_out.remove(&invocation_key(cmd, args));
    // Bump the aggregate first, then the per-tool tally: `st` is a `MutexGuard`,
    // so holding a `&mut` into one field across an access to another goes
    // through `DerefMut` twice and does not borrow-split.
    if read {
        st.activity.reads += 1;
    } else {
        st.activity.failed += 1;
    }
    let per_tool = st.by_tool.entry(cmd.to_string()).or_default();
    if read {
        per_tool.reads += 1;
    } else {
        per_tool.failed += 1;
    }
}

/// Run a `termux-*` helper with a hard timeout, returning its stdout on a clean
/// exit. A tool that would not spawn is cached as absent for [`ABSENT_TTL`]; an
/// invocation that timed out is backed off along [`TIMEOUT_BACKOFF`]'s ladder.
/// Either way the cost of a dead sensor is paid rarely rather than once per
/// scan — without a transient stall being mistaken for a missing tool.
pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
    let now = Instant::now();
    if let Some(reason) = check_skip(cmd, args, now) {
        tracing::debug!(cmd, reason, "termux_cmd: skipped");
        return None;
    }
    let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
    match timeout(Duration::from_millis(timeout_ms), fut).await {
        Err(_) => {
            let backoff = record_timeout(cmd, args, Instant::now());
            tracing::debug!(
                cmd,
                backoff_secs = backoff.as_secs(),
                "termux_cmd: timed out after {timeout_ms}ms"
            );
            None
        }
        Ok(Err(e)) => {
            tracing::debug!(cmd, error = %e, "termux_cmd: spawn/io failed");
            record_absent(cmd, Instant::now());
            None
        }
        Ok(Ok(output)) if !output.status.success() => {
            // A non-zero exit is a real, prompt run (tool present, just no
            // data / a handled error) — responsive, so do NOT penalise it.
            tracing::debug!(cmd, code = ?output.status.code(), "termux_cmd: non-zero exit");
            record_responsive(cmd, args, false);
            None
        }
        Ok(Ok(output)) => {
            record_responsive(cmd, args, true);
            Some(output.stdout)
        }
    }
}

/// Test-only accessor: was `cmd` cached as unavailable by a real `termux_cmd`
/// call — either absent (spawn failure) or backing off (timeout)? Lets a
/// sibling module's test pin "did this code path actually invoke the tool"
/// against the real, process-global caches instead of re-implementing them.
#[cfg(test)]
pub(crate) fn is_marked_unavailable_for_test(cmd: &str) -> bool {
    let st = state();
    st.absent.contains_key(cmd) || st.timed_out.contains_key(cmd)
}

/// Test-only accessor: clear any cached mark for `cmd` (both the binary-wide
/// absence and the bare-argv timeout backoff), so a test starts from a known
/// state regardless of what earlier tests in the same process did to the
/// shared, process-global [`STATE`].
#[cfg(test)]
pub(crate) fn clear_unavailable_for_test(cmd: &str) {
    let mut st = state();
    st.absent.remove(cmd);
    st.timed_out.remove(cmd);
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
