//! Scan-scoped adaptive circuit breaker for the keyless search engines.
//!
//! The primary search loop already skips an engine for the rest of a single
//! target dispatch once it fails first contact (the `dead_engines` set in
//! [`super`]'s `process`). But that memory is local to one `process()` call, so
//! a multi-target scan (depth ≥ 1 expansion) re-probes every dead engine once
//! per target — and a network-*timeout* engine (a host that never answers from
//! this egress IP) re-incurs its full per-request timeout on every dispatch.
//!
//! Real execution measured the cost: across a depth-1 scan's ~43 target
//! dispatches an always-timing-out engine (DuckDuckGo, ~8 s) spent its timeout
//! ~43 times — hundreds of seconds of dead wait that produced nothing, while
//! the deadness was perfectly deterministic (0 % success across 43 in-scan
//! probes and 7 independent `hse engines` sweeps).
//!
//! This breaker lifts the memory to *scan* scope. The decision is gated on real
//! productivity, so it can never mute an engine that yields results:
//!
//! * any time an engine produces a result (at any query position) it is marked
//!   productive for the rest of the scan and is **never** muted — this protects
//!   a flaky-but-valuable engine (e.g. one that blocks some heavy dork queries
//!   yet answers others);
//! * an engine that has produced *nothing* and has failed first contact in
//!   [`MUTE_THRESHOLD`] dispatches of the scan is muted for the remainder of
//!   that scan.
//!
//! Nothing is hardcoded about *which* engines are dead — the set is learned at
//! runtime, so the breaker adapts to each host's egress (a datacenter IP and a
//! Termux residential connection mute different engines) and re-probes fresh on
//! the next scan. State is keyed by `scan_id` and bounded
//! ([`MAX_TRACKED_SCANS`], FIFO-evicted) so a long-running `hse serve` process
//! cannot accumulate it without bound. On lock poisoning every operation
//! degrades to a no-op, so the breaker can only ever *reduce* wasted work — it
//! never changes which results a scan can find.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};

/// Consecutive first-contact failures (with zero lifetime production) an engine
/// must accrue within one scan before it is muted. `> 1` so a single transient
/// blip on the opening query never mutes an engine on its own; combined with the
/// productivity gate (any result clears it forever) this makes a false mute of a
/// working engine effectively impossible while still cutting a deterministically
/// dead engine after at most two probes.
const MUTE_THRESHOLD: u32 = 2;

/// Maximum number of distinct scans whose breaker state is retained at once,
/// FIFO-evicted. Far above the number of scans realistically in flight in
/// `hse serve`; bounds memory so the process-global registry can't grow without
/// limit over a long uptime.
const MAX_TRACKED_SCANS: usize = 64;

/// Per-engine breaker state within a single scan.
#[derive(Default, Clone, Copy)]
struct EngineState {
    /// Set once the engine returns any result in this scan — a productive engine
    /// is never muted, whatever its first-contact failure count.
    produced_ever: bool,
    /// Count of dispatches whose opening (first-contact) query this engine
    /// failed, while still having produced nothing.
    first_contact_fails: u32,
}

impl EngineState {
    fn muted(self) -> bool {
        !self.produced_ever && self.first_contact_fails >= MUTE_THRESHOLD
    }
}

/// Process-global registry of per-scan breaker state, with FIFO insertion order
/// for bounded eviction.
struct Registry {
    order: VecDeque<String>,
    by_scan: HashMap<String, HashMap<&'static str, EngineState>>,
}

static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    Mutex::new(Registry {
        order: VecDeque::new(),
        by_scan: HashMap::new(),
    })
});

/// Record one primary-pass fetch result for `engine` under `scan_id`.
/// `produced` is whether the fetch yielded any usable results; `first_contact`
/// is whether this was the dispatch's opening query (only those count toward the
/// failure threshold). No-op on lock poisoning.
pub(super) fn record(scan_id: &str, engine: &'static str, produced: bool, first_contact: bool) {
    let Ok(mut reg) = REGISTRY.lock() else {
        return;
    };
    if !reg.by_scan.contains_key(scan_id) {
        while reg.order.len() >= MAX_TRACKED_SCANS {
            match reg.order.pop_front() {
                Some(old) => {
                    reg.by_scan.remove(&old);
                }
                None => break,
            }
        }
        reg.order.push_back(scan_id.to_string());
    }
    let st = reg
        .by_scan
        .entry(scan_id.to_string())
        .or_default()
        .entry(engine)
        .or_default();
    if produced {
        st.produced_ever = true;
    } else if first_contact {
        st.first_contact_fails += 1;
    }
}

/// The set of engines currently muted for `scan_id` — those to skip entirely on
/// this dispatch. Empty for an unknown scan or on lock poisoning.
pub(super) fn muted_engines(scan_id: &str) -> HashSet<&'static str> {
    let Ok(reg) = REGISTRY.lock() else {
        return HashSet::new();
    };
    reg.by_scan
        .get(scan_id)
        .map(|engines| {
            engines
                .iter()
                .filter(|(_, st)| st.muted())
                .map(|(&name, _)| name)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests in this module: they exercise one process-global
    /// registry whose FIFO eviction (`registry_is_bounded_under_many_scans`)
    /// could otherwise drop a sibling test's entry mid-run under cargo's parallel
    /// test harness. Production needs no such lock — concurrent scans use
    /// distinct ids and the cap is far above any real in-flight count.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Acquire the serialisation lock, recovering it if a previous test panicked
    /// while holding it (a poisoned guard still serialises correctly).
    fn guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Drop any retained state for a scan id so a test starts clean regardless
    /// of other tests sharing this process-global registry.
    fn reset(scan_id: &str) {
        if let Ok(mut reg) = REGISTRY.lock() {
            reg.by_scan.remove(scan_id);
            reg.order.retain(|s| s != scan_id);
        }
    }

    fn tracked_scan_count() -> usize {
        REGISTRY.lock().map(|r| r.by_scan.len()).unwrap_or(0)
    }

    #[test]
    fn deterministically_dead_engine_is_muted_after_threshold() {
        let _g = guard();
        let scan = "breaker-test-dead";
        reset(scan);
        // Below threshold: tolerated (a transient blip must not mute on its own).
        for _ in 0..MUTE_THRESHOLD - 1 {
            record(scan, "google", false, true);
            assert!(!muted_engines(scan).contains("google"));
        }
        record(scan, "google", false, true); // threshold reached
        assert!(muted_engines(scan).contains("google"));
        reset(scan);
    }

    #[test]
    fn a_single_result_protects_an_engine_forever() {
        let _g = guard();
        let scan = "breaker-test-productive";
        reset(scan);
        // One real result, then many first-contact failures: never muted, because
        // the engine has proven it can yield (the flaky-but-valuable case).
        record(scan, "bing", true, true);
        for _ in 0..MUTE_THRESHOLD + 5 {
            record(scan, "bing", false, true);
        }
        assert!(
            !muted_engines(scan).contains("bing"),
            "an engine that ever produced a result must never be muted"
        );
        reset(scan);
    }

    #[test]
    fn non_first_contact_failures_do_not_count() {
        let _g = guard();
        let scan = "breaker-test-noncontact";
        reset(scan);
        // Failures on later queries (first_contact=false) never accrue.
        for _ in 0..MUTE_THRESHOLD + 3 {
            record(scan, "mojeek", false, false);
        }
        assert!(!muted_engines(scan).contains("mojeek"));
        reset(scan);
    }

    #[test]
    fn replaying_real_observed_outcomes_mutes_only_the_dead_set() {
        let _g = guard();
        // Outcome pattern taken verbatim from the 7-sweep `hse engines` aggregate:
        // the dead set never produced; the reliable set always produced.
        let scan = "breaker-test-real";
        reset(scan);
        let dead = [
            "google",
            "yandex",
            "brave",
            "mojeek",
            "startpage",
            "yahoo",
            "aol",
            "you",
            "qwant",
            "presearch",
            "searx",
            "duckduckgo",
        ];
        let reliable = ["bing", "dogpile", "metager", "swisscows"];
        for _dispatch in 0..7 {
            for e in dead {
                record(scan, e, false, true);
            }
            for e in reliable {
                record(scan, e, true, true);
            }
        }
        let muted = muted_engines(scan);
        for e in dead {
            assert!(
                muted.contains(e),
                "deterministically dead engine {e} must be muted"
            );
        }
        for e in reliable {
            assert!(
                !muted.contains(e),
                "reliable engine {e} must never be muted"
            );
        }
        reset(scan);
    }

    #[test]
    fn registry_is_bounded_under_many_scans() {
        let _g = guard();
        for i in 0..MAX_TRACKED_SCANS + 25 {
            record(&format!("breaker-bound-{i}"), "google", false, true);
        }
        assert!(
            tracked_scan_count() <= MAX_TRACKED_SCANS,
            "registry must stay within its FIFO cap"
        );
    }
}
