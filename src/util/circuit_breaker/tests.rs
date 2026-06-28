// Tests for the per-host circuit breaker. All transitions are driven by
// explicit `now` epoch-second values — no sleeping, no wall-clock reads — so the
// suite is fully deterministic.
use super::*;

/// Base epoch second for the time-driven tests; any fixed value works since the
/// state machine only compares relative to the `now` it is handed.
const T0: u64 = 1_000_000;

// ── Pure state machine ────────────────────────────────────────────────────────

#[test]
fn new_breaker_is_closed_and_allows() {
    let mut b = Breaker::new();
    assert_eq!(b.state(), BreakerState::Closed);
    assert!(b.allow(T0), "a fresh breaker lets requests through");
}

#[test]
fn closed_opens_after_threshold_consecutive_failures() {
    let mut b = Breaker::new();
    // One short of the threshold: still closed, still allowing.
    for _ in 0..(FAILURE_THRESHOLD - 1) {
        b.on_failure(T0);
        assert_eq!(b.state(), BreakerState::Closed);
        assert!(b.allow(T0));
    }
    // The threshold-th consecutive failure trips it.
    b.on_failure(T0);
    assert_eq!(b.state(), BreakerState::Open);
}

#[test]
fn open_short_circuits_until_cooldown_elapses() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert_eq!(b.state(), BreakerState::Open);

    // Before the cooldown: short-circuited, and still Open (no transition).
    assert!(!b.allow(T0), "open breaker fails fast immediately after tripping");
    assert!(!b.allow(T0 + COOLDOWN_SECS - 1), "still cooling down one second early");
    assert_eq!(b.state(), BreakerState::Open);
}

#[test]
fn after_cooldown_allows_once_and_goes_half_open() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    // At exactly retry_at the probe is admitted and the state becomes HalfOpen.
    assert!(b.allow(T0 + COOLDOWN_SECS), "probe admitted once the cooldown passes");
    assert_eq!(b.state(), BreakerState::HalfOpen);
    // HalfOpen keeps allowing (it represents the one in-flight probe) — the
    // outcome, not a second allow, decides the next state.
    assert!(b.allow(T0 + COOLDOWN_SECS));
}

#[test]
fn success_in_half_open_closes_and_resets() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert!(b.allow(T0 + COOLDOWN_SECS));
    assert_eq!(b.state(), BreakerState::HalfOpen);

    b.on_success(T0 + COOLDOWN_SECS);
    assert_eq!(b.state(), BreakerState::Closed);
    // Counter was reset: it now takes a fresh full streak to re-open.
    for _ in 0..(FAILURE_THRESHOLD - 1) {
        b.on_failure(T0 + COOLDOWN_SECS + 1);
        assert_eq!(b.state(), BreakerState::Closed);
    }
}

#[test]
fn failure_in_half_open_reopens_for_a_fresh_cooldown() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    let probe_at = T0 + COOLDOWN_SECS;
    assert!(b.allow(probe_at));
    assert_eq!(b.state(), BreakerState::HalfOpen);

    // The single probe failed → straight back to Open, cooling from `probe_at`.
    // This is the *second* open cycle, so the backoff doubles the wait to
    // `2 · COOLDOWN_SECS` (a host whose recovery probe keeps failing is given
    // progressively longer to settle — see `cooldown_doubles_each_open_cycle…`).
    b.on_failure(probe_at);
    assert_eq!(b.state(), BreakerState::Open);
    let reopen_cooldown = 2 * COOLDOWN_SECS;
    assert!(!b.allow(probe_at), "re-opened: short-circuits again immediately");
    assert!(
        !b.allow(probe_at + reopen_cooldown - 1),
        "fresh (doubled) cooldown from the probe time"
    );
    assert!(
        b.allow(probe_at + reopen_cooldown),
        "probe admitted again after the new, longer cooldown"
    );
    assert_eq!(b.state(), BreakerState::HalfOpen);
}

#[test]
fn single_success_resets_failure_counter_while_closed() {
    let mut b = Breaker::new();
    // Accumulate failures just under the threshold, then succeed.
    for _ in 0..(FAILURE_THRESHOLD - 1) {
        b.on_failure(T0);
    }
    assert_eq!(b.state(), BreakerState::Closed);
    b.on_success(T0);

    // The streak was wiped: a single further failure must NOT trip it (it would
    // have, were the earlier near-threshold failures still counted).
    b.on_failure(T0 + 1);
    assert_eq!(
        b.state(),
        BreakerState::Closed,
        "a success while closed must zero the consecutive-failure count"
    );
}

// ── Process-global registry free functions ────────────────────────────────────

#[test]
fn registry_isolates_distinct_hosts() {
    // Hostnames unique to this test so the process-global registry can't be
    // perturbed by (or perturb) any other test.
    let bad = "cb-test-bad.example";
    let good = "cb-test-good.example";

    // Trip `bad`'s breaker; `good` is never touched here.
    for _ in 0..FAILURE_THRESHOLD {
        record_failure(bad, T0);
    }
    assert!(!allow_host(bad, T0), "the failed host is short-circuited");
    assert_eq!(host_state(bad), Some(BreakerState::Open));
    // `bad`'s failures did not bleed into an unrelated host: it has no breaker
    // entry at all yet, and once admitted it is (and stays) Closed.
    assert_eq!(host_state(good), None, "an untouched host has no breaker yet");
    assert!(allow_host(good, T0), "an unrelated host is unaffected");
    assert_eq!(
        host_state(good),
        Some(BreakerState::Closed),
        "an allowed, never-failed host stays closed"
    );
}

#[test]
fn registry_records_success_failure_and_recovery() {
    let host = "cb-test-recover.example";

    // Below threshold → still allowed.
    for _ in 0..(FAILURE_THRESHOLD - 1) {
        record_failure(host, T0);
    }
    assert!(allow_host(host, T0));

    // Cross the threshold → open and short-circuiting.
    record_failure(host, T0);
    assert!(!allow_host(host, T0));
    assert_eq!(host_state(host), Some(BreakerState::Open));

    // After the cooldown the probe is admitted (half-open); a success closes it.
    assert!(allow_host(host, T0 + COOLDOWN_SECS));
    assert_eq!(host_state(host), Some(BreakerState::HalfOpen));
    record_success(host, T0 + COOLDOWN_SECS);
    // A success that returns the host to its clean ground state evicts the entry
    // outright (no zero-information row is kept): `host_state` is `None` again.
    assert_eq!(host_state(host), None, "a recovered host's clean entry is dropped");
    assert!(allow_host(host, T0 + COOLDOWN_SECS), "and it re-defaults to allowed");
}

#[test]
fn unknown_host_is_allowed() {
    assert!(
        allow_host("cb-test-never-seen.example", T0),
        "a host with no breaker yet is always allowed (closed by default)"
    );
}

#[test]
fn host_of_extracts_and_lowercases_host() {
    assert_eq!(host_of("https://Example.COM/path?q=1"), Some("example.com".to_owned()));
    assert_eq!(host_of("http://api.example.org:8443/x"), Some("api.example.org".to_owned()));
    // IPv6 literals keep their brackets (as `Url::host_str` yields them) — the
    // key just has to be stable, not address-normalised.
    assert_eq!(host_of("http://[2001:db8::1]/y"), Some("[2001:db8::1]".to_owned()));
    // No host / unparseable → None, so the caller leaves the fetch un-gated.
    assert_eq!(host_of("not a url"), None);
}

// ── Exponential backoff on repeated open cycles ───────────────────────────────

#[test]
fn cooldown_doubles_each_open_cycle_up_to_the_ceiling() {
    let mut b = Breaker::new();
    assert_eq!(b.open_cycles(), 0, "a fresh breaker has never tripped");

    // Cycle 0: the first trip uses the base cooldown.
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert_eq!(b.state(), BreakerState::Open);
    assert_eq!(b.open_cycles(), 1, "one open cycle recorded");
    assert!(!b.allow(T0 + COOLDOWN_SECS - 1), "base cooldown for the first cycle");
    assert!(b.allow(T0 + COOLDOWN_SECS), "probe admitted after the base cooldown");

    // Cycle 1: the probe fails → re-open for double the base cooldown.
    let t1 = T0 + COOLDOWN_SECS;
    b.on_failure(t1);
    assert_eq!(b.state(), BreakerState::Open);
    assert_eq!(b.open_cycles(), 2);
    assert!(!b.allow(t1 + 2 * COOLDOWN_SECS - 1), "second cycle waits 2× the base cooldown");
    assert!(b.allow(t1 + 2 * COOLDOWN_SECS), "probe admitted after the doubled cooldown");

    // Cycle 2: fails again → quadruple the base cooldown.
    let t2 = t1 + 2 * COOLDOWN_SECS;
    b.on_failure(t2);
    assert_eq!(b.open_cycles(), 3);
    assert!(!b.allow(t2 + 4 * COOLDOWN_SECS - 1), "third cycle waits 4× the base cooldown");
    assert!(b.allow(t2 + 4 * COOLDOWN_SECS));
}

#[test]
fn backoff_is_clamped_to_the_ceiling_and_never_overflows() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert_eq!(b.state(), BreakerState::Open);

    // Drive a long run of re-opens. Each iteration waits out the current cooldown
    // by stepping `MAX_COOLDOWN_SECS` forward (≥ any cycle's cooldown), admits the
    // probe, then fails it → re-open. This proves `open_cycles` climbs via
    // saturating_add without overflowing across many cycles.
    let mut t = T0;
    for _ in 0..40 {
        t += MAX_COOLDOWN_SECS; // past retry_at for any cycle (cooldown ≤ ceiling).
        assert!(b.allow(t), "probe admitted once the (clamped) cooldown elapses");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        b.on_failure(t); // probe failed → re-open.
        assert_eq!(b.state(), BreakerState::Open);
        assert!(!b.allow(t), "re-opened: short-circuits again immediately");
    }
    assert!(b.open_cycles() > 4, "many open cycles accumulated for a long-dead host");

    // Now that the backoff is long past saturating (open_cycles ≫ 4), the wait is
    // pinned at exactly the ceiling — never more, never overflowing.
    assert!(
        !b.allow(t + MAX_COOLDOWN_SECS - 1),
        "a saturated breaker still cools for the full ceiling"
    );
    assert!(
        b.allow(t + MAX_COOLDOWN_SECS),
        "but no longer than the ceiling — the probe is admitted at exactly MAX_COOLDOWN_SECS"
    );
}

#[test]
fn success_clears_backoff_so_a_recovered_host_pays_only_the_base_cooldown_again() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    // Re-open a couple of times to build up the backoff.
    assert!(b.allow(T0 + COOLDOWN_SECS));
    b.on_failure(T0 + COOLDOWN_SECS);
    assert!(b.open_cycles() >= 2);

    // Recover.
    b.on_success(T0 + COOLDOWN_SECS);
    assert_eq!(b.open_cycles(), 0, "success clears the open-cycle backoff");

    // A fresh trip now uses the base cooldown again, not the escalated one.
    let t = T0 + 10 * COOLDOWN_SECS;
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(t);
    }
    assert!(!b.allow(t + COOLDOWN_SECS - 1), "back to the base cooldown after recovery");
    assert!(b.allow(t + COOLDOWN_SECS));
}

#[test]
fn is_clean_closed_distinguishes_ground_state_from_carried_state() {
    let mut b = Breaker::new();
    assert!(b.is_clean_closed(), "a fresh breaker is in its clean ground state");

    b.on_failure(T0); // one failure, still closed
    assert!(!b.is_clean_closed(), "a closed breaker carrying a failure streak is not clean");

    b.on_success(T0);
    assert!(b.is_clean_closed(), "success returns it to the clean ground state");

    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert!(!b.is_clean_closed(), "an open breaker is never clean");
}

// ── Registry telemetry & bounded growth ───────────────────────────────────────

#[test]
fn host_open_cycles_surfaces_repeat_offenders() {
    let host = "cb-test-open-cycles.example";
    assert_eq!(host_open_cycles(host), None, "unknown host has no cycle count");

    for _ in 0..FAILURE_THRESHOLD {
        record_failure(host, T0);
    }
    assert_eq!(host_open_cycles(host), Some(1), "first trip → one open cycle");

    // Probe and fail it to rack up a second cycle.
    assert!(allow_host(host, T0 + COOLDOWN_SECS));
    record_failure(host, T0 + COOLDOWN_SECS);
    assert_eq!(host_open_cycles(host), Some(2), "a failed probe escalates the cycle count");
}

#[test]
fn healthy_host_success_leaves_no_permanent_registry_entry() {
    let host = "cb-test-no-leak.example";
    // A run of successes on a never-failing host must not accumulate an entry:
    // each returns it to the clean ground state, which is evicted.
    for _ in 0..10 {
        assert!(allow_host(host, T0));
        record_success(host, T0);
        assert_eq!(host_state(host), None, "a clean-closed host keeps no row");
    }
    // Recording success for a host with no entry is a no-op, not an insert.
    record_success("cb-test-unseen-success.example", T0);
    assert_eq!(host_state("cb-test-unseen-success.example"), None);
}

#[test]
fn registry_evicts_idle_clean_entries_when_over_the_soft_cap() {
    // Fill the registry past its soft cap with cold, clean-closed entries by
    // touching many distinct hosts with a stale `now`, then prove that inserting
    // a fresh host triggers a prune that reclaims the idle ones.
    let stale = T0;
    let baseline = registry_len();
    for i in 0..=MAX_ENTRIES {
        // Unique per-iteration host; `allow_host` inserts a clean Closed entry.
        let host = format!("cb-test-evict-{i}.example");
        let _ = allow_host(&host, stale);
    }
    // We pushed strictly more than MAX_ENTRIES distinct fresh hosts; even allowing
    // for entries other tests left behind, the map must have been over the cap at
    // some insert and pruned the now-idle clean entries.
    let fresh = stale + IDLE_TTL_SECS + 1;
    // One more insert at a time far past the idle TTL forces a prune pass that
    // drops the stale clean-closed entries inserted above.
    let _ = allow_host("cb-test-evict-trigger.example", fresh);
    assert!(
        registry_len() <= MAX_ENTRIES + 1 + baseline,
        "registry stays bounded near the soft cap, not growing without limit"
    );

    // A live (Open) host is never pruned even when idle past the TTL.
    let live = "cb-test-evict-live.example";
    for _ in 0..FAILURE_THRESHOLD {
        record_failure(live, stale);
    }
    assert_eq!(host_state(live), Some(BreakerState::Open));
    // Force more prune passes well past the idle TTL.
    for i in 0..(MAX_ENTRIES + 1) {
        let host = format!("cb-test-evict-round2-{i}.example");
        let _ = allow_host(&host, fresh);
    }
    assert_eq!(
        host_state(live),
        Some(BreakerState::Open),
        "an Open host survives pruning regardless of idle time"
    );
}
