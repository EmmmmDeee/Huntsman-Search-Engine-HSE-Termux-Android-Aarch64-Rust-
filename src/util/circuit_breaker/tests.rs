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
    // HalfOpen admits exactly ONE probe: a second concurrent caller is denied so
    // the recovering host isn't hit by a thundering herd. The probe's OUTCOME
    // (recorded via on_success/on_failure), not a second allow, decides the next
    // state.
    assert!(
        !b.allow(T0 + COOLDOWN_SECS),
        "a second concurrent caller must be denied while the probe is in flight"
    );
    assert_eq!(b.state(), BreakerState::HalfOpen);
}

#[test]
fn half_open_admits_exactly_one_probe_and_self_heals_a_lost_outcome() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    let probe_at = T0 + COOLDOWN_SECS;
    // The first caller after cooldown gets the single probe…
    assert!(b.allow(probe_at), "first caller after cooldown gets the probe");
    assert_eq!(b.state(), BreakerState::HalfOpen);
    // …every concurrent caller while it is in flight is short-circuited.
    for dt in [0, 1, COOLDOWN_SECS - 1] {
        assert!(
            !b.allow(probe_at + dt),
            "concurrent caller at +{dt}s must be denied while the probe is in flight"
        );
    }
    // Safety valve: if the probe's outcome is never recorded (a dropped request),
    // the breaker doesn't wedge HalfOpen forever — one cooldown later a fresh
    // probe is admitted.
    assert!(
        b.allow(probe_at + COOLDOWN_SECS),
        "a probe whose outcome was never recorded is retried after the deadline"
    );
    assert_eq!(b.state(), BreakerState::HalfOpen);
}

#[test]
fn success_in_half_open_closes_and_resets() {
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(T0);
    }
    assert!(b.allow(T0 + COOLDOWN_SECS));
    assert_eq!(b.state(), BreakerState::HalfOpen);

    b.on_success();
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
    b.on_failure(probe_at);
    assert_eq!(b.state(), BreakerState::Open);
    assert!(!b.allow(probe_at), "re-opened: short-circuits again immediately");
    assert!(!b.allow(probe_at + COOLDOWN_SECS - 1), "fresh cooldown from the probe time");
    assert!(b.allow(probe_at + COOLDOWN_SECS), "probe admitted again after the new cooldown");
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
    b.on_success();

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
    record_success(host);
    assert_eq!(host_state(host), Some(BreakerState::Closed));
    assert!(allow_host(host, T0 + COOLDOWN_SECS));
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

// ---- server-requested backoff ----------------------------------------------

#[test]
fn open_until_honours_a_server_deadline_without_five_failures_first() {
    // A 429 carrying Retry-After is a statement, not a guess: it must stop the
    // next request immediately rather than after FAILURE_THRESHOLD refusals.
    let mut b = Breaker::new();
    assert!(b.allow(1_000), "a fresh breaker is closed");
    b.open_until(1_060);
    assert_eq!(b.state(), BreakerState::Open);
    assert!(!b.allow(1_000), "still inside the requested backoff");
    assert!(!b.allow(1_059), "still inside the requested backoff");
    assert!(b.allow(1_060), "the named deadline has passed — probe allowed");
}

#[test]
fn open_until_never_shortens_an_existing_cooldown() {
    // A short server-stated backoff must not release a breaker that repeated
    // failures already opened for longer.
    let mut b = Breaker::new();
    for _ in 0..FAILURE_THRESHOLD {
        b.on_failure(1_000);
    }
    assert_eq!(b.state(), BreakerState::Open);
    b.open_until(1_005); // much shorter than COOLDOWN_SECS from 1_000
    assert!(
        !b.allow(1_010),
        "the longer failure-driven cooldown must still stand"
    );
    assert!(b.allow(1_000 + COOLDOWN_SECS));
}

#[test]
fn a_success_clears_a_server_requested_backoff() {
    // Once the host serves us again the breaker must recover, so one
    // rate-limited burst cannot shun a host permanently.
    let mut b = Breaker::new();
    b.open_until(9_999);
    b.on_success();
    assert_eq!(b.state(), BreakerState::Closed);
    assert!(b.allow(1_000));
}
