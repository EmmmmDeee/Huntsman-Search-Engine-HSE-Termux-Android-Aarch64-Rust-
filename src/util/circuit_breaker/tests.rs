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

#[test]
fn rate_limited_opens_on_the_first_hit_unlike_a_5xx() {
    // A 5xx is a guess about health and needs FAILURE_THRESHOLD of them to trip.
    // A 429 is the server stating its own contract, so ONE opens the breaker —
    // the distinction that stops a per-target loop from re-asking a server that
    // already said "not now" (the observed WiGLE 429 storm).
    let mut b = Breaker::new();
    b.on_rate_limited(T0, 60);
    assert_eq!(b.state(), BreakerState::Open);
    assert!(!b.allow(T0), "a single 429 short-circuits the next request");
}

#[test]
fn rate_limited_backs_off_for_the_server_requested_window() {
    // Deliberately NOT COOLDOWN_SECS: the assertions below only prove the
    // server's own window is honoured if it differs from the local default.
    const SERVER_WINDOW: u64 = 90;
    assert_ne!(
        SERVER_WINDOW, COOLDOWN_SECS,
        "test is only meaningful if the server window differs from the local default"
    );

    let mut b = Breaker::new();
    b.on_rate_limited(T0, SERVER_WINDOW);
    // Short-circuited for the whole window the server asked for — including
    // past the point the local default would have released it.
    assert!(!b.allow(T0 + COOLDOWN_SECS), "must not release on the local default");
    assert!(
        !b.allow(T0 + SERVER_WINDOW - 1),
        "still backing off one second before the server's window closes"
    );
    // …then admits exactly one probe.
    assert!(
        b.allow(T0 + SERVER_WINDOW),
        "probe admitted once the server's own window elapses"
    );
    assert_eq!(b.state(), BreakerState::HalfOpen);
}

#[test]
fn rate_limited_floors_a_zero_window_at_one_second() {
    // A `Retry-After: 0` (or a caller passing 0) must not produce an open breaker
    // that admits traffic in the same second — that would defeat the back-off.
    let mut b = Breaker::new();
    b.on_rate_limited(T0, 0);
    assert!(!b.allow(T0), "a zero window must still hold for its floored second");
    assert!(b.allow(T0 + 1), "and release one second later");
}

#[test]
fn registry_rate_limited_backs_every_caller_off_the_host() {
    let host = "cb-test-429.example";
    // One caller sees a 429 with a 90s server window…
    record_rate_limited(host, T0, 90);
    // …and every other caller sharing the host is short-circuited for it, with no
    // socket opened — the fix for eight consecutive 429 round-trips in one sweep.
    assert!(!allow_host(host, T0), "the host is backed off after a single 429");
    assert!(!allow_host(host, T0 + 89));
    assert!(allow_host(host, T0 + 90), "released after the server's own window");
    assert_eq!(host_state(host), Some(BreakerState::HalfOpen));
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
