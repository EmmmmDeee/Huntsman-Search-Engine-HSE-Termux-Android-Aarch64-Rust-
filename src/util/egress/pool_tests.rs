use super::*;

#[test]
fn record_transitions_untested_healthy_degraded_dead() {
    let mut e = EgressEntry::new("http://h:3128");
    assert_eq!(e.state, EgressState::Untested);
    e.record(true, 120, 100);
    assert_eq!(e.state, EgressState::Healthy);
    assert_eq!(e.latency_ms, 120);
    e.record(false, 0, 101);
    assert_eq!(e.state, EgressState::Degraded);
    e.record(false, 0, 102);
    assert_eq!(e.state, EgressState::Degraded);
    e.record(false, 0, 103);
    assert_eq!(e.state, EgressState::Dead, "3 consecutive failures ⇒ Dead");
    assert!(!e.is_usable());
    // A success revives it.
    e.record(true, 90, 104);
    assert_eq!(e.state, EgressState::Healthy);
    assert_eq!(e.consecutive_failures, 0);
}

#[test]
fn next_prefers_healthy_then_rotates_and_skips_dead() {
    let mut p = EgressPool::from_specs(["a", "b", "c"]);
    p.report("a", true, 100, 10);
    p.report("b", true, 100, 10);
    for t in 0..3 {
        p.report("c", false, 0, 20 + t);
    }
    let picks: Vec<String> = (0..4).filter_map(|_| p.select()).collect();
    assert!(
        picks.iter().all(|s| s == "a" || s == "b"),
        "dead c must be skipped: {picks:?}"
    );
    assert!(
        picks.contains(&"a".to_string()) && picks.contains(&"b".to_string()),
        "both healthy peers used: {picks:?}"
    );
}

#[test]
fn next_returns_none_when_all_dead_so_caller_falls_back_direct() {
    let mut p = EgressPool::from_specs(["a"]);
    for t in 0..3 {
        p.report("a", false, 0, t);
    }
    assert_eq!(
        p.select(),
        None,
        "all-dead pool ⇒ None ⇒ caller uses direct connection"
    );
}

#[test]
fn next_excluding_is_the_failover_primitive() {
    let mut p = EgressPool::from_specs(["a", "b"]);
    p.report("a", true, 100, 1);
    p.report("b", true, 100, 1);
    let first = p.select().unwrap();
    let second = p.next_excluding(std::slice::from_ref(&first)).unwrap();
    assert_ne!(first, second, "failover must pick a different healthy egress");
}

#[test]
fn healthy_beats_untested_beats_degraded_in_selection() {
    let mut p = EgressPool::from_specs(["healthy", "untested", "degraded"]);
    p.report("healthy", true, 50, 1);
    p.report("degraded", false, 0, 1);
    assert_eq!(
        p.select(),
        Some("healthy".to_string()),
        "Healthy is the top band"
    );
}

#[test]
fn merge_specs_preserves_existing_health_and_adds_new() {
    let mut p = EgressPool::from_specs(["a"]);
    for t in 0..3 {
        p.report("a", false, 0, t);
    }
    let added = p.merge_specs(vec!["a".to_string(), "b".to_string()]);
    assert_eq!(added, 1, "only b is new; re-seeing a must not re-add it");
    assert_eq!(p.select(), Some("b".to_string()));
}

#[test]
fn prune_dead_never_strands_the_pool() {
    let mut p = EgressPool::from_specs(["a", "b"]);
    for t in 0..3 {
        p.report("a", false, 0, t);
    }
    assert_eq!(p.prune_dead(2), 0, "only 1 usable ⇒ refuse to prune");
    assert_eq!(p.len(), 2);
    assert_eq!(p.prune_dead(1), 1, "keep_min satisfied ⇒ evict the dead one");
    assert_eq!(p.len(), 1);
}

#[test]
fn due_for_probe_flags_untested_and_stale() {
    let mut p = EgressPool::from_specs(["fresh", "stale"]);
    p.report("fresh", true, 100, 1000);
    p.report("stale", true, 100, 10);
    let due = p.due_for_probe(1000, 300, 10);
    assert!(
        due.contains(&"stale".to_string()),
        "last_ok 10 vs now 1000 ⇒ stale"
    );
    assert!(
        !due.contains(&"fresh".to_string()),
        "just-probed ⇒ not due"
    );
}

#[test]
fn parse_feed_body_handles_schemes_bare_and_junk() {
    let body = "# comment\n\n1.2.3.4:8080\nsocks5://5.6.7.8:1080\n9.9.9.9:3128 elite\nnotaproxy\n10.0.0.1:abc\n";
    let got = parse_feed_body(body);
    assert_eq!(
        got,
        vec![
            "http://1.2.3.4:8080".to_string(),
            "socks5://5.6.7.8:1080".to_string(),
            "http://9.9.9.9:3128".to_string(),
        ],
        "bare ip:port ⇒ http://, scheme preserved, comments/junk/bad-port dropped"
    );
}

#[test]
fn snapshot_exposes_state_without_mutating() {
    let mut p = EgressPool::from_specs(["a"]);
    p.report("a", true, 42, 1);
    let snap = p.snapshot();
    assert_eq!(snap.len(), 1);
    assert_eq!(snap[0].0, "a");
    assert_eq!(snap[0].1, EgressState::Healthy);
    assert_eq!(snap[0].2, 42);
    assert!(snap[0].3 > 0.0);
}
