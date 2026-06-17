use super::*;

// ── Tests carried from paid-only shodan.rs ───────────────────────

#[test]
fn accepts_only_ip() {
    let m = Shodan;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}

#[test]
fn cost_is_free() {
    assert!(matches!(Shodan.cost(), ModuleCost::Free));
}

// ── Tests carried from shodan_internetdb.rs ──────────────────────

#[test]
fn accepts_only_ip_not_domain() {
    let m = Shodan;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
}

// ── Merged-module tests ──────────────────────────────────────────

#[test]
fn priority_is_105() {
    assert_eq!(Shodan.priority(), 105);
}

#[test]
fn timeout_is_10s() {
    assert_eq!(Shodan.max_timeout_ms(), 10_000);
}

#[test]
fn name_is_shodan() {
    assert_eq!(Shodan.name(), "shodan");
}

#[test]
fn description_mentions_free_and_paid() {
    let desc = Shodan.description();
    assert!(desc.contains("free") || desc.contains("Free") || desc.contains("InternetDB"));
    assert!(desc.contains("paid") || desc.contains("Paid") || desc.contains("keyed"));
}

#[test]
fn target_entity_builds_ip_entity() {
    let e = target_entity("8.8.8.8", "scan-1");
    assert_eq!(e.kind, EntityKind::IpAddress);
    assert_eq!(e.value, "8.8.8.8");
    assert!((e.confidence - 0.90).abs() < 1e-9);
}
