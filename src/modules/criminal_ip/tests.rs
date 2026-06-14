use super::*;

#[test]
fn accepts_only_ip() {
    let m = CriminalIp;
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x")));
}
#[test]
fn cost_is_key_gated() {
    assert!(matches!(CriminalIp.cost(), ModuleCost::KeyGated));
}
