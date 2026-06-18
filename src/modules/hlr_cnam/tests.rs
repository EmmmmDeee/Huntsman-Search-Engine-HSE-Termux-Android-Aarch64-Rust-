use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};
use super::HlrCnam;

#[test]
fn metadata() {
    let m = HlrCnam;
    assert_eq!(m.name(), "hlr_cnam");
    assert_eq!(m.priority(), 138);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}
