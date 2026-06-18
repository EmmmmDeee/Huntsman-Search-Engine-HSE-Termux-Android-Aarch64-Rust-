use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};
use super::TroveAu;

#[test]
fn metadata() {
    let m = TroveAu;
    assert_eq!(m.name(), "trove_au");
    assert_eq!(m.priority(), 57);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::Organisation, "Acme Corp")));
    assert!(m.accepts(&Target::new(TargetKind::AbnAcn, "12345678901")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}
