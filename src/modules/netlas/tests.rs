use super::Netlas;
use crate::core::{
    module::{Module, ModuleCost},
    scan::{Target, TargetKind},
};

#[test]
fn metadata() {
    let m = Netlas;
    assert_eq!(m.name(), "netlas");
    assert_eq!(m.priority(), 79);
    assert!(!m.description().is_empty());
    assert_eq!(m.cost(), ModuleCost::KeyGated);
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::Email, "a@b.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Phone, "+61400000000")));
    assert!(m.max_timeout_ms() > 3000);
    assert!(!m.attack_techniques().is_empty());
}

#[test]
fn netlas_query_by_kind() {
    use super::netlas_query;
    use crate::core::scan::Target;
    let ip_q = netlas_query(&Target::new(TargetKind::IpAddress, "1.2.3.4"));
    assert!(ip_q.starts_with("ip:"));
    let domain_q = netlas_query(&Target::new(TargetKind::Domain, "example.com"));
    assert!(domain_q.starts_with("host:"));
    let email_q = netlas_query(&Target::new(TargetKind::Email, "a@b.com"));
    assert!(email_q.starts_with("certificate.subject.email:"));
}
