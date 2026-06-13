use super::*;

#[test]
fn accepts_domain_and_ip() {
    let m = CertIntel;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
}

#[test]
fn extract_sans_from_empty() {
    assert!(extract_sans_from_der(&[]).is_empty());
}

#[test]
fn extract_serial_from_short_der() {
    assert!(extract_serial_hex(&[0; 5]).is_empty());
}

#[test]
fn extract_field_from_empty() {
    assert!(extract_field_from_der(&[], &[0x55, 0x04, 0x03], true).is_none());
}

#[test]
fn module_metadata() {
    let m = CertIntel;
    assert_eq!(m.name(), "cert_intel");
    assert_eq!(m.priority(), 33);
    assert_eq!(m.max_timeout_ms(), 10_000);
}
