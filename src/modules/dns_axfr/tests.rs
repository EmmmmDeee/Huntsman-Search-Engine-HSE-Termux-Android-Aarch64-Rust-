use super::*;

#[test]
fn build_axfr_query_valid() {
    let q = build_axfr_query("example.com");
    assert!(q.len() > 12);
    // QTYPE should be 252 (AXFR)
    let qtype_pos = q.len() - 4;
    assert_eq!(q[qtype_pos], 0x00);
    assert_eq!(q[qtype_pos + 1], 0xFC); // 252
}

#[test]
fn extract_name_simple() {
    let buf = [
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
    ];
    let name = extract_name(&buf, 0).unwrap();
    assert_eq!(name, "example.com");
}

#[test]
fn extract_name_empty_returns_none() {
    let buf = [0u8];
    assert!(extract_name(&buf, 0).is_none());
}

#[tokio::test]
async fn module_metadata() {
    let m = DnsAxfr;
    assert_eq!(m.name(), "dns_axfr");
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
}

#[test]
fn build_axfr_query_encodes_domain_labels() {
    // "sub.example.com" encodes as 3/s/u/b, 7/e/x/a/m/p/l/e, 3/c/o/m, 0
    let q = build_axfr_query("sub.example.com");
    // Header is 12 bytes (4-byte ID+flags, 8-byte counts). First label starts at [12].
    assert_eq!(q[12], 3, "first label length must be 3 for 'sub'");
    assert_eq!(&q[13..16], b"sub");
}

#[test]
fn extract_name_with_multiple_labels() {
    let buf = [
        3, b's', b'u', b'b',
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        3, b'c', b'o', b'm',
        0,
    ];
    let name = extract_name(&buf, 0).unwrap();
    assert_eq!(name, "sub.example.com");
}

#[test]
fn module_metadata_full() {
    let m = DnsAxfr;
    assert_eq!(m.name(), "dns_axfr");
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Domain));
}
