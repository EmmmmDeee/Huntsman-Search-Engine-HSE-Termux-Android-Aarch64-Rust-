use super::*;

#[test]
fn accepts_domain_and_ip() {
    let m = CertIntel;
    assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
    assert!(m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::Email, "x@y")));
}

#[test]
fn module_metadata() {
    let m = CertIntel;
    assert_eq!(m.name(), "cert_intel");
    assert_eq!(m.priority(), 33);
    assert_eq!(m.max_timeout_ms(), 10_000);
    assert!(!m.description().is_empty());
    assert!(!m.attack_techniques().is_empty());
    assert!(m.produces().contains(&EntityKind::Domain));
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
fn extract_sans_deduplicates_and_sorts() {
    // Build a minimal DER fragment: SAN OID (55 1D 11) followed immediately by
    // two dNSName entries (tag 0x82). The parser starts scanning right after the
    // 3-byte OID, so there is no padding byte between OID and first tag.
    let domain = b"sub.example.com";
    let len = domain.len() as u8;
    let mut der: Vec<u8> = vec![0x55, 0x1D, 0x11, 0x82, len];
    der.extend_from_slice(domain);
    // Second identical entry — dedup must keep only one.
    der.push(0x82);
    der.push(len);
    der.extend_from_slice(domain);

    let sans = extract_sans_from_der(&der);
    assert_eq!(sans.len(), 1);
    assert_eq!(sans[0], "sub.example.com");
}

#[test]
fn extract_sans_rejects_short_or_domainless_names() {
    // "ab" has no dot and len ≤ 3 — must be filtered out.
    let short = b"ab";
    let len = short.len() as u8;
    let mut der: Vec<u8> = vec![0x55, 0x1D, 0x11, 0x82, len];
    der.extend_from_slice(short);
    assert!(extract_sans_from_der(&der).is_empty());
}

#[test]
fn extract_serial_hex_formats_with_colons() {
    // `extract_serial_hex` returns "" for inputs shorter than 15 bytes.
    // Build a 15-byte buffer: INTEGER tag + len=3 + payload, padded with zeros.
    let mut der: Vec<u8> = vec![0x02, 0x03, 0x01, 0x02, 0x03];
    der.extend(vec![0u8; 10]); // pad to 15 bytes
    let serial = extract_serial_hex(&der);
    assert_eq!(serial, "01:02:03");
}

#[test]
fn extract_sans_output_is_lowercased() {
    let domain = b"Mail.Example.COM";
    let len = domain.len() as u8;
    let mut der: Vec<u8> = vec![0x55, 0x1D, 0x11, 0x82, len];
    der.extend_from_slice(domain);
    let sans = extract_sans_from_der(&der);
    assert_eq!(sans.len(), 1);
    assert_eq!(sans[0], "mail.example.com");
}
