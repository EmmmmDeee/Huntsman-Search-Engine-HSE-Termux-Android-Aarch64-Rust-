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

// ── Real self-signed X.509 (DER) fixture ───────────────────────────────────
// `testdata/selfsigned.der` is an OpenSSL-generated self-signed certificate
// (CN/O = huntsman-test.example.com / "Huntsman SE Test", serial 0102030405,
// three dNSName SANs). The hand-built fragment tests above exercise the scanners
// in isolation; this one drives them against *real* ASN.1 DER — the exact thing
// the module receives from `peer_certificate()` — so a heuristic that only works
// on synthetic input (e.g. ignores the SAN extension's OCTET-STRING/SEQUENCE
// wrappers, or mistakes the version INTEGER for the serial) fails loudly here.
const SELF_SIGNED_DER: &[u8] = include_bytes!("testdata/selfsigned.der");

// X.500 AttributeType OIDs (value bytes only, as the scanners match).
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];
const OID_O: &[u8] = &[0x55, 0x04, 0x0A];

#[test]
fn real_cert_extracts_common_name() {
    // Self-signed ⇒ issuer CN == subject CN.
    assert_eq!(
        extract_field_from_der(SELF_SIGNED_DER, OID_CN, true).as_deref(),
        Some("huntsman-test.example.com"),
        "issuer CN from real DER"
    );
    assert_eq!(
        extract_field_from_der(SELF_SIGNED_DER, OID_CN, false).as_deref(),
        Some("huntsman-test.example.com"),
        "subject CN from real DER"
    );
}

#[test]
fn real_cert_extracts_organisation() {
    assert_eq!(
        extract_field_from_der(SELF_SIGNED_DER, OID_O, true).as_deref(),
        Some("Huntsman SE Test"),
        "issuer O from real DER"
    );
}

#[test]
fn real_cert_extracts_serial_not_version() {
    // The TBSCertificate begins `[0]{ INTEGER version } INTEGER serial`, so a
    // naive "first INTEGER" scan returns the version (02). The serial set at
    // generation is 0x01_02_03_04_05.
    assert_eq!(
        extract_serial_hex(SELF_SIGNED_DER),
        "01:02:03:04:05",
        "serial must skip the version INTEGER"
    );
}

#[test]
fn real_cert_extracts_all_three_sans() {
    // The SAN extension wraps the GeneralNames in OCTET STRING → SEQUENCE; the
    // scanner must descend through both to reach the dNSName (0x82) entries.
    let sans = extract_sans_from_der(SELF_SIGNED_DER);
    assert_eq!(
        sans,
        vec![
            "huntsman-test.example.com".to_string(),
            "sub1.huntsman-test.example.com".to_string(),
            "sub2.huntsman-test.example.com".to_string(),
        ],
        "all three dNSName SANs, sorted + lowercased"
    );
}

#[test]
fn real_cert_parse_certificate_emits_subdomains_and_evidence() {
    // End-to-end: parse_certificate on the real DER must surface the two SAN
    // subdomains as Domain entities and stamp issuer/subject/org/serial/SAN
    // evidence onto the certificate entity.
    let target = "huntsman-test.example.com";
    let mut entity = Entity::new(EntityKind::Domain, target, 0.9, "scan");
    let mut ev = Evidence::new("cert_intel", "TLS certificate");
    let mut result = ModuleResult::new();
    let mut seen = HashSet::new();
    parse_certificate(
        SELF_SIGNED_DER,
        target,
        "scan",
        &mut entity,
        &mut ev,
        &mut result,
        &mut seen,
    );

    let subs: Vec<&str> = result
        .entities
        .iter()
        .filter(|e| e.kind == EntityKind::Domain)
        .map(|e| e.value.as_str())
        .collect();
    assert!(
        subs.contains(&"sub1.huntsman-test.example.com")
            && subs.contains(&"sub2.huntsman-test.example.com"),
        "both SAN subdomains emitted as Domain entities, got {subs:?}"
    );
    // The apex (== target) is not a proper subdomain, so it is not re-emitted.
    assert!(
        !subs.contains(&"huntsman-test.example.com"),
        "apex SAN must not be emitted as its own subdomain"
    );
    assert_eq!(ev.attributes.get("issuer").map(String::as_str), Some("huntsman-test.example.com"));
    assert_eq!(ev.attributes.get("issuer_org").map(String::as_str), Some("Huntsman SE Test"));
    assert_eq!(ev.attributes.get("serial").map(String::as_str), Some("01:02:03:04:05"));
    assert_eq!(ev.attributes.get("san_count").map(String::as_str), Some("3"));
    assert!(
        result.entities.iter().all(|e| e.has_tag(tags::SUBDOMAIN) && e.has_tag("tls-san")),
        "every emitted SAN subdomain carries subdomain + tls-san tags"
    );
}

// ── Property tests: DER scanners never panic on hostile bytes ───────────────
// The scanners run on `peer_certificate()` bytes — attacker-controlled (the
// remote server presents the cert). A panic in any of them is a remote DoS of a
// long-lived `hse serve`/`live`, so the no-panic contract is pinned over
// thousands of arbitrary byte strings (incl. truncated TLVs, bogus long-form
// lengths, OID-prefixes with no value, 0x82 tags running off the end).
mod prop {
    use proptest::prelude::*;

    use super::super::{
        der_tlv_len, extract_field_from_der, extract_sans_from_der, extract_serial_hex,
    };

    proptest! {
        #[test]
        fn der_scanners_never_panic(der in proptest::collection::vec(any::<u8>(), 0..512)) {
            // Each must return (not panic) for any input; outputs are only
            // sanity-bounded — correctness on *valid* DER is covered by the
            // real-cert fixture tests above.
            let sans = extract_sans_from_der(&der);
            prop_assert!(sans.iter().all(|s| s.len() <= 253));
            let _ = extract_field_from_der(&der, &[0x55, 0x04, 0x03], true);
            let _ = extract_field_from_der(&der, &[0x55, 0x04, 0x0A], false);
            let serial = extract_serial_hex(&der);
            // Serial hex is ≤20 bytes ⇒ ≤ 20*3 chars ("xx:" each, minus one colon).
            prop_assert!(serial.len() <= 60);
        }

        #[test]
        fn der_tlv_len_is_consistent(der in proptest::collection::vec(any::<u8>(), 0..64), pos in 0usize..64) {
            // Never panics; when it decodes, the header length is ≥2 and the
            // reported content length fits the long-form it claims.
            if let Some((hdr, _len)) = der_tlv_len(&der, pos) {
                prop_assert!((2..=4).contains(&hdr));
            }
        }
    }
}
