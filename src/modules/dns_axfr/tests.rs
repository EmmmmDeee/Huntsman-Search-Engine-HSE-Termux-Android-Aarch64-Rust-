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
    let name = extract_name(&buf, 0).expect("should succeed");
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
    let name = extract_name(&buf, 0).expect("should succeed");
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

// ── Property tests: wire parsers never panic / loop on hostile bytes ─────────
// An AXFR response is supplied by the remote DNS server (attacker-controlled).
// `extract_name` decompresses DNS names — the classic infinite-loop (compression
// pointer cycle) and out-of-bounds DoS surface; `build_axfr_query` casts label
// lengths. Both contracts (terminates, never panics) are pinned over arbitrary
// input here.
mod prop {
    use proptest::prelude::*;

    use super::{build_axfr_query, extract_name};

    proptest! {
        /// `extract_name` always terminates and never panics for ANY buffer and
        /// ANY start offset — including buffers full of 0xC0 compression pointers
        /// that would loop forever without the jump cap, and offsets past the end.
        #[test]
        fn extract_name_is_total(buf in proptest::collection::vec(any::<u8>(), 0..256), pos in 0usize..300) {
            let _ = extract_name(&buf, pos);
        }

        /// A buffer that is entirely compression pointers (each `0xC0 0x00`
        /// jumping back to the start) must be rejected by the jump cap, not hang.
        #[test]
        fn extract_name_rejects_pointer_loops(n in 1usize..128) {
            let buf: Vec<u8> = std::iter::repeat_n([0xC0u8, 0x00], n).flatten().collect();
            // Returns None (cap tripped) rather than looping; the test completing
            // IS the assertion (a hang would time the suite out).
            prop_assert!(extract_name(&buf, 0).is_none());
        }

        /// `build_axfr_query` never panics on arbitrary domain text (the label
        /// length is a `u8` cast that must be saturated, not wrapped/overflowed).
        #[test]
        fn build_axfr_query_is_total(domain in ".{0,300}") {
            let pkt = build_axfr_query(&domain);
            // Header (12) + at least the root label + QTYPE/QCLASS.
            prop_assert!(pkt.len() >= 12);
        }
    }
}
