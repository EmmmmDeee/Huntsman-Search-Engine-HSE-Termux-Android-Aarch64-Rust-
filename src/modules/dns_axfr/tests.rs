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

#[test]
fn is_canonical_subdomain_of_zone_excludes_a_www_record_from_the_apex() {
    // Regression: a zone transfer routinely includes a "www" A/CNAME record
    // (near-universal DNS practice). It IS a proper subdomain of the raw
    // zone by string shape alone, but `Entity::new` strips the leading
    // "www." label and collapses it onto the exposed zone's own apex uid —
    // the same entity `process()` tags `axfr-permitted`/`tags::VULNERABLE`.
    // Before this was fixed, it was collected into `records` and later
    // unconditionally tagged "subdomain", surviving onto that entity via
    // `Entity::merge`'s tag-union.
    assert!(!is_canonical_subdomain_of_zone("www.example.com", "example.com"));
    // The literal apex is also excluded (pre-existing behaviour, preserved).
    assert!(!is_canonical_subdomain_of_zone("example.com", "example.com"));
    // A genuine subdomain is unaffected.
    assert!(is_canonical_subdomain_of_zone("mail.example.com", "example.com"));
    // An unrelated, mid-label-matching name is still rejected (the
    // label-boundary guarantee this function exists to preserve).
    assert!(!is_canonical_subdomain_of_zone("evilexample.com", "example.com"));
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
    // Regression: an active, target-touching zone-transfer probe testing for
    // an exploitable AXFR-open misconfiguration (tagged VULNERABLE on
    // success) must claim Active Scanning: Vulnerability Scanning
    // (T1595.002), mirroring subdomain_takeover's identical reasoning — the
    // DNS/topology-only codes under-represented that this is an exploit-
    // condition probe, not passive info-gathering.
    assert!(m.attack_techniques().contains(&"T1595.002"));
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

#[test]
fn an_unreached_nameserver_leaves_no_zone_transfer_verdict() {
    // Backlog #10 (the post-enumeration stage): three nameservers all
    // dropping TCP/53 used to record exactly what three refusing nameservers
    // record — an empty result, read as "no zone-transfer exposure".
    let unreached = vec![
        "ns1.example.com (192.0.2.1): connect timeout".to_string(),
        "ns2.example.com: no address record".to_string(),
    ];
    let err = sweep_verdict("example.com", 3, 1, &unreached, 0).expect_err("two unreached");
    let msg = err.to_string();
    assert!(msg.contains("2 of 3 nameserver(s) could not be reached") && msg.contains("1 answered") && msg.contains("connect timeout"), "{msg}");
    // Every nameserver answering (refusing) IS the clean negative.
    assert!(sweep_verdict("example.com", 3, 3, &[], 0).expect("refused by all").is_empty());
    // Nothing probed at all is not applicable, never a negative.
    assert!(matches!(
        sweep_verdict("example.com", 2, 0, &[], 2),
        Err(crate::core::error::Error::Skipped { class: crate::core::event::SkipClass::NotApplicable, .. })
    ));
    assert!(matches!(
        sweep_verdict("example.com", 0, 0, &[], 0),
        Err(crate::core::error::Error::Skipped { .. })
    ));
}

// ── a transfer read in part is declared, whichever way it was cut ────────────

/// A name in uncompressed wire form.
fn wire_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// One answer record: `name`, `rtype`, class IN, a TTL, and `rdata`.
fn rr(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut out = wire_name(name);
    out.extend_from_slice(&rtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&3600u32.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
    out
}

const SOA: u16 = 6;
const A: u16 = 1;

/// A response message for an AXFR of `zone` carrying `answers`, with `rcode`.
fn message(zone: &str, rcode: u8, answers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![0x12, 0x34, 0x84, rcode & 0x0F];
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
    out.extend(wire_name(zone));
    out.extend_from_slice(&252u16.to_be_bytes()); // QTYPE AXFR
    out.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    for a in answers {
        out.extend_from_slice(a);
    }
    out
}

fn soa() -> Vec<u8> {
    rr("example.com", SOA, &[0; 22])
}

fn host(n: &str) -> Vec<u8> {
    rr(&format!("{n}.example.com"), A, &[192, 0, 2, 1])
}

fn declared(msg: &AxfrMessage) -> (ModuleResult, Entity) {
    let mut result = ModuleResult::new();
    let mut zone = Entity::new(EntityKind::Domain, "example.com", 0.9, "s");
    mark_axfr_truncation(&mut result, &mut zone, msg);
    (result, zone)
}

#[test]
fn a_transfer_the_first_message_carries_whole_is_complete() {
    let msg = parse_axfr_message(
        &message("example.com", 0, &[soa(), host("ns1"), host("mail"), soa()]),
        "example.com",
    );
    assert_eq!(msg.records, ["ns1.example.com", "mail.example.com"]);
    assert_eq!((msg.ancount, msg.soa_seen), (4, 2));
    let (result, zone) = declared(&msg);
    assert!(result.truncation.is_none(), "{:?}", result.truncation);
    assert!(!zone.tags.iter().any(|t| t == "truncated"));
}

#[test]
fn a_first_message_without_the_closing_soa_is_a_partial_zone() {
    // FAILS before the fix: the check read only ANCOUNT against the cap, so
    // the first message of a zone split across several — the ordinary shape
    // of a large one — was reported as the complete inventory, although the
    // module's own comment named this case.
    let msg = parse_axfr_message(
        &message("example.com", 0, &[soa(), host("ns1"), host("mail")]),
        "example.com",
    );
    assert_eq!((msg.ancount, msg.soa_seen), (3, 1));
    let (result, zone) = declared(&msg);
    let why = result.truncation.expect("an unfinished transfer is not complete");
    assert!(why.contains("closing SOA"), "{why}");
    assert!(why.contains("did not report how many"), "the zone's size is unknown: {why}");
    assert!(zone.tags.iter().any(|t| t == "truncated"));
}

#[test]
fn a_message_beyond_the_parser_cap_is_declared_with_its_advertised_count() {
    let mut answers = vec![soa()];
    answers.extend((0..MAX_ANSWER_RECORDS + 10).map(|i| host(&format!("h{i}"))));
    answers.push(soa());
    let msg = parse_axfr_message(&message("example.com", 0, &answers), "example.com");
    assert_eq!(msg.ancount, MAX_ANSWER_RECORDS + 12);
    assert_eq!(
        msg.records.len(),
        MAX_ANSWER_RECORDS - 1,
        "the cap bounds the walk: the opening SOA is one of the records walked"
    );
    let (result, _) = declared(&msg);
    let why = result.truncation.expect("a capped walk is not complete");
    assert!(
        why.starts_with(&format!("{MAX_ANSWER_RECORDS} of {}", MAX_ANSWER_RECORDS + 12)),
        "{why}"
    );
}

#[test]
fn a_refusal_decodes_as_nothing() {
    let msg = parse_axfr_message(&message("example.com", 5, &[soa(), host("ns1"), soa()]), "example.com");
    assert_eq!(msg, AxfrMessage::default());
    assert!(parse_axfr_message(&[0; 5], "example.com").records.is_empty());
}
