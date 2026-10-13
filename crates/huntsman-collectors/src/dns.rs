//! Bounded RFC 1035 DNS wire encoding and question-aware answer parsing.
//!
//! The parser operates over a borrowed `&[u8]`, allocating only a small output vector and the
//! decoded owner names it needs to bind answers to the question. Every offset is bounds-checked,
//! name traversal follows compression pointers only strictly backwards and under a step cap, and
//! the answer count is clamped, so a malformed or adversarial response yields a typed error
//! rather than a panic, an unbounded allocation, or a decompression loop.
//!
//! # Trusting a datagram
//!
//! DNS over UDP is spoofable: an off-path attacker can race the real resolver with a forged
//! datagram. Two controls defend against that, applied by [`parse`] before any record is
//! surfaced:
//!
//! 1. **Response-to-query binding (load-bearing).** The datagram is accepted only if its
//!    transaction id equals the query's, the QR bit marks it a response, the OPCODE is QUERY,
//!    and it echoes exactly the question asked (QNAME case-insensitively, QTYPE and QCLASS). A
//!    datagram that fails any check is rejected with [`HuntsmanError::Protocol`], never merged.
//! 2. **Owner binding.** A returned A/AAAA record must be owned by the queried name or by a name
//!    reached from it through the answer's own CNAME chain; records owned by any other name are
//!    dropped.
//!
//! ## Transaction id scheme and its honest threat model
//!
//! [`transaction_id`] derives a 16-bit id from a per-process nonce, a per-query monotonic
//! counter, the queried name and the QTYPE, through a non-cryptographic keyed mix (FNV-1a with a
//! SplitMix64 finalizer). The engine forbids `SystemTime::now`-style clocks and `Math.random`
//! nondeterminism in library code and carries no RNG dependency, so the id is derived rather than
//! drawn from entropy.
//!
//! This makes the id **non-constant and not trivially guessable across processes** (the nonce is
//! the process id, unknown to an off-path attacker who cannot observe the process), and distinct
//! for consecutive queries within a process (the counter). It is deliberately **not**
//! cryptographically unpredictable: an attacker who learns the nonce and counter could reproduce
//! the id. True unpredictability would need an entropy source this crate does not depend on. The
//! id is therefore defense in depth; the load-bearing control is the strict response binding
//! above, and in particular the question echo, which a blind off-path spoofer must also match.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use huntsman_core::HuntsmanError;

/// RFC 1035 TYPE for an IPv4 host address.
pub const TYPE_A: u16 = 1;
/// RFC 3596 TYPE for an IPv6 host address.
pub const TYPE_AAAA: u16 = 28;
/// RFC 1035 TYPE for a canonical-name alias.
const TYPE_CNAME: u16 = 5;
/// RFC 6891 TYPE for the EDNS0 OPT pseudo-record.
const TYPE_OPT: u16 = 41;
/// RFC 1035 CLASS IN (Internet).
const CLASS_IN: u16 = 1;
/// Recursion-Desired flag in the query header.
const FLAG_RECURSION_DESIRED: u16 = 0x0100;
/// QR bit: set on a response.
const FLAG_QR: u16 = 0x8000;
/// TC bit: set when the message was truncated.
const FLAG_TC: u16 = 0x0200;
/// Mask for the 4-bit RCODE in the flags word.
const RCODE_MASK: u16 = 0x000F;
/// RCODE for a definitive "name does not exist".
const RCODE_NXDOMAIN: u8 = 3;

/// Maximum labels or pointer hops walked while decoding a name (loop and runaway guard).
const MAX_NAME_STEPS: usize = 128;
/// Maximum answer records parsed from one response (allocation guard).
const MAX_ANSWERS: usize = 64;
/// Fixed RR header width after the owner name: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2).
const RR_FIXED_LEN: usize = 10;
/// DNS message header width.
const HEADER_LEN: usize = 12;
/// Wire width of the EDNS0 OPT record this crate appends: root name(1) TYPE(2) CLASS(2) TTL(4)
/// RDLENGTH(2).
const OPT_LEN: usize = 11;

/// A resolved address record extracted from a DNS answer section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecord {
    /// An `A` record (IPv4).
    A(Ipv4Addr),
    /// An `AAAA` record (IPv6).
    Aaaa(Ipv6Addr),
}

impl DnsRecord {
    /// The address this record carries.
    #[must_use]
    pub fn ip(&self) -> IpAddr {
        match self {
            Self::A(addr) => IpAddr::V4(*addr),
            Self::Aaaa(addr) => IpAddr::V6(*addr),
        }
    }
}

/// The question a query asked, used to bind a response to the query that provoked it.
///
/// The `name` is the canonical, ASCII-lowercased owner name without a trailing root dot, exactly
/// as it appears in an [`huntsman_core::EntityKind::Domain`]. [`parse`] compares the response's
/// echoed question against this key case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryKey {
    /// Transaction id the query carried; the response must echo it.
    pub id: u16,
    /// Canonical queried owner name (lowercased, no trailing dot).
    pub name: String,
    /// Queried record type ([`TYPE_A`] or [`TYPE_AAAA`]); the response question must match it.
    pub qtype: u16,
}

/// The typed result of validating one response that is already bound to its query.
///
/// A datagram that fails the binding checks is not represented here; [`parse`] rejects it with
/// [`HuntsmanError::Protocol`] so the caller never mistakes a spoof for a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsOutcome {
    /// `NOERROR`: the address records bound to the queried name. An empty vector is a real zero
    /// answer (the name exists but has no record of this type), not a failure.
    Answers(Vec<DnsRecord>),
    /// `NXDOMAIN`: the queried name definitively does not exist.
    NameError,
    /// The TC bit was set: this UDP answer is truncated and must not be trusted as complete.
    Truncated,
    /// `SERVFAIL`, `REFUSED` or another non-`NOERROR`/`NXDOMAIN` RCODE: a server-side failure,
    /// carrying the RCODE. This is never a silent empty success.
    ServerFailure(u8),
}

fn protocol(message: &'static str) -> HuntsmanError {
    HuntsmanError::Protocol(message.to_owned())
}

/// A non-cryptographic 64-bit finalizer (SplitMix64) used to diffuse the keyed id mix.
fn splitmix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Derive a 16-bit transaction id from the inputs available at call time.
///
/// `nonce` is a per-process value, `counter` a per-query monotonic value; together with the
/// queried `name` (compared case-insensitively) and `qtype` they are folded through a keyed
/// FNV-1a mix and a SplitMix64 finalizer. See the [module documentation](self) for the scheme's
/// honest threat model: the id is defense in depth and is **not** cryptographically
/// unpredictable. The load-bearing anti-spoofing control is [`parse`]'s response binding.
#[must_use]
pub fn transaction_id(nonce: u64, counter: u64, name: &str, qtype: u16) -> u16 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut acc = FNV_OFFSET ^ nonce ^ splitmix64(counter);
    for byte in name.as_bytes() {
        acc ^= u64::from(byte.to_ascii_lowercase());
        acc = acc.wrapping_mul(FNV_PRIME);
    }
    acc ^= u64::from(qtype);
    acc = acc.wrapping_mul(FNV_PRIME);
    (splitmix64(acc) & 0xFFFF) as u16
}

/// Encode a standard recursive query for `domain` and `qtype`, advertising `edns_udp_payload`
/// through an EDNS0 OPT record so a large answer is negotiated rather than assumed.
///
/// # Errors
/// Returns [`HuntsmanError::Protocol`] if the domain or any label violates RFC 1035 length limits.
pub fn encode_query(
    id: u16,
    domain: &str,
    qtype: u16,
    edns_udp_payload: u16,
) -> Result<Vec<u8>, HuntsmanError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(protocol("query domain length out of range"));
    }
    let mut msg = Vec::with_capacity(HEADER_LEN + domain.len() + 6 + OPT_LEN);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&1u16.to_be_bytes()); // ARCOUNT (the EDNS OPT below)
    for label in domain.split('.') {
        let len = label.len();
        if len == 0 || len > 63 {
            return Err(protocol("query label length out of range"));
        }
        msg.push(u8::try_from(len).map_err(|_| protocol("label length overflow"))?);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root label terminator
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    // EDNS0 OPT pseudo-record (RFC 6891): NAME=root, TYPE=OPT, CLASS=requestor UDP payload size,
    // TTL=0 (extended-rcode 0, version 0, flags 0 — DO bit clear), RDLENGTH=0.
    msg.push(0);
    msg.extend_from_slice(&TYPE_OPT.to_be_bytes());
    msg.extend_from_slice(&edns_udp_payload.to_be_bytes());
    msg.extend_from_slice(&[0, 0, 0, 0]); // TTL
    msg.extend_from_slice(&0u16.to_be_bytes()); // RDLENGTH
    Ok(msg)
}

/// Validate a response against its `query` and return its typed outcome.
///
/// The response is bound to the query first (transaction id, QR bit, OPCODE, and the echoed
/// question); any mismatch is a rejection. A set TC bit yields [`DnsOutcome::Truncated`]. A
/// `NOERROR` response yields the A/AAAA records whose owner is the queried name or a name reached
/// through the answer's CNAME chain. `NXDOMAIN` yields [`DnsOutcome::NameError`] and every other
/// RCODE [`DnsOutcome::ServerFailure`].
///
/// # Errors
/// Returns [`HuntsmanError::Protocol`] if the datagram is truncated below a required boundary, a
/// name is malformed or compressed unsafely, or the response fails to bind to the query.
pub fn parse(query: &QueryKey, msg: &[u8]) -> Result<DnsOutcome, HuntsmanError> {
    if msg.len() < HEADER_LEN {
        return Err(protocol("DNS message shorter than its header"));
    }
    if u16::from_be_bytes([msg[0], msg[1]]) != query.id {
        return Err(protocol("DNS transaction id does not match the query"));
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & FLAG_QR == 0 {
        return Err(protocol("DNS message is not a response (QR bit clear)"));
    }
    if (flags >> 11) & 0x0F != 0 {
        return Err(protocol("DNS response OPCODE is not QUERY"));
    }
    if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(protocol("DNS response does not echo exactly one question"));
    }

    // The echoed question must match the query exactly.
    let (qname, after_name) = read_name(msg, HEADER_LEN)?;
    let q_end = after_name
        .checked_add(4)
        .ok_or_else(|| protocol("DNS question section overflow"))?;
    if q_end > msg.len() {
        return Err(protocol("DNS question section truncated"));
    }
    if qname != query.name.to_ascii_lowercase() {
        return Err(protocol(
            "DNS response question name does not match the query",
        ));
    }
    if u16::from_be_bytes([msg[after_name], msg[after_name + 1]]) != query.qtype {
        return Err(protocol(
            "DNS response question type does not match the query",
        ));
    }
    if u16::from_be_bytes([msg[after_name + 2], msg[after_name + 3]]) != CLASS_IN {
        return Err(protocol("DNS response question class is not IN"));
    }

    // Bound to the query. A truncated UDP answer must not be trusted as complete.
    if flags & FLAG_TC != 0 {
        return Ok(DnsOutcome::Truncated);
    }
    let rcode = (flags & RCODE_MASK) as u8;
    match rcode {
        0 => Ok(DnsOutcome::Answers(parse_answer_section(
            query, msg, q_end,
        )?)),
        RCODE_NXDOMAIN => Ok(DnsOutcome::NameError),
        other => Ok(DnsOutcome::ServerFailure(other)),
    }
}

/// One parsed resource record, keyed by its decoded owner name and the span of its RDATA.
struct ParsedRr {
    owner: String,
    rtype: u16,
    rclass: u16,
    rdata_start: usize,
    rdata_len: usize,
}

/// Decode the answer section and return the A/AAAA records bound to the queried name.
fn parse_answer_section(
    query: &QueryKey,
    msg: &[u8],
    start: usize,
) -> Result<Vec<DnsRecord>, HuntsmanError> {
    let answer_count = usize::from(u16::from_be_bytes([msg[6], msg[7]])).min(MAX_ANSWERS);
    let mut pos = start;
    let mut rrs: Vec<ParsedRr> = Vec::new();
    for _ in 0..answer_count {
        let (owner, after_name) = read_name(msg, pos)?;
        let header_end = after_name
            .checked_add(RR_FIXED_LEN)
            .ok_or_else(|| protocol("DNS resource record header overflow"))?;
        if header_end > msg.len() {
            return Err(protocol("DNS resource record header truncated"));
        }
        let rtype = u16::from_be_bytes([msg[after_name], msg[after_name + 1]]);
        let rclass = u16::from_be_bytes([msg[after_name + 2], msg[after_name + 3]]);
        let rdata_len = usize::from(u16::from_be_bytes([
            msg[after_name + 8],
            msg[after_name + 9],
        ]));
        let rdata_end = header_end
            .checked_add(rdata_len)
            .ok_or_else(|| protocol("DNS record data overflow"))?;
        if rdata_end > msg.len() {
            return Err(protocol("DNS record data truncated"));
        }
        rrs.push(ParsedRr {
            owner,
            rtype,
            rclass,
            rdata_start: header_end,
            rdata_len,
        });
        pos = rdata_end;
    }

    let reachable = reachable_names(query, msg, &rrs)?;

    let mut records = Vec::new();
    for rr in &rrs {
        if rr.rclass != CLASS_IN || !reachable.contains(&rr.owner) {
            continue;
        }
        match rr.rtype {
            TYPE_A if rr.rdata_len == 4 => {
                let o = &msg[rr.rdata_start..rr.rdata_start + 4];
                records.push(DnsRecord::A(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
            }
            TYPE_AAAA if rr.rdata_len == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&msg[rr.rdata_start..rr.rdata_start + 16]);
                records.push(DnsRecord::Aaaa(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    Ok(records)
}

/// The set of owner names an address record may carry to be accepted: the queried name plus every
/// name reachable from it through the answer section's own CNAME chain (bounded fixpoint).
fn reachable_names(
    query: &QueryKey,
    msg: &[u8],
    rrs: &[ParsedRr],
) -> Result<HashSet<String>, HuntsmanError> {
    let mut cnames: Vec<(String, String)> = Vec::new();
    for rr in rrs {
        if rr.rtype == TYPE_CNAME && rr.rclass == CLASS_IN {
            let (target, _) = read_name(msg, rr.rdata_start)?;
            cnames.push((rr.owner.clone(), target));
        }
    }
    let mut reachable = HashSet::new();
    reachable.insert(query.name.to_ascii_lowercase());
    let mut changed = true;
    let mut guard = 0usize;
    while changed && guard <= MAX_ANSWERS {
        changed = false;
        guard += 1;
        for (owner, target) in &cnames {
            if reachable.contains(owner) && !reachable.contains(target) {
                reachable.insert(target.clone());
                changed = true;
            }
        }
    }
    Ok(reachable)
}

/// Decode a (possibly compressed) domain name to its canonical lowercased presentation form,
/// returning the decoded name and the offset just after the name as encoded at `start`.
///
/// Compression pointers are followed only strictly backwards: each pointer target must be less
/// than every previous target and than the name's own start, which makes a forward pointer and a
/// pointer loop impossible, and the total step count is capped as a second guard. Malformed input
/// yields [`HuntsmanError::Protocol`]; the function never panics and never loops.
fn read_name(msg: &[u8], start: usize) -> Result<(String, usize), HuntsmanError> {
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut after: Option<usize> = None;
    let mut min_target = start;
    for _ in 0..=MAX_NAME_STEPS {
        let len = *msg
            .get(pos)
            .ok_or_else(|| protocol("DNS name ran past buffer"))?;
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    let next = after.unwrap_or(pos + 1);
                    return Ok((String::from_utf8_lossy(&out).into_owned(), next));
                }
                let label_start = pos + 1;
                let label_end = label_start
                    .checked_add(usize::from(len))
                    .ok_or_else(|| protocol("DNS label length overflow"))?;
                if label_end > msg.len() {
                    return Err(protocol("DNS label ran past buffer"));
                }
                if !out.is_empty() {
                    out.push(b'.');
                }
                out.extend(
                    msg[label_start..label_end]
                        .iter()
                        .map(u8::to_ascii_lowercase),
                );
                pos = label_end;
            }
            0xC0 => {
                let lo = *msg
                    .get(pos + 1)
                    .ok_or_else(|| protocol("DNS name pointer ran past buffer"))?;
                let target = (usize::from(len & 0x3F) << 8) | usize::from(lo);
                if after.is_none() {
                    after = Some(pos + 2);
                }
                if target >= min_target {
                    return Err(protocol("DNS name pointer must point strictly backwards"));
                }
                min_target = target;
                pos = target;
            }
            _ => return Err(protocol("reserved DNS label bits set")),
        }
    }
    Err(protocol("DNS name exceeded its step bound"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_wire(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for label in name.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v
    }

    /// A pointer to the question name, which always begins at offset 12.
    fn qname_ptr() -> Vec<u8> {
        vec![0xC0, 0x0C]
    }

    /// Build a response: header(id, flags), one question (qname/qtype/IN), then answer RRs given
    /// as (owner_wire, rtype, rclass, rdata).
    fn build(
        id: u16,
        flags: u16,
        qname: &str,
        qtype: u16,
        answers: &[(Vec<u8>, u16, u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&flags.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        msg.extend_from_slice(&name_wire(qname));
        msg.extend_from_slice(&qtype.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        for (owner, rtype, rclass, rdata) in answers {
            msg.extend_from_slice(owner);
            msg.extend_from_slice(&rtype.to_be_bytes());
            msg.extend_from_slice(&rclass.to_be_bytes());
            msg.extend_from_slice(&300u32.to_be_bytes()); // TTL
            msg.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            msg.extend_from_slice(rdata);
        }
        msg
    }

    fn key(id: u16, name: &str, qtype: u16) -> QueryKey {
        QueryKey {
            id,
            name: name.to_owned(),
            qtype,
        }
    }

    /// Parse and require success. `HuntsmanError` is not `PartialEq`, so comparisons are made on
    /// the [`DnsOutcome`] this returns rather than on the whole `Result`.
    fn ok(query: &QueryKey, msg: &[u8]) -> DnsOutcome {
        match parse(query, msg) {
            Ok(outcome) => outcome,
            Err(err) => panic!("parse rejected a well-formed datagram: {err}"),
        }
    }

    // --- encoding + EDNS -------------------------------------------------------------------

    #[test]
    fn encodes_a_query_with_an_edns_opt_record() {
        let query = match encode_query(0x1234, "example.com", TYPE_A, 4096) {
            Ok(bytes) => bytes,
            Err(err) => panic!("encode failed: {err}"),
        };
        assert_eq!(&query[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&query[2..4], &FLAG_RECURSION_DESIRED.to_be_bytes());
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([query[6], query[7]]), 0); // ANCOUNT
        assert_eq!(u16::from_be_bytes([query[10], query[11]]), 1); // ARCOUNT (OPT)
        assert_eq!(query[HEADER_LEN], 7); // "example"
                                          // The final OPT_LEN bytes are the OPT pseudo-record advertising 4096.
        let opt = &query[query.len() - OPT_LEN..];
        assert_eq!(opt[0], 0); // root owner
        assert_eq!(u16::from_be_bytes([opt[1], opt[2]]), TYPE_OPT);
        assert_eq!(u16::from_be_bytes([opt[3], opt[4]]), 4096); // UDP payload size
        assert_eq!(&opt[5..9], &[0, 0, 0, 0]); // TTL
        assert_eq!(u16::from_be_bytes([opt[9], opt[10]]), 0); // RDLENGTH
    }

    #[test]
    fn rejects_oversized_or_empty_labels() {
        let long = "a".repeat(64);
        assert!(encode_query(1, &long, TYPE_A, 4096).is_err());
        assert!(encode_query(1, "", TYPE_A, 4096).is_err());
    }

    // --- response binding (finding 1) ------------------------------------------------------

    #[test]
    fn binds_and_parses_an_a_record_through_a_compression_pointer() {
        let msg = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![93, 184, 216, 34])],
        );
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))])
        );
    }

    #[test]
    fn a_forged_transaction_id_is_rejected() {
        let msg = build(
            0x9999,
            0x8180,
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![6, 6, 6, 6])],
        );
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    #[test]
    fn a_query_masquerading_as_a_response_is_rejected() {
        let msg = build(
            0x1234,
            0x0100, // QR clear
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![6, 6, 6, 6])],
        );
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    #[test]
    fn a_non_query_opcode_is_rejected() {
        let msg = build(
            0x1234,
            0x8800, // QR set, OPCODE = 1 (not QUERY)
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![6, 6, 6, 6])],
        );
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    #[test]
    fn a_question_type_mismatch_is_rejected() {
        let msg = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_AAAA, // response echoes AAAA...
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![6, 6, 6, 6])],
        );
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err()); // ...but we asked A
    }

    #[test]
    fn a_question_name_mismatch_is_rejected() {
        let msg = build(
            0x1234,
            0x8180,
            "evil.example",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![6, 6, 6, 6])],
        );
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    #[test]
    fn question_name_match_is_case_insensitive() {
        let msg = build(
            0x1234,
            0x8180,
            "Example.COM",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![1, 2, 3, 4])],
        );
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))])
        );
    }

    // --- owner binding + CNAME chain (finding 2) -------------------------------------------

    #[test]
    fn an_owner_mismatched_record_is_dropped_not_returned() {
        // Bound to the query (question matches) but the answer is owned by attacker.example.
        let msg = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_A,
            &[(
                name_wire("attacker.example"),
                TYPE_A,
                CLASS_IN,
                vec![6, 6, 6, 6],
            )],
        );
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![])
        );
    }

    #[test]
    fn a_cname_chain_is_followed_to_its_address() {
        let msg = build(
            0x1234,
            0x8180,
            "www.example.com",
            TYPE_A,
            &[
                (
                    qname_ptr(),
                    TYPE_CNAME,
                    CLASS_IN,
                    name_wire("host.example.net"),
                ),
                (
                    name_wire("host.example.net"),
                    TYPE_A,
                    CLASS_IN,
                    vec![1, 2, 3, 4],
                ),
            ],
        );
        assert_eq!(
            ok(&key(0x1234, "www.example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))])
        );
    }

    #[test]
    fn an_address_off_the_cname_chain_is_dropped() {
        let msg = build(
            0x1234,
            0x8180,
            "www.example.com",
            TYPE_A,
            &[
                (
                    qname_ptr(),
                    TYPE_CNAME,
                    CLASS_IN,
                    name_wire("host.example.net"),
                ),
                (
                    name_wire("host.example.net"),
                    TYPE_A,
                    CLASS_IN,
                    vec![1, 2, 3, 4],
                ),
                // An A owned by an unrelated name injected into the same answer section.
                (
                    name_wire("unrelated.example"),
                    TYPE_A,
                    CLASS_IN,
                    vec![9, 9, 9, 9],
                ),
            ],
        );
        assert_eq!(
            ok(&key(0x1234, "www.example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![DnsRecord::A(Ipv4Addr::new(1, 2, 3, 4))])
        );
    }

    // --- unsafe compression (finding 2) ----------------------------------------------------

    #[test]
    fn a_self_referential_pointer_is_rejected_without_looping() {
        // Question example.com A occupies offsets 12..29; the answer owner at offset 29 is a
        // pointer to offset 29 (itself).
        let mut msg = build(0x1234, 0x8180, "example.com", TYPE_A, &[]);
        msg[7] = 1; // claim one answer
        msg.extend_from_slice(&[0xC0, 0x1D]); // pointer to offset 29
        msg.extend_from_slice(&[0; 14]); // filler so the RR header is in-bounds
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    #[test]
    fn a_forward_pointer_is_rejected() {
        let mut msg = build(0x1234, 0x8180, "example.com", TYPE_A, &[]);
        msg[7] = 1; // claim one answer
        msg.extend_from_slice(&[0xC0, 0x28]); // pointer to offset 40 (ahead of itself)
        msg.extend_from_slice(&[0; 20]);
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &msg).is_err());
    }

    // --- RCODE / TC (finding 3) ------------------------------------------------------------

    #[test]
    fn nxdomain_is_a_definitive_empty_result() {
        let msg = build(0x1234, 0x8183, "example.com", TYPE_A, &[]);
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::NameError
        );
    }

    #[test]
    fn servfail_and_refused_are_typed_failures() {
        let servfail = build(0x1234, 0x8182, "example.com", TYPE_A, &[]);
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &servfail),
            DnsOutcome::ServerFailure(2)
        );
        let refused = build(0x1234, 0x8185, "example.com", TYPE_A, &[]);
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &refused),
            DnsOutcome::ServerFailure(5)
        );
    }

    #[test]
    fn a_noerror_with_no_matching_record_is_a_real_zero() {
        let msg = build(0x1234, 0x8180, "example.com", TYPE_A, &[]);
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::Answers(vec![])
        );
    }

    #[test]
    fn a_truncated_flag_is_a_distinct_outcome() {
        // TC set even though an answer is present: the datagram must not be trusted as complete.
        let msg = build(
            0x1234,
            0x8380,
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![1, 2, 3, 4])],
        );
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_A), &msg),
            DnsOutcome::Truncated
        );
    }

    // --- AAAA (finding 5) ------------------------------------------------------------------

    #[test]
    fn an_aaaa_record_is_parsed() {
        let addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let msg = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_AAAA,
            &[(qname_ptr(), TYPE_AAAA, CLASS_IN, addr.octets().to_vec())],
        );
        assert_eq!(
            ok(&key(0x1234, "example.com", TYPE_AAAA), &msg),
            DnsOutcome::Answers(vec![DnsRecord::Aaaa(addr)])
        );
    }

    // --- malformed input -------------------------------------------------------------------

    #[test]
    fn short_and_truncated_and_garbage_datagrams_error_without_panicking() {
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &[0u8; 4]).is_err());
        let mut truncated = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![1, 2, 3, 4])],
        );
        truncated.truncate(truncated.len() - 2); // cut into the A rdata
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &truncated).is_err());
        // A header-only message with a bogus id never matches and never panics.
        assert!(parse(&key(0x1234, "example.com", TYPE_A), &[0xFFu8; HEADER_LEN]).is_err());
    }

    #[test]
    fn a_hostile_answer_count_does_not_loop_or_over_allocate() {
        let mut hostile = build(
            0x1234,
            0x8180,
            "example.com",
            TYPE_A,
            &[(qname_ptr(), TYPE_A, CLASS_IN, vec![1, 2, 3, 4])],
        );
        hostile[6] = 0xFF; // ANCOUNT = 65535
        hostile[7] = 0xFF;
        let result = parse(&key(0x1234, "example.com", TYPE_A), &hostile);
        match result {
            Err(_) => {}
            Ok(DnsOutcome::Answers(records)) => assert!(records.len() <= MAX_ANSWERS),
            Ok(other) => panic!("unexpected outcome: {other:?}"),
        }
    }

    // --- transaction id (finding 1, defense in depth) --------------------------------------

    #[test]
    fn transaction_id_is_deterministic_and_non_constant() {
        // Same inputs -> same id.
        assert_eq!(
            transaction_id(7, 3, "example.com", TYPE_A),
            transaction_id(7, 3, "example.com", TYPE_A)
        );
        // It is not the old hard-coded constant for a representative input.
        assert_ne!(transaction_id(0, 0, "example.com", TYPE_A), 0x1a2b);
        // Varying the counter yields more than one id over a batch (non-constant).
        let over_counters: HashSet<u16> = (0..64)
            .map(|c| transaction_id(42, c, "example.com", TYPE_A))
            .collect();
        assert!(over_counters.len() > 1, "id is constant across the counter");
        // Varying the domain yields more than one id over a batch.
        let over_domains: HashSet<u16> = (0..64)
            .map(|n| transaction_id(42, 0, &format!("h{n}.example.com"), TYPE_A))
            .collect();
        assert!(over_domains.len() > 1, "id is constant across domains");
    }
}
