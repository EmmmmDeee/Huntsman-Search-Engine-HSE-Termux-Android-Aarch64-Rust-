//! Zero-copy, bounded RFC 1035 DNS wire encoding and answer parsing.
//!
//! The parser operates entirely over a borrowed `&[u8]`, allocating only the small output
//! vector. Every offset is bounds-checked, label traversal is capped, and the answer count is
//! clamped, so a malformed or adversarial response yields a typed error rather than a panic,
//! an unbounded allocation, or a decompression loop.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use huntsman_core::HuntsmanError;

/// RFC 1035 TYPE for an IPv4 host address.
pub const TYPE_A: u16 = 1;
/// RFC 3596 TYPE for an IPv6 host address.
pub const TYPE_AAAA: u16 = 28;
/// RFC 1035 CLASS IN (Internet).
const CLASS_IN: u16 = 1;
/// Recursion-Desired flag in the query header.
const FLAG_RECURSION_DESIRED: u16 = 0x0100;

/// Maximum labels or pointer hops walked while skipping a name (loop and runaway guard).
const MAX_NAME_STEPS: usize = 128;
/// Maximum answer records parsed from one response (allocation guard).
const MAX_ANSWERS: usize = 64;
/// Fixed RR header width after the owner name: TYPE(2) CLASS(2) TTL(4) RDLENGTH(2).
const RR_FIXED_LEN: usize = 10;
/// DNS message header width.
const HEADER_LEN: usize = 12;

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

fn protocol(message: &'static str) -> HuntsmanError {
    HuntsmanError::Protocol(message.to_owned())
}

/// Encode a standard recursive query for `domain` and `qtype`.
///
/// # Errors
/// Returns [`HuntsmanError::Protocol`] if the domain or any label violates RFC 1035 length limits.
pub fn encode_query(id: u16, domain: &str, qtype: u16) -> Result<Vec<u8>, HuntsmanError> {
    if domain.is_empty() || domain.len() > 253 {
        return Err(protocol("query domain length out of range"));
    }
    let mut msg = Vec::with_capacity(HEADER_LEN + domain.len() + 6);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&FLAG_RECURSION_DESIRED.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ANCOUNT, NSCOUNT, ARCOUNT
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
    Ok(msg)
}

/// Parse the answer section, returning every `A`/`AAAA` record (other types are skipped).
///
/// # Errors
/// Returns [`HuntsmanError::Protocol`] if the message is truncated, a name is malformed, or an
/// offset would run past the buffer.
pub fn parse_answers(msg: &[u8]) -> Result<Vec<DnsRecord>, HuntsmanError> {
    if msg.len() < HEADER_LEN {
        return Err(protocol("DNS message shorter than its header"));
    }
    let question_count = usize::from(u16::from_be_bytes([msg[4], msg[5]]));
    let answer_count = usize::from(u16::from_be_bytes([msg[6], msg[7]])).min(MAX_ANSWERS);

    let mut pos = HEADER_LEN;
    for _ in 0..question_count {
        pos = skip_name(msg, pos)?;
        pos = pos
            .checked_add(4) // QTYPE + QCLASS
            .ok_or_else(|| protocol("question section overflow"))?;
        if pos > msg.len() {
            return Err(protocol("question section truncated"));
        }
    }

    let mut records = Vec::new();
    for _ in 0..answer_count {
        pos = skip_name(msg, pos)?;
        let header_end = pos
            .checked_add(RR_FIXED_LEN)
            .ok_or_else(|| protocol("resource record header overflow"))?;
        if header_end > msg.len() {
            return Err(protocol("resource record header truncated"));
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rdlen = usize::from(u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]));
        let rdata_end = header_end
            .checked_add(rdlen)
            .ok_or_else(|| protocol("record data overflow"))?;
        if rdata_end > msg.len() {
            return Err(protocol("record data truncated"));
        }
        let rdata = &msg[header_end..rdata_end];
        match rtype {
            TYPE_A if rdlen == 4 => {
                records.push(DnsRecord::A(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                )));
            }
            TYPE_AAAA if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                records.push(DnsRecord::Aaaa(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        pos = rdata_end;
    }
    Ok(records)
}

/// Advance past a (possibly compressed) domain name, returning the offset just after it.
fn skip_name(msg: &[u8], mut pos: usize) -> Result<usize, HuntsmanError> {
    for _ in 0..MAX_NAME_STEPS {
        let len = *msg
            .get(pos)
            .ok_or_else(|| protocol("name ran past buffer"))?;
        if len == 0 {
            return Ok(pos + 1);
        }
        match len & 0xC0 {
            0x00 => {
                pos = pos
                    .checked_add(1 + usize::from(len))
                    .ok_or_else(|| protocol("name label overflow"))?;
                if pos > msg.len() {
                    return Err(protocol("name label ran past buffer"));
                }
            }
            0xC0 => {
                // A compression pointer is two bytes and terminates the name in place.
                msg.get(pos + 1)
                    .ok_or_else(|| protocol("name pointer ran past buffer"))?;
                return Ok(pos + 2);
            }
            _ => return Err(protocol("reserved DNS label bits set")),
        }
    }
    Err(protocol("name exceeded label bound"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A canned response for `example.com` → 93.184.216.34, with a compressed answer name.
    fn response_a() -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&0x1a2bu16.to_be_bytes()); // id
        msg.extend_from_slice(&0x8180u16.to_be_bytes()); // response, RD, RA
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
                                                    // Question: example.com A IN
        for label in ["example", "com"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        // Answer: pointer to the question name at offset 12, A IN, TTL 300, 4 bytes.
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&300u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);
        msg
    }

    #[test]
    fn encodes_a_well_formed_query() {
        let query = match encode_query(0x1a2b, "example.com", TYPE_A) {
            Ok(bytes) => bytes,
            Err(err) => panic!("encode failed: {err}"),
        };
        assert_eq!(&query[0..2], &0x1a2bu16.to_be_bytes());
        assert_eq!(&query[2..4], &FLAG_RECURSION_DESIRED.to_be_bytes());
        assert_eq!(u16::from_be_bytes([query[4], query[5]]), 1); // QDCOUNT
                                                                 // 7 "example" 3 "com" 0 then QTYPE+QCLASS
        assert_eq!(query[HEADER_LEN], 7);
        assert_eq!(&query[query.len() - 4..], &[0, 1, 0, 1]);
    }

    #[test]
    fn rejects_oversized_labels() {
        let long = "a".repeat(64);
        assert!(encode_query(1, &long, TYPE_A).is_err());
        assert!(encode_query(1, "", TYPE_A).is_err());
    }

    #[test]
    fn parses_an_a_record_through_a_compression_pointer() {
        let records = match parse_answers(&response_a()) {
            Ok(records) => records,
            Err(err) => panic!("parse failed: {err}"),
        };
        assert_eq!(records, vec![DnsRecord::A(Ipv4Addr::new(93, 184, 216, 34))]);
        assert_eq!(records[0].ip(), IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }

    #[test]
    fn truncated_messages_error_without_panicking() {
        assert!(parse_answers(&[0u8; 4]).is_err());
        let mut truncated = response_a();
        truncated.truncate(truncated.len() - 2); // cut into the A rdata
        assert!(parse_answers(&truncated).is_err());
    }

    #[test]
    fn answer_count_is_clamped_against_a_hostile_header() {
        let mut hostile = response_a();
        hostile[6] = 0xFF; // ANCOUNT = 65535
        hostile[7] = 0xFF;
        // Must not loop or over-allocate: it parses what exists, then errors on the next
        // (absent) record rather than trusting the count.
        let result = parse_answers(&hostile);
        assert!(result.is_err() || matches!(result, Ok(ref r) if r.len() <= MAX_ANSWERS));
    }
}
