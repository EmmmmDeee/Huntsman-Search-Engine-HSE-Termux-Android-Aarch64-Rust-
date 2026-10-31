//! DNS messages in their wire form (RFC 1035), in-tree: a query for one name and type, and an
//! answer read back with its question and every record it carries. DNS-over-HTTPS in the RFC 8484
//! form (`application/dns-message`) carries these, for resolvers that do not speak the JSON form,
//! and so does plain DNS over UDP. Names in an answer may be compressed; a pointer loop, a label
//! past the end of the message or a record cut short is an error, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::base64::base16_lower;

/// The largest UDP answer a query offers to take (EDNS0), so a long record set is not truncated.
pub const UDP_PAYLOAD: u16 = 4096;
/// Pointers followed in one name before the name is refused as a loop.
const MAX_POINTERS: usize = 32;
/// The longest name in wire form, its labels and their length octets and the root's zero octet
/// (RFC 1035 section 3.1). A longer one is refused, so a record pointing at a hostile name
/// cannot make every record a copy of tens of kilobytes of escaped text.
const MAX_NAME_OCTETS: usize = 255;

/// Record types by their code.
pub const A: u16 = 1;
pub const AAAA: u16 = 28;

/// Response codes.
pub const NOERROR: u8 = 0;
pub const NXDOMAIN: u8 = 3;

/// Why a body is not a DNS message, or a name cannot be asked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    #[error("DNS message ends early")]
    Truncated,
    #[error("DNS message has a malformed name")]
    BadName,
    #[error("DNS message is a query, not an answer")]
    NotAnswer,
    #[error("not a name that can be asked: {0}")]
    BadQuery(String),
}

/// What an answer said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: u16,
    /// The response code: 0 no error, 2 server failure, 3 the name does not exist, 5 refused.
    pub rcode: u8,
    /// The answer was cut to fit (TC): it is not the whole answer.
    pub truncated: bool,
    /// The question the answer is to.
    pub question: Option<Question>,
    pub answers: Vec<Record>,
    /// The resolver's extended errors (RFC 8914), such as a filter's "Filtered".
    pub extended_errors: Vec<ExtendedError>,
}

/// An extended DNS error (RFC 8914): why a resolver answered as it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendedError {
    pub code: u16,
    /// The resolver's own words, often empty.
    pub text: String,
}

impl ExtendedError {
    /// `Blocked`, `Censored` and `Filtered`: the resolver withheld the answer by its own policy.
    pub const WITHHELD: [u16; 3] = [15, 16, 17];

    /// The code's name in RFC 8914's registry, with the resolver's text after it. **Pure.**
    #[must_use]
    pub fn describe(&self) -> String {
        let name = match self.code {
            0 => "Other",
            1 => "Unsupported DNSKEY Algorithm",
            2 => "Unsupported DS Digest Type",
            3 => "Stale Answer",
            4 => "Forged Answer",
            5 => "DNSSEC Indeterminate",
            6 => "DNSSEC Bogus",
            7 => "Signature Expired",
            8 => "Signature Not Yet Valid",
            9 => "DNSKEY Missing",
            10 => "RRSIGs Missing",
            11 => "No Zone Key Bit Set",
            12 => "NSEC Missing",
            13 => "Cached Error",
            14 => "Not Ready",
            15 => "Blocked",
            16 => "Censored",
            17 => "Filtered",
            18 => "Prohibited",
            19 => "Stale NXDOMAIN Answer",
            20 => "Not Authoritative",
            21 => "Not Supported",
            22 => "No Reachable Authority",
            23 => "Network Error",
            24 => "Invalid Data",
            _ => "Unassigned",
        };
        if self.text.is_empty() {
            format!("{} {name}", self.code)
        } else {
            format!("{} {name}: {}", self.code, self.text)
        }
    }

    /// Whether the resolver says it withheld the answer by policy. **Pure.**
    #[must_use]
    pub fn withheld(&self) -> bool {
        Self::WITHHELD.contains(&self.code)
    }
}

impl Message {
    /// The addresses among the answer's records, in order. **Pure.**
    #[must_use]
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.answers
            .iter()
            .filter_map(|record| match record.data {
                Data::A(address) => Some(IpAddr::V4(address)),
                Data::Aaaa(address) => Some(IpAddr::V6(address)),
                _ => None,
            })
            .collect()
    }
}

/// A message's question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub kind: u16,
}

/// One resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub kind: u16,
    pub ttl: u32,
    pub data: Data,
}

/// A record's data, read by its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// `CNAME`, `NS`, `PTR` and `DNAME`: one name.
    Name(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Txt(Vec<String>),
    Soa {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Caa {
        flags: u8,
        tag: String,
        value: String,
    },
    /// Any other type, as its bytes.
    Other(Vec<u8>),
}

impl Data {
    /// The record's data in presentation form, as a zone file writes it. **Pure.**
    #[must_use]
    pub fn presentation(&self) -> String {
        match self {
            Self::A(address) => address.to_string(),
            Self::Aaaa(address) => address.to_string(),
            Self::Name(name) => name.clone(),
            Self::Mx {
                preference,
                exchange,
            } => format!("{preference} {exchange}"),
            Self::Txt(strings) => strings
                .iter()
                .map(|text| format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            Self::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            // RFC 3597 section 5: `\#`, the length, then the data in hex, which is absent when
            // the length is zero.
            Self::Other(bytes) if bytes.is_empty() => "\\# 0".to_owned(),
            Self::Other(bytes) => format!("\\# {} {}", bytes.len(), base16_lower(bytes)),
        }
    }
}

/// The name of a record type, or `TYPEn` for one without. **Pure.**
#[must_use]
pub fn type_name(kind: u16) -> String {
    match kind {
        A => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        AAAA => "AAAA".into(),
        33 => "SRV".into(),
        39 => "DNAME".into(),
        257 => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

/// The name of a response code, or `RCODEn` for one without. **Pure.**
#[must_use]
pub fn rcode_name(rcode: u8) -> String {
    match rcode {
        NOERROR => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        NXDOMAIN => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

/// Whether DNS can carry `name`: ASCII, at most 253 bytes without its root dot, and every label 1
/// to 63 bytes (RFC 1035, 2.3.4). A name past that is never sent, by the wire query or the system
/// resolver, so no answer can be read for it. **Pure.**
#[must_use]
pub fn askable_name(name: &str) -> bool {
    let bare = name.strip_suffix('.').unwrap_or(name);
    bare.len() <= 253
        && bare.is_ascii()
        && bare.split('.').all(|label| (1..=63).contains(&label.len()))
}

/// A recursive query for `name` and `kind` with id `id`, offering EDNS0. **Pure.**
///
/// # Errors
/// [`WireError::BadQuery`] for a name that is not ASCII, has an empty label, a label over 63
/// bytes, or is over 253 bytes.
pub fn query(id: u16, name: &str, kind: u16) -> Result<Vec<u8>, WireError> {
    let bare = name.strip_suffix('.').unwrap_or(name);
    let bad = || WireError::BadQuery(name.to_owned());
    if !askable_name(name) {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(bare.len() + 30);
    out.extend_from_slice(&id.to_be_bytes());
    // Recursion desired; one question, one additional record (the OPT).
    out.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in bare.split('.') {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|length| (1..=63).contains(length))
            .ok_or_else(bad)?;
        out.push(length);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&[0, 1]);
    // EDNS0 OPT: the root name, type 41, the payload size as its class, no flags or options.
    out.extend_from_slice(&[0, 0, 41]);
    out.extend_from_slice(&UDP_PAYLOAD.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    Ok(out)
}

/// The question of any message, query or answer. **Pure.**
///
/// # Errors
/// [`WireError`] when `body` holds no whole question.
pub fn question(body: &[u8]) -> Result<Question, WireError> {
    let header = body.get(..12).ok_or(WireError::Truncated)?;
    if u16::from_be_bytes([header[4], header[5]]) == 0 {
        return Err(WireError::Truncated);
    }
    let (name, at) = read_name(body, 12)?;
    let kind = body.get(at..at + 2).ok_or(WireError::Truncated)?;
    Ok(Question {
        name,
        kind: u16::from_be_bytes([kind[0], kind[1]]),
    })
}

/// Read an answer. **Pure.**
///
/// # Errors
/// [`WireError`] when `body` is not a whole DNS answer.
pub fn parse(body: &[u8]) -> Result<Message, WireError> {
    let header = body.get(..12).ok_or(WireError::Truncated)?;
    let word = |at: usize| u16::from_be_bytes([header[at], header[at + 1]]);
    let flags = word(2);
    if flags & 0x8000 == 0 {
        return Err(WireError::NotAnswer);
    }
    let mut at = 12;
    let mut first = None;
    for _ in 0..word(4) {
        let (name, next) = read_name(body, at)?;
        let kind = body.get(next..next + 4).ok_or(WireError::Truncated)?;
        first.get_or_insert(Question {
            name,
            kind: u16::from_be_bytes([kind[0], kind[1]]),
        });
        at = next + 4;
    }
    let mut answers = Vec::new();
    for _ in 0..word(6) {
        let (record, next) = read_record(body, at)?;
        answers.push(record);
        at = next;
    }
    Ok(Message {
        id: word(0),
        rcode: u8::try_from(flags & 0x0f).unwrap_or_default(),
        truncated: flags & 0x0200 != 0,
        question: first,
        answers,
        extended_errors: extended_errors(body, at, word(8), word(10)),
    })
}

/// The extended errors in the OPT record of the additional section, read past `authority`
/// records from `at`. Only what reads cleanly is kept: a malformed tail does not undo the answer.
/// **Pure.**
fn extended_errors(
    body: &[u8],
    mut at: usize,
    authority: u16,
    additional: u16,
) -> Vec<ExtendedError> {
    let mut out = Vec::new();
    for index in 0..u32::from(authority) + u32::from(additional) {
        let Ok((record, next)) = read_record(body, at) else {
            break;
        };
        at = next;
        let (true, Data::Other(mut options)) = (
            index >= u32::from(authority) && record.kind == 41,
            record.data,
        ) else {
            continue;
        };
        while options.len() >= 4 {
            let code = u16::from_be_bytes([options[0], options[1]]);
            let length = usize::from(u16::from_be_bytes([options[2], options[3]]));
            let Some(value) = options.get(4..4 + length) else {
                break;
            };
            if code == 15 && value.len() >= 2 {
                out.push(ExtendedError {
                    code: u16::from_be_bytes([value[0], value[1]]),
                    text: String::from_utf8_lossy(&value[2..])
                        .trim_end_matches('\0')
                        .to_owned(),
                });
            }
            options.drain(..4 + length);
        }
    }
    out
}

fn read_record(body: &[u8], at: usize) -> Result<(Record, usize), WireError> {
    let (name, at) = read_name(body, at)?;
    let fixed = body.get(at..at + 10).ok_or(WireError::Truncated)?;
    let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
    let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
    let start = at + 10;
    let end = start + usize::from(u16::from_be_bytes([fixed[8], fixed[9]]));
    if end > body.len() {
        return Err(WireError::Truncated);
    }
    let data = read_data(body, kind, start, end)?;
    Ok((
        Record {
            name,
            kind,
            ttl,
            data,
        },
        end,
    ))
}

fn read_data(body: &[u8], kind: u16, start: usize, end: usize) -> Result<Data, WireError> {
    let rdata = &body[start..end];
    let short = |at: usize| {
        rdata
            .get(at..at + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or(WireError::Truncated)
    };
    Ok(match kind {
        A => Data::A(Ipv4Addr::from(
            <[u8; 4]>::try_from(rdata).map_err(|_| WireError::Truncated)?,
        )),
        AAAA => Data::Aaaa(Ipv6Addr::from(
            <[u8; 16]>::try_from(rdata).map_err(|_| WireError::Truncated)?,
        )),
        2 | 5 | 12 | 39 => Data::Name(name_within(body, start, end)?),
        15 => Data::Mx {
            preference: short(0)?,
            exchange: name_within(body, start + 2, end)?,
        },
        16 => Data::Txt(character_strings(rdata)?),
        6 => read_soa(body, start, end)?,
        33 => Data::Srv {
            priority: short(0)?,
            weight: short(2)?,
            port: short(4)?,
            target: name_within(body, start + 6, end)?,
        },
        257 => {
            let (&flags, rest) = rdata.split_first().ok_or(WireError::Truncated)?;
            let (&length, rest) = rest.split_first().ok_or(WireError::Truncated)?;
            let tag = rest
                .get(..usize::from(length))
                .ok_or(WireError::Truncated)?;
            Data::Caa {
                flags,
                tag: String::from_utf8_lossy(tag).into_owned(),
                value: String::from_utf8_lossy(&rest[usize::from(length)..]).into_owned(),
            }
        }
        _ => Data::Other(rdata.to_vec()),
    })
}

/// The name a record's data holds at `start`, which must end by the data's `end`: one that runs
/// on past it reads bytes outside the record. **Pure.**
fn name_within(body: &[u8], start: usize, end: usize) -> Result<String, WireError> {
    if start >= end {
        return Err(WireError::Truncated);
    }
    let (name, next) = read_name(body, start)?;
    if next > end {
        return Err(WireError::Truncated);
    }
    Ok(name)
}

fn read_soa(body: &[u8], start: usize, end: usize) -> Result<Data, WireError> {
    let (mname, at) = read_name(body, start)?;
    let (rname, at) = read_name(body, at)?;
    let numbers = body
        .get(at..at + 20)
        .filter(|_| at + 20 <= end)
        .ok_or(WireError::Truncated)?;
    let number =
        |i: usize| u32::from_be_bytes([numbers[i], numbers[i + 1], numbers[i + 2], numbers[i + 3]]);
    Ok(Data::Soa {
        mname,
        rname,
        serial: number(0),
        refresh: number(4),
        retry: number(8),
        expire: number(12),
        minimum: number(16),
    })
}

/// The character-strings of a TXT record, each as text. **Pure.**
fn character_strings(mut rdata: &[u8]) -> Result<Vec<String>, WireError> {
    let mut out = Vec::new();
    while let Some((&length, rest)) = rdata.split_first() {
        let text = rest
            .get(..usize::from(length))
            .ok_or(WireError::Truncated)?;
        out.push(String::from_utf8_lossy(text).into_owned());
        rdata = &rest[usize::from(length)..];
    }
    Ok(out)
}

/// The name at `at`, following compression pointers, and where the message goes on after it.
/// **Pure.**
fn read_name(body: &[u8], mut at: usize) -> Result<(String, usize), WireError> {
    let mut labels: Vec<String> = Vec::new();
    let mut resume = None;
    let mut pointers = 0;
    // The root's zero octet, then each label and its length octet.
    let mut octets = 1;
    loop {
        let &length = body.get(at).ok_or(WireError::Truncated)?;
        match length {
            0 => {
                let name = if labels.is_empty() {
                    ".".to_owned()
                } else {
                    labels.join(".")
                };
                return Ok((name, resume.unwrap_or(at + 1)));
            }
            1..=63 => {
                octets += 1 + usize::from(length);
                if octets > MAX_NAME_OCTETS {
                    return Err(WireError::BadName);
                }
                let label = body
                    .get(at + 1..at + 1 + usize::from(length))
                    .ok_or(WireError::Truncated)?;
                labels.push(label.iter().map(|&byte| escape(byte)).collect());
                at += 1 + usize::from(length);
            }
            0xc0..=0xff => {
                let &low = body.get(at + 1).ok_or(WireError::Truncated)?;
                pointers += 1;
                if pointers > MAX_POINTERS {
                    return Err(WireError::BadName);
                }
                resume.get_or_insert(at + 2);
                at = (usize::from(length & 0x3f) << 8) | usize::from(low);
            }
            _ => return Err(WireError::BadName),
        }
    }
}

/// A label byte as presentation text: printable ASCII as itself, a dot or backslash escaped, any
/// other byte as `\DDD`. **Pure.**
fn escape(byte: u8) -> String {
    match byte {
        b'.' | b'\\' => format!("\\{}", char::from(byte)),
        0x21..=0x7e => char::from(byte).to_string(),
        _ => format!("\\{byte:03}"),
    }
}

#[cfg(test)]
pub(crate) mod tests;
