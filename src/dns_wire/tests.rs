use super::*;

/// `name` in wire form, uncompressed. **Test only.**
fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name
        .trim_end_matches('.')
        .split('.')
        .filter(|l| !l.is_empty())
    {
        out.push(u8::try_from(label.len()).expect("label"));
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

/// One record's data for [`answer`]: an address, a name, or raw bytes.
pub(crate) enum Rdata<'a> {
    Address(&'a str),
    Name(&'a str),
    Raw(Vec<u8>),
}

/// An answer to `query` (a message [`super::query`] built) with `rcode`, the query's id and
/// question, `records` as `(type, data)` for the asked name, and, when `extended` is set, an OPT
/// record carrying that extended error. **Test only.**
pub(crate) fn answer(
    query: &[u8],
    rcode: u8,
    records: &[(u16, Rdata<'_>)],
    extended: Option<(u16, &str)>,
) -> Vec<u8> {
    let asked = question(query).expect("a question");
    let (_, after) = read_name(query, 12).expect("a name");
    let mut out = query[..2].to_vec();
    out.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1]);
    let count = u16::try_from(records.len()).expect("count");
    out.extend_from_slice(&count.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, u8::from(extended.is_some())]);
    out.extend_from_slice(&query[12..after + 4]);
    for (kind, data) in records {
        let rdata = match data {
            Rdata::Address(text) => match text.parse::<IpAddr>().expect("address") {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            },
            Rdata::Name(name) => encode_name(name),
            Rdata::Raw(bytes) => bytes.clone(),
        };
        out.extend_from_slice(&encode_name(&asked.name));
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0x0e, 0x10]);
        out.extend_from_slice(&u16::try_from(rdata.len()).expect("rdata").to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    if let Some((code, text)) = extended {
        let length = u16::try_from(text.len() + 2).expect("text");
        out.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&(length + 4).to_be_bytes());
        out.extend_from_slice(&15_u16.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&code.to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }
    out
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

/// Cloudflare's answer to `www.github.com A`, its names compressed.
const GITHUB_A: &str = "abcd81800001000200000000037777770667697468756203636f6d0000010001\
c00c0005000100000bbb0002c010c010000100010000001b00048c527003";
/// Cloudflare's answer to `example.com TXT`.
const EXAMPLE_TXT: &str = "abcd81800001000200000000076578616d706c6503636f6d0000100001\
c00c00100001000000cf000c0b763d73706631202d616c6c\
c00c00100001000000cf0021205f6b326e31793476773371746234736b6478396537647874393771726d6d7139";
/// Quad9's answer to `isitblocked.org A`: no such name, with extended error 17, Filtered.
const QUAD9_FILTERED: &str = "abcd810300010000000000010b69736974626c6f636b6564036f7267000001\
000100002904d0000000000006000f00020011";

#[test]
fn a_query_is_the_rfc_1035_form_with_edns0() {
    let asked = query(0x1234, "www.Example.com.", A).expect("query");
    assert_eq!(
        asked,
        [
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1][..],
            &b"\x03www\x07Example\x03com\x00"[..],
            &[0, 1, 0, 1][..],
            &[0, 0, 41, 0x10, 0x00, 0, 0, 0, 0, 0, 0][..],
        ]
        .concat()
    );
    assert_eq!(
        question(&asked),
        Ok(Question {
            name: "www.Example.com".into(),
            kind: A
        })
    );
    assert_eq!(parse(&asked), Err(WireError::NotAnswer));
    let long = format!("{}.com", "a".repeat(64));
    let too_long = vec!["a".repeat(60); 5].join(".");
    for bad in [
        "",
        ".",
        "a..b",
        long.as_str(),
        too_long.as_str(),
        "bücher.de",
    ] {
        assert!(
            matches!(query(1, bad, A), Err(WireError::BadQuery(_))),
            "{bad}"
        );
    }
}

#[test]
fn real_answers_read_with_their_compressed_names_and_records() {
    let github = parse(&hex(GITHUB_A)).expect("github");
    assert_eq!(
        (github.id, github.rcode, github.truncated),
        (0xabcd, NOERROR, false)
    );
    assert_eq!(
        github.question,
        Some(Question {
            name: "www.github.com".into(),
            kind: A
        })
    );
    let records: Vec<(String, String, u32, String)> = github
        .answers
        .iter()
        .map(|r| {
            (
                r.name.clone(),
                type_name(r.kind),
                r.ttl,
                r.data.presentation(),
            )
        })
        .collect();
    assert_eq!(
        records,
        [
            (
                "www.github.com".into(),
                "CNAME".into(),
                3003,
                "github.com".into()
            ),
            ("github.com".into(), "A".into(), 27, "140.82.112.3".into()),
        ]
    );
    assert_eq!(
        github.addresses(),
        ["140.82.112.3".parse::<IpAddr>().expect("ip")]
    );

    let txt = parse(&hex(EXAMPLE_TXT)).expect("txt");
    let texts: Vec<String> = txt.answers.iter().map(|r| r.data.presentation()).collect();
    assert_eq!(
        texts,
        ["\"v=spf1 -all\"", "\"_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9\""]
    );

    let filtered = parse(&hex(QUAD9_FILTERED)).expect("quad9");
    assert_eq!(rcode_name(filtered.rcode), "NXDOMAIN");
    assert!(filtered.answers.is_empty());
    assert_eq!(filtered.extended_errors.len(), 1);
    assert!(filtered.extended_errors[0].withheld());
    assert_eq!(filtered.extended_errors[0].describe(), "17 Filtered");
}

/// An answer carrying one record of each type the reader writes a presentation form for, an
/// unknown type with data and one without, and an extended DNS error.
fn every_record_type() -> Vec<u8> {
    let asked = query(7, "example.com", 255).expect("query");
    let mut caa = vec![0, 5];
    caa.extend_from_slice(b"issueletsencrypt.org");
    let mut soa = [
        encode_name("ns.example.com"),
        encode_name("hostmaster.example.com"),
    ]
    .concat();
    for number in [2024_u32, 7200, 3600, 1_209_600, 300] {
        soa.extend_from_slice(&number.to_be_bytes());
    }
    answer(
        &asked,
        NOERROR,
        &[
            (AAAA, Rdata::Address("2001:db8::1")),
            (2, Rdata::Name("ns.example.com")),
            (
                15,
                Rdata::Raw([vec![0, 10], encode_name("mx.example.com")].concat()),
            ),
            (16, Rdata::Raw(b"\x05a\"b\\c\x00".to_vec())),
            (
                33,
                Rdata::Raw([vec![0, 1, 0, 2, 0x01, 0xbb], encode_name("sip.example.com")].concat()),
            ),
            (257, Rdata::Raw(caa)),
            (6, Rdata::Raw(soa)),
            (99, Rdata::Raw(vec![0xde, 0xad])),
            (100, Rdata::Raw(Vec::new())),
        ],
        Some((0, "")),
    )
}

#[test]
fn every_record_type_reads_in_presentation_form() {
    let message = parse(&every_record_type()).expect("answer");
    let forms: Vec<String> = message
        .answers
        .iter()
        .map(|r| format!("{} {}", type_name(r.kind), r.data.presentation()))
        .collect();
    assert_eq!(
        forms,
        [
            "AAAA 2001:db8::1",
            "NS ns.example.com",
            "MX 10 mx.example.com",
            "TXT \"a\\\"b\\\\c\" \"\"",
            "SRV 1 2 443 sip.example.com",
            "CAA 0 issue \"letsencrypt.org\"",
            "SOA ns.example.com hostmaster.example.com 2024 7200 3600 1209600 300",
            "TYPE99 \\# 2 dead",
            "TYPE100 \\# 0",
        ]
    );
    assert_eq!(message.extended_errors[0].describe(), "0 Other");
    assert!(!message.extended_errors[0].withheld());
}

/// Data of a type without a presentation form of its own is written in RFC 3597 section 5's
/// generic form: `\#`, the data's length in bytes, then its hex, and `\# 0` when there is none.
#[test]
fn unknown_record_data_takes_the_rfc_3597_generic_form() {
    assert_eq!(Data::Other(vec![0xde, 0xad]).presentation(), "\\# 2 dead");
    assert_eq!(Data::Other(Vec::new()).presentation(), "\\# 0");
    assert_eq!(
        Data::Other(vec![0xab; 300]).presentation(),
        format!("\\# 300 {}", "ab".repeat(300))
    );
}

/// A cut, looping or malformed body is an error, never a panic.
#[test]
fn a_hostile_body_is_an_error() {
    let whole = hex(GITHUB_A);
    for cut in 0..whole.len() {
        assert!(parse(&whole[..cut]).is_err(), "cut at {cut}");
    }
    // The CNAME's target points at itself.
    let mut looping = whole.clone();
    let at = whole.len() - 18;
    looping[at..at + 2].copy_from_slice(&[0xc0, u8::try_from(at).expect("offset")]);
    assert!(parse(&looping).is_err());
    // A label length in the reserved 0x40-0xbf range.
    let mut reserved = whole;
    reserved[12] = 0x45;
    assert_eq!(parse(&reserved), Err(WireError::BadName));
    // A malformed OPT record after a whole answer leaves the answer standing.
    let mut tail = hex(QUAD9_FILTERED);
    let length = tail.len();
    tail[length - 7] = 0xff;
    let message = parse(&tail).expect("answer");
    assert_eq!(message.rcode, NXDOMAIN);
    assert!(message.extended_errors.is_empty());
    let label = (0..=255_u8).map(escape).collect::<String>();
    assert!(label.starts_with("\\000\\001"));
    assert!(
        label.contains("\\.")
            && label.contains("\\\\")
            && label.contains("ABC")
            && label.contains("xyz")
    );
}

/// A name longer than 255 octets is refused however it is reached, and the longest legal one
/// still reads: one oversized name pointed at by every record would otherwise be copied, escaped,
/// into each of them.
#[test]
fn a_name_past_255_octets_is_refused() {
    // Four 62-octet labels and a 1-octet one, each with its length octet, and the root make 255
    // octets: the longest name RFC 1035 allows.
    let label = |byte: u8| {
        let mut out = vec![62];
        out.extend(std::iter::repeat_n(byte, 62));
        out
    };
    let header = [0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
    let longest: Vec<u8> = (b'a'..=b'd').flat_map(label).chain([1, b'e', 0]).collect();
    assert_eq!(longest.len(), 255);
    let record = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0, 2, 1];
    let message = |name: &[u8]| {
        let mut out = header.to_vec();
        out.extend_from_slice(name);
        out.extend_from_slice(&[0, 1, 0, 1]);
        out.extend_from_slice(&record);
        out
    };
    let read = parse(&message(&longest)).expect("the longest legal name");
    assert_eq!(read.question.expect("question").name.len(), 4 * 62 + 1 + 4);
    assert_eq!(read.answers.len(), 1);
    // One octet more: a 2-octet last label.
    let over: Vec<u8> = (b'a'..=b'd')
        .flat_map(label)
        .chain([2, b'e', b'f', 0])
        .collect();
    assert_eq!(over.len(), 256);
    assert_eq!(parse(&message(&over)), Err(WireError::BadName));
    assert_eq!(question(&message(&over)), Err(WireError::BadName));
    // The same length reached through a pointer: a record owner of one label pointing on into
    // the longest name.
    let mut pointed = message(&longest);
    let answer = 12 + longest.len() + 4;
    pointed.splice(answer..answer + 2, [1, b'x', 0xc0, 0x0c]);
    assert_eq!(parse(&pointed), Err(WireError::BadName));
}

/// A name in a record's data must end inside that record: one that runs on into the bytes after
/// it is not what the record holds.
#[test]
fn a_name_in_record_data_cannot_run_past_the_record() {
    let query = query(0x1234, "a", 5).expect("query");
    let mut empty = answer(&query, NOERROR, &[(5, Rdata::Raw(Vec::new()))], None);
    empty.extend_from_slice(&[4, b'e', b'v', b'i', b'l', 0]);
    assert_eq!(parse(&empty), Err(WireError::Truncated));
    let mut mx = answer(&query, NOERROR, &[(15, Rdata::Raw(vec![0, 10]))], None);
    mx.extend_from_slice(&[4, b'e', b'v', b'i', b'l', 0]);
    assert_eq!(parse(&mx), Err(WireError::Truncated));
    let mut srv = answer(
        &query,
        NOERROR,
        &[(33, Rdata::Raw(vec![0, 1, 0, 2, 0, 3, 4]))],
        None,
    );
    srv.extend_from_slice(&[b'e', b'v', b'i', b'l', 0]);
    assert_eq!(parse(&srv), Err(WireError::Truncated));
    // A name that ends inside its record, compressed or not, still reads.
    let whole = answer(&query, NOERROR, &[(5, Rdata::Name("b.example"))], None);
    assert_eq!(
        parse(&whole).expect("answer").answers[0].data,
        Data::Name("b.example".into())
    );
    let mut mx = vec![0, 10];
    mx.extend_from_slice(&[0xc0, 0x0c]);
    let pointer = answer(&query, NOERROR, &[(15, Rdata::Raw(mx))], None);
    assert_eq!(
        parse(&pointer).expect("answer").answers[0].data,
        Data::Mx {
            preference: 10,
            exchange: "a".into()
        }
    );
}

/// Every corruption of real and built answers (a byte, an extreme count or pointer, a cut, a
/// repeated stretch) is read or refused: none panics, however its names and counts point.
#[test]
fn a_corrupted_answer_is_read_or_refused_never_a_panic() {
    for (name, body) in [
        ("github", hex(GITHUB_A)),
        ("txt", hex(EXAMPLE_TXT)),
        ("filtered", hex(QUAD9_FILTERED)),
        ("every type", every_record_type()),
    ] {
        for (case, bytes) in crate::test_support::mutations(&body, 0xD45_3E1F, 5_000)
            .into_iter()
            .enumerate()
        {
            let outcome = std::panic::catch_unwind(|| {
                if let Ok(message) = parse(&bytes) {
                    for record in &message.answers {
                        let _ = record.data.presentation();
                    }
                    for error in &message.extended_errors {
                        let _ = error.describe();
                    }
                }
                let _ = question(&bytes);
            });
            assert!(outcome.is_ok(), "{name} case {case} panicked");
        }
    }
}

/// What DNS can carry, one rule for the wire query and the system resolver's callers: at most 253
/// bytes, labels of 1 to 63, ASCII.
#[test]
fn a_name_is_askable_only_within_dns_limits() {
    assert!(askable_name("2.0.0.127.zen.spamhaus.org"));
    assert!(askable_name("example.com."));
    let label = "a".repeat(63);
    assert!(askable_name(&format!("{label}.example")));
    assert!(!askable_name(&format!("{label}a.example")));
    assert!(!askable_name(&format!("{}.com", "a.".repeat(126))));
    assert!(!askable_name("a..example"));
    assert!(!askable_name("bücher.example"));
    assert!(query(1, &format!("{label}a.example"), 1).is_err());
}
