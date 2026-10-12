//! The parsers that read text an outside party controls (DNS TXT records, URIs and ASN strings)
//! must not panic on any input, must accept exactly the records their gate accepts, and must keep
//! the bounds their output promises. Every input comes from a fixed xorshift sequence, so a
//! failure reproduces from the seed and the iteration that failed.

use huntsman_recon::{dmarc, http, spf, textnorm, tlsrpt};

/// A fixed-seed xorshift64 generator. Each test carries its own seed, so every run sees the same
/// inputs.
struct XorShift(u64);

impl XorShift {
    fn draw(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, bound: usize) -> usize {
        let bound = u64::try_from(bound).unwrap_or(u64::MAX);
        usize::try_from(self.draw() % bound).unwrap_or(0)
    }
}

/// Fragments that records are built from, plus the bytes that break byte-indexed code:
/// multi-byte scalars, a combining mark, NUL and the ASCII control characters.
const FRAGMENTS: &[&str] = &[
    "v=spf1",
    "v=DMARC1",
    "v=TLSRPTv1",
    " ",
    "\t",
    "\r",
    "\n",
    "\0",
    ";",
    "=",
    ":",
    "/",
    "@",
    "%",
    "!",
    ",",
    "+",
    "-",
    "~",
    "?",
    "include:",
    "ip4:",
    "ip6:",
    "a",
    "mx",
    "all",
    "redirect=",
    "exp=",
    "p=",
    "sp=",
    "pct=",
    "rua=",
    "ruf=",
    "mailto:",
    "https://",
    "http://",
    "[",
    "]",
    "::",
    "0",
    "100",
    "101",
    "65535",
    "AS",
    "é",
    "€",
    "🙂",
    "\u{301}",
];

fn fragment_record(rng: &mut XorShift) -> String {
    let parts = 1 + rng.below(12);
    let mut text = String::new();
    for _ in 0..parts {
        text.push_str(FRAGMENTS[rng.below(FRAGMENTS.len())]);
    }
    text
}

fn arbitrary_unicode(rng: &mut XorShift) -> String {
    let len = rng.below(48);
    (0..len)
        .filter_map(|_| char::from_u32(u32::try_from(rng.draw() % 0x11_0000).unwrap_or(0x20)))
        .collect()
}

/// Runs every untrusted-text parser on `text` and checks what each one promises.
fn check_parsers(text: &str) {
    let spf_record = spf::parse(text);
    assert_eq!(
        spf_record.is_some(),
        spf::is_spf(text),
        "spf gate on {text:?}"
    );
    if let Some(record) = spf_record {
        // Each term after the version tag yields at most one directive or one invalid term.
        let terms = text.split_whitespace().count().saturating_sub(1);
        assert!(
            record.directives.len() + record.invalid_terms.len() <= terms,
            "spf terms on {text:?}"
        );
    }

    assert_eq!(
        dmarc::parse(text).is_some(),
        dmarc::is_dmarc(text),
        "dmarc gate on {text:?}"
    );

    let tlsrpt_record = tlsrpt::parse(text);
    assert_eq!(
        tlsrpt_record.is_some(),
        tlsrpt::is_tlsrpt(text),
        "tlsrpt gate on {text:?}"
    );
    if let Some(record) = tlsrpt_record {
        // The rua list is one comma-separated field, so it yields at most one entry per segment.
        let segments = text.matches(',').count() + 1;
        assert!(
            record.emails.len() + record.urls.len() <= segments,
            "tlsrpt entries on {text:?}"
        );
    }

    let _ = textnorm::parse_asn(text);
    let _ = http::parse_http_uri(text);
}

#[test]
fn record_parsers_survive_protocol_fragments() {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for _ in 0..20_000 {
        check_parsers(&fragment_record(&mut rng));
    }
}

#[test]
fn record_parsers_survive_arbitrary_unicode() {
    let mut rng = XorShift(0xd1b5_4a32_d192_ed03);
    for _ in 0..20_000 {
        check_parsers(&arbitrary_unicode(&mut rng));
    }
}

#[test]
fn known_hostile_records_do_not_panic() {
    for text in [
        "v=spf1 é",
        "v=spf1 🙂 -all",
        "v=spf1 +\u{301}",
        "v=DMARC1; p=é; pct=٣",
        "v=TLSRPTv1; rua=mailto:é@a.b,https://é",
        "AS٣",
        "\0v=spf1",
    ] {
        check_parsers(text);
    }
}
