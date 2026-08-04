//! Entity extraction: regex patterns, confidence scoring, kind classification.
//!
//! Extracts candidate entities from unstructured text (OCR, PDFs, etc.) with:
//! - Pattern matching (email, IPv4, IPv6, domain, URL, social handle, MD5/SHA hashes)
//! - Confidence scoring based on format validation + extraction method
//! - Auto-kind classification via heuristics + JSON schema mapping

pub mod classifier;
pub mod extractor;
pub mod patterns;

pub use extractor::EntityExtractor;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// `cargo-fuzz` harness entry point for the ingest text pipeline.
///
/// `data` stands in for a document `hse ingest` was pointed at — a crawled
/// page, a breach dump, an OCR'd image, an imported file. It is
/// attacker-controlled in the only sense that matters here: nothing upstream
/// constrains its bytes, and an operator ingesting a hostile file must not be
/// able to crash the tool with it. The bytes are taken through
/// `from_utf8_lossy` rather than rejected when invalid, because that is exactly
/// what the real path does — so the fuzzer reaches the replacement-character
/// and multi-byte boundaries a UTF-8-only corpus never would.
///
/// That boundary handling is the point. [`classifier::EntityClassifier::boost_confidence`]
/// slices a window of surrounding context around each match, and byte-indexed
/// slicing of a multi-byte string is the classic way to panic on input someone
/// else chose. `crate::util::str_util::char_window` rounds both ends to a char
/// boundary precisely to prevent that; this target is what proves it holds for
/// inputs nobody thought to write down.
///
/// Both extraction layers are exercised, not just the outer one: the raw
/// [`patterns::extract_by_patterns`] pass (whose hex-token classifier and
/// `Ipv6Addr`-validated candidate scan were rewritten wholesale in #350) and
/// the full [`EntityExtractor`] pipeline over it — boost, threshold, dedup,
/// batch-fold. `min_confidence` is `0.0` so the threshold filter discards
/// nothing and every extracted entity still reaches dedup and batching.
///
/// Exists so `fuzz/fuzz_targets/ingest_text.rs` — an intentionally
/// non-workspace-member crate, see `fuzz/README.md` — has one stable entry,
/// mirroring the shape `modules::cert_intel::fuzz_entry_parse_der` established.
/// `#[doc(hidden)]` keeps it out of rendered docs. Results are discarded
/// deliberately: the property under test is "never panics, never hangs, never
/// slices off a char boundary", not any particular extracted value.
#[doc(hidden)]
pub fn fuzz_entry_extract_text(data: &[u8]) {
    let text = String::from_utf8_lossy(data);

    let raw = patterns::extract_by_patterns(&text);
    let _ = patterns::deduplicate(raw);

    if let Ok(extractor) = EntityExtractor::new(0.0) {
        let _ = extractor.extract_from_text(&text);
        let _ = extractor.extract_and_batch(&text);
    }
}

/// Entity kind detected by the classifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum EntityKind {
    Email,
    Phone,
    Ipv4,
    Ipv6,
    Domain,
    Username,
    Hash,
    Person,
    Organization,
    Url,
    SocialHandle,
    IpRange,
    Port,
    Identifier,
    Unknown(String),
}

/// Parse an HSE target-kind string. Infallible — an unrecognised kind is
/// preserved verbatim as [`EntityKind::Unknown`] rather than rejected, so a
/// document naming a kind HSE doesn't model yet still round-trips. `From`
/// rather than `FromStr` for exactly that reason: there is no error case.
impl From<&str> for EntityKind {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "email" => Self::Email,
            "phone" => Self::Phone,
            "ipv4" | "ip" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "domain" => Self::Domain,
            "username" => Self::Username,
            "hash" => Self::Hash,
            "person" => Self::Person,
            "organization" => Self::Organization,
            "url" => Self::Url,
            "social" | "handle" => Self::SocialHandle,
            "iprange" => Self::IpRange,
            "port" => Self::Port,
            "id" | "identifier" => Self::Identifier,
            other => Self::Unknown(other.to_string()),
        }
    }
}

impl EntityKind {
    pub fn to_str(&self) -> &str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Domain => "domain",
            Self::Username => "username",
            Self::Hash => "hash",
            Self::Person => "person",
            Self::Organization => "organization",
            Self::Url => "url",
            Self::SocialHandle => "social",
            Self::IpRange => "iprange",
            Self::Port => "port",
            Self::Identifier => "identifier",
            Self::Unknown(s) => s.as_str(),
        }
    }
}

/// Extracted entity with confidence and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedEntity {
    pub kind: EntityKind,
    pub value: String,
    pub confidence: f64,              // 0.0-1.0
    pub context: Option<String>,      // Surrounding text for validation
    pub source_pattern: String,       // "email_rfc5322", "phone_e164", etc.
    pub boost_reason: Option<String>, // Why confidence was boosted
}

/// Extraction error.
#[derive(Error, Debug)]
pub enum ExtractionError {
    #[error("Classifier config load failed: {0}")]
    ConfigError(String),
    #[error("Pattern compilation failed: {0}")]
    PatternError(String),
    #[error("Invalid entity: {0}")]
    ValidationError(String),
}

pub type ExtractionResult<T> = Result<T, ExtractionError>;

#[cfg(test)]
mod tests {
    use super::*;

    /// The fuzz entry must survive the input classes a fuzzer reaches first,
    /// on the stable toolchain and on every push.
    ///
    /// `fuzz.yml` runs on a Monday schedule and its own path filter, so without
    /// this the harness could rot for a week — or be wired up wrong and nobody
    /// would know until the next scheduled run. These cases are the ones with a
    /// mechanism behind them, not arbitrary noise:
    ///
    /// - **Char boundaries.** Confidence boosting slices a context window around
    ///   each match. Byte-slicing a multi-byte string is the classic panic, so
    ///   every case here puts a match immediately beside non-ASCII text — 2-, 3-
    ///   and 4-byte code points, and a lone match at each end of the input.
    /// - **Invalid UTF-8.** The real path is `from_utf8_lossy`, so bare
    ///   continuation bytes and truncated sequences become replacement
    ///   characters mid-window rather than being rejected upstream.
    /// - **Degenerate runs.** A long hex run and a long colon run drive the
    ///   hex-token classifier and the `Ipv6Addr`-gated candidate scan — both
    ///   rewritten in #350 — at their length boundaries (32/40/64/128).
    #[test]
    fn fuzz_entry_survives_boundary_and_invalid_utf8_input() {
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\xff\xfe\xfd".to_vec(),
            b"caf\xc3".to_vec(),
            b"\x80\x80a@b.com\x80\x80".to_vec(),
            "café a@b.com naïve".as_bytes().to_vec(),
            "☃2001:db8::1☃".as_bytes().to_vec(),
            "𝔘a@b.com𝔘".as_bytes().to_vec(),
            "日本語 https://例え.jp/パス 日本語".as_bytes().to_vec(),
            "a@b.com".as_bytes().to_vec(),
            b"@".to_vec(),
            b"::".to_vec(),
            b":::::::::::::::::::::::::::::".to_vec(),
            vec![b'a'; 4096],
            vec![b'f'; 4096],
            vec![b':'; 4096],
            {
                let mut v = "é".repeat(64).into_bytes();
                v.extend_from_slice(b"5d41402abc4b2a76b9719d911017c592");
                v.extend_from_slice("é".repeat(64).as_bytes());
                v
            },
            {
                // Each exact hash length the classifier switches on, adjacent to
                // multi-byte text on both sides.
                let mut v = "☃".as_bytes().to_vec();
                for n in [32usize, 40, 64, 128] {
                    v.extend_from_slice(&vec![b'a'; n]);
                    v.extend_from_slice("☃".as_bytes());
                }
                v
            },
        ];

        // The property is "returns at all" — no panic, no char-boundary slice,
        // no hang. Values are deliberately not asserted: that mirrors what the
        // fuzz target itself checks, and pinning extracted values here would
        // duplicate the extraction tests in `patterns.rs` while making this
        // harness check fail for reasons that have nothing to do with the
        // harness.
        for case in &cases {
            fuzz_entry_extract_text(case);
        }
    }

    #[test]
    fn entity_kind_from_string() {
        assert_eq!(EntityKind::from("email"), EntityKind::Email);
        assert_eq!(EntityKind::from("PHONE"), EntityKind::Phone);
        assert_eq!(EntityKind::from("domain"), EntityKind::Domain);
        assert_eq!(
            EntityKind::from("unknown_type"),
            EntityKind::Unknown("unknown_type".to_string())
        );
    }

    #[test]
    fn entity_kind_to_string() {
        assert_eq!(EntityKind::Email.to_str(), "email");
        assert_eq!(EntityKind::Person.to_str(), "person");
    }
}
