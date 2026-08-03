//! Entity extraction: regex patterns, confidence scoring, kind classification.
//!
//! Extracts candidate entities from unstructured text (OCR, PDFs, etc.) with:
//! - Pattern matching (email, IPv4, domain, URL, social handle, MD5/SHA hashes)
//! - Confidence scoring based on format validation + extraction method
//! - Auto-kind classification via heuristics + JSON schema mapping

pub mod classifier;
pub mod extractor;
pub mod patterns;

pub use extractor::EntityExtractor;

use serde::{Deserialize, Serialize};
use thiserror::Error;

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
