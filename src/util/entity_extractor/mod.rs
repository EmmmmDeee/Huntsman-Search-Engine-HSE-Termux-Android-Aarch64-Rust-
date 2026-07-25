//! Entity extraction: regex patterns, confidence scoring, kind classification.
//!
//! Extracts candidate entities from unstructured text (OCR, PDFs, etc.) with:
//! - Pattern matching (email, phone, hash, IP, domain, person name, etc.)
//! - Confidence scoring based on format validation + extraction method
//! - Auto-kind classification via heuristics + JSON schema mapping

pub mod patterns;
pub mod classifier;
pub mod extractor;

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

impl EntityKind {
    /// Convert from string (HSE target kind).
    pub fn from_str(s: &str) -> Self {
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
    pub confidence: f64, // 0.0-1.0
    pub context: Option<String>, // Surrounding text for validation
    pub source_pattern: String, // "email_rfc5322", "phone_e164", etc.
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
        assert_eq!(EntityKind::from_str("email"), EntityKind::Email);
        assert_eq!(EntityKind::from_str("PHONE"), EntityKind::Phone);
        assert_eq!(EntityKind::from_str("domain"), EntityKind::Domain);
        assert_eq!(EntityKind::from_str("unknown_type"), EntityKind::Unknown("unknown_type".to_string()));
    }

    #[test]
    fn entity_kind_to_string() {
        assert_eq!(EntityKind::Email.to_str(), "email");
        assert_eq!(EntityKind::Person.to_str(), "person");
    }
}
