//! Lightweight offline entity classifier and extractor.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::au_id;
use crate::canonical::{canonical_domain, canonical_email, canonical_phone, canonical_url};
use crate::entity::EntityKind;

pub const ACTIONABLE_FLOOR: f64 = 0.50;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Classified {
    pub kind: EntityKind,
    pub value: String,
    pub confidence: f64,
    pub signal: &'static str,
}

impl Classified {
    #[must_use]
    pub fn is_actionable(&self) -> bool {
        self.confidence >= ACTIONABLE_FLOOR && self.kind != EntityKind::Other
    }
}

#[must_use]
pub fn classify(raw: &str) -> Classified {
    let value = raw.trim();
    if value.is_empty() {
        return Classified {
            kind: EntityKind::Other,
            value: String::new(),
            confidence: 0.0,
            signal: "empty",
        };
    }
    if canonical_url(value).is_some() {
        return classified(EntityKind::Url, value, 0.90, "scheme");
    }
    if canonical_email(value).is_some() {
        return classified(EntityKind::Email, value, 0.85, "rfc-shape");
    }
    if parse_ipv4(value) {
        return classified(EntityKind::IpAddress, value, 0.92, "parsed");
    }
    if canonical_domain(value).is_some() {
        return classified(EntityKind::Domain, value, 0.75, "domain-shape");
    }
    if canonical_phone(value).is_some() {
        return classified(EntityKind::Phone, value, 0.80, "dialable-shape");
    }
    if au_id::classify(value).is_ok() {
        return classified(EntityKind::AbnAcn, value, 0.95, "checksum");
    }
    if value.starts_with('@') {
        return classified(EntityKind::Username, value, 0.40, "handle");
    }
    let lowered = value.to_ascii_lowercase();
    if ["pty ltd", "llc", "inc", "corp", "gmbh"]
        .iter()
        .any(|suffix| lowered.contains(suffix))
    {
        return classified(EntityKind::Organisation, value, 0.60, "company-suffix");
    }
    if lowered.contains("street")
        || lowered.contains("st ")
        || lowered.contains("road")
        || lowered.contains("rd ")
        || value.chars().any(|c| c.is_ascii_digit())
    {
        return classified(EntityKind::Address, value, 0.60, "street-shape");
    }
    if value.split_whitespace().count() >= 2 {
        return classified(EntityKind::Person, value, 0.50, "multiword");
    }
    classified(EntityKind::Other, value, 0.20, "residual")
}

#[must_use]
pub fn extract(text: &str) -> Vec<Classified> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for token in text.split_whitespace() {
        let token = token.trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';' | '!'
            )
        });
        if token.is_empty() {
            continue;
        }
        let classified = classify(token.trim_end_matches(['.', ':', '?']));
        if classified.kind != EntityKind::Other
            && seen.insert((classified.kind.clone(), classified.value.clone()))
        {
            out.push(classified);
        }
    }
    out
}

fn classified(kind: EntityKind, value: &str, confidence: f64, signal: &'static str) -> Classified {
    Classified {
        kind,
        value: value.trim().to_owned(),
        confidence,
        signal,
    }
}

fn parse_ipv4(raw: &str) -> bool {
    let parts = raw.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u8>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_structural_values() {
        assert_eq!(classify("https://example.com").kind, EntityKind::Url);
        assert_eq!(classify("Ada@Example.com").kind, EntityKind::Email);
        assert_eq!(classify("8.8.8.8").kind, EntityKind::IpAddress);
    }

    #[test]
    fn extracts_unique_entities_from_text() {
        let found = extract("mail ada@example.com and visit https://example.com, @Ada!");
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|item| item.kind == EntityKind::Email));
        assert!(found.iter().any(|item| item.kind == EntityKind::Url));
    }
}
