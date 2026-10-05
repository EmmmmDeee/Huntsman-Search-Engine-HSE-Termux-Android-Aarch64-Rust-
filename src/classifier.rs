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
    if let Some(coordinates) = parse_decimal_coordinates(value) {
        return classified(EntityKind::Coordinates, &coordinates, 0.85, "lat-lon");
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

/// Recognises a `LAT,LON` pair in decimal degrees and returns it as `lat,lon`.
///
/// Both components must be plain signed decimals with a fractional part, so
/// thousands-separated numbers (`1,000`) and decimal-comma values (`12,5`) are not
/// mistaken for coordinates. Latitude must lie in `-90..=90` and longitude in
/// `-180..=180`.
fn parse_decimal_coordinates(raw: &str) -> Option<String> {
    let (lat, lon) = raw.split_once(',')?;
    let lat = decimal_degree(lat, 2, 90.0)?;
    let lon = decimal_degree(lon, 3, 180.0)?;
    Some(format!("{lat},{lon}"))
}

fn decimal_degree(raw: &str, max_int_digits: usize, limit: f64) -> Option<&str> {
    let trimmed = raw.trim();
    let unsigned = trimmed
        .strip_prefix('-')
        .or_else(|| trimmed.strip_prefix('+'))
        .unwrap_or(trimmed);
    let (int, frac) = unsigned.split_once('.')?;
    if int.is_empty()
        || int.len() > max_int_digits
        || frac.is_empty()
        || !int.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let degrees: f64 = unsigned.parse().ok()?;
    if degrees > limit {
        return None;
    }
    Some(trimmed.strip_prefix('+').unwrap_or(trimmed))
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
    fn classifies_decimal_degree_coordinates() {
        let brisbane = classify("-27.4698,153.0251");
        assert_eq!(brisbane.kind, EntityKind::Coordinates);
        assert_eq!(brisbane.value, "-27.4698,153.0251");
        assert!(brisbane.is_actionable());

        let spaced = classify(" 37.7749, -122.4194 ");
        assert_eq!(spaced.kind, EntityKind::Coordinates);
        assert_eq!(spaced.value, "37.7749,-122.4194");

        let signed = classify("+0.0,+0.0");
        assert_eq!(signed.kind, EntityKind::Coordinates);
        assert_eq!(signed.value, "0.0,0.0");

        for bounds in ["90.0,180.0", "-90.0,-180.0"] {
            assert_eq!(classify(bounds).kind, EntityKind::Coordinates, "{bounds}");
        }
    }

    #[test]
    fn rejects_out_of_range_or_non_decimal_coordinates() {
        for raw in [
            "90.1,0.0",
            "-90.5,0.0",
            "0.0,180.1",
            "0.0,-181.0",
            "123.4,12.5",
            "12.5,1234.5",
            "1e1,2.0",
            "NaN,0.0",
            "1.5,inf",
            "12.,5.0",
            ".5,5.0",
            "1.5,2.5,3.5",
        ] {
            assert_ne!(classify(raw).kind, EntityKind::Coordinates, "{raw}");
        }
    }

    #[test]
    fn ordinary_numbers_and_addresses_are_not_coordinates() {
        for raw in ["1,000", "12,500", "12,100.50", "1.000,50", "12,5"] {
            assert_ne!(classify(raw).kind, EntityKind::Coordinates, "{raw}");
        }
        for raw in [
            "12 Smith Street",
            "Unit 3, 12 Smith St Brisbane",
            "1.5 Example Road, 2.5 km north",
        ] {
            assert_eq!(classify(raw).kind, EntityKind::Address, "{raw}");
        }
    }

    #[test]
    fn extracts_unique_entities_from_text() {
        let found = extract("mail ada@example.com and visit https://example.com, @Ada!");
        assert_eq!(found.len(), 3);
        assert!(found.iter().any(|item| item.kind == EntityKind::Email));
        assert!(found.iter().any(|item| item.kind == EntityKind::Url));
    }
}
