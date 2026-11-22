//! Brisbane-first offline geographic triage of provenance-linked OSINT observations.
//!
//! This additive view reuses the canonical osint_casework JSON schema, input validation,
//! claim review and receipts. Place text and matching subject labels are source assertions,
//! not verified residence, identity, travel, ownership or kinship. It makes no HTTP calls.
//! Classification is deliberately conservative: a postcode is not proof of Brisbane.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::error::Error;
use crate::osint_casework::{self, CaseInput, MAX_CASE_BYTES};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoClass {
    BrisbaneAnchor,
    QueenslandUnconfirmedBrisbane,
    OtherAustralia,
    International,
    Unresolved,
}

impl GeoClass {
    const fn priority(self) -> u8 {
        match self {
            Self::BrisbaneAnchor => 1,
            Self::QueenslandUnconfirmedBrisbane => 2,
            Self::OtherAustralia => 3,
            Self::International => 4,
            Self::Unresolved => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoAnchor {
    pub city: &'static str,
    pub state: &'static str,
    pub country: &'static str,
    pub timezone: &'static str,
    pub interpretation: &'static str,
}

pub const BRISBANE_ANCHOR: GeoAnchor = GeoAnchor {
    city: "Brisbane",
    state: "Queensland",
    country: "Australia",
    timezone: "Australia/Brisbane",
    interpretation: "research priority only; not evidence of any person's location",
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeographicLead {
    pub observation_id: String,
    pub subject: String,
    pub predicate: String,
    pub place_as_reported: String,
    pub source_url: String,
    pub source_root: String,
    pub event_at_unix: Option<i64>,
    pub category: GeoClass,
    pub priority: u8,
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrossBorderLabelLead {
    pub subject_label: String,
    pub brisbane_observation_ids: Vec<String>,
    pub international_observation_ids: Vec<String>,
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeoCaseReport {
    pub anchor: GeoAnchor,
    pub case: osint_casework::CaseReview,
    pub geographic_leads: Vec<GeographicLead>,
    pub possible_cross_border_label_matches: Vec<CrossBorderLabelLead>,
    pub unclassified_location_claims: usize,
    pub evidence_policy: &'static str,
}

fn normal(value: &str) -> String {
    value
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_location_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "located_in"
            | "based_in"
            | "operates_in"
            | "business_location"
            | "event_location"
            | "registered_in"
            | "jurisdiction"
            | "born_in"
            | "birth_place"
            | "lived_in"
            | "resides_in"
            | "place_of_publication"
    )
}

fn matches_part(parts: &[String], entire: &str, names: &[&str]) -> bool {
    names.iter().any(|name| {
        entire == *name
            || parts.iter().any(|part| part == name)
            || entire.starts_with(&format!("{name} "))
            || entire.ends_with(&format!(" {name}"))
    })
}

/// Classify explicit place labels without geocoding, inference or postcode lookup.
/// Contradictory jurisdictions are unresolved. Unknown localities stay unresolved.
#[must_use]
pub fn classify_place(value: &str) -> GeoClass {
    if value.trim().is_empty() || value.len() > 256 {
        return GeoClass::Unresolved;
    }
    let whole = normal(value);
    let parts: Vec<String> = value.split(',').map(normal).collect();
    let first = parts.first().map(String::as_str).unwrap_or("");
    let city = [
        "brisbane",
        "brisbane city",
        "brisbane cbd",
        "south brisbane",
        "fortitude valley",
        "toowong",
        "yeronga",
        "durack",
        "indooroopilly",
    ]
    .contains(&first)
        || [
            "brisbane qld",
            "brisbane queensland",
            "brisbane australia",
            "brisbane qld australia",
            "brisbane queensland australia",
            "south brisbane qld",
            "south brisbane queensland",
            "south brisbane queensland australia",
        ]
        .contains(&whole.as_str());

    let qld = matches_part(
        &parts,
        &whole,
        &[
            "qld",
            "queensland",
            "gold coast",
            "sunshine coast",
            "cairns",
            "ipswich",
            "toowoomba",
            "gympie",
            "maleny",
            "southport",
        ],
    );

    let other_au = matches_part(
        &parts,
        &whole,
        &[
            "perth",
            "western australia",
            "wa",
            "sydney",
            "new south wales",
            "nsw",
            "melbourne",
            "victoria",
            "vic",
            "adelaide",
            "south australia",
            "sa",
            "tasmania",
            "hobart",
            "darwin",
            "nt",
            "act",
        ],
    );

    let foreign = matches_part(
        &parts,
        &whole,
        &[
            "dubai",
            "united arab emirates",
            "uae",
            "abu dhabi",
            "sharjah",
            "canada",
            "alberta",
            "red deer",
            "calgary",
            "vietnam",
            "hue",
            "england",
            "london",
            "hong kong",
            "new zealand",
        ],
    );

    if (city || qld) && (foreign || other_au) || foreign && other_au {
        return GeoClass::Unresolved;
    }
    if city {
        GeoClass::BrisbaneAnchor
    } else if qld {
        GeoClass::QueenslandUnconfirmedBrisbane
    } else if other_au {
        GeoClass::OtherAustralia
    } else if foreign {
        GeoClass::International
    } else {
        GeoClass::Unresolved
    }
}

/// Review an existing canonical OSINT case as Brisbane-prioritised location leads.
///
/// # Errors
/// Returns the canonical case validation error for invalid/oversized records.
pub fn inspect_json(bytes: &[u8]) -> Result<GeoCaseReport, Error> {
    if bytes.len() > MAX_CASE_BYTES {
        return Err(Error::invalid("OSINT geo-case exceeds 256 KiB"));
    }
    let input: CaseInput =
        serde_json::from_slice(bytes).map_err(|_| Error::invalid("invalid OSINT case JSON"))?;
    let case = osint_casework::review(&input)?;

    type Seen = (String, BTreeSet<String>, BTreeSet<String>);
    let mut observed: BTreeMap<String, Seen> = BTreeMap::new();
    let mut leads = Vec::new();
    let mut unresolved = 0;

    for row in &input.observations {
        if !is_location_predicate(&row.predicate) {
            continue;
        }
        let category = classify_place(&row.value);
        if category == GeoClass::Unresolved {
            unresolved += 1;
        }
        let key = normal(&row.subject);
        if !key.is_empty() {
            let entry = observed.entry(key).or_insert_with(|| {
                (row.subject.clone(), BTreeSet::new(), BTreeSet::new())
            });
            if category == GeoClass::BrisbaneAnchor {
                entry.1.insert(row.id.clone());
            } else if category == GeoClass::International {
                entry.2.insert(row.id.clone());
            }
        }
        leads.push(GeographicLead {
            observation_id: row.id.clone(),
            subject: row.subject.clone(),
            predicate: row.predicate.clone(),
            place_as_reported: row.value.clone(),
            source_url: row.source_url.clone(),
            source_root: row.source_root.clone(),
            event_at_unix: row.event_at_unix,
            category,
            priority: category.priority(),
            interpretation: "source_assertion_only_not_proof_of_person_identity_or_location",
        });
    }
    leads.sort_by(|a, b| {
        (a.priority, &a.observation_id).cmp(&(b.priority, &b.observation_id))
    });

    let possible_cross_border_label_matches = observed
        .into_values()
        .filter_map(|(name, brisbane, international)| {
            if brisbane.is_empty() || international.is_empty() {
                return None;
            }
            Some(CrossBorderLabelLead {
                subject_label: name,
                brisbane_observation_ids: brisbane.into_iter().collect(),
                international_observation_ids: international.into_iter().collect(),
                interpretation: "same_label_only_not_identity_migration_or_family_proof",
            })
        })
        .collect();

    Ok(GeoCaseReport {
        anchor: BRISBANE_ANCHOR,
        case,
        geographic_leads: leads,
        possible_cross_border_label_matches,
        unclassified_location_claims: unresolved,
        evidence_policy: "Brisbane priority is a query strategy; matching place labels do not verify a person's residence, identity, movement or kinship",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brisbane_is_not_a_state_or_postcode() {
        assert_eq!(classify_place("Brisbane, Queensland, Australia"), GeoClass::BrisbaneAnchor);
        assert_eq!(classify_place("South Brisbane, QLD"), GeoClass::BrisbaneAnchor);
        assert_eq!(classify_place("Gold Coast, QLD"), GeoClass::QueenslandUnconfirmedBrisbane);
        assert_eq!(classify_place("QLD 4077"), GeoClass::QueenslandUnconfirmedBrisbane);
        assert_eq!(classify_place("Perth, Western Australia"), GeoClass::OtherAustralia);
        assert_eq!(classify_place("Dubai, United Arab Emirates"), GeoClass::International);
        assert_eq!(classify_place("Brisbane Road, Dubai"), GeoClass::International);
        assert_eq!(classify_place("Brisbane, Dubai"), GeoClass::Unresolved);
        assert_eq!(classify_place("Brisbane, WA"), GeoClass::Unresolved);
        assert_eq!(classify_place("Gold Coast, WA"), GeoClass::Unresolved);
        assert_eq!(classify_place("4077"), GeoClass::Unresolved);
    }

    #[test]
    fn matching_labels_are_leads_not_verified_identities() {
        let data = br#"{"case_id":"demo","observations":[
          {"id":"a","subject":"Example Person","predicate":"based_in","value":"Dubai, UAE","source_url":"https://example.net/a","source_root":"a","observed_at_unix":1},
          {"id":"b","subject":"EXAMPLE PERSON","predicate":"business_location","value":"Brisbane, QLD","source_url":"https://example.org/b","source_root":"b","observed_at_unix":2},
          {"id":"c","subject":"Example Person","predicate":"parent_of","value":"Brisbane","source_url":"https://example.org/c","source_root":"b","observed_at_unix":3}
        ]}"#;
        let result = inspect_json(data).unwrap();
        assert_eq!(result.geographic_leads.len(), 2);
        assert_eq!(result.geographic_leads[0].observation_id, "b");
        assert_eq!(result.possible_cross_border_label_matches.len(), 1);
        assert_eq!(
            result.possible_cross_border_label_matches[0].interpretation,
            "same_label_only_not_identity_migration_or_family_proof"
        );
        assert_eq!(result.anchor.timezone, "Australia/Brisbane");
        assert!(result.case.claims.iter().all(|claim| !claim.status.contains("verified")));
    }

    #[test]
    fn canonical_validation_is_not_bypassed() {
        let bad = br#"{"case_id":"bad","observations":[{"id":"a","subject":"X","predicate":"based_in","value":"Brisbane","source_url":"https://user:pw@example.org/a","source_root":"x","observed_at_unix":1}]}"#;
        assert!(inspect_json(bad).is_err());
        assert!(inspect_json(&vec![b' '; MAX_CASE_BYTES + 1]).is_err());
    }
}
