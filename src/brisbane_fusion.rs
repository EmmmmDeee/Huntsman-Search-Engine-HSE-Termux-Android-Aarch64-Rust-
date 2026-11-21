//! Brisbane-anchored, source-first geographic correlation over an existing OSINT case.
//!
//! Pure, deterministic and offline. Each place is a *source assertion*, not proof of
//! residence, travel, identity, kinship or present location. Matching subject labels
//! across sources yields a held candidate, never a verified identity.
//! Source receipts, conflict detection and chronology use osint_casework's existing
//! authority rather than introducing competing evidence rules.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::error::Error;
use crate::osint_casework::{self, CaseInput, CaseReview, MAX_CASE_BYTES};

/// Explicit investigation anchor; never inferred from a phone's GPS.
pub const ANCHOR: &str = "Brisbane, Queensland, Australia";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GeographyTier {
    Brisbane,
    SouthEastQueensland,
    DubaiUae,
    Canada,
    WesternAustralia,
    Other,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlaceAssertion {
    pub observation_id: String,
    pub subject: String,
    pub predicate: String,
    pub reported_place: String,
    pub tier: GeographyTier,
    pub source_url: String,
    pub declared_source_root: String,
    pub observed_at_unix: u64,
    pub event_at_unix: Option<i64>,
    /// Classification of the words in the assertion, not a geocoding or presence proof.
    pub interpretation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeographyLead {
    pub subject_label: String,
    pub brisbane_observation_ids: Vec<String>,
    pub regional_observation_ids: Vec<String>,
    pub external_observation_ids: Vec<String>,
    pub assessment: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrisbaneReport {
    pub anchor: &'static str,
    pub case: CaseReview,
    pub place_assertions: Vec<PlaceAssertion>,
    pub tentative_cross_border_leads: Vec<GeographyLead>,
    pub brisbane_assertions: usize,
    pub south_east_queensland_assertions: usize,
    pub external_assertions: usize,
    pub unresolved_assertions: usize,
    pub evidence_policy: &'static str,
}

#[derive(Default)]
struct Accumulator {
    labels: BTreeSet<String>,
    brisbane: BTreeSet<String>,
    regional: BTreeSet<String>,
    external: BTreeSet<String>,
}

/// Normalise only comparison keys; the displayed original wording is retained.
fn normal(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_lowercase().collect::<String>()
            } else {
                " ".to_owned()
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_location_predicate(predicate: &str) -> bool {
    matches!(
        predicate,
        "located_in" | "works_in" | "operates_in" | "business_location"
            | "birth_place" | "event_location" | "jurisdiction"
            | "has_business_postcode" | "professional_location"
    )
}

fn classify(place: &str) -> GeographyTier {
    match normal(place).as_str() {
        "brisbane"
        | "brisbane qld"
        | "brisbane queensland"
        | "brisbane qld australia"
        | "brisbane queensland australia"
        | "brisbane city queensland australia" => GeographyTier::Brisbane,

        "gold coast"
        | "gold coast qld"
        | "gold coast queensland"
        | "gold coast queensland australia"
        | "ipswich queensland"
        | "logan queensland"
        | "sunshine coast queensland"
        | "moreton bay queensland" => GeographyTier::SouthEastQueensland,

        "dubai" | "dubai uae" | "dubai united arab emirates"
        | "united arab emirates" | "uae" | "abu dhabi"
        | "abu dhabi uae" => GeographyTier::DubaiUae,

        "canada" | "alberta canada" | "calgary alberta canada"
        | "red deer alberta canada" | "red deer alberta"
        | "calgary alberta" => GeographyTier::Canada,

        "perth western australia" | "western australia"
        | "perth wa australia" | "perth wa" => GeographyTier::WesternAustralia,

        // Postal codes and ambiguous locality tokens intentionally remain unresolved;
        // they must be mapped with a dated, authoritative postcode/locality source.
        "qld 4077" | "4077" | "qld 4217" | "4217" => GeographyTier::Unresolved,

        _ => GeographyTier::Other,
    }
}

/// Reuse strict source/credential URL, record-count and duplicate-ID validation.
pub fn review(input: &CaseInput) -> Result<BrisbaneReport, Error> {
    let base = osint_casework::review(input)?;
    let mut places = Vec::new();
    let mut by_subject: BTreeMap<String, Accumulator> = BTreeMap::new();
    let mut brisbane = 0usize;
    let mut regional = 0usize;
    let mut external = 0usize;
    let mut unresolved = 0usize;

    for row in &input.observations {
        if !is_location_predicate(&row.predicate) {
            continue;
        }
        let tier = classify(&row.value);
        match tier {
            GeographyTier::Brisbane => brisbane += 1,
            GeographyTier::SouthEastQueensland => regional += 1,
            GeographyTier::DubaiUae
            | GeographyTier::Canada
            | GeographyTier::WesternAustralia
            | GeographyTier::Other => external += 1,
            GeographyTier::Unresolved => unresolved += 1,
        }
        let entry = by_subject.entry(normal(&row.subject)).or_default();
        entry.labels.insert(row.subject.clone());
        match tier {
            GeographyTier::Brisbane => {
                entry.brisbane.insert(row.id.clone());
            }
            GeographyTier::SouthEastQueensland => {
                entry.regional.insert(row.id.clone());
            }
            GeographyTier::DubaiUae
            | GeographyTier::Canada
            | GeographyTier::WesternAustralia
            | GeographyTier::Other => {
                entry.external.insert(row.id.clone());
            }
            GeographyTier::Unresolved => {}
        }
        places.push(PlaceAssertion {
            observation_id: row.id.clone(),
            subject: row.subject.clone(),
            predicate: row.predicate.clone(),
            reported_place: row.value.clone(),
            tier,
            source_url: row.source_url.clone(),
            declared_source_root: row.source_root.clone(),
            observed_at_unix: row.observed_at_unix,
            event_at_unix: row.event_at_unix,
            interpretation: "reported_place_only_not_verified_residence_or_identity",
        });
    }

    // Deterministic Brisbane-first result order. Regional records follow, then
    // international/collateral pivots and unresolved postal-code assertions.
    places.sort_by(|a, b| {
        (&a.tier, &a.subject, &a.observation_id)
            .cmp(&(&b.tier, &b.subject, &b.observation_id))
    });

    let mut leads = Vec::new();
    for (_key, item) in by_subject {
        if item.external.is_empty()
            || (item.brisbane.is_empty() && item.regional.is_empty())
        {
            continue;
        }
        leads.push(GeographyLead {
            subject_label: item.labels.into_iter().next().unwrap_or_default(),
            brisbane_observation_ids: item.brisbane.into_iter().collect(),
            regional_observation_ids: item.regional.into_iter().collect(),
            external_observation_ids: item.external.into_iter().collect(),
            assessment: "shared_subject_label_cross_region_candidate_not_identity_or_travel_proof",
        });
    }
    leads.sort_by(|a, b| a.subject_label.cmp(&b.subject_label));

    Ok(BrisbaneReport {
        anchor: ANCHOR,
        case: base,
        place_assertions: places,
        tentative_cross_border_leads: leads,
        brisbane_assertions: brisbane,
        south_east_queensland_assertions: regional,
        external_assertions: external,
        unresolved_assertions: unresolved,
        evidence_policy: "Brisbane is an explicit case anchor; source-claimed places, not verified physical presence. Same name or location is never an automatic identity or family merge.",
    })
}

/// Analyse bounded input; no network calls, secrets or GPS read.
pub fn review_json(data: &[u8]) -> Result<BrisbaneReport, Error> {
    if data.len() > MAX_CASE_BYTES {
        return Err(Error::invalid("OSINT case exceeds 256 KiB"));
    }
    let case: CaseInput =
        serde_json::from_slice(data).map_err(|_| Error::invalid("invalid case JSON"))?;
    review(&case)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osint_casework::Observation;

    fn row(id: &str, subject: &str, predicate: &str, place: &str) -> Observation {
        Observation {
            id: id.to_owned(),
            subject: subject.to_owned(),
            predicate: predicate.to_owned(),
            value: place.to_owned(),
            source_url: format!("https://example.org/{id}"),
            source_root: "operator_asserted".to_owned(),
            observed_at_unix: 1_800_000_000,
            event_at_unix: None,
            content_sha256: None,
        }
    }
    fn case(rows: Vec<Observation>) -> CaseInput {
        CaseInput { case_id: "example".to_owned(), observations: rows }
    }
    #[test]
    fn prioritises_explicit_brisbane_over_regional_and_remote_observations() {
        let input = case(vec![
            row("dubai", "Example Person", "works_in", "Dubai, UAE"),
            row("regional", "Example Person", "works_in", "Gold Coast, Queensland, Australia"),
            row("brisbane", "Example Person", "works_in", "Brisbane, Queensland, Australia"),
        ]);
        let result = review(&input).unwrap();
        assert_eq!(result.anchor, ANCHOR);
        assert_eq!(result.place_assertions[0].tier, GeographyTier::Brisbane);
        assert_eq!(result.place_assertions[1].tier, GeographyTier::SouthEastQueensland);
        assert_eq!(result.place_assertions[2].tier, GeographyTier::DubaiUae);
        assert_eq!(result.tentative_cross_border_leads.len(), 1);
        assert_eq!(
            result.tentative_cross_border_leads[0].assessment,
            "shared_subject_label_cross_region_candidate_not_identity_or_travel_proof"
        );
    }
    #[test]
    fn postcode_and_similar_sounding_locality_are_not_brisbane_proof() {
        let input = case(vec![
            row("postcode", "A", "has_business_postcode", "QLD 4077"),
            row("near", "B", "located_in", "Brisbane North"),
            row("real", "C", "located_in", "Brisbane"),
        ]);
        let result = review(&input).unwrap();
        assert_eq!(result.brisbane_assertions, 1);
        assert_eq!(result.unresolved_assertions, 1);
        assert_eq!(result.external_assertions, 1);
        assert!(result.tentative_cross_border_leads.is_empty());
    }
    #[test]
    fn no_cross_border_lead_without_exact_subject_label() {
        let input = case(vec![
            row("a", "Example Alpha", "works_in", "Brisbane"),
            row("b", "Example Beta", "works_in", "Dubai"),
        ]);
        assert!(review(&input).unwrap().tentative_cross_border_leads.is_empty());
    }
    #[test]
    fn reuses_existing_source_validation_and_conflict_detection() {
        let mut bad = row("x", "Example", "located_in", "Brisbane");
        bad.source_url = "https://example.org/?api_key=secret".to_owned();
        assert!(review(&case(vec![bad])).is_err());
        let input = case(vec![
            row("one", "Example", "birth_place", "Brisbane"),
            row("two", "Example", "birth_place", "Dubai"),
        ]);
        assert_eq!(review(&input).unwrap().case.claims[0].status, "conflicting_accounts");
    }
    #[test]
    fn deterministic_when_sources_are_reordered() {
        let mut rows = vec![
            row("one", "Example Person", "works_in", "Gold Coast"),
            row("two", "Example Person", "works_in", "Dubai"),
        ];
        let first = review(&case(rows.clone())).unwrap();
        rows.reverse();
        assert_eq!(first, review(&case(rows)).unwrap());
    }
}