//! Evidence-attributed assertions about a saved entity, not an identity or truth oracle.
//!
//! Identical values from multiple mirrors are **not** counted as independent proof.
//! An attribute can be an investigative lead without becoming a verified claim.
//! Conflicting recorded values are alternatives, not automatically deceptive conduct.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::confidence::VerificationMethod;
use crate::entity::{Entity, EntityKind};

const MAX_EVIDENCE: usize = 128;
const MAX_ASSERTIONS: usize = 128;
const MAX_ASSERTION_VALUE_BYTES: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceRole {
    OperatorSeed,
    Inferred,
    SourceAttributed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dimension {
    Identity,
    Affiliation,
    Ownership,
    Control,
    Incentive,
    Capability,
    Relationship,
    Conduct,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceTrace {
    pub index: usize,
    pub source: String,
    pub source_family: String,
    pub scan_id: Option<String>,
    pub recorded_at_unix: u64,
    pub ancestry_node: Option<String>,
    pub verification_metadata: Option<VerificationMethod>,
    pub role: EvidenceRole,
    pub merged_observation_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttributedAssertion {
    pub dimension: Dimension,
    pub attribute: String,
    pub value: String,
    pub evidence_indices: Vec<usize>,
    /// Source-family labels are diagnostic. They do not prove independent origins.
    pub reported_source_families: Vec<String>,
    pub status: &'static str,
}

/// Chronology describes when Huntsman recorded evidence, never when a fact was true.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValueObservation {
    pub value: String,
    pub evidence_indices: Vec<usize>,
    pub first_observed_unix: Option<u64>,
    pub last_observed_unix: Option<u64>,
    /// Unknown source timestamps prevent an apparently ordered sequence from proving order.
    pub has_undated_observations: bool,
}

/// Triage labels are observational, not assertions of supersession or contradiction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TemporalPattern {
    SharedEvidenceRecord,
    OrderedObservationWindows,
    OverlappingObservationWindows,
    InsufficientTimestamps,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompetingValues {
    pub attribute: String,
    pub values: Vec<String>,
    /// Different values may represent temporal change, scope differences or error.
    pub interpretation: &'static str,
    pub temporal_pattern: TemporalPattern,
    /// Bounded by the same assertion limit as the parent report, in value order.
    pub observations: Vec<ValueObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EntityReality {
    pub uid: String,
    pub kind: EntityKind,
    pub public_label: String,
    pub identity_status: &'static str,
    pub traces: Vec<EvidenceTrace>,
    pub assertions: Vec<AttributedAssertion>,
    pub competing_values: Vec<CompetingValues>,
    pub omitted_evidence: usize,
    pub omitted_assertions: usize,
    pub limitations: Vec<&'static str>,
}

fn sensitive_attribute(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "token",
        "api_key",
        "apikey",
        "credential",
        "secret",
        "private_key",
        "authorization",
        "cookie",
        "session",
    ]
    .iter()
    .any(|part| name.contains(part))
}

fn dimension(name: &str) -> Dimension {
    match name.to_ascii_lowercase().as_str() {
        "legal_name" | "name" | "alias" | "aliases" | "identity" | "display_name" => {
            Dimension::Identity
        }
        "company_name" | "company" | "employer" | "director_name" | "affiliation" | "member_of"
        | "appointment" | "role" => Dimension::Affiliation,
        "owner" | "ownership" | "beneficial_owner" | "shareholder" | "registrant" => {
            Dimension::Ownership
        }
        "control" | "controller" | "operator" | "administrator" => Dimension::Control,
        "incentive" | "funding" | "revenue" | "economic_interest" => Dimension::Incentive,
        "ports" | "services" | "capability" | "capabilities" | "vulns" => Dimension::Capability,
        "relationship" | "relation" | "linked_account" | "linked_profile" => {
            Dimension::Relationship
        }
        "conduct" | "action" | "event" | "activity" | "incident" => Dimension::Conduct,
        _ => Dimension::Other,
    }
}

type AttributeIndex = BTreeMap<(String, String), (BTreeSet<usize>, BTreeSet<String>)>;

fn observation_window(value: String, indices: &[usize], entity: &Entity) -> ValueObservation {
    let mut first_observed_unix: Option<u64> = None;
    let mut last_observed_unix: Option<u64> = None;
    let mut has_undated_observations = false;
    for &index in indices {
        let Some(evidence) = entity.evidence.get(index) else {
            continue;
        };
        // A folded observation retains its additional source timestamps; the
        // primary timestamp alone would invent non-overlapping observation windows.
        for provenance in
            std::iter::once(&evidence.provenance).chain(&evidence.merged_provenance)
        {
            let time = provenance.recorded_at_unix;
            if time == 0 {
                has_undated_observations = true;
                continue;
            }
            first_observed_unix = Some(first_observed_unix.map_or(time, |prior| prior.min(time)));
            last_observed_unix = Some(last_observed_unix.map_or(time, |prior| prior.max(time)));
        }
    }
    ValueObservation {
        value,
        evidence_indices: indices.to_vec(),
        first_observed_unix,
        last_observed_unix,
        has_undated_observations,
    }
}

fn temporal_pattern(observations: &[ValueObservation]) -> TemporalPattern {
    for (index, left) in observations.iter().enumerate() {
        if observations[index + 1..].iter().any(|right| {
            left.evidence_indices
                .iter()
                .any(|id| right.evidence_indices.contains(id))
        }) {
            return TemporalPattern::SharedEvidenceRecord;
        }
    }
    if observations.iter().any(|window| {
        window.has_undated_observations
            || window.first_observed_unix.is_none()
            || window.last_observed_unix.is_none()
    }) {
        return TemporalPattern::InsufficientTimestamps;
    }
    let mut chronological = observations.iter().collect::<Vec<_>>();
    chronological.sort_by_key(|window| window.first_observed_unix);
    if chronological.windows(2).all(|pair| {
        pair[0]
            .last_observed_unix
            .zip(pair[1].first_observed_unix)
            .is_some_and(|(previous, next)| previous < next)
    }) {
        TemporalPattern::OrderedObservationWindows
    } else {
        TemporalPattern::OverlappingObservationWindows
    }
}

fn summarise_assertions(
    grouped: AttributeIndex,
    traces: &[EvidenceTrace],
    entity: &Entity,
) -> (Vec<AttributedAssertion>, Vec<CompetingValues>) {
    let mut by_attribute = BTreeMap::<String, Vec<ValueObservation>>::new();
    let assertions = grouped
        .into_iter()
        .map(|((attribute, value), (indices, families))| {
            let evidence_indices = indices.iter().copied().collect::<Vec<_>>();
            by_attribute
                .entry(attribute.clone())
                .or_default()
                .push(observation_window(value.clone(), &evidence_indices, entity));
            let status = if indices
                .iter()
                .all(|index| traces[*index].role == EvidenceRole::OperatorSeed)
            {
                "operator_seed_only"
            } else if indices
                .iter()
                .all(|index| traces[*index].role == EvidenceRole::Inferred)
            {
                "inferred_only"
            } else if indices
                .iter()
                .any(|index| traces[*index].role == EvidenceRole::SourceAttributed)
            {
                "source_attribution_not_independently_verified"
            } else {
                "mixed_seed_and_inference"
            };
            AttributedAssertion {
                dimension: dimension(&attribute),
                attribute,
                value,
                evidence_indices,
                reported_source_families: families.into_iter().collect(),
                status,
            }
        })
        .collect();
    let competing_values = by_attribute
        .into_iter()
        .filter_map(|(attribute, observations)| {
            (observations.len() > 1).then(|| CompetingValues {
                attribute,
                values: observations.iter().map(|window| window.value.clone()).collect(),
                interpretation: "competing_recorded_values_not_proven_contradiction",
                temporal_pattern: temporal_pattern(&observations),
                observations,
            })
        })
        .collect();

    (assertions, competing_values)
}

/// Build a bounded, read-only index of source-attributed claims for an entity.
///
/// No source family, discovery score, provider verification flag, or matching
/// string by itself proves legal identity, beneficial ownership or intent.
#[must_use]
pub fn assess(entity: &Entity) -> EntityReality {
    let sensitive_entity = matches!(entity.kind, EntityKind::Credential | EntityKind::ApiKey);
    let mut traces = Vec::new();
    let mut grouped = AttributeIndex::new();
    let mut omitted_assertions = 0usize;

    for (index, evidence) in entity.evidence.iter().take(MAX_EVIDENCE).enumerate() {
        let role = if evidence.is_operator_seed() {
            EvidenceRole::OperatorSeed
        } else if evidence.is_inferred {
            EvidenceRole::Inferred
        } else {
            EvidenceRole::SourceAttributed
        };
        let family = evidence.provenance.corroboration_key();
        traces.push(EvidenceTrace {
            index,
            source: evidence.provenance.source.clone(),
            source_family: family.clone(),
            scan_id: evidence.provenance.scan_id.clone(),
            recorded_at_unix: evidence.provenance.recorded_at_unix,
            ancestry_node: evidence.ancestry_node.as_ref().map(|node| node.0.clone()),
            verification_metadata: evidence.verification,
            role,
            merged_observation_count: evidence.merged_provenance.len() + 1,
        });

        if sensitive_entity {
            continue;
        }
        for (attribute, raw_value) in &evidence.attributes {
            if sensitive_attribute(attribute) || attribute == "evidence_role" {
                continue;
            }
            for value in raw_value
                .split("; ")
                .map(str::trim)
                .filter(|part| !part.is_empty())
            {
                if value.len() > MAX_ASSERTION_VALUE_BYTES {
                    omitted_assertions += 1;
                    continue;
                }
                if grouped.len() >= MAX_ASSERTIONS
                    && !grouped.contains_key(&(attribute.clone(), value.to_owned()))
                {
                    omitted_assertions += 1;
                    continue;
                }
                let entry = grouped
                    .entry((attribute.clone(), value.to_owned()))
                    .or_default();
                entry.0.insert(index);
                entry.1.insert(family.clone());
            }
        }
    }

    let (assertions, competing_values) = summarise_assertions(grouped, &traces, entity);

    EntityReality {
        uid: entity.uid.clone(),
        kind: entity.kind.clone(),
        public_label: if sensitive_entity {
            "[redacted sensitive identifier]".to_owned()
        } else {
            entity.value.clone()
        },
        identity_status: "not_established_by_identifier_or_source_attribution",
        traces,
        assertions,
        competing_values,
        omitted_evidence: entity.evidence.len().saturating_sub(MAX_EVIDENCE),
        omitted_assertions,
        limitations: vec![
            "source_family_labels_do_not_prove_independence",
            "primary_source_authenticity_not_established",
            "ownership_control_intent_and_conduct_require_claim_specific_proof",
            "competing_values_may_reflect_time_scope_or_error",
            "unobserved_facts_remain_unknown",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Evidence, EvidenceProvenance};

    #[test]
    fn mirrors_and_operator_seeds_do_not_become_verified_identity() {
        let subject = Entity::builder(EntityKind::Person, "Ada Example", 0.99, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("operator_input"), "seed")
                    .with_attr("evidence_role", crate::entity::SEED_EVIDENCE_ROLE)
                    .with_attr("owner", "Company A"),
            )
            .evidence(
                Evidence::new(EvidenceProvenance::new("register-mirror"), "copy")
                    .with_attr("owner", "Company A"),
            )
            .build();
        let report = assess(&subject);
        assert_eq!(
            report.identity_status,
            "not_established_by_identifier_or_source_attribution"
        );
        assert_eq!(report.traces[0].role, EvidenceRole::OperatorSeed);
        assert_eq!(report.assertions.len(), 1);
        assert_eq!(report.assertions[0].evidence_indices, vec![0, 1]);
        assert_eq!(report.assertions[0].dimension, Dimension::Ownership);
        assert_eq!(
            report.assertions[0].status,
            "source_attribution_not_independently_verified"
        );
    }

    #[test]
    fn a_claim_supported_only_by_a_user_seed_is_never_presented_as_source_observed() {
        let subject = Entity::builder(EntityKind::Organisation, "Example", 0.9, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("operator_input"), "query")
                    .with_attr("owner", "Claimed owner"),
            )
            .build();
        let report = assess(&subject);
        assert_eq!(report.assertions[0].status, "operator_seed_only");
        assert_eq!(report.traces[0].role, EvidenceRole::OperatorSeed);
    }

    #[test]
    fn competing_reports_are_not_automatically_falsehoods() {
        let subject = Entity::builder(EntityKind::Organisation, "Example Ltd", 0.9, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("source-a"), "a").with_attr("owner", "A"),
            )
            .evidence(
                Evidence::new(EvidenceProvenance::new("source-b"), "b").with_attr("owner", "B"),
            )
            .build();
        let report = assess(&subject);
        assert_eq!(report.competing_values.len(), 1);
        assert_eq!(report.competing_values[0].values, vec!["A", "B"]);
        assert_eq!(
            report.competing_values[0].interpretation,
            "competing_recorded_values_not_proven_contradiction"
        );
    }

    fn timed_owner(source: &str, value: &str, recorded_at_unix: u64) -> Evidence {
        let mut provenance = EvidenceProvenance::new(source);
        provenance.recorded_at_unix = recorded_at_unix;
        Evidence::new(provenance, "public registry result").with_attr("owner", value)
    }

    #[test]
    fn ordered_observations_are_leads_not_proven_ownership_changes() {
        let subject = Entity::builder(EntityKind::Organisation, "Example", 0.9, "scan")
            .evidence(timed_owner("registry-a", "Old", 100))
            .evidence(timed_owner("registry-b", "New", 300))
            .build();
        let report = assess(&subject);
        let issue = &report.competing_values[0];
        assert_eq!(issue.temporal_pattern, TemporalPattern::OrderedObservationWindows);
        assert_eq!(issue.observations[0].value, "New");
        assert_eq!(issue.observations[0].first_observed_unix, Some(300));
        assert_eq!(issue.observations[1].value, "Old");
        assert_eq!(issue.observations[1].last_observed_unix, Some(100));
        assert_eq!(
            issue.interpretation,
            "competing_recorded_values_not_proven_contradiction"
        );
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(
            json["competing_values"][0]["temporal_pattern"],
            "ordered_observation_windows"
        );
    }

    #[test]
    fn values_in_one_evidence_record_do_not_imply_a_chronological_transition() {
        let subject = Entity::builder(EntityKind::Organisation, "Example", 0.9, "scan")
            .evidence(
                timed_owner("registry", "A", 100).with_attr("owner", "B"),
            )
            .build();
        let report = assess(&subject);
        let issue = &report.competing_values[0];
        assert_eq!(issue.temporal_pattern, TemporalPattern::SharedEvidenceRecord);
        assert_eq!(issue.observations[0].evidence_indices, vec![0]);
        assert_eq!(issue.observations[1].evidence_indices, vec![0]);
    }

    #[test]
    fn folded_provenance_blocks_false_temporal_order() {
        let mut earlier = timed_owner("registry-a", "A", 100);
        let mut merged = EvidenceProvenance::new("registry-a");
        merged.recorded_at_unix = 400;
        earlier.merged_provenance.push(merged);
        let subject = Entity::builder(EntityKind::Organisation, "Example", 0.9, "scan")
            .evidence(earlier)
            .evidence(timed_owner("registry-b", "B", 200))
            .build();
        let report = assess(&subject);
        let issue = &report.competing_values[0];
        assert_eq!(issue.temporal_pattern, TemporalPattern::OverlappingObservationWindows);
        assert_eq!(issue.observations[0].first_observed_unix, Some(100));
        assert_eq!(issue.observations[0].last_observed_unix, Some(400));
    }

    #[test]
    fn unknown_source_time_fails_closed() {
        let subject = Entity::builder(EntityKind::Organisation, "Example", 0.9, "scan")
            .evidence(timed_owner("registry-a", "A", 0))
            .evidence(timed_owner("registry-b", "B", 200))
            .build();
        let report = assess(&subject);
        let issue = &report.competing_values[0];
        assert_eq!(issue.temporal_pattern, TemporalPattern::InsufficientTimestamps);
        assert_eq!(issue.observations[0].first_observed_unix, None);
        assert!(issue.observations[0].has_undated_observations);
    }

    #[test]
    fn credential_subjects_and_secret_attributes_are_not_exposed() {
        let key = Entity::builder(EntityKind::ApiKey, "secret-key-value", 0.9, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("secret-source"), "found")
                    .with_attr("api_key", "secret-key-value"),
            )
            .build();
        let report = assess(&key);
        assert!(!report.public_label.contains("secret-key-value"));
        assert!(report.assertions.is_empty());

        let org = Entity::builder(EntityKind::Organisation, "Example", 0.7, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("source"), "found")
                    .with_attr("api_token", "secret-key-value")
                    .with_attr("acn", "123456789"),
            )
            .build();
        let report = assess(&org);
        assert_eq!(report.assertions.len(), 1);
        assert_eq!(report.assertions[0].attribute, "acn");
    }

    #[test]
    fn evidence_and_assertion_budgets_are_observable() {
        let mut entity = Entity::new(EntityKind::Organisation, "Example", 0.7, "scan");
        for index in 0..=MAX_EVIDENCE {
            entity.add_evidence(
                Evidence::new(EvidenceProvenance::new("source"), "record")
                    .with_attr("alias", format!("alias-{index}")),
            );
        }
        let report = assess(&entity);
        assert_eq!(report.traces.len(), MAX_EVIDENCE);
        assert_eq!(report.omitted_evidence, 1);
        assert_eq!(report.assertions.len(), MAX_ASSERTIONS);
    }
}
