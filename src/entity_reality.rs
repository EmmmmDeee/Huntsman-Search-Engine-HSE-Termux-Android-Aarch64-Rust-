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
const MAX_VALUE_BYTES: usize = 1_024;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompetingValues {
    pub attribute: String,
    pub values: Vec<String>,
    /// Different values may represent temporal change, scope differences or error.
    pub interpretation: &'static str,
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

/// Build a bounded, read-only index of source-attributed claims for an entity.
///
/// No source family, discovery score, provider verification flag, or matching
/// string by itself proves legal identity, beneficial ownership or intent.
#[must_use]
pub fn assess(entity: &Entity) -> EntityReality {
    let sensitive_entity = matches!(entity.kind, EntityKind::Credential | EntityKind::ApiKey);
    let mut traces = Vec::new();
    let mut grouped = BTreeMap::<(String, String), (BTreeSet<usize>, BTreeSet<String>)>::new();
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
                if value.len() > MAX_VALUE_BYTES {
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

    let mut by_attribute = BTreeMap::<String, BTreeSet<String>>::new();
    let assertions = grouped
        .into_iter()
        .map(|((attribute, value), (indices, families))| {
            by_attribute
                .entry(attribute.clone())
                .or_default()
                .insert(value.clone());
            AttributedAssertion {
                dimension: dimension(&attribute),
                attribute,
                value,
                evidence_indices: indices.into_iter().collect(),
                reported_source_families: families.into_iter().collect(),
                status: "source_attribution_not_independently_verified",
            }
        })
        .collect();
    let competing_values = by_attribute
        .into_iter()
        .filter_map(|(attribute, values)| {
            (values.len() > 1).then(|| CompetingValues {
                attribute,
                values: values.into_iter().collect(),
                interpretation: "competing_recorded_values_not_proven_contradiction",
            })
        })
        .collect();

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
        for index in 0..(MAX_EVIDENCE + 1) {
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
