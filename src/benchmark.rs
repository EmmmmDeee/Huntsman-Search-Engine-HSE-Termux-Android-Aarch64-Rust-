//! The person-resolution acceptance scorer: a run's entities against the public facts a benchmark
//! expects and forbids, as recall, precision, provenance coverage and proven-independent support.

use serde::Serialize;

use crate::entity::Entity;
use crate::evidence_ancestry::EvidenceAncestryGraph;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExpectedPublicFact {
    pub entity_kind: crate::entity::EntityKind,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ForbiddenPublicFact {
    pub entity_kind: crate::entity::EntityKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CoverageRatio {
    pub numerator: usize,
    pub denominator: usize,
}

impl CoverageRatio {
    #[must_use]
    pub const fn new(numerator: usize, denominator: usize) -> Self {
        if denominator == 0 {
            Self {
                numerator: 1,
                denominator: 1,
            }
        } else {
            Self {
                numerator,
                denominator,
            }
        }
    }

    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.numerator == self.denominator
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonResolutionScore {
    pub expected_facts: usize,
    pub matched_facts: usize,
    pub recall: CoverageRatio,
    pub supported_entities: usize,
    pub emitted_entities: usize,
    pub precision: CoverageRatio,
    pub entities_with_evidence: usize,
    pub entities_without_evidence: usize,
    pub provenance_coverage: CoverageRatio,
    pub unsupported_person_entities: usize,
    pub forbidden_facts: usize,
    pub forbidden_facts_emitted: usize,
    pub required_independent_person_support: usize,
    pub proven_independent_person_support: usize,
    pub independence_check_complete: bool,
    pub accepted: bool,
}

fn person_independence_support(
    entities: &[Entity],
    expected: &std::collections::BTreeSet<(crate::entity::EntityKind, String, &str)>,
    ancestry: Option<&EvidenceAncestryGraph>,
    required: usize,
) -> (usize, bool, bool) {
    use std::collections::BTreeSet;

    if required == 0 {
        return (0, true, true);
    }
    let nodes: BTreeSet<_> = entities
        .iter()
        .filter(|entity| {
            entity.kind == crate::entity::EntityKind::Person
                && expected
                    .iter()
                    .any(|(kind, value, _)| entity.kind == *kind && entity.value == *value)
        })
        .flat_map(|entity| {
            entity
                .evidence
                .iter()
                .filter_map(|evidence| evidence.ancestry_node.as_ref())
        })
        .collect();
    let count = ancestry.and_then(|graph| {
        graph
            .proven_independent_route_count(nodes.iter().copied(), required, 100_000)
            .ok()
    });
    let proven = count.map_or(0, |value| value.proven);
    let complete = count.is_some_and(|value| !value.incomplete);
    (proven, complete, complete && proven >= required)
}

fn resolution_accepted(
    recall: CoverageRatio,
    precision: CoverageRatio,
    provenance_coverage: CoverageRatio,
    unsupported_person_entities: usize,
    forbidden_facts_emitted: usize,
    independence_accepted: bool,
) -> bool {
    recall.is_complete()
        && precision.is_complete()
        && provenance_coverage.is_complete()
        && unsupported_person_entities == 0
        && forbidden_facts_emitted == 0
        && independence_accepted
}

type ExpectedFactKey<'a> = (crate::entity::EntityKind, String, &'a str);
type ForbiddenFactKey = (crate::entity::EntityKind, String);

fn resolution_fact_sets<'a>(
    expected: &'a [ExpectedPublicFact],
    forbidden: &[ForbiddenPublicFact],
) -> (
    std::collections::BTreeSet<ExpectedFactKey<'a>>,
    std::collections::BTreeSet<ForbiddenFactKey>,
) {
    let expected = expected
        .iter()
        .map(|fact| {
            (
                fact.entity_kind.clone(),
                crate::entity::normalise(&fact.entity_kind, &fact.value),
                fact.source.as_str(),
            )
        })
        .collect();
    let forbidden = forbidden
        .iter()
        .map(|fact| {
            (
                fact.entity_kind.clone(),
                crate::entity::normalise(&fact.entity_kind, &fact.value),
            )
        })
        .collect();
    (expected, forbidden)
}

#[must_use]
pub fn score_person_resolution_with_ancestry(
    entities: &[Entity],
    expected: &[ExpectedPublicFact],
    forbidden: &[ForbiddenPublicFact],
    ancestry: Option<&EvidenceAncestryGraph>,
    required_independent_person_support: usize,
) -> PersonResolutionScore {
    let (expected, forbidden) = resolution_fact_sets(expected, forbidden);

    let matched_facts = expected
        .iter()
        .filter(|(kind, value, source)| {
            entities.iter().any(|entity| {
                entity.kind == *kind
                    && entity.value == *value
                    && entity
                        .evidence
                        .iter()
                        .any(|evidence| evidence.provenance.source == **source)
            })
        })
        .count();
    let supported_entities = entities
        .iter()
        .filter(|entity| {
            expected.iter().any(|(kind, value, source)| {
                entity.kind == *kind
                    && entity.value == *value
                    && entity
                        .evidence
                        .iter()
                        .any(|evidence| evidence.provenance.source == *source)
            })
        })
        .count();
    let entities_with_evidence = entities
        .iter()
        .filter(|entity| !entity.evidence.is_empty())
        .count();
    let entities_without_evidence = entities.len().saturating_sub(entities_with_evidence);
    let unsupported_person_entities = entities
        .iter()
        .filter(|entity| {
            entity.kind == crate::entity::EntityKind::Person
                && !expected
                    .iter()
                    .any(|(kind, value, _)| entity.kind == *kind && entity.value == *value)
        })
        .count();
    let forbidden_facts_emitted = forbidden
        .iter()
        .filter(|(kind, value)| {
            entities
                .iter()
                .any(|entity| entity.kind == *kind && entity.value == *value)
        })
        .count();

    let (proven_independent_person_support, independence_check_complete, independence_accepted) =
        person_independence_support(
            entities,
            &expected,
            ancestry,
            required_independent_person_support,
        );

    let recall = CoverageRatio::new(matched_facts, expected.len());
    let precision = CoverageRatio::new(supported_entities, entities.len());
    let provenance_coverage = CoverageRatio::new(entities_with_evidence, entities.len());
    let accepted = resolution_accepted(
        recall,
        precision,
        provenance_coverage,
        unsupported_person_entities,
        forbidden_facts_emitted,
        independence_accepted,
    );

    PersonResolutionScore {
        expected_facts: expected.len(),
        matched_facts,
        recall,
        supported_entities,
        emitted_entities: entities.len(),
        precision,
        entities_with_evidence,
        entities_without_evidence,
        provenance_coverage,
        unsupported_person_entities,
        forbidden_facts: forbidden.len(),
        forbidden_facts_emitted,
        required_independent_person_support,
        proven_independent_person_support,
        independence_check_complete,
        accepted,
    }
}
