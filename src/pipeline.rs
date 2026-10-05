//! Bounded composition types for high-level investigations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::classifier;
use crate::collection::{
    ObservationBatch, RawObservation, UpstreamOrigin, bounded_batch, coverage_events,
};
use crate::coverage::{ProviderCoverage, provider_coverage_from_events};
use crate::entity::{CANDIDATE_CONF, Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::evidence_ancestry::{
    AncestryError, EvidenceAncestryGraph, EvidenceAncestryNode, EvidenceNodeId, canonical_family,
};
use crate::graph::{EntityRelation, RelationKind as GraphRelationKind};
use crate::relation::{self, RelationKind as DomainRelationKind};
use crate::sha256::{hex32, sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvestigationMode {
    Offline,
    GuardedNetwork,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvestigationInput {
    pub scan_id: String,
    pub seeds: Vec<String>,
    pub mode: InvestigationMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineLimits {
    pub max_targets: usize,
    pub max_entities: usize,
    pub max_relations: usize,
    pub max_dispatches: usize,
    pub max_response_bytes: usize,
    pub max_archive_captures: usize,
    pub max_cross_scan_frontier: usize,
    pub max_cross_scan_visited: usize,
    pub max_generation: u32,
    pub max_export_bytes: usize,
    pub max_concurrent: usize,
}

impl Default for PipelineLimits {
    fn default() -> Self {
        Self {
            max_targets: 256,
            max_entities: 4096,
            max_relations: 8192,
            max_dispatches: 512,
            max_response_bytes: crate::http::DEFAULT_MAX_BODY,
            max_archive_captures: 4096,
            max_cross_scan_frontier: 128,
            max_cross_scan_visited: 512,
            max_generation: 4,
            max_export_bytes: 8 * 1024 * 1024,
            max_concurrent: 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedSeed {
    pub raw: String,
    pub kind: EntityKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedRejection {
    Empty,
    Unsupported,
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedNormalization {
    pub accepted: Vec<NormalizedSeed>,
    pub rejected: Vec<(String, SeedRejection)>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnalysisSnapshot {
    pub entities: Vec<Entity>,
    pub relations: Vec<EntityRelation>,
    pub coverage: Vec<ProviderCoverage>,
    pub ancestry: EvidenceAncestryGraph,
    pub truncated: bool,
}

fn seed_rank(kind: &EntityKind) -> u8 {
    match kind {
        EntityKind::Email => 0,
        EntityKind::Username => 1,
        EntityKind::Phone => 2,
        EntityKind::Person => 3,
        EntityKind::Organisation => 4,
        EntityKind::Domain => 5,
        EntityKind::Url => 6,
        EntityKind::IpAddress => 7,
        EntityKind::Coordinates => 8,
        EntityKind::Address => 9,
        EntityKind::AbnAcn => 10,
        EntityKind::Asn => 11,
        EntityKind::MacAddress => 12,
        EntityKind::CryptoAddress => 13,
        EntityKind::DeviceId => 14,
        EntityKind::Ssid => 15,
        EntityKind::TrackingId => 16,
        EntityKind::ApiKey => 17,
        EntityKind::Credential => 18,
        EntityKind::Document => 19,
        EntityKind::Other => 20,
    }
}

#[must_use]
pub fn normalize_seeds(input: &InvestigationInput, limits: &PipelineLimits) -> SeedNormalization {
    let mut accepted = BTreeMap::<(u8, String), NormalizedSeed>::new();
    let mut rejected = Vec::new();

    for raw in &input.seeds {
        if raw.trim().is_empty() {
            rejected.push((raw.clone(), SeedRejection::Empty));
            continue;
        }
        let classified = classifier::classify(raw);
        if classified.kind == EntityKind::Other {
            rejected.push((raw.clone(), SeedRejection::Unsupported));
            continue;
        }
        let entity = Entity::new(
            classified.kind.clone(),
            classified.value,
            classified.confidence,
            input.scan_id.clone(),
        );
        if entity.value.trim().is_empty() {
            rejected.push((
                raw.clone(),
                SeedRejection::Invalid("canonical value is empty".to_string()),
            ));
            continue;
        }
        let seed = NormalizedSeed {
            raw: raw.clone(),
            kind: entity.kind,
            value: entity.value,
        };
        accepted
            .entry((seed_rank(&seed.kind), seed.value.clone()))
            .or_insert(seed);
    }

    let unique_count = accepted.len();
    let accepted = accepted
        .into_values()
        .take(limits.max_targets)
        .collect::<Vec<_>>();
    SeedNormalization {
        accepted,
        rejected,
        truncated: unique_count > limits.max_targets,
    }
}

fn ancestry_id(prefix: &str, material: &str) -> EvidenceNodeId {
    EvidenceNodeId(format!("{prefix}:{}", hex32(&sha256(material.as_bytes()))))
}

fn upstream_family(upstream: Option<&UpstreamOrigin>) -> String {
    let Some(upstream) = upstream else {
        return "unknown upstream".to_string();
    };
    let provider = upstream
        .provider
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let dataset = upstream
        .dataset
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match (provider, dataset) {
        (Some(provider), Some(dataset)) => canonical_family(&format!("{provider} {dataset}")),
        (Some(provider), None) => canonical_family(provider),
        (None, Some(dataset)) => canonical_family(dataset),
        (None, None) => "unknown upstream".to_string(),
    }
}

fn scan_id_for(batch: &ObservationBatch, observation: &RawObservation) -> String {
    batch
        .events
        .iter()
        .find(|event| {
            event.provider_id == observation.provider_id && event.target == observation.target
        })
        .or_else(|| batch.events.first())
        .map_or_else(|| "collection".to_string(), |event| event.scan_id.clone())
}

fn ensure_ancestry(
    graph: &mut EvidenceAncestryGraph,
    observation: &RawObservation,
) -> Result<EvidenceNodeId, AncestryError> {
    let family = upstream_family(observation.upstream.as_ref());
    let root_id = ancestry_id("root", &family);
    if graph.get(&root_id).is_none() {
        graph.insert(EvidenceAncestryNode {
            id: root_id.clone(),
            source_family: family,
            parents: BTreeSet::new(),
            derived: false,
        })?;
    }
    let relay_material = format!(
        "{}|{}|{}|{}|{}",
        root_id.0,
        observation.provider_id,
        observation.kind,
        observation.value,
        observation.target.value
    );
    let relay_id = ancestry_id("relay", &relay_material);
    if graph.get(&relay_id).is_none() {
        graph.insert(EvidenceAncestryNode {
            id: relay_id.clone(),
            source_family: observation.provider_id.clone(),
            parents: BTreeSet::from([root_id]),
            derived: true,
        })?;
    }
    Ok(relay_id)
}

fn evidence_for(
    batch: &ObservationBatch,
    observation: &RawObservation,
    ancestry_node: EvidenceNodeId,
) -> Evidence {
    let family = upstream_family(observation.upstream.as_ref());
    let mut provenance = EvidenceProvenance::for_scan(family, scan_id_for(batch, observation));
    if let Some(observed_at) = observation.observed_at_unix {
        provenance.recorded_at_unix = observed_at;
    }
    let mut evidence = Evidence::new(provenance, observation.summary.clone())
        .with_attr("collector", observation.provider_id.clone())
        .with_ancestry(ancestry_node);
    if let Some(upstream) = &observation.upstream {
        evidence = evidence.with_optional_attrs([
            ("upstream_provider", upstream.provider.as_deref()),
            ("upstream_dataset", upstream.dataset.as_deref()),
            ("upstream_artifact", upstream.artifact.as_deref()),
        ]);
    }
    for (key, value) in &observation.attributes {
        evidence = evidence.with_attr(key.clone(), value.clone());
    }
    evidence
}

fn graph_kind(kind: DomainRelationKind) -> GraphRelationKind {
    match kind {
        DomainRelationKind::SameAs
        | DomainRelationKind::SameIdentity
        | DomainRelationKind::IdentifiedBy => GraphRelationKind::SameAs,
        DomainRelationKind::AliasOf => GraphRelationKind::AliasOf,
        DomainRelationKind::LocatedAt => GraphRelationKind::LocatedAt,
        DomainRelationKind::EmployedBy
        | DomainRelationKind::OfficerOf
        | DomainRelationKind::MemberOf => GraphRelationKind::MemberOf,
        DomainRelationKind::ControlledBy => GraphRelationKind::Owns,
        DomainRelationKind::SharesSecretWith => GraphRelationKind::ExposedWith,
        DomainRelationKind::HostedOn
        | DomainRelationKind::ResolvesTo
        | DomainRelationKind::OperatedBy => GraphRelationKind::Uses,
        DomainRelationKind::SubdomainOf
        | DomainRelationKind::BelongsToDomain
        | DomainRelationKind::RegisteredBy
        | DomainRelationKind::CoLocatedWith
        | DomainRelationKind::DerivedFrom
        | DomainRelationKind::AssociatedWith
        | DomainRelationKind::SameOperator => GraphRelationKind::AssociatedWith,
    }
}

fn derive_relations(entities: &[Entity], scan_id: &str) -> Vec<EntityRelation> {
    let mut relations = relation::derive_all(entities, scan_id)
        .into_iter()
        .map(|relation| {
            EntityRelation::new(
                relation.from_uid,
                relation.to_uid,
                graph_kind(relation.kind),
                relation.confidence,
            )
        })
        .collect::<Vec<_>>();
    relations.sort_by(|left, right| {
        left.from_uid
            .cmp(&right.from_uid)
            .then_with(|| left.to_uid.cmp(&right.to_uid))
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
    });
    relations
}

/// Normalize provider observations into one provenance-aware analysis snapshot.
///
/// # Errors
/// Fails closed if evidence ancestry is malformed.
pub fn normalize_observations(
    batch: ObservationBatch,
    limits: &PipelineLimits,
) -> Result<AnalysisSnapshot, AncestryError> {
    let batch = bounded_batch(batch, limits);
    let coverage = provider_coverage_from_events(&coverage_events(&batch));
    let mut ancestry = EvidenceAncestryGraph::default();
    let mut entities = BTreeMap::<String, Entity>::new();

    for observation in &batch.observations {
        let ancestry_node = ensure_ancestry(&mut ancestry, observation)?;
        let scan_id = scan_id_for(&batch, observation);
        let mut candidate = Entity::new(
            observation.kind.clone(),
            observation.value.clone(),
            CANDIDATE_CONF,
            scan_id,
        );
        if let Some(observed_at) = observation.observed_at_unix {
            candidate.observed_at_unix = observed_at;
        }
        let evidence = evidence_for(&batch, observation, ancestry_node);
        if let Some(existing) = entities.get_mut(&candidate.uid) {
            existing.add_evidence(evidence);
        } else {
            candidate.add_evidence(evidence);
            entities.insert(candidate.uid.clone(), candidate);
        }
    }

    let entities = entities.into_values().collect::<Vec<_>>();
    let scan_id = batch
        .events
        .first()
        .map_or("collection", |event| event.scan_id.as_str());
    let mut relations = derive_relations(&entities, scan_id);
    let relation_overflow = relations.len() > limits.max_relations;
    relations.truncate(limits.max_relations);

    Ok(AnalysisSnapshot {
        entities,
        relations,
        coverage,
        ancestry,
        truncated: batch.truncated || relation_overflow,
    })
}
