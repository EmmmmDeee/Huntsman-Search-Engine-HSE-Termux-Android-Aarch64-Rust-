//! Bounded composition types for high-level investigations.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::classifier;
use crate::entity::{Entity, EntityKind};

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
