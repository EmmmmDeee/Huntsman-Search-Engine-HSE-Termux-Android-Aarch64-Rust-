//! Evidence-gated next-query frontier.
//!
//! This module does not execute collection. It turns already-verified entities into
//! deterministic, deduplicated candidate actions, exposing the factors behind the
//! ordering. Secret-bearing entity classes are deliberately non-expandable.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::confidence::Classification;
use crate::entity::{Entity, EntityKind};
use crate::http::parse_http_uri;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    ExactSearch,
    DomainLookup,
    ProfileSearch,
    RegistryLookup,
    InfrastructureLookup,
    GeoLookup,
    WebProbe,
    DocumentSearch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontierCandidate {
    pub kind: ActionKind,
    pub query: String,
    pub basis_uids: Vec<String>,
    pub basis_classification: String,
    pub derived: bool,
    pub information_gain: u8,
    pub discriminative_power: u8,
    pub reliability: u8,
    pub resolve_probability: u8,
    pub cost: u8,
    pub redundancy_penalty: u8,
    pub score: u64,
}

#[derive(Debug, Clone)]
struct Draft {
    kind: ActionKind,
    query: String,
    basis_uids: BTreeSet<String>,
    derived: bool,
    information_gain: u8,
    discriminative_power: u8,
    reliability: u8,
    resolve_probability: u8,
    cost: u8,
}

/// Convert verified entities into a deterministic action frontier.
///
/// The score is intentionally ordinal rather than probabilistic. Its components are
/// exposed so callers can challenge the ranking instead of treating it as evidence.
#[must_use]
pub fn rank_entity_frontier(entities: &[Entity]) -> Vec<FrontierCandidate> {
    let mut drafts: BTreeMap<(ActionKind, String), Draft> = BTreeMap::new();

    let mut ordered = entities.iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.uid.cmp(&right.uid));

    for entity in ordered {
        if entity.classify() != Classification::Verified {
            continue;
        }
        if matches!(entity.kind, EntityKind::Credential | EntityKind::ApiKey) {
            continue;
        }

        for seed in seeds_for(entity) {
            let key = (seed.kind, seed.query.clone());
            let reliability = reliability_for(entity);
            match drafts.get_mut(&key) {
                Some(existing) => {
                    existing.basis_uids.insert(entity.uid.clone());
                    existing.derived &= seed.derived;
                    existing.information_gain = existing.information_gain.max(seed.information_gain);
                    existing.discriminative_power =
                        existing.discriminative_power.max(seed.discriminative_power);
                    existing.reliability = existing.reliability.max(reliability);
                    existing.resolve_probability =
                        existing.resolve_probability.max(seed.resolve_probability);
                    existing.cost = existing.cost.min(seed.cost);
                }
                None => {
                    drafts.insert(
                        key,
                        Draft {
                            kind: seed.kind,
                            query: seed.query,
                            basis_uids: BTreeSet::from([entity.uid.clone()]),
                            derived: seed.derived,
                            information_gain: seed.information_gain,
                            discriminative_power: seed.discriminative_power,
                            reliability,
                            resolve_probability: seed.resolve_probability,
                            cost: seed.cost,
                        },
                    );
                }
            }
        }
    }

    let mut frontier = drafts
        .into_values()
        .map(|draft| {
            let distinct_bases = draft.basis_uids.len();
            let redundancy_penalty = u8::try_from(distinct_bases.saturating_sub(1).saturating_mul(10))
                .unwrap_or(u8::MAX)
                .min(80);
            let score = score(
                draft.information_gain,
                draft.discriminative_power,
                draft.reliability,
                draft.resolve_probability,
                draft.cost,
                redundancy_penalty,
            );
            FrontierCandidate {
                kind: draft.kind,
                query: draft.query,
                basis_uids: draft.basis_uids.into_iter().collect(),
                basis_classification: "verified".to_owned(),
                derived: draft.derived,
                information_gain: draft.information_gain,
                discriminative_power: draft.discriminative_power,
                reliability: draft.reliability,
                resolve_probability: draft.resolve_probability,
                cost: draft.cost,
                redundancy_penalty,
                score,
            }
        })
        .collect::<Vec<_>>();

    frontier.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.discriminative_power.cmp(&left.discriminative_power))
            .then_with(|| left.cost.cmp(&right.cost))
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.query.cmp(&right.query))
    });
    frontier
}

#[derive(Debug, Clone)]
struct Seed {
    kind: ActionKind,
    query: String,
    derived: bool,
    information_gain: u8,
    discriminative_power: u8,
    resolve_probability: u8,
    cost: u8,
}

fn seeds_for(entity: &Entity) -> Vec<Seed> {
    let exact = |kind, gain, discrimination, probability, cost| Seed {
        kind,
        query: entity.value.clone(),
        derived: false,
        information_gain: gain,
        discriminative_power: discrimination,
        resolve_probability: probability,
        cost,
    };

    match entity.kind {
        EntityKind::Email => {
            let mut out = vec![exact(ActionKind::ExactSearch, 92, 98, 88, 12)];
            if let Some((_, domain)) = entity.value.rsplit_once('@') {
                if !domain.is_empty() {
                    out.push(Seed {
                        kind: ActionKind::DomainLookup,
                        query: domain.to_owned(),
                        derived: true,
                        information_gain: 72,
                        discriminative_power: 62,
                        resolve_probability: 78,
                        cost: 18,
                    });
                }
            }
            out
        }
        EntityKind::Username => vec![exact(ActionKind::ProfileSearch, 88, 90, 82, 18)],
        EntityKind::Domain => vec![
            exact(ActionKind::DomainLookup, 86, 82, 86, 16),
            exact(ActionKind::WebProbe, 80, 72, 82, 24),
        ],
        EntityKind::Url => {
            let mut out = vec![exact(ActionKind::WebProbe, 84, 88, 86, 22)];
            if let Ok(uri) = parse_http_uri(&entity.value) {
                if let Some(host) = uri.host() {
                    out.push(Seed {
                        kind: ActionKind::DomainLookup,
                        query: host.to_ascii_lowercase(),
                        derived: true,
                        information_gain: 70,
                        discriminative_power: 60,
                        resolve_probability: 76,
                        cost: 18,
                    });
                }
            }
            out
        }
        EntityKind::IpAddress | EntityKind::Asn | EntityKind::MacAddress => {
            vec![exact(ActionKind::InfrastructureLookup, 86, 90, 84, 16)]
        }
        EntityKind::AbnAcn | EntityKind::Organisation => {
            vec![exact(ActionKind::RegistryLookup, 88, 88, 88, 18)]
        }
        EntityKind::Coordinates | EntityKind::Address => {
            vec![exact(ActionKind::GeoLookup, 82, 78, 82, 20)]
        }
        EntityKind::Document => vec![exact(ActionKind::DocumentSearch, 78, 74, 76, 24)],
        EntityKind::Person | EntityKind::Phone | EntityKind::CryptoAddress => {
            vec![exact(ActionKind::ExactSearch, 86, 86, 80, 16)]
        }
        EntityKind::DeviceId | EntityKind::Ssid | EntityKind::TrackingId | EntityKind::Other => {
            vec![exact(ActionKind::ExactSearch, 72, 72, 64, 18)]
        }
        EntityKind::Credential | EntityKind::ApiKey => Vec::new(),
    }
}

fn reliability_for(entity: &Entity) -> u8 {
    let corroboration_bonus = entity.source_count().saturating_sub(1).min(4) * 4;
    82u8.saturating_add(u8::try_from(corroboration_bonus).unwrap_or(16))
}

fn score(
    information_gain: u8,
    discriminative_power: u8,
    reliability: u8,
    resolve_probability: u8,
    cost: u8,
    redundancy_penalty: u8,
) -> u64 {
    let numerator = u64::from(information_gain)
        * u64::from(discriminative_power)
        * u64::from(reliability)
        * u64::from(resolve_probability);
    let denominator = u64::from(cost).saturating_add(10)
        * u64::from(redundancy_penalty).saturating_add(100);
    numerator / denominator.max(1)
}
