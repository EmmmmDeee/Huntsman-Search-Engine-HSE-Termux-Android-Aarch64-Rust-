//! Deterministic claim aggregation for IP-investigation observations.

use std::collections::{BTreeMap, BTreeSet};

use crate::evidence_ancestry::canonical_family;

use super::{
    IpClaim, IpClaimKind, IpClaimState, IpInvestigation, IpObservation, IpObservationKind,
    TemporalState,
};

const CURRENT_MAX_AGE_SECONDS: u64 = 86_400;
const RECENT_MAX_AGE_SECONDS: u64 = 30 * 86_400;
const HISTORICAL_MAX_AGE_SECONDS: u64 = 365 * 86_400;

/// Derive claims from the current observation set without manufacturing independence.
pub fn apply_observations(investigation: &mut IpInvestigation) {
    let mut grouped: BTreeMap<IpClaimKind, Vec<&IpObservation>> = BTreeMap::new();
    for observation in &investigation.observations {
        grouped
            .entry(claim_kind(observation.kind))
            .or_default()
            .push(observation);
    }

    investigation.claims = grouped
        .into_iter()
        .map(|(kind, observations)| build_claim(kind, &observations))
        .collect();
}

/// Count canonical independent source families supporting one derived claim.
#[must_use]
pub fn independent_support_count(investigation: &IpInvestigation, kind: IpClaimKind) -> usize {
    investigation
        .claims
        .iter()
        .find(|claim| claim.kind == kind)
        .map_or(0, |claim| claim.dependency_ids.len())
}

/// Classify observation freshness from event time, never retrieval time alone.
#[must_use]
pub fn temporal_state_for_observation(observation: &IpObservation) -> TemporalState {
    let Some(observed_at) = observation.observed_at_unix else {
        return TemporalState::UnknownCurrent;
    };
    if observed_at > observation.retrieved_at_unix {
        return TemporalState::UnknownCurrent;
    }

    let age = observation.retrieved_at_unix - observed_at;
    if age <= CURRENT_MAX_AGE_SECONDS {
        TemporalState::Current
    } else if age <= RECENT_MAX_AGE_SECONDS {
        TemporalState::Recent
    } else if age <= HISTORICAL_MAX_AGE_SECONDS {
        TemporalState::Historical
    } else {
        TemporalState::Stale
    }
}

fn build_claim(kind: IpClaimKind, observations: &[&IpObservation]) -> IpClaim {
    let mut support_ids: Vec<String> = observations
        .iter()
        .map(|observation| observation.id.clone())
        .collect();
    support_ids.sort();
    support_ids.dedup();

    let dependency_ids: Vec<String> = observations
        .iter()
        .map(|observation| canonical_family(&observation.source_family))
        .filter(|family| !family.is_empty())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let contradiction_ids = contradiction_ids(observations);
    let state = if contradiction_ids.is_empty() {
        IpClaimState::Supported
    } else {
        IpClaimState::Contradicted
    };

    IpClaim {
        kind,
        state,
        temporal: aggregate_temporal_state(observations),
        support_ids,
        contradiction_ids,
        dependency_ids,
    }
}

fn aggregate_temporal_state(observations: &[&IpObservation]) -> TemporalState {
    if observations.is_empty() {
        return TemporalState::UnknownCurrent;
    }

    let mut freshest: Option<TemporalState> = None;
    for observation in observations {
        let state = temporal_state_for_observation(observation);
        if state == TemporalState::UnknownCurrent {
            return TemporalState::UnknownCurrent;
        }
        freshest = match freshest {
            None => Some(state),
            Some(current) if freshness_rank(state) < freshness_rank(current) => Some(state),
            Some(current) => Some(current),
        };
    }
    freshest.unwrap_or(TemporalState::UnknownCurrent)
}

const fn freshness_rank(state: TemporalState) -> u8 {
    match state {
        TemporalState::Current => 0,
        TemporalState::Recent => 1,
        TemporalState::Historical => 2,
        TemporalState::Stale => 3,
        TemporalState::UnknownCurrent => 4,
        TemporalState::Invalidated => 5,
    }
}

fn contradiction_ids(observations: &[&IpObservation]) -> Vec<String> {
    let mut contradicted = BTreeSet::new();
    for (index, left) in observations.iter().enumerate() {
        for right in observations.iter().skip(index + 1) {
            if observations_conflict(left, right) {
                contradicted.insert(left.id.clone());
                contradicted.insert(right.id.clone());
            }
        }
    }
    contradicted.into_iter().collect()
}

fn observations_conflict(left: &IpObservation, right: &IpObservation) -> bool {
    if left.kind != right.kind {
        return false;
    }
    comparable_keys(left.kind).iter().any(|key| {
        let Some(left_value) = left.attributes.get(*key) else {
            return false;
        };
        let Some(right_value) = right.attributes.get(*key) else {
            return false;
        };
        normalize_fact_value(key, left_value) != normalize_fact_value(key, right_value)
    })
}

fn normalize_fact_value(key: &str, value: &str) -> String {
    if key == "asns" {
        return value
            .split([',', ';'])
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(";");
    }
    value
        .split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

const fn comparable_keys(kind: IpObservationKind) -> &'static [&'static str] {
    match kind {
        IpObservationKind::Allocation => &[
            "handle",
            "start_address",
            "end_address",
            "name",
            "operator",
            "organization",
            "parent_handle",
        ],
        IpObservationKind::Routing => &["prefix", "asns", "operator", "organization"],
        IpObservationKind::Geolocation => &["country", "region", "city"],
        IpObservationKind::Anonymization => &["type", "classification"],
        IpObservationKind::InfrastructureClass => &["class", "classification", "type"],
        IpObservationKind::ReverseDns
        | IpObservationKind::HistoricalDns
        | IpObservationKind::Certificate
        | IpObservationKind::Service
        | IpObservationKind::Reputation => &[],
    }
}

const fn claim_kind(kind: IpObservationKind) -> IpClaimKind {
    match kind {
        IpObservationKind::Allocation => IpClaimKind::Allocation,
        IpObservationKind::Routing => IpClaimKind::Routing,
        IpObservationKind::ReverseDns => IpClaimKind::ReverseDns,
        IpObservationKind::HistoricalDns => IpClaimKind::HistoricalDns,
        IpObservationKind::Certificate => IpClaimKind::Certificate,
        IpObservationKind::Service => IpClaimKind::Service,
        IpObservationKind::Reputation => IpClaimKind::Reputation,
        IpObservationKind::Anonymization => IpClaimKind::Anonymization,
        IpObservationKind::Geolocation => IpClaimKind::Geolocation,
        IpObservationKind::InfrastructureClass => IpClaimKind::InfrastructureClass,
    }
}
