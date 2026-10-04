use std::collections::BTreeMap;

use huntsman_recon::ip::claims::{
    apply_observations, independent_support_count, temporal_state_for_observation,
};
use huntsman_recon::ip::{
    IpClaimKind, IpClaimState, IpInvestigation, IpObservation, IpObservationKind, IpTarget,
    TemporalState,
};

fn observation(
    id: &str,
    source_family: &str,
    kind: IpObservationKind,
    attributes: &[(&str, &str)],
    observed_at_unix: Option<u64>,
    retrieved_at_unix: u64,
) -> IpObservation {
    IpObservation {
        id: id.into(),
        provider_id: format!("provider-{id}"),
        source_family: source_family.into(),
        kind,
        summary: format!("summary-{id}"),
        attributes: attributes
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect::<BTreeMap<_, _>>(),
        observed_at_unix,
        retrieved_at_unix,
        raw_digest: None,
    }
}

fn investigation() -> IpInvestigation {
    IpInvestigation::new(IpTarget::parse("1.1.1.1").expect("target"))
}

#[test]
fn duplicate_lineage_counts_as_one_independent_support() {
    let mut investigation = investigation();
    investigation.observations = vec![
        observation(
            "a",
            "  RIR   RDAP ",
            IpObservationKind::Allocation,
            &[("handle", "APNIC-1")],
            Some(1_000),
            1_100,
        ),
        observation(
            "b",
            "rir rdap",
            IpObservationKind::Allocation,
            &[("handle", "APNIC-1")],
            Some(1_000),
            1_100,
        ),
    ];

    apply_observations(&mut investigation);

    assert_eq!(
        independent_support_count(&investigation, IpClaimKind::Allocation),
        1
    );
    let claim = investigation
        .claims
        .iter()
        .find(|claim| claim.kind == IpClaimKind::Allocation)
        .expect("allocation claim");
    assert_eq!(claim.state, IpClaimState::Supported);
    assert_eq!(claim.support_ids.len(), 2);
    assert_eq!(claim.dependency_ids, vec!["rir rdap"]);
}

#[test]
fn distinct_lineages_remain_independent_supports() {
    let mut investigation = investigation();
    investigation.observations = vec![
        observation(
            "a",
            "rir-rdap",
            IpObservationKind::Allocation,
            &[("handle", "APNIC-1")],
            Some(1_000),
            1_100,
        ),
        observation(
            "b",
            "registry-publication",
            IpObservationKind::Allocation,
            &[("handle", "APNIC-1")],
            Some(1_000),
            1_100,
        ),
    ];

    apply_observations(&mut investigation);

    assert_eq!(
        independent_support_count(&investigation, IpClaimKind::Allocation),
        2
    );
}

#[test]
fn conflicting_routing_facts_remain_explicit_contradictions() {
    let mut investigation = investigation();
    investigation.observations = vec![
        observation(
            "route-a",
            "routing-a",
            IpObservationKind::Routing,
            &[("prefix", "1.1.1.0/24"), ("asns", "13335")],
            Some(10_000),
            10_100,
        ),
        observation(
            "route-b",
            "routing-b",
            IpObservationKind::Routing,
            &[("prefix", "1.1.0.0/16"), ("asns", "64500")],
            Some(10_000),
            10_100,
        ),
    ];

    apply_observations(&mut investigation);

    let claim = investigation
        .claims
        .iter()
        .find(|claim| claim.kind == IpClaimKind::Routing)
        .expect("routing claim");
    assert_eq!(claim.state, IpClaimState::Contradicted);
    assert_eq!(claim.support_ids, vec!["route-a", "route-b"]);
    assert_eq!(claim.contradiction_ids, vec!["route-a", "route-b"]);
}

#[test]
fn historical_observation_is_not_made_current_by_recent_retrieval() {
    let observation = observation(
        "old",
        "historical-source",
        IpObservationKind::HistoricalDns,
        &[("hostname", "old.example")],
        Some(1_000),
        40_000_000,
    );

    let temporal = temporal_state_for_observation(&observation);

    assert!(matches!(
        temporal,
        TemporalState::Historical | TemporalState::Stale
    ));
    assert_ne!(temporal, TemporalState::Current);
}

#[test]
fn missing_observation_time_is_unknown_current() {
    let observation = observation(
        "undated",
        "source",
        IpObservationKind::ReverseDns,
        &[],
        None,
        40_000_000,
    );

    assert_eq!(
        temporal_state_for_observation(&observation),
        TemporalState::UnknownCurrent
    );
}

#[test]
fn infrastructure_claim_model_exposes_no_person_attribution_path() {
    let encoded = serde_json::to_string(&[
        IpClaimKind::Allocation,
        IpClaimKind::Routing,
        IpClaimKind::ReverseDns,
        IpClaimKind::HistoricalDns,
        IpClaimKind::Certificate,
        IpClaimKind::Service,
        IpClaimKind::Reputation,
        IpClaimKind::Anonymization,
        IpClaimKind::Geolocation,
        IpClaimKind::InfrastructureClass,
    ])
    .expect("serialize claim kinds");

    assert!(!encoded.contains("person"));
    assert!(!encoded.contains("human"));
}
