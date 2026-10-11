//! The lineage + merge-rule contract, exercised only through the public API a
//! collection front-end calls: `lineage::resolve_with_lineage`.
//!
//! Lineage family labels remain useful diagnostics and de-duplication keys, but are
//! not themselves proof that two observations are independent acquisition routes.

use huntsman_recon::entity::{Evidence, EvidenceProvenance};
use huntsman_recon::evidence_ancestry::EvidenceNodeId;
use huntsman_recon::identity_resolution::{
    AutoMergePolicy, HoldReason, IdentityResolutionDecision, ResolutionState,
};
use huntsman_recon::lineage::{
    CandidateOutcome, Lineage, LineageError, MergeOutcome, Observation, Resolution,
    resolve_with_lineage,
};

fn observation(id: &str, collector: &str, attrs: &[(&str, &str)]) -> Observation {
    Observation {
        id: id.into(),
        evidence: attrs.iter().fold(
            Evidence::new(EvidenceProvenance::new(collector), format!("record {id}")),
            |e, (k, v)| e.with_attr(*k, *v),
        ),
    }
}

fn candidate(support: &[&str], probability: Option<f64>) -> IdentityResolutionDecision {
    IdentityResolutionDecision {
        left_entity_uid: "email:jane@example.com".into(),
        right_entity_uid: "username:janecitizen".into(),
        state: ResolutionState::Match,
        probability,
        supporting: support.iter().copied().map(EvidenceNodeId::from).collect(),
        contradicting: vec![],
        temporal_conflict: false,
        geographic_conflict: false,
        decided_at_unix: 1_790_000_000,
    }
}

fn corpus() -> Vec<Observation> {
    vec![
        observation("hibp-1", "hibp", &[("breach", "Adobe")]),
        observation("dehashed-1", "dehashed", &[("dbname", "Adobe")]),
        observation("dehashed-2", "dehashed", &[("dbname", "LinkedIn")]),
        observation("abr-1", "abn_lookup", &[("registry", "ABR")]),
    ]
}

fn one(observations: Vec<Observation>, c: IdentityResolutionDecision) -> CandidateOutcome {
    let mut r = resolve_with_lineage(observations, vec![c], AutoMergePolicy::default()).unwrap();
    assert_eq!(r.candidates.len(), 1, "a candidate was dropped");
    r.candidates.remove(0)
}

fn reasons(outcome: &CandidateOutcome) -> &[HoldReason] {
    match &outcome.outcome {
        MergeOutcome::Held { reasons } => reasons,
        MergeOutcome::AutoMerge => &[],
    }
}

fn insufficient_one() -> HoldReason {
    HoldReason::InsufficientIndependentFamilies {
        found: 1,
        required: 2,
    }
}

#[test]
fn same_dataset_through_two_collectors_is_one_family_and_no_auto_merge() {
    let out = one(corpus(), candidate(&["hibp-1", "dehashed-1"], Some(0.99)));
    assert_eq!(out.independent_families, ["adobe"]);
    assert_eq!(
        out.outcome,
        MergeOutcome::Held {
            reasons: vec![insufficient_one()]
        }
    );
}

#[test]
fn missing_probability_and_unproven_independence_are_both_reported() {
    let out = one(corpus(), candidate(&["hibp-1", "dehashed-2"], None));
    assert_eq!(out.independent_families, ["adobe", "linkedin"]);
    assert_eq!(
        reasons(&out),
        [HoldReason::ProbabilityMissing, insufficient_one()]
    );
    assert_eq!(out.decision.probability, None);
}

#[test]
fn invalid_probability_does_not_hide_unproven_independence() {
    for p in [f64::NAN, f64::NEG_INFINITY, 1.000_001, -0.5] {
        let out = one(corpus(), candidate(&["hibp-1", "dehashed-2"], Some(p)));
        assert!(
            matches!(
                reasons(&out),
                [
                    HoldReason::ProbabilityInvalid { .. },
                    HoldReason::InsufficientIndependentFamilies {
                        found: 1,
                        required: 2
                    }
                ]
            ),
            "{p}: {:?}",
            out.outcome
        );
    }
    let low = one(corpus(), candidate(&["hibp-1", "dehashed-2"], Some(0.89)));
    assert!(matches!(
        reasons(&low),
        [
            HoldReason::ProbabilityBelowThreshold { .. },
            HoldReason::InsufficientIndependentFamilies {
                found: 1,
                required: 2
            }
        ]
    ));
}

#[test]
fn distinct_lineage_labels_do_not_auto_merge_without_independence_proof() {
    for support in [
        ["hibp-1", "dehashed-2"],
        ["dehashed-1", "dehashed-2"],
        ["hibp-1", "abr-1"],
    ] {
        let out = one(corpus(), candidate(&support, Some(0.95)));
        assert_eq!(out.independent_families.len(), 2);
        assert_eq!(reasons(&out), [insufficient_one()], "{support:?}");
    }
    // The probability floor remains inclusive; independence is an orthogonal gate.
    let edge = one(corpus(), candidate(&["hibp-1", "dehashed-2"], Some(0.90)));
    assert_eq!(reasons(&edge), [insufficient_one()]);
}

#[test]
fn collector_name_never_becomes_lineage() {
    // A collector named after one dump relays another; and two copies under
    // different relay names of one dump stay one family.
    let obs = vec![
        observation("x-1", "adobe", &[("breach", "LinkedIn")]),
        observation("x-2", "linkedin", &[("dbname", "LinkedIn")]),
        observation("x-3", "registry-mirror", &[]),
    ];
    let out = one(obs, candidate(&["x-1", "x-2", "x-3"], Some(0.99)));
    assert_eq!(out.independent_families, ["linkedin"]);
    assert_eq!(out.unattributed_support, [EvidenceNodeId::from("x-3")]);
    assert!(matches!(
        reasons(&out),
        [HoldReason::InsufficientIndependentFamilies { found: 1, .. }]
    ));
}

#[test]
fn verified_registry_counts_as_a_family_but_record_locators_do_not() {
    let obs = vec![
        observation("registry", "abn_lookup", &[("registry", "ABR")]),
        observation(
            "url",
            "paste_collector",
            &[("source_url", "https://paste.example/a")],
        ),
        observation("id", "dump_collector", &[("source_id", "row-1")]),
    ];
    let out = one(obs, candidate(&["registry", "url", "id"], Some(0.99)));
    assert_eq!(out.independent_families, ["abr"]);
    assert_eq!(
        out.unattributed_support,
        [EvidenceNodeId::from("url"), EvidenceNodeId::from("id")]
    );
    assert!(matches!(
        reasons(&out),
        [HoldReason::InsufficientIndependentFamilies { found: 1, .. }]
    ));
}

#[test]
fn unknown_support_holds_instead_of_counting() {
    let out = one(
        corpus(),
        candidate(&["hibp-1", "dehashed-2", "ghost"], Some(0.99)),
    );
    assert!(matches!(
        reasons(&out),
        [HoldReason::UnknownAncestry { detail }] if detail.contains("ghost")
    ));
    // A root id is not an observation either: support cannot cite a family directly.
    let root = one(
        corpus(),
        candidate(&["hibp-1", "lineage:linkedin"], Some(0.99)),
    );
    assert!(
        reasons(&root)
            .iter()
            .any(|r| matches!(r, HoldReason::UnknownAncestry { .. }))
    );
}

#[test]
fn nothing_is_dropped_truncated_or_misattributed() {
    let mut input = corpus();
    input.push(observation("none-1", "hibp", &[]));
    input.push(observation(
        "combo-1",
        "combolists",
        &[("breach", "Adobe"), ("breach", "Canva")],
    ));
    let long = "x".repeat(10_000);
    input.push(observation("long-1", "pastes", &[("dataset", &long)]));
    let candidates = vec![
        candidate(&["hibp-1", "dehashed-1"], Some(0.99)),
        candidate(&["hibp-1", "dehashed-2"], None),
        candidate(&["hibp-1", "dehashed-2"], Some(f64::NAN)),
        candidate(&["hibp-1", "dehashed-2"], Some(0.99)),
        candidate(&["none-1", "combo-1", "long-1"], Some(0.99)),
    ];
    let r: Resolution = resolve_with_lineage(
        input.clone(),
        candidates.clone(),
        AutoMergePolicy::default(),
    )
    .unwrap();

    assert_eq!(r.observations.len(), input.len());
    for (out, original) in r.observations.iter().zip(&input) {
        assert_eq!(&out.observation, original, "observation altered");
        assert_eq!(
            out.observation.evidence.provenance.source,
            original.evidence.provenance.source
        );
    }
    assert_eq!(r.observations[4].lineage, Lineage::Unattributed);
    assert!(matches!(
        r.observations[5].lineage,
        Lineage::Ambiguous { .. }
    ));
    assert_eq!(
        r.observations[6].lineage.family().map(str::len),
        Some(10_000),
        "long upstream name truncated"
    );

    assert_eq!(r.candidates.len(), candidates.len());
    for (out, original) in r.candidates.iter().zip(&candidates) {
        assert_eq!(out.decision.supporting, original.supporting);
        assert_eq!(out.decision.left_entity_uid, original.left_entity_uid);
        assert_eq!(
            out.decision.probability.map(f64::to_bits),
            original.probability.map(f64::to_bits)
        );
    }
    let merged: Vec<bool> = r
        .candidates
        .iter()
        .map(|c| c.outcome == MergeOutcome::AutoMerge)
        .collect();
    assert_eq!(merged, [false, false, false, false, false]);
    assert_eq!(
        r.candidates[4].unattributed_support,
        [
            EvidenceNodeId::from("none-1"),
            EvidenceNodeId::from("combo-1")
        ]
    );
    assert_eq!(r.candidates[4].independent_families.len(), 1);

    // The whole resolution survives a save/reload, NaN probability and all.
    let json = serde_json::to_string(&r).unwrap();
    let back: Resolution = serde_json::from_str(&json).unwrap();
    assert_eq!(back.observations, r.observations);
    assert_eq!(back.candidates[2].outcome, r.candidates[2].outcome);
    assert_eq!(
        back.candidates[2].decision.probability, None,
        "JSON has no NaN"
    );
}

/// Review fix: a non-finite or out-of-range policy floor cannot produce a stored
/// `Resolution` that fails to reload.
#[test]
fn invalid_policy_is_rejected_before_resolving() {
    for floor in [f64::NAN, f64::INFINITY, 1.5, -0.1] {
        let policy = AutoMergePolicy {
            min_match_probability: floor,
            ..AutoMergePolicy::default()
        };
        let got = resolve_with_lineage(corpus(), vec![candidate(&["hibp-1"], Some(0.99))], policy);
        assert!(
            matches!(got, Err(LineageError::InvalidPolicy(_))),
            "{floor}: {got:?}"
        );
    }
}

/// Unknown support is reported in the rule's fixed order, and the original decision is
/// still validated (an empty support id is `InvalidCandidate`).
#[test]
fn unknown_support_keeps_validation_and_reason_order() {
    let empty = one(corpus(), candidate(&["hibp-1", ""], Some(0.99)));
    assert!(
        matches!(
            reasons(&empty),
            [
                HoldReason::InvalidCandidate,
                HoldReason::UnknownAncestry { .. }
            ]
        ),
        "{:?}",
        empty.outcome
    );
    let ghost = one(corpus(), candidate(&["hibp-1", "ghost"], None));
    assert!(
        matches!(
            reasons(&ghost),
            [
                HoldReason::ProbabilityMissing,
                HoldReason::UnknownAncestry { .. }
            ]
        ),
        "{:?}",
        ghost.outcome
    );
}
