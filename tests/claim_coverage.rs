use std::collections::BTreeSet;

use huntsman_recon::claim_coverage::{
    CoverageBlocker, CoverageCompleteness, CoverageObservation, CoverageOutcome,
    CoverageRequirement,
};
use huntsman_recon::intelligence::{ClaimId, TemporalValidity};

fn requirement() -> CoverageRequirement {
    CoverageRequirement {
        evidence_class: "breach".into(),
        query_scope: "account:ada@example.com".into(),
        temporal: TemporalValidity {
            not_before_unix: Some(1_700_000_000),
            not_after_unix: Some(1_800_000_000),
        },
        minimum_completeness: CoverageCompleteness::MateriallyComplete,
    }
}

fn observation(
    provider: &str,
    outcome: CoverageOutcome,
    completeness: CoverageCompleteness,
) -> CoverageObservation {
    CoverageObservation {
        provider_id: provider.into(),
        claim_id: ClaimId::from("claim-1"),
        outcome,
        evidence_classes: BTreeSet::from(["breach".to_string()]),
        query_scope: "account:ada@example.com".into(),
        temporal: TemporalValidity {
            not_before_unix: Some(1_650_000_000),
            not_after_unix: Some(1_850_000_000),
        },
        completeness,
        recorded_at_unix: 1_800_000_001,
    }
}

#[test]
fn failed_collection_is_not_negative_evidence() {
    let observations = [observation(
        "provider-a",
        CoverageOutcome::Failed {
            reason: "timeout".into(),
        },
        CoverageCompleteness::Unknown,
    )];

    let assessment = requirement().evaluate(&ClaimId::from("claim-1"), &observations);

    assert!(!assessment.negative_admissible);
    assert!(assessment.qualifying_providers.is_empty());
    assert!(
        assessment
            .blockers
            .contains(&CoverageBlocker::CollectionFailure)
    );
}

#[test]
fn partial_coverage_cannot_close_required_negative_obligation() {
    let observations = [observation(
        "provider-a",
        CoverageOutcome::CleanNegative,
        CoverageCompleteness::Partial,
    )];

    let assessment = requirement().evaluate(&ClaimId::from("claim-1"), &observations);

    assert!(!assessment.negative_admissible);
    assert!(assessment.qualifying_providers.is_empty());
    assert!(
        assessment
            .blockers
            .contains(&CoverageBlocker::IncompleteCoverage)
    );
}

#[test]
fn clean_negative_qualifies_only_when_class_scope_time_and_completeness_match() {
    let good = observation(
        "provider-good",
        CoverageOutcome::CleanNegative,
        CoverageCompleteness::Complete,
    );
    let mut wrong_class = good.clone();
    wrong_class.provider_id = "wrong-class".into();
    wrong_class.evidence_classes = BTreeSet::from(["session".to_string()]);
    let mut wrong_scope = good.clone();
    wrong_scope.provider_id = "wrong-scope".into();
    wrong_scope.query_scope = "account:other@example.com".into();
    let mut wrong_time = good.clone();
    wrong_time.provider_id = "wrong-time".into();
    wrong_time.temporal.not_before_unix = Some(1_750_000_000);

    let assessment = requirement().evaluate(
        &ClaimId::from("claim-1"),
        &[wrong_class, wrong_scope, wrong_time, good],
    );

    assert!(assessment.negative_admissible);
    assert_eq!(
        assessment.qualifying_providers,
        BTreeSet::from(["provider-good".to_string()])
    );
}

#[test]
fn applicable_positive_observation_defeats_an_absence_conclusion() {
    let negative = observation(
        "provider-negative",
        CoverageOutcome::CleanNegative,
        CoverageCompleteness::Complete,
    );
    let positive = observation(
        "provider-positive",
        CoverageOutcome::Positive,
        CoverageCompleteness::Complete,
    );

    let assessment = requirement().evaluate(&ClaimId::from("claim-1"), &[negative, positive]);

    assert!(!assessment.negative_admissible);
    assert!(
        assessment
            .blockers
            .contains(&CoverageBlocker::PositiveObservation)
    );
}

#[test]
fn bounded_observation_cannot_cover_unbounded_requirement() {
    let mut unbounded = requirement();
    unbounded.temporal = TemporalValidity::default();
    let bounded = observation(
        "provider-bounded",
        CoverageOutcome::CleanNegative,
        CoverageCompleteness::Complete,
    );

    let assessment = unbounded.evaluate(&ClaimId::from("claim-1"), &[bounded]);

    assert!(!assessment.negative_admissible);
    assert!(assessment.qualifying_providers.is_empty());
    assert!(
        assessment
            .blockers
            .contains(&CoverageBlocker::NoApplicableObservation)
    );
}

#[test]
fn a_malformed_requirement_or_claim_admits_no_negative() {
    let clean = observation(
        "provider-a",
        CoverageOutcome::CleanNegative,
        CoverageCompleteness::Complete,
    );
    let mut inverted = requirement();
    inverted.temporal = TemporalValidity {
        not_before_unix: Some(1_800_000_000),
        not_after_unix: Some(1_700_000_000),
    };
    let mut point = clean.clone();
    point.temporal = TemporalValidity {
        not_before_unix: Some(1_750_000_000),
        not_after_unix: Some(1_750_000_000),
    };
    // Each observation matches its requirement field for field, so only the
    // well-formedness check can refuse it.
    let mut blank_class = requirement();
    blank_class.evidence_class = " ".into();
    let mut blank_class_observation = clean.clone();
    blank_class_observation.evidence_classes = BTreeSet::from([" ".to_string()]);
    let mut blank_scope = requirement();
    blank_scope.query_scope = " ".into();
    let mut blank_scope_observation = clean.clone();
    blank_scope_observation.query_scope = " ".into();
    let mut blank_claim_observation = clean.clone();
    blank_claim_observation.claim_id = ClaimId::from(" ");

    for (requirement, claim, observation) in [
        (inverted, "claim-1", point),
        (blank_class, "claim-1", blank_class_observation),
        (blank_scope, "claim-1", blank_scope_observation),
        (requirement(), " ", blank_claim_observation),
    ] {
        let assessment = requirement.evaluate(&ClaimId::from(claim), &[observation]);
        assert!(!assessment.negative_admissible, "{requirement:?} {claim:?}");
        assert!(assessment.qualifying_providers.is_empty());
        assert_eq!(
            assessment.blockers,
            BTreeSet::from([CoverageBlocker::NoApplicableObservation])
        );
    }
}

#[test]
fn open_ended_and_point_windows_are_well_formed() {
    let unbounded = TemporalValidity::default();
    let half_open = |start| TemporalValidity {
        not_before_unix: Some(start),
        not_after_unix: None,
    };
    let point = TemporalValidity {
        not_before_unix: Some(1_750_000_000),
        not_after_unix: Some(1_750_000_000),
    };
    for (required, observed) in [
        (unbounded.clone(), unbounded),
        (half_open(1_700_000_000), half_open(1_650_000_000)),
        (
            point,
            observation(
                "provider-a",
                CoverageOutcome::CleanNegative,
                CoverageCompleteness::Complete,
            )
            .temporal,
        ),
    ] {
        let mut requirement = requirement();
        requirement.temporal = required;
        let mut clean = observation(
            "provider-a",
            CoverageOutcome::CleanNegative,
            CoverageCompleteness::Complete,
        );
        clean.temporal = observed;
        let assessment = requirement.evaluate(&ClaimId::from("claim-1"), &[clean]);
        assert!(assessment.negative_admissible, "{requirement:?}");
    }
}

#[test]
fn an_unnamed_provider_cannot_vouch_for_absence_but_still_blocks_it() {
    for (outcome, blocker) in [
        (
            CoverageOutcome::CleanNegative,
            CoverageBlocker::IncompleteCoverage,
        ),
        (
            CoverageOutcome::Failed {
                reason: "timeout".into(),
            },
            CoverageBlocker::CollectionFailure,
        ),
        (
            CoverageOutcome::Partial,
            CoverageBlocker::IncompleteCoverage,
        ),
    ] {
        let unnamed = observation("  ", outcome, CoverageCompleteness::Complete);
        let assessment = requirement().evaluate(&ClaimId::from("claim-1"), &[unnamed]);
        assert!(!assessment.negative_admissible);
        assert!(assessment.qualifying_providers.is_empty());
        assert_eq!(assessment.blockers, BTreeSet::from([blocker]));
    }

    let observations = [
        observation(
            "provider-a",
            CoverageOutcome::CleanNegative,
            CoverageCompleteness::Complete,
        ),
        observation(
            "",
            CoverageOutcome::Positive,
            CoverageCompleteness::Complete,
        ),
    ];
    let assessment = requirement().evaluate(&ClaimId::from("claim-1"), &observations);
    assert!(!assessment.negative_admissible);
    assert_eq!(
        assessment.blockers,
        BTreeSet::from([CoverageBlocker::PositiveObservation])
    );
}
