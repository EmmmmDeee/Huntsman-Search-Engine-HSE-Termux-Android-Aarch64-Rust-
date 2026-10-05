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
