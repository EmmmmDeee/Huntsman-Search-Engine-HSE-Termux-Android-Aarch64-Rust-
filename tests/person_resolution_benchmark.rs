use huntsman_recon::benchmark::{ExpectedPublicFact, ForbiddenPublicFact, score_person_resolution};
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

fn observed(kind: EntityKind, value: &str, source: &str) -> Entity {
    let mut entity = Entity::new(kind, value, 0.8, "fixture");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan(source, "fixture"),
        "captured public professional/project evidence",
    ));
    entity
}

fn expected(kind: EntityKind, value: &str, source: &str) -> ExpectedPublicFact {
    ExpectedPublicFact {
        entity_kind: kind,
        value: value.to_string(),
        source: source.to_string(),
    }
}

#[test]
fn public_person_resolution_fixture_requires_recall_precision_and_provenance() {
    let entities = vec![
        observed(EntityKind::Person, "Talia Bacot-Keating", "public_profile"),
        observed(EntityKind::Organisation, "Anza Power", "public_profile"),
        observed(
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "project_document",
        ),
    ];
    let expected = vec![
        expected(EntityKind::Person, "Talia Bacot-Keating", "public_profile"),
        expected(EntityKind::Organisation, "Anza Power", "public_profile"),
        expected(
            EntityKind::Document,
            "Nook Battery Energy Storage System",
            "project_document",
        ),
        expected(EntityKind::Person, "Talia Bacot-Keating", "public_profile"),
    ];
    let forbidden = vec![ForbiddenPublicFact {
        entity_kind: EntityKind::Person,
        value: "Different Talia Bacot".to_string(),
    }];

    let score = score_person_resolution(&entities, &expected, &forbidden);
    assert_eq!(
        score.expected_facts, 3,
        "duplicate expectations must collapse"
    );
    assert_eq!(score.matched_facts, 3);
    assert!(score.recall.is_complete());
    assert!(score.precision.is_complete());
    assert!(score.provenance_coverage.is_complete());
    assert_eq!(score.forbidden_facts, 1);
    assert_eq!(score.forbidden_facts_emitted, 0);
    assert_eq!(score.unsupported_person_entities, 0);
    assert!(score.accepted);
}

#[test]
fn evidence_bearing_wrong_identity_cannot_hide_behind_perfect_recall() {
    let entities = vec![
        observed(EntityKind::Person, "Talia Bacot-Keating", "public_profile"),
        observed(
            EntityKind::Person,
            "Different Talia Bacot",
            "other_public_record",
        ),
    ];
    let expected = vec![expected(
        EntityKind::Person,
        "Talia Bacot-Keating",
        "public_profile",
    )];
    let forbidden = vec![ForbiddenPublicFact {
        entity_kind: EntityKind::Person,
        value: "Different Talia Bacot".to_string(),
    }];

    let score = score_person_resolution(&entities, &expected, &forbidden);
    assert!(
        score.recall.is_complete(),
        "recall alone is intentionally insufficient"
    );
    assert!(!score.precision.is_complete());
    assert!(score.provenance_coverage.is_complete());
    assert_eq!(score.unsupported_person_entities, 1);
    assert_eq!(score.forbidden_facts_emitted, 1);
    assert!(!score.accepted);
}

#[test]
fn wrong_source_does_not_satisfy_expected_fact() {
    let entities = vec![observed(
        EntityKind::Person,
        "Talia Bacot-Keating",
        "unrelated_source",
    )];
    let expected = vec![expected(
        EntityKind::Person,
        "Talia Bacot-Keating",
        "public_profile",
    )];

    let score = score_person_resolution(&entities, &expected, &[]);
    assert_eq!(score.matched_facts, 0);
    assert!(!score.recall.is_complete());
    assert!(!score.precision.is_complete());
    assert!(!score.accepted);
}
