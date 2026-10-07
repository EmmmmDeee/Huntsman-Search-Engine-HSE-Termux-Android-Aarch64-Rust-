use huntsman_recon::benchmark::{ExpectedPublicFact, score_person_resolution};
use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

fn observed(kind: EntityKind, value: &str, source: &str) -> Entity {
    let mut entity = Entity::new(kind, value, 0.8, "fixture");
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan(source, "fixture"),
        "captured public professional/project evidence",
    ));
    entity
}

#[test]
fn public_person_resolution_fixture_scores_recall_and_provenance() {
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
        ExpectedPublicFact {
            entity_kind: EntityKind::Person,
            value: "Talia Bacot-Keating".to_string(),
            source: "public_profile".to_string(),
        },
        ExpectedPublicFact {
            entity_kind: EntityKind::Organisation,
            value: "Anza Power".to_string(),
            source: "public_profile".to_string(),
        },
        ExpectedPublicFact {
            entity_kind: EntityKind::Document,
            value: "Nook Battery Energy Storage System".to_string(),
            source: "project_document".to_string(),
        },
    ];

    let score = score_person_resolution(&entities, &expected);
    assert_eq!(score.expected_facts, 3);
    assert_eq!(score.matched_facts, 3);
    assert_eq!(score.recall.numerator, 3);
    assert_eq!(score.recall.denominator, 3);
    assert!(score.recall.is_complete());
    assert_eq!(score.provenance_coverage.numerator, 3);
    assert_eq!(score.provenance_coverage.denominator, 3);
    assert!(score.provenance_coverage.is_complete());
    assert_eq!(score.unsupported_person_entities, 0);
}

#[test]
fn unsupported_person_merge_is_visible_to_the_score() {
    let entities = vec![
        observed(EntityKind::Person, "Talia Bacot-Keating", "public_profile"),
        Entity::new(EntityKind::Person, "Talia Bacot Keating", 0.9, "fixture"),
    ];
    let score = score_person_resolution(&entities, &[]);
    assert_eq!(score.unsupported_person_entities, 1);
    assert_eq!(score.entities_without_evidence, 1);
}
