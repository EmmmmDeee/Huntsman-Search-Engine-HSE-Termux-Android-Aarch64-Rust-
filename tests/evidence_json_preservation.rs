//! Distinct structured source answers remain intact when entities are consolidated.
use std::collections::BTreeSet;

use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};

const OLDER: &str = r#"[{"name":"Log4Shell; actively exploited","modified":"2022-01-13"}]"#;
const NEWER: &str = r#"[{"name":"Log4Shell; actively exploited","modified":"2026-10-15"}]"#;

fn observed(time: u64, raw: &str, label: &str) -> Entity {
    let mut provenance = EvidenceProvenance::new("otx");
    provenance.recorded_at_unix = time;
    let evidence = Evidence::new(provenance, "OTX: named in one pulse")
        .with_attr("raw_pulses", raw)
        .with_attr("pulses", label);
    Entity::builder(EntityKind::IpAddress, "45.155.205.233", 0.6, "scan-merge")
        .evidence(evidence)
        .build()
}

#[test]
fn unequal_json_answers_keep_both_original_documents_and_timestamps() {
    for mut entities in [
        vec![observed(100, OLDER, "old"), observed(200, NEWER, "new")],
        vec![observed(200, NEWER, "new"), observed(100, OLDER, "old")],
    ] {
        merge_by_uid(&mut entities);
        assert_eq!(entities.len(), 1);
        assert_eq!(entities[0].evidence.len(), 2);
        let actual: BTreeSet<_> = entities[0]
            .evidence
            .iter()
            .map(|evidence| {
                let raw = evidence.attributes.get("raw_pulses").unwrap();
                let parsed: serde_json::Value = serde_json::from_str(raw).unwrap();
                assert!(parsed.is_array());
                (evidence.provenance.recorded_at_unix, raw.clone())
            })
            .collect();
        assert_eq!(
            actual,
            BTreeSet::from([(100, OLDER.to_owned()), (200, NEWER.to_owned())])
        );
        let labels: BTreeSet<_> = entities[0]
            .evidence
            .iter()
            .filter_map(|evidence| evidence.attributes.get("pulses").cloned())
            .collect();
        assert_eq!(labels, BTreeSet::from(["old".to_owned(), "new".to_owned()]));
    }
}

#[test]
fn equal_json_answers_preserve_existing_coalescing_behavior() {
    let mut entities = vec![
        observed(100, OLDER, "first"),
        observed(200, OLDER, "second"),
    ];
    merge_by_uid(&mut entities);
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].evidence.len(), 1);
    let evidence = &entities[0].evidence[0];
    assert_eq!(
        evidence.attributes.get("raw_pulses").map(String::as_str),
        Some(OLDER)
    );
    assert_eq!(
        evidence.attributes.get("pulses").map(String::as_str),
        Some("first; second")
    );
    assert_eq!(evidence.merged_provenance.len(), 1);
}

#[test]
fn mismatched_document_and_scalar_cannot_be_spliced() {
    let mut entities = vec![
        observed(100, OLDER, "first"),
        observed(200, "unknown", "second"),
    ];
    merge_by_uid(&mut entities);
    assert_eq!(entities.len(), 1);
    assert_eq!(entities[0].evidence.len(), 2);
}

#[test]
fn unequal_opaque_raw_text_keeps_both_provider_answers() {
    let source = |time, raw: &str| {
        let mut provenance = EvidenceProvenance::new("submd");
        provenance.recorded_at_unix = time;
        Entity::builder(EntityKind::Domain, "example.org", 0.5, "scan-merge")
            .evidence(
                Evidence::new(provenance, "Subdomain source response")
                    .with_attr("raw_answer", raw),
            )
            .build()
    };
    let mut entities = vec![
        source(100, "host-a; host-b"),
        source(200, "host-c; host-d"),
    ];
    merge_by_uid(&mut entities);
    assert_eq!(entities.len(), 1);
    let answers: BTreeSet<_> = entities[0]
        .evidence
        .iter()
        .filter_map(|evidence| evidence.attributes.get("raw_answer").cloned())
        .collect();
    assert_eq!(
        answers,
        BTreeSet::from(["host-a; host-b".to_owned(), "host-c; host-d".to_owned()])
    );
}
