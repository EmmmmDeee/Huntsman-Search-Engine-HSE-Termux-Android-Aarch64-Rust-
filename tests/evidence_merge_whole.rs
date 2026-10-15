//! Two records of one source about one entity merge without breaking a raw answer. Sources keep
//! their whole answer as one JSON document (`raw_answer`, `raw_pulses`), and its text can hold
//! `; `, the separator merged attribute values are split on. These run `merge_by_uid`, which the
//! lookups, `scan`, `correlate` and saved-scan loading use to fold entities with one uid.

use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};

const OLDER: &str = r#"[{"name":"Log4Shell; actively exploited","modified":"2022-01-13"},{"name":"Scanner; port 22"}]"#;
const LATER: &str = r#"[{"name":"Log4Shell; actively exploited","modified":"2026-10-15"},{"name":"Scanner; port 22"}]"#;

fn observed(recorded_at_unix: u64, raw: &str, pulse: &str) -> Entity {
    let mut provenance = EvidenceProvenance::new("otx");
    provenance.recorded_at_unix = recorded_at_unix;
    let evidence = Evidence::new(provenance, "OTX: named in 2 pulse(s)")
        .with_attr("raw_pulses", raw)
        .with_attr("pulses", pulse);
    let mut entity = Entity::new(EntityKind::IpAddress, "45.155.205.233", 0.6, "scan-merge");
    entity.add_evidence(evidence);
    entity
}

fn merged(entities: Vec<Entity>) -> Evidence {
    let mut entities = entities;
    merge_by_uid(&mut entities);
    assert_eq!(entities.len(), 1, "{entities:#?}");
    let evidence = &entities[0].evidence;
    assert_eq!(evidence.len(), 1, "{evidence:#?}");
    evidence[0].clone()
}

#[test]
fn a_raw_answer_stays_one_whole_document_and_the_later_one_is_kept() {
    for entities in [
        vec![observed(100, OLDER, "a"), observed(200, LATER, "b")],
        vec![observed(200, LATER, "b"), observed(100, OLDER, "a")],
    ] {
        let evidence = merged(entities);
        let raw = evidence.attributes.get("raw_pulses").map(String::as_str);
        assert_eq!(raw, Some(LATER), "{evidence:#?}");
        assert!(serde_json::from_str::<serde_json::Value>(raw.unwrap_or_default()).is_ok());
        assert_eq!(
            evidence.attr_values("pulses").collect::<Vec<_>>(),
            ["a", "b"]
        );
    }
}
