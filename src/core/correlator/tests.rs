use std::collections::HashSet;

use super::*;
use crate::core::entity::{Entity, EntityKind, Evidence};

// ── Candidate quarantine ────────────────────────────────────────────

fn ent(kind: EntityKind, value: &str, conf: f64, src: &str, candidate: bool) -> Entity {
    let mut e = Entity::new(kind, value, conf, "scan");
    e.add_evidence(Evidence::new(src, "x".to_string()));
    if candidate {
        e.tag(crate::core::tags::CANDIDATE);
    }
    e
}

#[test]
fn rule_context_by_uid_indexes_every_entity_and_caches() {
    let ents = vec![
        ent(EntityKind::Email, "a@example.com", 0.9, "src-a", false),
        ent(EntityKind::Username, "alice", 0.8, "src-b", false),
        ent(EntityKind::Domain, "example.com", 0.7, "src-c", false),
    ];
    let ctx = RuleContext::new(&ents);

    let by_uid = ctx.by_uid();
    assert_eq!(by_uid.len(), ents.len());
    for e in &ents {
        let got = by_uid.get(e.uid.as_str()).expect("each entity is reachable by its own uid");
        assert_eq!(got.uid, e.uid);
        assert_eq!(got.value, e.value);
    }
    drop(by_uid);

    let again = ctx.by_uid();
    assert_eq!(again.len(), ents.len());
    assert!(again.contains_key(ents[0].uid.as_str()));
}
