use super::*;
use crate::core::test_support::InMemoryStore;

fn ent(kind: EntityKind, value: &str, conf: f64, scan: &str) -> Entity {
    Entity::new(kind, value, conf, scan)
}

#[test]
fn candidate_gate_picks_specific_personal_identifiers_only() {
    // Specific personal identifiers qualify…
    assert!(is_cross_scan_candidate(&ent(
        EntityKind::Email,
        "a@b.com",
        0.6,
        "s"
    )));
    assert!(is_cross_scan_candidate(&ent(
        EntityKind::Phone,
        "+61400000000",
        0.6,
        "s"
    )));
    assert!(is_cross_scan_candidate(&ent(
        EntityKind::Person,
        "Jane Citizen",
        0.5,
        "s"
    )));

    // …but infrastructure, single-token names, coarse geo, speculative
    // permutations, low confidence, and already-recalled nodes do NOT.
    assert!(!is_cross_scan_candidate(&ent(
        EntityKind::Domain,
        "google.com",
        0.9,
        "s"
    )));
    assert!(!is_cross_scan_candidate(&ent(
        EntityKind::Person,
        "Madonna",
        0.9,
        "s"
    )));
    let mut coarse = ent(EntityKind::Address, "QLD 4000, Australia", 0.6, "s");
    coarse.tag("postcode-only");
    assert!(!is_cross_scan_candidate(&coarse));
    let mut perm = ent(EntityKind::Username, "jcitizen", 0.6, "s");
    perm.tag("permuted");
    assert!(!is_cross_scan_candidate(&perm));
    assert!(!is_cross_scan_candidate(&ent(
        EntityKind::Email,
        "a@b.com",
        0.2,
        "s"
    )));
    let mut recalled = ent(EntityKind::Email, "a@b.com", 0.6, "s");
    recalled.tag(crate::core::tags::RECALLED);
    assert!(!is_cross_scan_candidate(&recalled));
}

#[test]
fn bridges_a_finding_seen_in_an_earlier_scan_without_inflating_confidence() {
    let store = InMemoryStore::new();
    // A PRIOR scan (a different investigation) recorded this phone.
    store
        .upsert_entity(&ent(EntityKind::Phone, "+61400111222", 0.7, "prior-scan"))
        .unwrap();

    // This scan freshly discovers the same phone plus a brand-new email.
    let shared = ent(EntityKind::Phone, "+61400111222", 0.55, "this-scan");
    let conf_before = shared.c_effective();
    let sources_before = shared.source_count();
    let fresh = ent(EntityKind::Email, "nobody@example.com", 0.6, "this-scan");
    let mut entities = vec![shared, fresh];

    let linked = link_cross_scan_history(&store, &mut entities, "this-scan");
    assert_eq!(linked, 1, "only the phone bridges to the prior scan");

    let shared = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    assert!(shared.has_tag("cross-scan"));
    assert!(
        shared.evidence.iter().any(|ev| ev.source
            == "cross_scan_history"
            && ev.summary.contains("earlier scan")),
        "carries the cross-scan provenance evidence"
    );
    // Non-corroborating: the history link must NOT inflate confidence or sources
    // (a recurrence can't tell a re-scan from an independent sighting).
    assert!((shared.c_effective() - conf_before).abs() < 1e-9);
    assert_eq!(shared.source_count(), sources_before);

    // The brand-new email (no prior sighting) is untouched.
    let fresh = entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .unwrap();
    assert!(!fresh.has_tag("cross-scan"));

    // Idempotent: a second pass bridges nothing new.
    assert_eq!(
        link_cross_scan_history(&store, &mut entities, "this-scan"),
        0
    );
}
