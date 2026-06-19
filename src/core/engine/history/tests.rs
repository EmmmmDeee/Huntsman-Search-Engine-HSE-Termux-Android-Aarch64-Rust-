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

#[test]
fn cooccurrence_bridges_a_pair_seen_together_before() {
    let store = InMemoryStore::new();
    // A PRIOR investigation recorded a phone and an email TOGETHER.
    store
        .upsert_entity(&ent(EntityKind::Phone, "+61400111222", 0.7, "prior-scan"))
        .unwrap();
    store
        .upsert_entity(&ent(
            EntityKind::Email,
            "jane@example.com",
            0.7,
            "prior-scan",
        ))
        .unwrap();

    // This scan freshly rediscovers BOTH of them (not yet persisted).
    let mut entities = vec![
        ent(EntityKind::Phone, "+61400111222", 0.55, "this-scan"),
        ent(EntityKind::Email, "jane@example.com", 0.55, "this-scan"),
    ];

    let linked = link_cross_scan_cooccurrence(&store, &mut entities, "this-scan");
    assert_eq!(linked, 2, "both endpoints of the recurring pair are bridged");

    let phone = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    let email = entities
        .iter()
        .find(|e| e.kind == EntityKind::Email)
        .unwrap();
    assert!(phone.has_tag("cross-scan-cooccurrence"));
    assert!(email.has_tag("cross-scan-cooccurrence"));
    // Each endpoint's evidence names the OTHER as the co-occurring partner.
    assert!(
        phone.evidence.iter().any(|ev| ev.source == CROSS_SCAN_SOURCE
            && ev.summary.starts_with(COOCCURRENCE_MARKER)
            && ev.summary.contains("jane@example.com")),
        "phone names the email partner"
    );
    assert!(
        email.evidence.iter().any(|ev| ev.source == CROSS_SCAN_SOURCE
            && ev.summary.starts_with(COOCCURRENCE_MARKER)
            && ev.summary.contains("+61400111222")),
        "email names the phone partner"
    );
}

#[test]
fn no_cooccurrence_when_pair_never_shared_a_prior_scan() {
    let store = InMemoryStore::new();
    // The phone and the email each recur, but in DIFFERENT prior scans — they
    // were never seen together, so there is no recurring association to bridge.
    store
        .upsert_entity(&ent(EntityKind::Phone, "+61400111222", 0.7, "prior-a"))
        .unwrap();
    store
        .upsert_entity(&ent(EntityKind::Email, "jane@example.com", 0.7, "prior-b"))
        .unwrap();

    let mut entities = vec![
        ent(EntityKind::Phone, "+61400111222", 0.55, "this-scan"),
        ent(EntityKind::Email, "jane@example.com", 0.55, "this-scan"),
    ];

    let linked = link_cross_scan_cooccurrence(&store, &mut entities, "this-scan");
    assert_eq!(
        linked, 0,
        "co-recurrence in separate scans is not co-occurrence"
    );
    assert!(
        entities
            .iter()
            .all(|e| !e.has_tag("cross-scan-cooccurrence"))
    );
}

#[test]
fn cooccurrence_is_idempotent_and_never_inflates_confidence() {
    let store = InMemoryStore::new();
    store
        .upsert_entity(&ent(EntityKind::Phone, "+61400111222", 0.7, "prior-scan"))
        .unwrap();
    store
        .upsert_entity(&ent(
            EntityKind::Email,
            "jane@example.com",
            0.7,
            "prior-scan",
        ))
        .unwrap();

    // Capture the phone endpoint's pre-link confidence/sources.
    let phone = ent(EntityKind::Phone, "+61400111222", 0.55, "this-scan");
    let conf_before = phone.c_effective();
    let sources_before = phone.source_count();
    let mut entities = vec![
        phone,
        ent(EntityKind::Email, "jane@example.com", 0.55, "this-scan"),
    ];

    assert_eq!(
        link_cross_scan_cooccurrence(&store, &mut entities, "this-scan"),
        2
    );
    let phone_after = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    let evidence_after = phone_after.evidence.len();
    // Non-corroborating: the co-occurrence evidence reuses CROSS_SCAN_SOURCE, so
    // it must not raise the effective confidence or the corroborating-source count.
    assert!((phone_after.c_effective() - conf_before).abs() < 1e-9);
    assert_eq!(phone_after.source_count(), sources_before);

    // Idempotent: a second pass adds no new links and no duplicate evidence.
    assert_eq!(
        link_cross_scan_cooccurrence(&store, &mut entities, "this-scan"),
        0
    );
    assert_eq!(
        entities
            .iter()
            .find(|e| e.kind == EntityKind::Phone)
            .unwrap()
            .evidence
            .len(),
        evidence_after,
        "re-run attaches no duplicate co-occurrence evidence"
    );
}

#[test]
fn cooccurrence_partners_recorded_in_deterministic_order() {
    let store = InMemoryStore::new();
    // One prior scan recorded a phone alongside TWO emails.
    store
        .upsert_entity(&ent(EntityKind::Phone, "+61400111222", 0.7, "prior-scan"))
        .unwrap();
    store
        .upsert_entity(&ent(EntityKind::Email, "aaa@example.com", 0.7, "prior-scan"))
        .unwrap();
    store
        .upsert_entity(&ent(EntityKind::Email, "zzz@example.com", 0.7, "prior-scan"))
        .unwrap();

    // Insert the current entities in a DIFFERENT (reverse-sorted) order than the
    // partners' value order, so a stable result can only come from sorting.
    let mut entities = vec![
        ent(EntityKind::Phone, "+61400111222", 0.55, "this-scan"),
        ent(EntityKind::Email, "zzz@example.com", 0.55, "this-scan"),
        ent(EntityKind::Email, "aaa@example.com", 0.55, "this-scan"),
    ];

    link_cross_scan_cooccurrence(&store, &mut entities, "this-scan");

    // The phone's two co-occurrence records name its partners in a stable,
    // value-sorted order regardless of discovery order.
    let phone = entities
        .iter()
        .find(|e| e.kind == EntityKind::Phone)
        .unwrap();
    let partners: Vec<&str> = phone
        .evidence
        .iter()
        .filter(|ev| ev.summary.starts_with(COOCCURRENCE_MARKER))
        .map(|ev| {
            if ev.summary.contains("aaa@example.com") {
                "aaa@example.com"
            } else {
                "zzz@example.com"
            }
        })
        .collect();
    assert_eq!(partners, vec!["aaa@example.com", "zzz@example.com"]);
}
