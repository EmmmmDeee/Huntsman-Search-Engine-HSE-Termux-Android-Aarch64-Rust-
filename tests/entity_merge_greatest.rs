//! GREATEST-semantics merge tests.
//!
//! `Entity::merge` is an architecture invariant: confidence and corroboration
//! only ever increase; evidence and tags are unioned; the canonical display value
//! is chosen deterministically. These tests freeze that contract so future
//! refactors cannot silently regress it.

use huntsman_search_engine::core::entity::{Entity, EntityKind, Evidence};

#[test]
fn merge_takes_greatest_confidence() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-a");
    let b = Entity::new(EntityKind::Email, "x@example.com", 0.8, "scan-b");

    a.merge(b);

    assert!(
        (a.confidence - 0.8).abs() < f64::EPSILON,
        "GREATEST: confidence must rise to the higher of the two values"
    );
}

#[test]
fn merge_never_lowers_confidence() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.8, "scan-a");
    let b = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-b");

    a.merge(b);

    assert!(
        (a.confidence - 0.8).abs() < f64::EPSILON,
        "GREATEST: confidence must never decrease on merge"
    );
}

#[test]
fn merge_sums_corroboration() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-a");
    a.corroboration = 3;
    let mut b = Entity::new(EntityKind::Email, "x@example.com", 0.7, "scan-b");
    b.corroboration = 5;

    a.merge(b);

    assert_eq!(
        a.corroboration, 8,
        "GREATEST: corroboration must sum across merged entities"
    );
}

#[test]
fn merge_unions_tags() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-a");
    a.tag("breach");
    a.tag("paste-exposed");

    let mut b = Entity::new(EntityKind::Email, "x@example.com", 0.7, "scan-b");
    b.tag("breach"); // duplicate
    b.tag("dark-web");

    a.merge(b);

    assert!(a.has_tag("breach"));
    assert!(a.has_tag("paste-exposed"));
    assert!(a.has_tag("dark-web"));
    assert_eq!(a.tags.len(), 3, "duplicate tags must not be duplicated");
}

#[test]
fn merge_unions_distinct_evidence() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-a");
    a.add_evidence(Evidence::new("hibp", "seen in breach dump A"));

    let mut b = Entity::new(EntityKind::Email, "x@example.com", 0.7, "scan-b");
    b.add_evidence(Evidence::new("dehashed", "seen in paste"));

    a.merge(b);

    assert_eq!(
        a.evidence.len(),
        2,
        "distinct evidence from different sources must be kept"
    );
    assert!(a.has_evidence_from("hibp"));
    assert!(a.has_evidence_from("dehashed"));
}

#[test]
fn merge_deduplicates_same_source_and_summary() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan-a");
    a.add_evidence(Evidence::new("hibp", "seen"));

    let mut b = Entity::new(EntityKind::Email, "x@example.com", 0.7, "scan-b");
    b.add_evidence(Evidence::new("hibp", "seen"));

    a.merge(b);

    assert_eq!(
        a.evidence.len(),
        1,
        "identical (source, summary) evidence must deduplicate"
    );
}

#[test]
fn merge_is_commutative_for_confidence_corroboration_tags_evidence() {
    // Build two entities with different confidence, corroboration, tags and
    // evidence. Merge in both orders and assert the *resulting* entity is the
    // same — this is the Determinism Requirement for the fold.
    let mut a = Entity::new(EntityKind::Email, "X@Example.Com", 0.6, "scan");
    a.corroboration = 2;
    a.tag("breach");
    a.add_evidence(Evidence::new("hibp", "seen"));

    let mut b = Entity::new(EntityKind::Email, "x@example.com", 0.8, "scan");
    b.corroboration = 3;
    b.tag("paste-exposed");
    b.add_evidence(Evidence::new("dehashed", "seen"));

    let mut ab = a.clone();
    ab.merge(b.clone());

    let mut ba = b.clone();
    ba.merge(a);

    assert_eq!(ab.confidence, ba.confidence, "confidence merge is commutative");
    assert_eq!(
        ab.corroboration, ba.corroboration,
        "corroboration merge is commutative"
    );
    let mut ab_tags = ab.tags.clone();
    let mut ba_tags = ba.tags.clone();
    ab_tags.sort();
    ba_tags.sort();
    assert_eq!(
        ab_tags, ba_tags,
        "tag membership is independent of merge order"
    );
    assert_eq!(
        ab.raw_value, ba.raw_value,
        "canonical raw_value is independent of merge order"
    );
    assert_eq!(
        ab.evidence.len(),
        ba.evidence.len(),
        "evidence count is independent of merge order"
    );
}

#[test]
#[should_panic(expected = "merge: UID mismatch")]
fn merge_panics_on_different_uids_in_debug() {
    // `Entity::merge` uses `debug_assert_eq!` for the UID precondition. In
    // release builds the check is elided and the merge silently returns, but
    // tests run in debug so the guard fires. This documents the contract.
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan");
    let b = Entity::new(EntityKind::Email, "y@example.com", 0.8, "scan");
    a.merge(b);
}

#[test]
fn merge_keeps_earliest_generation() {
    let mut a = Entity::new(EntityKind::Email, "x@example.com", 0.6, "scan");
    a.generation = 5;

    let b = Entity::new(EntityKind::Email, "x@example.com", 0.8, "scan");
    // `generation` defaults to 0 for a freshly-built entity that has not yet been
    // assigned a real expansion round; merging it must not reset an existing,
    // earlier-or-equal real generation.

    a.merge(b);

    assert_eq!(
        a.generation, 5,
        "merge must preserve the earliest real generation and not reset to 0"
    );
}
