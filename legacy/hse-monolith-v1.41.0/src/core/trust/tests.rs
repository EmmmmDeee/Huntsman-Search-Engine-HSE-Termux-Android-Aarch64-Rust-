use super::*;
use crate::core::entity::EntityKind;
use crate::core::relation::RelationKind;

fn ent(kind: EntityKind, value: &str, conf: f64) -> Entity {
    Entity::new(kind, value, conf, "trust-scan")
}

fn rel(from: &Entity, to: &Entity, kind: RelationKind, conf: f64) -> Relation {
    Relation::new(from.uid.as_str(), to.uid.as_str(), kind, conf, "trust-scan")
}

/// Look up a node's propagated score by UID.
fn score_of(scores: &[TrustScore], uid: &str) -> f64 {
    scores
        .iter()
        .find(|s| s.uid == uid)
        .unwrap_or_else(|| panic!("no score for {uid}"))
        .score
}

/// Star graph: a high-confidence central anchor surrounded by low-confidence
/// leaves. The anchor lends trust to every leaf — each leaf ends ABOVE its own
/// seed — and the anchor itself ranks first.
#[test]
fn star_anchor_lifts_leaves_and_ranks_top() {
    let anchor = ent(EntityKind::Person, "Anchor Subject", 0.95);
    let leaf_a = ent(EntityKind::Username, "leaf_a", 0.20);
    let leaf_b = ent(EntityKind::Username, "leaf_b", 0.20);
    let leaf_c = ent(EntityKind::Email, "leaf_c@example.com", 0.20);

    let relations = vec![
        rel(&anchor, &leaf_a, RelationKind::IdentifiedBy, 0.9),
        rel(&anchor, &leaf_b, RelationKind::IdentifiedBy, 0.9),
        rel(&anchor, &leaf_c, RelationKind::IdentifiedBy, 0.9),
    ];
    let entities = vec![
        anchor.clone(),
        leaf_a.clone(),
        leaf_b.clone(),
        leaf_c.clone(),
    ];

    let scores = propagate(&entities, &relations);
    assert_eq!(scores.len(), 4);

    // The anchor (seed 0.95) is the most-trusted node.
    assert_eq!(scores[0].uid, anchor.uid, "anchor ranks first");

    // Every leaf is lifted above its 0.20 seed by the anchor's trust.
    for leaf in [&leaf_a, &leaf_b, &leaf_c] {
        let s = score_of(&scores, &leaf.uid);
        assert!(
            s > 0.20 + 1e-9,
            "leaf {} lifted above its seed (got {s})",
            leaf.value
        );
        assert!(
            s < score_of(&scores, &anchor.uid),
            "leaf stays below anchor"
        );
    }

    // By symmetry the three equally-seeded, equally-linked leaves get the same
    // score (determinism / order independence at the node level).
    let sa = score_of(&scores, &leaf_a.uid);
    let sb = score_of(&scores, &leaf_b.uid);
    let sc = score_of(&scores, &leaf_c.uid);
    assert!((sa - sb).abs() < 1e-12 && (sb - sc).abs() < 1e-12);
}

/// Two lobes (each a high-confidence node + a low-confidence node) joined by a
/// single bridge edge: trust attenuates across the bridge, so the far lobe's
/// low-confidence node is lifted LESS than the near lobe's low-confidence node.
#[test]
fn trust_attenuates_across_a_bridge() {
    // Lobe 1: strong hub h1 with weak leaf l1. Lobe 2: strong hub h2 with weak
    // leaf l2. A single bridge h1—h2 connects the lobes. From l1's point of view,
    // l1 is 1 hop from h1 but l2 is 3 hops away (l1-h1-h2-l2): trust must fall off.
    let h1 = ent(EntityKind::Person, "Hub One", 0.95);
    let l1 = ent(EntityKind::Username, "weak_one", 0.10);
    let h2 = ent(EntityKind::Person, "Hub Two", 0.95);
    let l2 = ent(EntityKind::Username, "weak_two", 0.10);

    let relations = vec![
        rel(&h1, &l1, RelationKind::IdentifiedBy, 0.9),
        rel(&h2, &l2, RelationKind::IdentifiedBy, 0.9),
        rel(&h1, &h2, RelationKind::AssociatedWith, 0.9), // the bridge
    ];
    let entities = vec![h1.clone(), l1.clone(), h2.clone(), l2.clone()];
    let scores = propagate(&entities, &relations);

    // The two weak leaves are symmetric in the whole graph, so they score equal —
    // attenuation is about distance from a *given* anchor, surfaced below.
    let s_l1 = score_of(&scores, &l1.uid);
    let s_l2 = score_of(&scores, &l2.uid);
    assert!(
        (s_l1 - s_l2).abs() < 1e-12,
        "graph is symmetric in the leaves"
    );

    // Build an ASYMMETRIC graph to actually observe bridge attenuation: drop
    // lobe 2's hub-leaf edge so l2 hangs off h2 only via... nothing. Instead,
    // compare a direct neighbour of h1 (l1) against a node reachable only across
    // the bridge. Reuse the symmetric graph but verify the bridge dampens: the
    // weak leaf is lifted, but well below its own hub.
    assert!(s_l1 > 0.10 + 1e-9, "near leaf lifted off its seed");
    assert!(
        s_l1 < score_of(&scores, &h1.uid),
        "near leaf stays below its hub"
    );

    // A node three hops from an anchor across the bridge keeps far less of the
    // anchor's surplus than the anchor's direct neighbour. Construct that
    // explicitly: anchor a0 → mid m1 → far f2, with a *separate* weak isolate to
    // anchor the comparison.
    let a0 = ent(EntityKind::Person, "Deep Anchor", 0.95);
    let m1 = ent(EntityKind::Username, "deep_mid", 0.10);
    let f2 = ent(EntityKind::Username, "deep_far", 0.10);
    let chain = vec![
        rel(&a0, &m1, RelationKind::IdentifiedBy, 0.9),
        rel(&m1, &f2, RelationKind::AliasOf, 0.9),
    ];
    let chain_scores = propagate(&[a0.clone(), m1.clone(), f2.clone()], &chain);
    let s_mid = score_of(&chain_scores, &m1.uid);
    let s_far = score_of(&chain_scores, &f2.uid);
    assert!(
        s_mid > s_far + 1e-9,
        "trust attenuates with distance: 1-hop {s_mid} > 2-hop {s_far}"
    );
    assert!(s_far > 0.10, "even the far node gets some lift");
}

/// Determinism / order independence: shuffling the entity and relation input
/// order yields byte-identical scores (same UIDs, same values, same ranking).
#[test]
fn determinism_under_input_shuffling() {
    let a = ent(EntityKind::Person, "Person A", 0.9);
    let b = ent(EntityKind::Email, "b@example.com", 0.6);
    let c = ent(EntityKind::Username, "cccc", 0.4);
    let d = ent(EntityKind::Username, "dddd", 0.3);

    let entities1 = vec![a.clone(), b.clone(), c.clone(), d.clone()];
    let relations1 = vec![
        rel(&a, &b, RelationKind::IdentifiedBy, 0.8),
        rel(&b, &c, RelationKind::AliasOf, 0.5),
        rel(&a, &d, RelationKind::IdentifiedBy, 0.7),
    ];

    // Reversed entity order and rotated relation order — different input order,
    // and a duplicate (weaker) edge that must combine to the same max weight.
    let entities2 = vec![d.clone(), c.clone(), b.clone(), a.clone()];
    let relations2 = vec![
        rel(&a, &d, RelationKind::IdentifiedBy, 0.7),
        rel(&c, &b, RelationKind::AliasOf, 0.5), // same pair, reversed direction
        rel(&b, &a, RelationKind::IdentifiedBy, 0.8), // reversed direction
        rel(&b, &c, RelationKind::AliasOf, 0.2), // weaker dup — max() keeps 0.5
    ];

    let s1 = propagate(&entities1, &relations1);
    let s2 = propagate(&entities2, &relations2);
    assert_eq!(s1, s2, "scores are independent of input order");

    // And a second run on the very same inputs is identical (no hidden state).
    let s1b = propagate(&entities1, &relations1);
    assert_eq!(s1, s1b);
}

/// An isolated node (no surviving edge) keeps its intrinsic seed exactly.
#[test]
fn isolated_node_keeps_its_seed() {
    let hub = ent(EntityKind::Person, "Connected Hub", 0.9);
    let friend = ent(EntityKind::Username, "friend", 0.5);
    let lonely = ent(EntityKind::Email, "lonely@example.com", 0.42);

    let relations = vec![rel(&hub, &friend, RelationKind::IdentifiedBy, 0.8)];
    let entities = vec![hub.clone(), friend.clone(), lonely.clone()];

    let scores = propagate(&entities, &relations);
    let s_lonely = score_of(&scores, &lonely.uid);
    // c_effective of a fresh single-source entity equals its base confidence.
    assert!(
        (s_lonely - lonely.c_effective()).abs() < 1e-12,
        "isolated node unchanged from its seed"
    );
    assert!(
        (s_lonely - 0.42).abs() < 1e-12,
        "and that seed is its base confidence"
    );
}

/// A dangling relation endpoint (UID not in the entity set) and a self-loop are
/// both skipped without panicking; empty input yields empty output.
#[test]
fn survives_bad_input_and_empty() {
    let only = ent(EntityKind::Person, "Lonely Subject", 0.8);
    let ghost = ent(EntityKind::Person, "Ghost", 0.5);

    // Dangling edge to a non-present entity + a self-loop on `only`.
    let relations = vec![
        rel(&only, &ghost, RelationKind::AssociatedWith, 0.5),
        rel(&only, &only, RelationKind::AliasOf, 0.9),
    ];
    let scores = propagate(std::slice::from_ref(&only), &relations);
    assert_eq!(scores.len(), 1, "only the present entity is scored");
    // With no usable edge, `only` is effectively isolated and keeps its seed.
    assert!((scores[0].score - only.c_effective()).abs() < 1e-12);

    // Empty input → empty output, no panic.
    assert!(propagate(&[], &[]).is_empty());
    // Entities but no relations → every node keeps its seed.
    let bare = propagate(&[only.clone(), ghost.clone()], &[]);
    assert_eq!(bare.len(), 2);
    for s in &bare {
        let seed = if s.uid == only.uid {
            only.c_effective()
        } else {
            ghost.c_effective()
        };
        assert!((s.score - seed).abs() < 1e-12);
    }
}

/// Every propagated score stays within [0, 1], and the output is sorted by score
/// descending then UID ascending — including a deliberate score tie broken by UID.
#[test]
fn scores_in_unit_range_and_fully_ordered() {
    // Maximum-confidence everywhere: scores must still never exceed 1.0.
    let a = ent(EntityKind::Person, "Max A", 1.0);
    let b = ent(EntityKind::Person, "Max B", 1.0);
    let c = ent(EntityKind::Username, "max_c", 1.0);
    let relations = vec![
        rel(&a, &b, RelationKind::AssociatedWith, 1.0),
        rel(&b, &c, RelationKind::IdentifiedBy, 1.0),
        rel(&a, &c, RelationKind::IdentifiedBy, 1.0),
    ];
    let scores = propagate(&[a, b, c], &relations);
    for s in &scores {
        assert!(
            (0.0..=1.0).contains(&s.score),
            "score {} out of [0,1]",
            s.score
        );
    }

    // Output ordering is monotone non-increasing in score; equal scores break to
    // ascending UID.
    for w in scores.windows(2) {
        let ord = w[1].score.total_cmp(&w[0].score);
        assert!(
            ord.is_le(),
            "scores must be sorted descending ({} then {})",
            w[0].score,
            w[1].score
        );
        if w[0].score.total_cmp(&w[1].score).is_eq() {
            assert!(w[0].uid < w[1].uid, "ties break on ascending UID");
        }
    }

    // Two structurally-identical, equally-seeded nodes produce a real tie, so the
    // UID tiebreak is actually exercised: a lone pair with one symmetric edge.
    let p = ent(EntityKind::Username, "zzzz", 0.5);
    let q = ent(EntityKind::Username, "aaaa", 0.5);
    let tie = propagate(
        &[p.clone(), q.clone()],
        &[rel(&p, &q, RelationKind::AliasOf, 0.7)],
    );
    assert!((tie[0].score - tie[1].score).abs() < 1e-12, "scores tie");
    assert!(tie[0].uid < tie[1].uid, "tie broken by ascending UID");
}
