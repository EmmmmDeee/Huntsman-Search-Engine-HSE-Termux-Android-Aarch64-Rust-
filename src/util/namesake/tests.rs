use super::{AMBIGUOUS_NAME, NameCollisions};
use crate::core::entity::{Entity, EntityKind};

const ORG: EntityKind = EntityKind::Organisation;
const PERSON: EntityKind = EntityKind::Person;

#[test]
fn a_name_seen_once_is_not_a_collision() {
    let seen = NameCollisions::of(&ORG, ["Acme Ltd", "Beta Pty", "Gamma GmbH"]);
    assert!(!seen.any());
    assert!(seen.is_empty());
    assert_eq!(seen.len(), 0);
    for n in ["Acme Ltd", "Beta Pty", "Gamma GmbH"] {
        assert!(!seen.is_shared(&ORG, n));
    }
}

#[test]
fn a_name_seen_twice_is_a_collision_whatever_its_casing_or_spacing() {
    let seen = NameCollisions::of(
        &ORG,
        [
            "Meridian Holdings Limited",
            "  MERIDIAN   holdings Limited ",
        ],
    );
    assert!(seen.any());
    assert_eq!(seen.len(), 1);
    assert!(seen.is_shared(&ORG, "meridian holdings limited"));
    assert!(seen.is_shared(&ORG, "Meridian  Holdings  Limited"));
}

#[test]
fn the_key_is_the_engine_s_own_identity_not_an_imitation_of_it() {
    // The whole design argument, asserted rather than asserted-about: every
    // spelling this flags as one name is a spelling the engine actually fuses
    // into one uid, and the non-ASCII case an ASCII-only fold would miss is
    // included deliberately.
    for (a, b) in [
        ("Meridian Holdings Limited", "MERIDIAN HOLDINGS LIMITED"),
        ("Meridian Holdings Limited", "Meridian  Holdings  Limited"),
        ("Meridian Holdings Limited", "  Meridian Holdings Limited  "),
        ("MÜLLER GMBH", "Müller GmbH"),
        ("İstanbul Holding", "i\u{307}stanbul holding"),
    ] {
        let ea = Entity::new(ORG, a, 0.5, "s");
        let eb = Entity::new(ORG, b, 0.5, "s");
        assert_eq!(
            ea.uid, eb.uid,
            "the engine must fuse {a:?} and {b:?}; if it stops, this module's \
             collision rule changes meaning and its doc comment must be revisited"
        );
        assert!(
            NameCollisions::of(&ORG, [a, b]).any(),
            "{a:?} and {b:?} fuse in the engine but were not flagged as a collision"
        );
    }
}

#[test]
fn a_collision_is_exactly_a_shared_uid_for_every_kind() {
    // The delegation invariant, stated as a biconditional rather than as a
    // guess about any one kind's folding rules: two names collide here IFF the
    // engine gives them one uid. Per-kind identity semantics live in
    // `normalise`/`identity_fold` and this module must never hold a second
    // opinion about them — a hand-rolled fold would be that second opinion.
    //
    // (The first draft of this test asserted that `Username` is case-SIGNIFICANT
    // and was wrong: `normalise` lowercases it. Deriving the expectation from
    // the engine instead of from an assumption is the point.)
    let cases: &[(EntityKind, &str, &str)] = &[
        (
            ORG,
            "Meridian Holdings Limited",
            "MERIDIAN HOLDINGS LIMITED",
        ),
        (
            ORG,
            "Meridian Holdings Limited",
            "Meridian  Holdings  Limited",
        ),
        (ORG, "MÜLLER GMBH", "Müller GmbH"),
        (ORG, "Acme Ltd", "Beta Pty"),
        (PERSON, "Jane Smith", "jane  smith"),
        (PERSON, "Jane Smith", "John Smith"),
        (EntityKind::Username, "Meridian", "MERIDIAN"),
        (EntityKind::Username, "meridian", "other_handle"),
    ];

    let mut fused = 0usize;
    let mut distinct = 0usize;
    for (kind, a, b) in cases {
        let same_uid = Entity::new(kind.clone(), *a, 0.5, "s").uid
            == Entity::new(kind.clone(), *b, 0.5, "s").uid;
        if same_uid {
            fused += 1;
        } else {
            distinct += 1;
        }
        assert_eq!(
            NameCollisions::of(kind, [*a, *b]).any(),
            same_uid,
            "{kind}: {a:?} vs {b:?} — a collision must mean exactly \
             \"the engine fuses these\""
        );
    }

    // Vacuity guard: the table must exercise BOTH directions, or the
    // biconditional above could hold trivially.
    assert!(
        fused >= 3,
        "only {fused} fusing pair(s) — one direction untested"
    );
    assert!(
        distinct >= 3,
        "only {distinct} distinct pair(s) — the other direction untested"
    );
}

#[test]
fn only_the_colliding_name_is_flagged() {
    let seen = NameCollisions::of(&ORG, ["Dup Ltd", "Dup Ltd", "Unique Ltd"]);
    assert!(seen.is_shared(&ORG, "Dup Ltd"));
    assert!(
        !seen.is_shared(&ORG, "Unique Ltd"),
        "a singly-held name in a result set that contains a collision must stay clean"
    );
    assert_eq!(seen.len(), 1);
}

#[test]
fn blank_names_are_not_identities_and_never_collide() {
    // Two rows with no legal name are two missing values, not one shared
    // identity; flagging them would put `ambiguous-name` on rows that carry no
    // name to be ambiguous about.
    let seen = NameCollisions::of(&ORG, ["", "   ", "\t", "Real Co"]);
    assert!(!seen.any(), "empty names must not count as a collision");
    assert!(!seen.is_shared(&ORG, ""));
}

#[test]
fn three_holders_are_still_one_collided_name() {
    let seen = NameCollisions::of(&PERSON, ["Smith Pty", "smith pty", "SMITH PTY"]);
    assert_eq!(seen.len(), 1);
    assert!(seen.is_shared(&PERSON, "Smith Pty"));
}

#[test]
fn the_tag_is_not_the_candidate_quarantine() {
    // An ambiguous name is not a non-match: the records genuinely match and the
    // operator must see every one of them. `tags::CANDIDATE` is filtered out of
    // exports; this must never become that.
    assert_eq!(AMBIGUOUS_NAME, "ambiguous-name");
    assert_ne!(AMBIGUOUS_NAME, crate::core::tags::CANDIDATE);
}
