use super::*;
use crate::core::entity::{Entity, EntityKind};

/// Construct an entity of `kind` from a raw value. `Entity::new` normalises the
/// value per kind (deriving the UID), which is exactly the production path whose
/// missed-duplicates we are resolving.
fn ent(kind: EntityKind, value: &str) -> Entity {
    Entity::new(kind, value, 0.6, "s")
}

/// The single group expected from `entities`, asserting there is exactly one.
fn only_group(entities: &[Entity]) -> ResolutionGroup {
    let mut groups = suggest_merges(entities);
    assert_eq!(groups.len(), 1, "expected exactly one group, got {groups:?}");
    groups.pop().expect("should succeed")
}

/// Sorted UIDs of a set of entities — the expected `members` shape.
fn sorted_uids(entities: &[&Entity]) -> Vec<String> {
    let mut uids: Vec<String> = entities.iter().map(|e| e.uid.clone()).collect();
    uids.sort();
    uids
}

// ── Email: Gmail dot/＋tag equivalence ─────────────────────────────────────────

#[test]
fn two_gmail_variants_group_on_canonical_mailbox() {
    // Dot-blindness + `+tag` + googlemail alias: both reach `john@gmail.com`.
    let a = ent(EntityKind::Email, "jo.hn@gmail.com");
    let b = ent(EntityKind::Email, "john+x@googlemail.com");
    // They are genuinely separate entities the exact matcher misses.
    assert_ne!(a.uid, b.uid);
    assert_ne!(a.value, b.value);

    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.kind, "email");
    assert_eq!(g.canonical, "john@gmail.com");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
    assert!(g.reason.contains("Gmail") || g.reason.contains("mailbox"));
}

#[test]
fn non_gmail_address_keeps_its_dots_so_dotted_pair_does_not_group() {
    // On a non-Gmail provider dots are SIGNIFICANT: `a.b@corp.com` and
    // `ab@corp.com` are different mailboxes and must NOT be merged.
    let a = ent(EntityKind::Email, "a.b@corp.com");
    let b = ent(EntityKind::Email, "ab@corp.com");
    assert!(suggest_merges(&[a, b]).is_empty());
}

#[test]
fn non_gmail_plus_tag_is_stripped_so_those_group() {
    // `+tag` IS stripped everywhere (widely-supported subaddressing), so two
    // non-Gmail addresses differing only by a tag DO group — dots stay intact.
    let a = ent(EntityKind::Email, "sales@corp.com");
    let b = ent(EntityKind::Email, "sales+promo@corp.com");
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.canonical, "sales@corp.com");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

// ── Phone: digit canonicalisation, conservatively ─────────────────────────────

#[test]
fn two_phone_formats_of_the_same_digits_group() {
    // The entity normaliser already digit-strips a phone (so two punctuation
    // variants of `0400111222` ALREADY share a UID — the exact matcher's job).
    // The presentation difference that SURVIVES normalisation as a distinct UID
    // is the leading `+` sigil, which the normaliser keeps: `+61 400 111 222`
    // and a scraped `61 400 111 222` are the same dialled digits, two UIDs. The
    // resolver reunites them on the digits-only canonical.
    let a = ent(EntityKind::Phone, "+61 400 111 222");
    let b = ent(EntityKind::Phone, "61 400 111 222");
    assert_ne!(a.uid, b.uid, "the + sigil keeps them on separate UIDs");
    assert_ne!(a.value, b.value);
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.kind, "phone");
    assert_eq!(g.canonical, "61400111222");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

#[test]
fn distinct_numbers_do_not_group() {
    // Different digits → different canonical → never grouped.
    let a = ent(EntityKind::Phone, "+61 400 111 222");
    let b = ent(EntityKind::Phone, "+61 400 999 888");
    assert!(suggest_merges(&[a, b]).is_empty());
}

#[test]
fn country_code_difference_is_not_inferred_away() {
    // Conservative: we do NOT reconcile the international `61…` form against the
    // national trunk-`0` `0…` form (that could merge distinct numbers across
    // countries). Their DIGITS differ, and we match on exact digit equality
    // only, so these stay separate.
    let a = ent(EntityKind::Phone, "+61 400 111 222"); // digits 61400111222
    let b = ent(EntityKind::Phone, "0400 111 222"); // digits 0400111222
    assert!(suggest_merges(&[a, b]).is_empty());
}

// ── Person: token-multiset equality, not partial overlap ──────────────────────

#[test]
fn name_comma_reversal_groups_to_natural_order() {
    // "Jane Citizen" and the surname-first "Citizen, Jane" are one person: the
    // comma folds to natural order, so both canonicalise to "jane citizen".
    let a = ent(EntityKind::Person, "Jane Citizen");
    let b = ent(EntityKind::Person, "Citizen, Jane");
    assert_ne!(a.uid, b.uid);
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.kind, "person");
    assert_eq!(g.canonical, "jane citizen");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

#[test]
fn shared_surname_only_does_not_group() {
    // A mere shared surname is NOT a same-entity signal — different given names
    // → no group (false-merge guard).
    let a = ent(EntityKind::Person, "Jane Citizen");
    let b = ent(EntityKind::Person, "John Citizen");
    assert!(suggest_merges(&[a, b]).is_empty());
}

#[test]
fn token_swapped_names_are_distinct_people() {
    // Regression: two DISTINCT people whose names are token permutations of each
    // other (no comma) must NOT merge. The previous implementation sorted the
    // whole token multiset, collapsing "Cameron Tyler" and "Tyler Cameron" to one
    // key and fusing them via an undamped SameAs. Only an explicit surname-first
    // comma justifies reordering.
    let a = ent(EntityKind::Person, "Cameron Tyler");
    let b = ent(EntityKind::Person, "Tyler Cameron");
    assert!(
        suggest_merges(&[a, b]).is_empty(),
        "token-swapped names without a comma are two different people"
    );
    // The same for another common given/given pair.
    let c = ent(EntityKind::Person, "Grace Kelly");
    let d = ent(EntityKind::Person, "Kelly Grace");
    assert!(suggest_merges(&[c, d]).is_empty());
}

#[test]
fn hyphenated_compound_surname_does_not_merge_with_an_unrelated_three_token_name() {
    // Regression: `canonical_name` used to route through `canonical_tokens`,
    // which treats EVERY non-alphanumeric character (including a hyphen) as a
    // token boundary. That folded the hyphenated compound surname "Smith-Jones"
    // into the SAME two tokens "smith" + "jones" a genuinely different name
    // ("Smith Jones", three whitespace tokens: a different given/middle name or
    // simply a different, unrelated person) also produces — both canonicalised
    // to "anna smith jones" and were fused into one full-trust SameAs edge.
    let a = ent(EntityKind::Person, "Anna Smith-Jones");
    let b = ent(EntityKind::Person, "Anna Smith Jones");
    assert!(
        suggest_merges(&[a, b]).is_empty(),
        "a hyphenated surname and an unrelated 3-token name must not merge"
    );
}

#[test]
fn hyphenated_surname_still_merges_across_comma_reversal() {
    // The fix above must not regress the legitimate equivalence this module
    // exists to catch: the comma surname-first form of the SAME hyphenated name
    // still canonicalises identically (the hyphen itself is preserved verbatim,
    // not treated as noise to fold away OR as a token boundary). Case/whitespace
    // variants are deliberately NOT exercised here — `identity_fold` already
    // folds those for `Person` at the UID layer, before this module ever runs,
    // so they would not be distinct entities to merge in the first place.
    let a = ent(EntityKind::Person, "Anna Smith-Jones");
    let b = ent(EntityKind::Person, "Smith-Jones, Anna");
    assert_ne!(a.uid, b.uid, "comma form is a distinct UID the resolver must unify");
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.canonical, "anna smith-jones");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

#[test]
fn apostrophe_surname_does_not_merge_with_an_unrelated_three_token_name() {
    // Same defect class and same fix, for an apostrophe rather than a hyphen —
    // common in Irish/Scottish/French-derived Australian surnames (O'Brien,
    // D'Souza). "O'Brien" must stay one token, not split into "o" + "brien".
    let a = ent(EntityKind::Person, "Mary O'Brien");
    let b = ent(EntityKind::Person, "Mary O Brien");
    assert!(
        suggest_merges(&[a, b]).is_empty(),
        "an apostrophe surname and an unrelated 3-token name must not merge"
    );
}

#[test]
fn comma_before_generational_suffix_still_canonicalises_with_natural_order() {
    // Regression: `canonical_name` used to treat ANY single comma as the
    // bibliographic surname-first marker, so "John Smith, Jr." reordered to
    // "Jr. John Smith" — while the equally-standard no-comma spelling
    // "John Smith Jr." kept natural order. The two canonicalised differently
    // and could never merge, permanently fragmenting one suffixed person's
    // corroboration whenever sources disagreed on the comma-before-suffix
    // convention. `is_generational_suffix_only` (mirroring name_intel's
    // GEN_SUFFIXES list) now excludes a suffix-only post-comma segment from
    // the surname-first reorder, so both spellings land on "john smith jr".
    let a = ent(EntityKind::Person, "John Smith, Jr.");
    let b = ent(EntityKind::Person, "John Smith Jr.");
    assert_ne!(a.uid, b.uid, "distinct raw spellings going in");
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.canonical, "john smith jr");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

#[test]
fn comma_before_a_real_given_name_still_reorders_as_surname_first() {
    // The fix above must not regress the ordinary surname-first case: a
    // post-comma segment that is a real given name (not a suffix) still
    // triggers the reorder.
    let a = ent(EntityKind::Person, "Smith, John");
    let b = ent(EntityKind::Person, "John Smith");
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.canonical, "john smith");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

// ── Username: formatting noise only ───────────────────────────────────────────

#[test]
fn username_canonicalises_case_and_whitespace() {
    // The entity normaliser lowercases+strips a leading `@`, so to get two
    // DISTINCT stored values we vary internal whitespace, which the resolver
    // still canonicalises away — unlike separator punctuation (see the
    // false-merge regression test below), a run of whitespace really is
    // formatting noise for a handle.
    let a = ent(EntityKind::Username, "Jordan  Avery");
    let b = ent(EntityKind::Username, "jordan avery");
    assert_ne!(a.value, b.value);
    let g = only_group(&[a.clone(), b.clone()]);
    assert_eq!(g.kind, "username");
    assert_eq!(g.canonical, "jordan avery");
    assert_eq!(g.members, sorted_uids(&[&a, &b]));
}

#[test]
fn username_separator_variants_do_not_merge() {
    // Regression: `canonical_handle` used to route through a tokeniser that
    // treated '.', '_' and '-' as interchangeable separators (the same
    // fixed defect class as the hyphenated-Person-name tests above), so
    // "jordan.avery" and "jordan_avery" canonicalised identically and were
    // fused into a full-trust SameAs relation edge on spelling coincidence
    // alone. No platform treats those as the same login — GitHub allows only
    // hyphens, Twitter/X only underscores, Instagram both dots and
    // underscores as DISTINCT characters — so two independently-registered
    // accounts must not be merged on separator choice.
    let a = ent(EntityKind::Username, "jordan.avery");
    let b = ent(EntityKind::Username, "jordan_avery");
    let c = ent(EntityKind::Username, "jordan-avery");
    assert!(
        suggest_merges(&[a, b, c]).is_empty(),
        "distinct separator characters must not merge two independently-registered handles"
    );
}

// ── No-duplicate / empty cases ────────────────────────────────────────────────

#[test]
fn singleton_yields_no_group() {
    // One entity (or several unrelated ones) → nothing to merge.
    let only = ent(EntityKind::Email, "solo@gmail.com");
    assert!(suggest_merges(&[only]).is_empty());

    let unrelated = [
        ent(EntityKind::Email, "alice@gmail.com"),
        ent(EntityKind::Phone, "0400 111 222"),
        ent(EntityKind::Person, "Bob Roberts"),
    ];
    assert!(suggest_merges(&unrelated).is_empty());
}

#[test]
fn empty_input_yields_empty_output() {
    assert!(suggest_merges(&[]).is_empty());
}

#[test]
fn already_exact_duplicates_are_not_resuggested() {
    // Two entities whose RAW values normalise to the SAME stored value share a
    // UID — the exact matcher already owns them, so this module suggests nothing
    // (the group needs ≥2 DISTINCT stored values, not just ≥2 entities).
    let a = ent(EntityKind::Email, "Same@Gmail.com");
    let b = ent(EntityKind::Email, "same@gmail.com");
    assert_eq!(a.uid, b.uid, "same canonical value → same UID");
    assert!(suggest_merges(&[a, b]).is_empty());
}

#[test]
fn different_kinds_with_same_canonical_do_not_cross_group() {
    // Grouping is strictly within a kind. A username and a person that happen to
    // share a canonical string are never merged together.
    let u_a = ent(EntityKind::Username, "Jane  Citizen");
    let u_b = ent(EntityKind::Username, "jane citizen");
    let p_a = ent(EntityKind::Person, "Jane Citizen");
    let p_b = ent(EntityKind::Person, "Citizen, Jane");
    let groups = suggest_merges(&[u_a, u_b, p_a, p_b]);
    assert_eq!(groups.len(), 2, "one username group, one person group");
    assert!(groups.iter().all(|g| g.members.len() == 2));
    let kinds: Vec<&str> = groups.iter().map(|g| g.kind.as_str()).collect();
    assert!(kinds.contains(&"username") && kinds.contains(&"person"));
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn output_is_deterministic_under_input_shuffling() {
    // A mixed corpus with two email dups, two phone dups and two name dups.
    let base = vec![
        ent(EntityKind::Email, "jo.hn@gmail.com"),
        ent(EntityKind::Email, "john+x@googlemail.com"),
        ent(EntityKind::Phone, "+61 400 111 222"),
        ent(EntityKind::Phone, "61 400 111 222"),
        ent(EntityKind::Person, "Jane Citizen"),
        ent(EntityKind::Person, "Citizen, Jane"),
        ent(EntityKind::Email, "noise@example.org"),
    ];
    let expected = suggest_merges(&base);
    assert_eq!(expected.len(), 3);

    // Every rotation of the input must yield byte-identical output (members
    // sorted by UID, groups sorted by (kind, canonical)).
    for shift in 1..base.len() {
        let mut shuffled = base.clone();
        shuffled.rotate_left(shift);
        assert_eq!(
            suggest_merges(&shuffled),
            expected,
            "output changed under rotation by {shift}"
        );
    }

    // A full reversal too, as an independent permutation.
    let mut reversed = base.clone();
    reversed.reverse();
    assert_eq!(suggest_merges(&reversed), expected);

    // Groups are sorted by (kind, canonical): email < person < phone.
    let kinds: Vec<&str> = expected.iter().map(|g| g.kind.as_str()).collect();
    assert_eq!(kinds, vec!["email", "person", "phone"]);
}

#[test]
fn three_way_gmail_group_lists_all_members_sorted() {
    // Three spellings of one mailbox collapse into a single 3-member group.
    let a = ent(EntityKind::Email, "j.o.h.n@gmail.com");
    let b = ent(EntityKind::Email, "john+promo@gmail.com");
    let c = ent(EntityKind::Email, "JOHN@googlemail.com");
    let g = only_group(&[a.clone(), b.clone(), c.clone()]);
    assert_eq!(g.canonical, "john@gmail.com");
    assert_eq!(g.members, sorted_uids(&[&a, &b, &c]));
    // Members are strictly ascending (sorted, de-duplicated).
    assert!(g.members.windows(2).all(|w| w[0] < w[1]));
}
