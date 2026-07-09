// Unit tests for `core::coref` — cross-identifier co-reference scoring. Included
// into the module via `include!` so tests reach private items directly.

use super::*;
use crate::core::entity::{Entity, EntityKind, Evidence};

/// A username and the email whose local part canonicalises to the same handle
/// must be a strong co-reference (handle-equivalence), and the candidate must be
/// oriented and labelled.
#[test]
fn handle_equivalence_links_a_username_to_a_matching_email() {
    let user = Entity::new(EntityKind::Username, "jsmith", 0.7, "s");
    let email = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.7, "s");
    let out = resolve_coreferences(&[user, email], DEFAULT_MIN_SCORE, 50);
    assert_eq!(out.len(), 1, "the username and email co-refer");
    let c = &out[0];
    assert!(c.signals.contains(&"handle-equivalence"));
    assert!(c.score >= 0.80, "exact handle match is strong, got {}", c.score);
    assert!(c.uid_a <= c.uid_b, "endpoints are oriented by UID");
}

/// A Person's full name embedded in another selector's handle fires the
/// name-token tier (not the weaker substring tier).
#[test]
fn name_tokens_inside_a_handle_link_a_person() {
    let person = Entity::new(EntityKind::Person, "John Smith", 0.7, "s");
    let user = Entity::new(EntityKind::Username, "johnsmith_au", 0.7, "s");
    let out = resolve_coreferences(&[person, user], DEFAULT_MIN_SCORE, 50);
    assert_eq!(out.len(), 1);
    assert!(out[0].signals.contains(&"name-token-match"));
    assert!(out[0].score >= 0.62);
}

/// A single shared first-name token must NOT, alone, link two people — the
/// name-token tier needs ≥2 tokens, so namesakes don't fuse.
#[test]
fn a_single_shared_first_name_does_not_link_strangers() {
    let a = Entity::new(EntityKind::Person, "John Smith", 0.7, "s");
    let b = Entity::new(EntityKind::Person, "John Citizen", 0.7, "s");
    // No shared source, different surnames → below threshold, nothing emitted.
    let out = resolve_coreferences(&[a, b], DEFAULT_MIN_SCORE, 50);
    assert!(
        out.is_empty(),
        "two unrelated Johns must not be co-referenced: {out:?}"
    );
}

/// Independent signals compound under noisy-OR: handle-equivalence plus a shared
/// source scores strictly higher than handle-equivalence alone.
#[test]
fn independent_signals_compound() {
    // Pair 1: handle-equivalence only.
    let u1 = Entity::new(EntityKind::Username, "jsmith", 0.7, "s");
    let e1 = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.7, "s");
    let plain = resolve_coreferences(&[u1, e1], DEFAULT_MIN_SCORE, 50)[0].score;

    // Pair 2: same handle-equivalence AND a shared corroborating source.
    let mut u2 = Entity::new(EntityKind::Username, "jsmith", 0.7, "s");
    u2.add_evidence(Evidence::new("oathnet_pro", "breach record"));
    let mut e2 = Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.7, "s");
    e2.add_evidence(Evidence::new("oathnet_pro", "breach record"));
    let corro_v = resolve_coreferences(&[u2, e2], DEFAULT_MIN_SCORE, 50);
    let corro = &corro_v[0];

    assert!(
        corro.score > plain,
        "a shared source must lift the score: {} !> {}",
        corro.score,
        plain
    );
    assert!(corro.signals.contains(&"shared-source"));
    assert!(corro.signals.contains(&"handle-equivalence"));
}

/// A single shared source is deliberately sub-threshold on its own — one common
/// crawl source is weak co-occurrence, not a co-reference.
#[test]
fn a_single_shared_source_alone_is_below_threshold() {
    let mut a = Entity::new(EntityKind::Email, "alice@example.com", 0.7, "s");
    a.add_evidence(Evidence::new("search_engines", "snippet"));
    let mut b = Entity::new(EntityKind::Phone, "+61400111222", 0.7, "s");
    b.add_evidence(Evidence::new("search_engines", "snippet"));
    let out = resolve_coreferences(&[a, b], DEFAULT_MIN_SCORE, 50);
    assert!(
        out.is_empty(),
        "one shared generic source must not co-refer unrelated selectors: {out:?}"
    );
    // But with a low floor it surfaces as weak co-occurrence (and is honest about it).
    let weak = resolve_coreferences(
        &[
            {
                let mut a = Entity::new(EntityKind::Email, "alice@example.com", 0.7, "s");
                a.add_evidence(Evidence::new("search_engines", "snippet"));
                a
            },
            {
                let mut b = Entity::new(EntityKind::Phone, "+61400111222", 0.7, "s");
                b.add_evidence(Evidence::new("search_engines", "snippet"));
                b
            },
        ],
        0.0,
        50,
    );
    assert_eq!(weak.len(), 1);
    assert!(weak[0].score < DEFAULT_MIN_SCORE);
    assert_eq!(weak[0].signals, vec!["shared-source"]);
}

/// Multiple shared corroborating sources compound into a real tie even with no
/// string similarity — the breach-row linkage case (an email and a phone seen
/// together across several independent breaches).
#[test]
fn multiple_shared_sources_link_dissimilar_selectors() {
    let mut email = Entity::new(EntityKind::Email, "victim@example.com", 0.7, "s");
    let mut phone = Entity::new(EntityKind::Phone, "+61400999888", 0.7, "s");
    for src in ["oathnet_pro", "dehashed", "snusbase"] {
        email.add_evidence(Evidence::new(src, "breach record"));
        phone.add_evidence(Evidence::new(src, "breach record"));
    }
    let out = resolve_coreferences(&[email, phone], DEFAULT_MIN_SCORE, 50);
    assert_eq!(out.len(), 1, "3 shared breaches co-refer email↔phone");
    assert!(out[0].score >= DEFAULT_MIN_SCORE);
    assert_eq!(out[0].signals, vec!["shared-source"]);
}

/// Non-identity kinds (a domain, an address, a coordinate) are never endpoints,
/// and the output is deterministic regardless of input order.
#[test]
fn only_identity_kinds_pair_and_output_is_order_independent() {
    let mk = || {
        vec![
            Entity::new(EntityKind::Username, "jsmith", 0.7, "s"),
            Entity::new(EntityKind::Email, "jsmith@gmail.com", 0.7, "s"),
            Entity::new(EntityKind::Domain, "jsmith.com", 0.7, "s"),
            Entity::new(EntityKind::Address, "1 King St, Sydney NSW 2000", 0.7, "s"),
        ]
    };
    let forward = resolve_coreferences(&mk(), DEFAULT_MIN_SCORE, 50);
    let mut rev = mk();
    rev.reverse();
    let backward = resolve_coreferences(&rev, DEFAULT_MIN_SCORE, 50);
    assert_eq!(forward, backward, "output must be input-order independent");
    // The only identity pair is username↔email; the domain/address never pair.
    assert_eq!(forward.len(), 1);
    assert!(matches!(forward[0].kind_a, EntityKind::Username | EntityKind::Email));
    assert!(matches!(forward[0].kind_b, EntityKind::Username | EntityKind::Email));
}

/// `limit` caps the result to the strongest candidates.
#[test]
fn limit_caps_the_strongest_candidates() {
    // All three canonicalise to "johnsmith", so all three pairs are handle-equivalent.
    let ents = vec![
        Entity::new(EntityKind::Username, "johnsmith", 0.7, "s"),
        Entity::new(EntityKind::Email, "johnsmith@gmail.com", 0.7, "s"),
        Entity::new(EntityKind::Person, "John Smith", 0.7, "s"),
    ];
    let all = resolve_coreferences(&ents, DEFAULT_MIN_SCORE, 50);
    assert!(all.len() >= 2, "several pairs co-refer among johnsmith/John Smith");
    let one = resolve_coreferences(&ents, DEFAULT_MIN_SCORE, 1);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0].score, all[0].score, "the kept one is the strongest");
}

/// Two emails that share only a LOCAL-PART but sit on different domains are NOT
/// the same mailbox — `john@gmail.com` vs `john@acme-corp.com`. They must not
/// reach the 0.80 handle-equivalence tier (which is promoted straight into an
/// `AliasOf` graph edge), so no promotable co-reference is emitted for the pair.
#[test]
fn different_domain_emails_do_not_handle_equivalence_merge() {
    let a = Entity::new(EntityKind::Email, "john@gmail.com", 0.7, "s");
    let b = Entity::new(EntityKind::Email, "john@acme-corp.com", 0.7, "s");
    let out = resolve_coreferences(&[a, b], DEFAULT_MIN_SCORE, 50);
    assert!(
        out.iter().all(|c| !c.signals.contains(&"handle-equivalence")),
        "different-domain emails must not fire handle-equivalence"
    );
    // And nothing reaches the 0.80 promotion threshold from the local-part alone.
    assert!(
        out.iter().all(|c| c.score < 0.80),
        "a bare local-part collision must not reach the AliasOf promotion floor"
    );
}

/// Role/generic local parts are the worst case for the domain-blind bug —
/// `info@a.com` and `info@b.com` are unrelated companies. They must not merge.
#[test]
fn role_local_parts_across_domains_do_not_merge() {
    let a = Entity::new(EntityKind::Email, "info@alpha.com", 0.7, "s");
    let b = Entity::new(EntityKind::Email, "info@beta.com", 0.7, "s");
    let out = resolve_coreferences(&[a, b], 0.80, 50);
    assert!(out.is_empty(), "role emails on different domains must not co-refer at promotion score");
}

/// The tightening is domain-aware, not email-hostile: the SAME gmail mailbox
/// spelled with dot-blindness on the `gmail.com`/`googlemail.com` alias pair
/// still canonicalises together (`j.o.h.n@gmail.com` ≡ `john@googlemail.com`)
/// and keeps firing handle-equivalence — the domain difference is folded away by
/// `canonical_email`, exactly the case a naive domain-equality check would break.
#[test]
fn same_gmail_mailbox_spellings_still_merge() {
    let a = Entity::new(EntityKind::Email, "j.o.h.n@gmail.com", 0.7, "s");
    let b = Entity::new(EntityKind::Email, "john@googlemail.com", 0.7, "s");
    let out = resolve_coreferences(&[a, b], DEFAULT_MIN_SCORE, 50);
    assert_eq!(out.len(), 1, "same underlying gmail mailbox still co-refers");
    assert!(out[0].signals.contains(&"handle-equivalence"));
    assert!(out[0].score >= 0.80);
}

/// The cross-kind local-part bridge is preserved: an email's local part still
/// links to a matching username regardless of the email's domain (this is the
/// intended alias signal, e.g. AU-076).
#[test]
fn cross_kind_localpart_bridge_survives_the_tightening() {
    let email = Entity::new(EntityKind::Email, "jsmith@acme-corp.com", 0.7, "s");
    let user = Entity::new(EntityKind::Username, "jsmith", 0.7, "s");
    let out = resolve_coreferences(&[email, user], DEFAULT_MIN_SCORE, 50);
    assert_eq!(out.len(), 1, "email local ↔ username bridge must still fire");
    assert!(out[0].signals.contains(&"handle-equivalence"));
    assert!(out[0].score >= 0.80);
}

/// `noisy_or` is order-independent, monotone, and bounded in `0.0..=1.0`.
#[test]
fn noisy_or_is_bounded_and_order_independent() {
    assert!((noisy_or([]) - 0.0).abs() < 1e-12);
    let a = noisy_or([0.5, 0.5]);
    let b = noisy_or([0.5, 0.5, 0.0]);
    assert!((a - 0.75).abs() < 1e-12, "two 0.5s → 0.75, got {a}");
    assert!((a - b).abs() < 1e-12, "a zero-weight signal changes nothing");
    assert!(noisy_or([0.9, 0.9, 0.9]) <= 1.0);
    // Adding a signal never lowers the score (monotonic).
    assert!(noisy_or([0.5, 0.3]) >= noisy_or([0.5]));
}
