use super::{PROVIDERS, generate};
use crate::core::scan::{Target, TargetKind};

#[test]
fn email_pack_covers_every_provider_in_rank_order_under_one_parent() {
    let t = Target::new(TargetKind::Email, "alice@example.com");
    let pack = generate(&t, 1_700_000_000);
    // Every provider accepts Email, so all six appear.
    assert_eq!(pack.len(), PROVIDERS.len());
    // Ranks are ascending and stable (1..=N in manual-pack order).
    let ranks: Vec<u32> = pack.iter().map(|q| q.rank).collect();
    assert_eq!(ranks, vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(pack[0].provider, "Intelligence X");
    // One shared parent_query_id groups the whole pack under the seed.
    let parent = &pack[0].parent_query_id;
    assert!(parent.starts_with("qp-"));
    assert!(pack.iter().all(|q| &q.parent_query_id == parent));
    // Every entry carries the operator's own value, the kind, a grounded
    // entrypoint, and the stamped time.
    for q in &pack {
        assert_eq!(q.query, "alice@example.com");
        assert_eq!(q.query_type, "email");
        assert!(!q.manual_entrypoint.is_empty());
        assert_eq!(q.generated_at, 1_700_000_000);
    }
}

#[test]
fn parent_query_id_is_stable_and_target_specific() {
    let a = generate(&Target::new(TargetKind::Email, "alice@example.com"), 1);
    let b = generate(&Target::new(TargetKind::Email, "alice@example.com"), 2);
    let c = generate(&Target::new(TargetKind::Email, "bob@example.com"), 1);
    // Same target → same parent id regardless of timestamp; different target →
    // different id, so packs never cross-link.
    assert_eq!(a[0].parent_query_id, b[0].parent_query_id);
    assert_ne!(a[0].parent_query_id, c[0].parent_query_id);
}

#[test]
fn narrow_email_only_providers_are_dropped_for_a_username() {
    // XposedOrNot and HIBP accept only email/domain, so a username pack omits
    // them rather than inventing an unsupported query.
    let pack = generate(&Target::new(TargetKind::Username, "kylo4kylo"), 0);
    let names: Vec<&str> = pack.iter().map(|q| q.provider).collect();
    assert!(names.contains(&"OathNet"));
    assert!(names.contains(&"Intelligence X"));
    assert!(!names.contains(&"XposedOrNot"));
    assert!(!names.contains(&"Have I Been Pwned"));
}

#[test]
fn a_kind_no_manual_provider_accepts_yields_an_empty_pack() {
    // A coordinate is not an exposure selector for any manual breach provider —
    // emit nothing rather than a meaningless query.
    let pack = generate(&Target::new(TargetKind::Coordinates, "-27.47,153.02"), 0);
    assert!(pack.is_empty());
}

#[test]
fn empty_value_yields_an_empty_pack() {
    let pack = generate(&Target::new(TargetKind::Email, "   "), 0);
    assert!(pack.is_empty());
}

#[test]
fn gateway_and_high_trust_caveats_are_carried_to_the_operator() {
    let pack = generate(&Target::new(TargetKind::Email, "alice@example.com"), 0);
    let stolen_tax = pack.iter().find(|q| q.provider == "Stolen.tax").unwrap();
    assert!(
        stolen_tax
            .expected_result_class
            .to_ascii_lowercase()
            .contains("gateway"),
        "a multi-source gateway must be flagged as non-independent for the operator"
    );
    let hibp = pack
        .iter()
        .find(|q| q.provider == "Have I Been Pwned")
        .unwrap();
    assert!(
        hibp.expected_result_class
            .to_ascii_lowercase()
            .contains("miss"),
        "HIBP's result class must warn that a miss is not proof of no exposure"
    );
}

#[test]
fn provider_ranks_are_unique_and_dense() {
    // Stable, unique ranks 1..=N — no two providers share a manual-pack rank.
    let mut ranks: Vec<u32> = PROVIDERS.iter().map(|p| p.rank).collect();
    ranks.sort_unstable();
    let expected: Vec<u32> = (1..=PROVIDERS.len() as u32).collect();
    assert_eq!(ranks, expected);
}
