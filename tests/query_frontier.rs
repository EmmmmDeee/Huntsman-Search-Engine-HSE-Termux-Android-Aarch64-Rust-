use huntsman_recon::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use huntsman_recon::query_frontier::{ActionKind, rank_entity_frontier};

fn verified(kind: EntityKind, value: &str, source: &str) -> Entity {
    Entity::builder(kind, value, 0.98, "scan")
        .evidence(Evidence::new(
            EvidenceProvenance::new(source),
            "direct observation",
        ))
        .build()
}

#[test]
fn expands_only_verified_entities_into_ranked_next_actions() {
    let email = verified(EntityKind::Email, "Alice@Example.com", "directory");
    let weak = Entity::new(EntityKind::Username, "maybe-alice", 0.2, "scan");

    let frontier = rank_entity_frontier(&[weak, email]);

    assert_ne!(frontier.len(), 0);
    assert!(
        frontier
            .iter()
            .all(|candidate| candidate.basis_classification == "verified")
    );
    assert!(frontier.iter().any(|candidate| {
        candidate.kind == ActionKind::ExactSearch && candidate.query == "alice@example.com"
    }));
    assert!(frontier.iter().any(|candidate| {
        candidate.kind == ActionKind::DomainLookup && candidate.query == "example.com"
    }));
    assert!(
        frontier
            .iter()
            .all(|candidate| !candidate.query.contains("maybe-alice"))
    );
}

#[test]
fn exact_discriminating_identifier_beats_broader_derived_pivot() {
    let email = verified(EntityKind::Email, "alice@example.com", "directory");
    let frontier = rank_entity_frontier(&[email]);

    let exact = frontier
        .iter()
        .find(|candidate| candidate.kind == ActionKind::ExactSearch)
        .expect("exact email query");
    let domain = frontier
        .iter()
        .find(|candidate| candidate.kind == ActionKind::DomainLookup)
        .expect("derived domain query");

    assert!(exact.score > domain.score);
    assert!(exact.discriminative_power > domain.discriminative_power);
    assert!(domain.derived);
}

#[test]
fn duplicate_entities_do_not_multiply_the_same_query() {
    let a = verified(EntityKind::Email, "alice@example.com", "directory-a");
    let b = verified(EntityKind::Email, "ALICE@example.com", "directory-b");

    let frontier = rank_entity_frontier(&[a, b]);
    let exact: Vec<_> = frontier
        .iter()
        .filter(|candidate| {
            candidate.kind == ActionKind::ExactSearch && candidate.query == "alice@example.com"
        })
        .collect();

    assert_eq!(exact.len(), 1);
    assert_eq!(
        exact[0].basis_uids.len(),
        1,
        "same canonical entity is one evidentiary basis"
    );
}

#[test]
fn frontier_is_deterministic_across_input_order() {
    let email = verified(EntityKind::Email, "alice@example.com", "directory");
    let domain = verified(EntityKind::Domain, "example.net", "dns");

    let forward = rank_entity_frontier(&[email.clone(), domain.clone()]);
    let reverse = rank_entity_frontier(&[domain, email]);
    assert_eq!(forward, reverse);
}

#[test]
fn credentials_and_api_keys_never_become_queries() {
    let credential = verified(EntityKind::Credential, "super-secret", "operator");
    let api_key = verified(EntityKind::ApiKey, "deadbeef", "operator");
    assert_eq!(rank_entity_frontier(&[credential, api_key]), Vec::new());
}
