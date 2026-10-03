use std::collections::BTreeSet;

use huntsman_recon::intelligence::EvidenceId;
use huntsman_recon::proof::{
    AssumptionId, DependencyDomainId, DerivationId, MinimalProofEnvironment, derive_environment,
    minimalize_environments,
};

fn set<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn env(assertions: &[&str], roots: &[&str]) -> MinimalProofEnvironment {
    MinimalProofEnvironment {
        assertions: set(assertions.iter().copied().map(EvidenceId::from)),
        roots: set(roots.iter().map(|value| (*value).to_owned())),
        dependencies: BTreeSet::new(),
        derivations: BTreeSet::new(),
        assumptions: BTreeSet::new(),
    }
}

#[test]
fn duplicate_and_superset_environments_collapse_to_minimal_antichain() {
    let minimal = env(&["a"], &["root-a"]);
    let mut superset = minimal.clone();
    superset.assertions.insert(EvidenceId::from("b"));
    superset.roots.insert("root-b".into());
    superset
        .dependencies
        .insert(DependencyDomainId::from("shared-parser"));

    let result = minimalize_environments(vec![superset, minimal.clone(), minimal.clone()], 8, 16);

    assert!(!result.incomplete);
    assert_eq!(result.environments, vec![minimal]);
}

#[test]
fn result_order_is_deterministic_independent_of_input_order() {
    let a = env(&["a"], &["root-a"]);
    let b = env(&["b"], &["root-b"]);

    let left = minimalize_environments(vec![b.clone(), a.clone()], 8, 16);
    let right = minimalize_environments(vec![a.clone(), b.clone()], 8, 16);

    assert_eq!(left, right);
    assert_eq!(left.environments, vec![a, b]);
}

#[test]
fn derived_environment_inherits_roots_and_cannot_manufacture_new_witnesses() {
    let mut left = env(&["a"], &["root-a"]);
    left.assumptions.insert(AssumptionId::from("same-subject"));
    let mut right = env(&["b"], &["root-b"]);
    right
        .dependencies
        .insert(DependencyDomainId::from("resolver-v1"));

    let derived = derive_environment(&[left, right], DerivationId::from("join-v1"));

    assert_eq!(
        derived.roots,
        set(["root-a".to_owned(), "root-b".to_owned()])
    );
    assert_eq!(derived.assertions.len(), 2);
    assert!(
        derived
            .assumptions
            .contains(&AssumptionId::from("same-subject"))
    );
    assert!(
        derived
            .dependencies
            .contains(&DependencyDomainId::from("resolver-v1"))
    );
    assert_eq!(derived.derivations, set([DerivationId::from("join-v1")]));
}

#[test]
fn bounds_mark_the_result_incomplete_instead_of_silently_strengthening_it() {
    let too_large = env(&["a", "b", "c"], &["root-a"]);
    let a = env(&["a"], &["root-a"]);
    let b = env(&["b"], &["root-b"]);

    let result = minimalize_environments(vec![too_large, b, a.clone()], 1, 2);

    assert!(result.incomplete);
    assert_eq!(result.environments, vec![a]);
}
