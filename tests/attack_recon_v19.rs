use std::collections::{BTreeMap, BTreeSet};

use huntsman_recon::attack;

#[test]
fn reconnaissance_v19_2_has_twelve_families_and_thirty_seven_leaves() {
    assert_eq!(attack::RECONNAISSANCE_VERSION, "19.2");

    let all = attack::reconnaissance();
    assert_eq!(all.len(), 46, "TA0043 v19.2 has 12 parents + 34 sub-techniques");
    assert!(all.iter().any(|item| item.id == "T1681"));
    assert!(all.iter().any(|item| item.id == "T1682"));

    let families = attack::reconnaissance_families();
    assert_eq!(families.len(), 12);
    assert!(families.iter().all(|item| !item.is_subtechnique));

    let leaves = attack::reconnaissance_leaves();
    assert_eq!(leaves.len(), 37, "34 sub-techniques + 3 standalone techniques");
    let leaf_ids: BTreeSet<_> = leaves.iter().map(|item| item.id).collect();
    for id in ["T1594", "T1681", "T1682"] {
        assert!(leaf_ids.contains(id), "standalone leaf {id} missing");
    }
    for id in ["T1589", "T1590", "T1591", "T1592", "T1593", "T1595", "T1596", "T1597", "T1598"] {
        assert!(!leaf_ids.contains(id), "parent {id} must be a roll-up, not a scored leaf");
    }
}

#[test]
fn deliberate_product_exclusions_are_not_reported_as_engineering_gaps() {
    let excluded: BTreeSet<_> = attack::intentional_exclusions()
        .iter()
        .map(|item| item.id)
        .collect();
    assert_eq!(
        excluded,
        BTreeSet::from(["T1598.001", "T1598.002", "T1598.003", "T1598.004", "T1682"])
    );

    let cov = attack::coverage(&BTreeMap::new());
    assert!(cov.covered.is_empty());
    assert_eq!(cov.intentional_exclusions.len(), 5);
    assert_eq!(cov.uncovered.len(), 32);
    assert_eq!(cov.catalog_leaf_count, 37);
    assert_eq!(cov.applicable_leaf_count, 32);
    assert_eq!(cov.coverage_fraction, 0.0);
    assert!(cov.uncovered.iter().any(|item| item.id == "T1681"));
    assert!(!cov.uncovered.iter().any(|item| item.id.starts_with("T1598.")));
    assert!(!cov.uncovered.iter().any(|item| item.id == "T1682"));
}

#[test]
fn parent_evidence_rolls_up_but_does_not_score_as_a_leaf() {
    let exercised = BTreeMap::from([
        ("T1590".to_owned(), 3_usize),
        ("T1596.002".to_owned(), 5_usize),
    ]);
    let cov = attack::coverage(&exercised);
    assert_eq!(cov.covered.len(), 1);
    assert_eq!(cov.covered[0].technique.id, "T1596.002");
    assert_eq!(cov.coverage_fraction, 1.0 / 32.0);

    let network = cov
        .family_rollups
        .iter()
        .find(|row| row.technique.id == "T1590")
        .expect("T1590 family");
    assert_eq!(network.direct_count, 3);
    assert_eq!(network.covered_leaf_count, 0);

    let technical = cov
        .family_rollups
        .iter()
        .find(|row| row.technique.id == "T1596")
        .expect("T1596 family");
    assert_eq!(technical.direct_count, 0);
    assert_eq!(technical.covered_leaf_count, 1);
}

#[test]
fn ontology_mappings_do_not_manufacture_structural_capability() {
    let cov = attack::static_reconnaissance_coverage(std::iter::empty::<&str>());
    assert!(cov.covered.is_empty(), "metadata-only mappings are not implementation evidence");
    assert_eq!(cov.uncovered.len(), 32);
    assert_eq!(cov.intentional_exclusions.len(), 5);
}
