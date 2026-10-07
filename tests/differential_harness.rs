use huntsman_recon::differential::{
    AllowedDifference, DifferenceKind, DifferentialEntity, DifferentialManifest, compare_legacy,
    verify_sha256,
};
use huntsman_recon::entity::EntityKind;

#[test]
fn public_differential_harness_enforces_no_legacy_regressions() {
    let expected = vec![
        DifferentialEntity::new(EntityKind::Email, "ada@example.org")
            .with_source("legacy_source")
            .with_dataset("Example"),
        DifferentialEntity::new(EntityKind::Username, "adalovelace"),
    ];
    let observed = vec![
        DifferentialEntity::new(EntityKind::Email, "ada@example.org")
            .with_source("other_source")
            .with_dataset("Example"),
        DifferentialEntity::new(EntityKind::Username, "ada"),
        DifferentialEntity::new(EntityKind::Domain, "example.org"),
    ];

    let differences = compare_legacy(&expected, &observed, &[]);
    assert_eq!(differences.len(), 2);
    assert!(
        differences
            .iter()
            .any(|difference| difference.kind == DifferenceKind::Misattributed)
    );
    assert!(
        differences
            .iter()
            .any(|difference| difference.kind == DifferenceKind::Truncated)
    );
}

#[test]
fn reviewed_differences_are_exact_and_manifest_hashes_are_pinned() {
    let expected = vec![DifferentialEntity::new(EntityKind::Username, "adalovelace")];
    let observed = vec![DifferentialEntity::new(EntityKind::Username, "ada")];
    let allowed = vec![AllowedDifference {
        kind: DifferenceKind::Truncated,
        expected: expected[0].clone(),
        observed: Some(observed[0].clone()),
        reason: "legacy oracle intentionally truncates this recorded fixture".into(),
    }];

    assert!(compare_legacy(&expected, &observed, &allowed).is_empty());

    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let json = format!(
        r#"{{
          "oracle_commit":"7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58",
          "capability":"fixture",
          "input_sha256":"{abc}",
          "golden_sha256":"{abc}",
          "allowed_differences":[]
        }}"#
    );
    let manifest: DifferentialManifest = serde_json::from_str(&json).unwrap();
    assert!(manifest.is_well_formed());
    assert!(verify_sha256(b"abc", &manifest.input_sha256).is_ok());
    assert!(verify_sha256(b"abd", &manifest.input_sha256).is_err());
}
