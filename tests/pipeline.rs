use huntsman_recon::entity::EntityKind;
use huntsman_recon::pipeline::{
    InvestigationInput, InvestigationMode, NormalizedSeed, PipelineLimits, SeedRejection,
    normalize_seeds,
};

fn input(seeds: &[&str]) -> InvestigationInput {
    InvestigationInput {
        scan_id: "scan-test".to_string(),
        seeds: seeds.iter().map(|s| (*s).to_string()).collect(),
        mode: InvestigationMode::Offline,
    }
}

#[test]
fn normalize_seeds_is_deterministic_and_bounded() {
    let limits = PipelineLimits {
        max_targets: 2,
        ..PipelineLimits::default()
    };
    let result = normalize_seeds(
        &input(&["Example.COM", "ada@example.com", "8.8.8.8"]),
        &limits,
    );
    assert_eq!(result.accepted.len(), 2);
    assert!(result.truncated);
    assert_eq!(result.accepted[0].kind, EntityKind::Email);
    assert_eq!(result.accepted[0].value, "ada@example.com");
    assert_eq!(result.accepted[1].kind, EntityKind::Domain);
    assert_eq!(result.accepted[1].value, "example.com");
}

#[test]
fn malformed_and_empty_seeds_are_explicit_rejections() {
    let result = normalize_seeds(
        &input(&["", "   ", "not-a-supported-single-token"]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted, Vec::<NormalizedSeed>::new());
    assert_eq!(result.rejected.len(), 3);
    assert!(matches!(&result.rejected[0].1, SeedRejection::Empty));
    assert!(matches!(&result.rejected[1].1, SeedRejection::Empty));
    assert!(matches!(&result.rejected[2].1, SeedRejection::Unsupported));
}

#[test]
fn unicode_confusable_or_whitespace_only_seed_never_panics() {
    let result = normalize_seeds(
        &input(&["\u{2003}\u{2003}", "ｅxample.com", "@аda"]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted.len() + result.rejected.len(), 3);
}

#[test]
fn duplicate_canonical_seeds_are_deduplicated() {
    let result = normalize_seeds(
        &input(&[
            "Example.COM",
            "example.com.",
            "ADA@EXAMPLE.COM",
            "ada@example.com",
        ]),
        &PipelineLimits::default(),
    );
    assert_eq!(result.accepted.len(), 2);
    assert_eq!(result.accepted[0].kind, EntityKind::Email);
    assert_eq!(result.accepted[0].value, "ada@example.com");
    assert_eq!(result.accepted[1].kind, EntityKind::Domain);
    assert_eq!(result.accepted[1].value, "example.com");
    assert!(!result.truncated);
}
