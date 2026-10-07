use huntsman_recon::differential::{
    DifferentialEntity, DifferentialManifest, compare_legacy, snapshot_entities,
};
use huntsman_recon::phone_cli::{self, PhoneRun};
use serde::Deserialize;

const ORACLE: &str = "7dca720b5bf51f20b4e27d5ca29cc570ec2f9a58";
const CAPABILITY: &str = "phone_offline";
const INPUT: &[u8] = include_bytes!("fixtures/differential/phone_input.json");
const GOLDEN: &[u8] = include_bytes!("fixtures/differential/phone_golden_7dca720.json");
const MANIFEST: &[u8] = include_bytes!("fixtures/differential/phone_manifest.json");

#[derive(Debug, Deserialize)]
struct GoldenCase {
    input: String,
    expected: Vec<DifferentialEntity>,
}

#[test]
fn phone_offline_matches_recorded_7dca720_golden_without_legacy_regressions() {
    let manifest: DifferentialManifest = serde_json::from_slice(MANIFEST).expect("manifest JSON");
    manifest
        .validate_artifacts(CAPABILITY, ORACLE, INPUT, GOLDEN)
        .expect("pinned differential artifacts");

    let inputs: Vec<String> = serde_json::from_slice(INPUT).expect("input JSON");
    let golden: Vec<GoldenCase> = serde_json::from_slice(GOLDEN).expect("golden JSON");
    assert_eq!(inputs.len(), golden.len(), "fixture case count changed");

    for (input, case) in inputs.iter().zip(&golden) {
        assert_eq!(input, &case.input, "input/golden ordering drifted");
        let report = match phone_cli::run(input, 1) {
            PhoneRun::Printed { report, .. } => report,
            PhoneRun::Failed(message) => panic!("phone {input:?} failed: {message}"),
        };
        let observed = snapshot_entities(&report.entities);
        let regressions = compare_legacy(
            &case.expected,
            &observed,
            &manifest.allowed_differences,
        );
        assert!(
            regressions.is_empty(),
            "phone {input:?} regressed from {ORACLE}: {regressions:#?}"
        );
    }
}

#[test]
fn phone_golden_is_attributed_to_legacy_phone_modules() {
    let golden: Vec<GoldenCase> = serde_json::from_slice(GOLDEN).expect("golden JSON");
    for case in golden {
        assert!(!case.expected.is_empty(), "{:?} has no oracle output", case.input);
        for entity in case.expected {
            assert_eq!(entity.kind.as_str(), "phone");
            assert!(
                matches!(entity.source.as_deref(), Some("phone_intl" | "phone_au")),
                "unexpected legacy source for {:?}: {:?}",
                case.input,
                entity.source
            );
        }
    }
}
