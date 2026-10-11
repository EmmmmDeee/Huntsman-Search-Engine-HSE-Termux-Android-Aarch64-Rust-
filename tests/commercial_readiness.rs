use std::collections::BTreeSet;
use std::path::PathBuf;

use huntsman_recon::commercial_readiness::{benchmarks, manifest, readiness_markdown};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn declared_implementation_and_proof_paths_exist() {
    let manifest = manifest().expect("capability manifest must validate");

    for capability in manifest.capabilities {
        for path in capability
            .implementation
            .iter()
            .chain(capability.proof.iter())
        {
            assert!(
                root().join(path).is_file(),
                "{} references missing {}",
                capability.id,
                path
            );
        }
    }
}

#[test]
fn benchmark_receipts_reference_known_capabilities() {
    let manifest = manifest().expect("capability manifest must validate");
    let benchmarks = benchmarks().expect("benchmark manifest must validate");
    let ids: BTreeSet<_> = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.as_str())
        .collect();

    for receipt in benchmarks.benchmarks {
        assert!(
            ids.contains(receipt.capability.as_str()),
            "benchmark {} references unknown capability {}",
            receipt.id,
            receipt.capability
        );
    }
}

#[test]
fn generated_report_is_current() {
    let expected = readiness_markdown().expect("report generation must succeed");
    let actual = std::fs::read_to_string(root().join("docs/COMMERCIAL_READINESS.generated.md"))
        .expect("generated readiness report must exist");

    assert_eq!(
        actual, expected,
        "regenerate docs/COMMERCIAL_READINESS.generated.md from manifests"
    );
}

#[test]
fn baseline_does_not_fabricate_benchmark_receipts() {
    let benchmarks = benchmarks().expect("benchmark manifest must validate");
    assert!(
        benchmarks.benchmarks.is_empty(),
        "baseline must stay measurement-free until reproducible receipts are added"
    );
}
