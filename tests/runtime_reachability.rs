use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

const ALLOWED: [&str; 5] = ["runtime", "adapter", "exporter", "leaf", "diagnostic"];
const REQUIRED_RUNTIME: [&str; 21] = [
    "analysis",
    "collection",
    "community",
    "coref",
    "correlator",
    "coverage",
    "cross_scan",
    "dependency",
    "entity",
    "evidence_ancestry",
    "gap",
    "graph",
    "intelligence",
    "metrics",
    "module",
    "pipeline",
    "pivot",
    "planner",
    "relation",
    "roi",
    "runtime",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn compiled_modules() -> BTreeSet<String> {
    fs::read_to_string(root().join("src/lib.rs"))
        .expect("src/lib.rs")
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("pub mod ")
                .and_then(|name| name.strip_suffix(';'))
                .map(str::to_string)
        })
        .collect()
}

fn dispositions() -> BTreeMap<String, String> {
    let text = fixtures::text("runtime_module_dispositions.tsv");
    let mut out = BTreeMap::new();
    for (line_number, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            3,
            "line {} must have three TSV fields",
            line_number + 1
        );
        let module = fields[0].trim();
        let class = fields[1].trim();
        let rationale = fields[2].trim();
        assert!(
            !module.is_empty(),
            "line {} has empty module",
            line_number + 1
        );
        assert!(ALLOWED.contains(&class), "{module}: unknown class {class}");
        assert!(!rationale.is_empty(), "{module}: missing rationale");
        assert!(
            out.insert(module.to_string(), class.to_string()).is_none(),
            "module {module} classified more than once"
        );
    }
    out
}

#[test]
fn every_compiled_module_has_exactly_one_runtime_disposition() {
    let compiled = compiled_modules();
    let classified = dispositions().into_keys().collect::<BTreeSet<_>>();
    assert_eq!(classified, compiled);
}

#[test]
fn integration_spine_modules_are_runtime_reachable_by_policy() {
    let dispositions = dispositions();
    for module in REQUIRED_RUNTIME {
        assert_eq!(
            dispositions.get(module).map(String::as_str),
            Some("runtime"),
            "{module} must remain part of the runtime spine"
        );
    }
}

/// The spine runs from the one shipped binary, so the prebuilt release reaches it too.
#[test]
fn the_shipped_binary_runs_the_spine() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["plan", "example.com"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("termination="));
}
