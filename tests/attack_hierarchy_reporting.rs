use std::process::Command;

use serde_json::Value;

fn hse_json(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_hse"))
        .args(args)
        .output()
        .expect("hse must execute");
    assert!(
        output.status.success(),
        "hse {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("hse JSON output must parse")
}

#[test]
fn static_attack_status_scores_leaf_capabilities_without_double_counting_parents() {
    let v = hse_json(&["attack", "status", "--json"]);

    assert_eq!(v["coverage_basis"], "leaf-techniques");
    assert_eq!(v["leaf_techniques_covered"], 27);
    assert_eq!(v["leaf_techniques_total"], 37);
    assert_eq!(v["attack_objects_covered"], 32);
    assert_eq!(v["attack_objects_total"], 46);

    let fraction = v["coverage_fraction"]
        .as_f64()
        .expect("coverage_fraction must be numeric");
    assert!(
        (fraction - (27.0 / 37.0)).abs() < 1e-12,
        "coverage must score independent leaf capabilities, got {fraction}"
    );
}

#[test]
fn static_attack_gaps_separate_actionable_gaps_from_intentional_exclusions() {
    let v = hse_json(&["attack", "gaps", "--json"]);

    let actionable: Vec<&str> = v["capability_gaps"]
        .as_array()
        .expect("capability_gaps array")
        .iter()
        .map(|row| row["id"].as_str().expect("gap id"))
        .collect();
    assert_eq!(
        actionable,
        ["T1590.003", "T1591.003", "T1592.003", "T1592.004"]
    );

    let excluded: Vec<&str> = v["intentional_exclusions"]
        .as_array()
        .expect("intentional_exclusions array")
        .iter()
        .map(|row| row["id"].as_str().expect("exclusion id"))
        .collect();
    assert_eq!(
        excluded,
        [
            "T1598.001",
            "T1598.002",
            "T1598.003",
            "T1598.004",
            "T1681",
            "T1682",
        ]
    );

    assert_eq!(v["uncovered_leaf_total"], 10);
}
