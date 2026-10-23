//! The fortified controller is an executable xtask contract, not a second agent runtime.
use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask runs")
}

#[test]
fn plan_provides_machine_readable_roles_and_phases() {
    let result = xtask(&["fortify", "plan"]);
    assert!(result.status.success(), "{result:?}");
    let plan: serde_json::Value = serde_json::from_slice(&result.stdout).expect("plan JSON");
    assert_eq!(plan["schema"], "huntsman.fortified-pipeline/1");
    assert_eq!(plan["roles"].as_array().map(Vec::len), Some(16));
    assert_eq!(plan["phases"].as_array().map(Vec::len), Some(5));
    assert_eq!(plan["roles"][1]["reports_to"], "strategy");
    assert_eq!(plan["phases"][4]["predecessor"], "optimize");
}

#[test]
fn repository_preflight_checks_existing_release_gates() {
    let result = xtask(&["fortify", "validate"]);
    assert!(result.status.success(), "{result:?}");
    assert!(String::from_utf8_lossy(&result.stdout).contains("PASS"));
}

#[test]
fn status_is_observation_not_a_claim_of_deployment() {
    let result = xtask(&["fortify", "status"]);
    assert!(result.status.success(), "{result:?}");
    let status: serde_json::Value = serde_json::from_slice(&result.stdout).expect("status JSON");
    assert_eq!(status["verification"], "not run by status");
    assert_eq!(status["deployment"], "not performed");
    assert!(status["commit"].as_str().is_some_and(|sha| sha.len() == 40));
}

#[test]
fn economics_covers_every_cost_without_overflow() {
    let result = xtask(&["fortify", "score", "100", "15", "10", "20", "5"]);
    assert!(result.status.success(), "{result:?}");
    let score: serde_json::Value = serde_json::from_slice(&result.stdout).expect("score JSON");
    assert_eq!(score["expected_net_value_units"], "50");
    assert_eq!(score["decision"], "candidate");

    let loss = xtask(&["fortify", "score", "4", "2", "2", "1", "0"]);
    assert!(loss.status.success(), "{loss:?}");
    let score: serde_json::Value = serde_json::from_slice(&loss.stdout).expect("score JSON");
    assert_eq!(score["expected_net_value_units"], "-1");
    assert_eq!(score["decision"], "defer");
}

#[test]
fn refuse_unimplemented_and_malformed_operations() {
    for args in [
        &["fortify", "run", "deploy"][..],
        &["fortify", "score", "-1", "0", "0", "0", "0"],
        &["fortify", "score", "1", "0", "0"],
        &["fortify", "merge"],
    ] {
        let result = xtask(args);
        assert_eq!(result.status.code(), Some(64), "{result:?}");
    }
}
