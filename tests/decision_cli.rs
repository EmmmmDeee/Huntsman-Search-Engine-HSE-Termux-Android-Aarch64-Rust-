use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde_json::{Value, json};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-decision-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn request_json() -> Value {
    json!({
        "state": {
            "state_version": "cli-state-1",
            "unresolved_proof_obligations": ["claim:identity"],
            "all_relevant_claims_defeated": false,
            "frontier": {
                "admissible_work": 2,
                "delayed_retry_work": 0,
                "in_flight_work": 0,
                "derivable_novel_work": 0
            },
            "termination_signals": {
                "cancelled": false,
                "fatal_error": false,
                "max_depth_reached": false,
                "time_limit_reached": false,
                "request_budget_exhausted": false,
                "provider_budget_exhausted": false,
                "resource_limit_reached": false,
                "marginal_gain_below_floor": false
            }
        },
        "candidates": [{
            "id": "fallback",
            "capability": "lookup",
            "provider": "provider:fallback",
            "target": "subject@example.com",
            "eligibility": {
                "hard_constraints": [{"id": "scope:public", "satisfied": true}],
                "dependencies": [{"id": "dependency:ready", "satisfied": true}],
                "permissions": [{"id": "permission:network", "satisfied": true}],
                "provider_executable": true,
                "preconditions": [{"id": "target:valid", "satisfied": true}],
                "blocked_reasons": []
            },
            "satisfied_obligations": ["claim:identity"],
            "expected_decision_impact": 0.7,
            "roi_inputs": {
                "source_count": 1,
                "independent_root_count": 1,
                "entity_confidence": 0.4,
                "optionality_prior": 0.6,
                "novelty_prior": 0.8,
                "reliability_prior": 0.9,
                "cost_per_request_usd": 0.0,
                "quota_remaining": true,
                "configured_timeout_ms": 1000,
                "already_dispatched_this_module_target": false,
                "geoint_bearing": false
            },
            "resource_cost": 0.05,
            "irreversible_risk": 0.0,
            "blast_radius": 0.0
        }]
    })
}

#[test]
fn decide_command_emits_reconstructable_decision_record() {
    let dir = scratch("valid");
    let request = dir.join("request.json");
    fs::write(
        &request,
        serde_json::to_vec_pretty(&request_json()).unwrap(),
    )
    .unwrap();

    let out = bin().arg("decide").arg(&request).output().unwrap();
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let record: Value = serde_json::from_slice(&out.stdout).expect("decision output must be JSON");
    assert_eq!(record["state_version"], "cli-state-1");
    assert_eq!(record["decision"]["kind"], "select");
    assert_eq!(record["decision"]["detail"], "fallback");
    assert_eq!(record["ranking"][0]["action_id"], "fallback");
    assert_eq!(record["evidence_lineage_inputs"]["fallback"], 1);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn decide_command_rejects_invalid_json_without_emitting_a_decision() {
    let dir = scratch("invalid");
    let request = dir.join("bad.json");
    fs::write(&request, b"{not-json").unwrap();

    let out = bin().arg("decide").arg(&request).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, Vec::<u8>::new());

    let _ = fs::remove_dir_all(&dir);
}
