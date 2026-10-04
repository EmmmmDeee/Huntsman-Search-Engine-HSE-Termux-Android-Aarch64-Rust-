use std::collections::BTreeMap;
use std::process::Command;

use huntsman_recon::ip::render::{render_text, render_text_with_evidence};
use huntsman_recon::ip::{
    IpBudgetUsage, IpClaim, IpClaimKind, IpClaimState, IpFailure, IpFailureKind, IpInvestigation,
    IpObservation, IpObservationKind, IpTarget, TemporalState,
};
use serde_json::Value;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn run(args: &[&str]) -> std::process::Output {
    bin().args(args).output().expect("run huntsman-recon")
}

#[test]
fn missing_or_bad_ip_exits_before_any_investigation() {
    let missing = run(&["ip"]);
    assert_eq!(missing.status.code(), Some(64));
    assert!(missing.stdout.is_empty());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("huntsman-recon ip"));

    let bad = run(&["ip", "not-an-ip"]);
    assert_eq!(bad.status.code(), Some(65));
    assert!(bad.stdout.is_empty());
    assert!(String::from_utf8_lossy(&bad.stderr).contains("invalid IP address"));
}

#[test]
fn non_public_ip_is_classified_without_public_provider_execution() {
    for target in ["10.1.2.3", "192.0.2.10", "2001:db8::1"] {
        let output = run(&["ip", target, "--json"]);
        assert!(
            output.status.success(),
            "{target}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
        assert_ne!(value["target"]["scope"], "public");
        assert_eq!(value["observations"], serde_json::json!([]));
        assert_eq!(value["budget_used"]["calls"], 0);
        assert_eq!(value["termination_reason"], "non_public_target");
    }
}

#[test]
fn json_contains_the_complete_investigation_state_shape() {
    let output = run(&["ip", "192.0.2.10", "--json"]);
    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).expect("JSON output");
    for key in [
        "target",
        "observations",
        "failures",
        "claims",
        "actions_considered",
        "budget_used",
        "termination_reason",
    ] {
        assert!(value.get(key).is_some(), "missing JSON key {key}");
    }
}

#[test]
fn human_and_json_views_share_the_same_target_and_termination_facts() {
    let text = run(&["ip", "192.0.2.10"]);
    let json = run(&["ip", "192.0.2.10", "--json"]);
    assert!(text.status.success());
    assert!(json.status.success());

    let text = String::from_utf8(text.stdout).expect("UTF-8 text");
    let value: Value = serde_json::from_slice(&json.stdout).expect("JSON output");
    let canonical = value["target"]["address"].as_str().expect("target address");
    let termination = value["termination_reason"]
        .as_str()
        .expect("termination reason");
    assert!(text.contains(canonical));
    assert!(text.contains(termination));
}

#[test]
fn evidence_flag_adds_provenance_without_changing_claim_truth() {
    let normal = run(&["ip", "192.0.2.10"]);
    let evidence = run(&["ip", "192.0.2.10", "--evidence"]);
    assert!(normal.status.success());
    assert!(evidence.status.success());
    let normal = String::from_utf8(normal.stdout).expect("normal text");
    let evidence = String::from_utf8(evidence.stdout).expect("evidence text");
    assert!(!normal.contains("evidence:"));
    assert!(evidence.contains("evidence:"));
    assert!(evidence.contains("claim_states_unchanged=true"));
}

#[test]
fn unknown_ip_flag_is_a_usage_error() {
    let output = run(&["ip", "192.0.2.10", "--wat"]);
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty());
}

#[test]
fn renderer_preserves_useful_output_when_one_source_failed() {
    let target = IpTarget::parse("1.1.1.1").expect("target");
    let mut investigation = IpInvestigation::new(target);
    investigation.observations.push(IpObservation {
        id: "routing-1".into(),
        provider_id: "ripestat_network_info".into(),
        source_family: "ripe-stat-network-info".into(),
        kind: IpObservationKind::Routing,
        summary: "1.1.1.0/24 via AS13335".into(),
        attributes: BTreeMap::from([
            ("prefix".into(), "1.1.1.0/24".into()),
            ("asns".into(), "13335".into()),
        ]),
        observed_at_unix: None,
        retrieved_at_unix: 1_000,
        raw_digest: None,
    });
    investigation.failures.push(IpFailure {
        provider_id: "rdap".into(),
        kind: IpFailureKind::Network,
        detail: "offline fixture".into(),
        source_outcome: None,
    });
    investigation.claims.push(IpClaim {
        kind: IpClaimKind::Routing,
        state: IpClaimState::Supported,
        temporal: TemporalState::UnknownCurrent,
        support_ids: vec!["routing-1".into()],
        contradiction_ids: Vec::new(),
        dependency_ids: vec!["ripe-stat-network-info".into()],
    });
    investigation.budget_used = IpBudgetUsage {
        calls: 2,
        actions: 2,
        max_depth_reached: 0,
    };
    investigation.termination_reason = Some("fixed_point".into());

    let text = render_text(&investigation);
    assert!(text.contains("AS13335"));
    assert!(text.contains("rdap"));
    assert!(text.contains("offline fixture"));

    let evidence = render_text_with_evidence(&investigation);
    assert!(evidence.contains("ripe-stat-network-info"));
    assert!(evidence.contains("routing-1"));
}
