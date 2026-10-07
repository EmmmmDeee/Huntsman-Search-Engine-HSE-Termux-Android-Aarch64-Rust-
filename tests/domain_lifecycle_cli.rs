use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn observation(id: &str, time: u64, value: &str) -> Value {
    json!({"id":id,"host":"example.com","provider":"resolver",
        "upstream":"resolver-dataset","source_url":"https://resolver.example/query",
        "retrieved_at":time,"event_at":time,"outcome":"success","truncated":false,
        "kind":"dns","scope":"NS","value":value})
}

fn run(observations: Vec<Value>) -> std::process::Output {
    let observations = Value::Array(observations);
    let dir = std::env::temp_dir().join(format!(
        "hse-lifecycle-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.json");
    fs::write(
        &input,
        serde_json::to_vec(
            &json!({"schema_version":1,"domain":"example.com","observations":observations}),
        )
        .unwrap(),
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["domain-lifecycle", "analyze"])
        .arg(&input)
        .args(["--as-of", "1000"])
        .output()
        .unwrap();
    fs::remove_dir_all(dir).unwrap();
    output
}

fn report(observations: Vec<Value>) -> Value {
    let output = run(observations);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn infrastructure_change_has_evidence_and_does_not_claim_ownership() {
    let r = report(vec![
        observation("a", 100, "ns1.example.net"),
        observation("b", 200, "ns2.example.net"),
    ]);
    assert_eq!(r["findings"][0]["kind"], "infrastructure_change");
    assert_eq!(r["findings"][0]["evidence_ids"], json!(["a", "b"]));
    assert_eq!(r["ownership"], "unknown");
    assert_eq!(r["availability"], "unknown");
}

#[test]
fn shuffled_input_has_identical_output() {
    let a = observation("a", 100, "ns1.example.net");
    let b = observation("b", 200, "ns2.example.net");
    assert_eq!(report(vec![a.clone(), b.clone()]), report(vec![b, a]));
}

#[test]
fn failed_or_truncated_collection_cannot_create_a_change() {
    for (outcome, truncated) in [("challenge", false), ("success", true), ("timeout", false)] {
        let mut b = observation("b", 200, "ns2.example.net");
        b["outcome"] = json!(outcome);
        b["truncated"] = json!(truncated);
        let r = report(vec![observation("a", 100, "ns1.example.net"), b]);
        assert_eq!(r["findings"], json!([]));
        assert_eq!(r["coverage_gaps"].as_array().unwrap().len(), 1);
    }
}

#[test]
fn conflicting_same_time_observations_are_not_silently_resolved() {
    let r = report(vec![
        observation("a", 100, "ns1.example.net"),
        observation("b", 100, "ns2.example.net"),
        observation("c", 200, "ns3.example.net"),
    ]);
    assert_eq!(r["findings"], json!([]));
    assert_eq!(r["conflicts"].as_array().unwrap().len(), 1);
}

#[test]
fn different_upstreams_do_not_form_a_change_timeline() {
    let mut b = observation("b", 200, "ns2.example.net");
    b["upstream"] = json!("other-dataset");
    assert_eq!(
        report(vec![observation("a", 100, "ns1.example.net"), b])["findings"],
        json!([])
    );
}

#[test]
fn missing_event_time_is_a_gap_not_an_invented_date() {
    let mut b = observation("b", 200, "ns2.example.net");
    b["event_at"] = Value::Null;
    let r = report(vec![observation("a", 100, "ns1.example.net"), b]);
    assert_eq!(r["findings"], json!([]));
    assert_eq!(r["coverage_gaps"].as_array().unwrap().len(), 1);
}

#[test]
fn invalid_provenance_future_time_and_foreign_hosts_are_rejected() {
    for (field, value) in [
        ("source_url", json!("")),
        ("event_at", json!(1001)),
        ("host", json!("other.example")),
        ("upstream", json!("")),
    ] {
        let mut a = observation("a", 100, "ns1.example.net");
        a[field] = value;
        let out = run(vec![a]);
        assert_eq!(out.status.code(), Some(65));
        assert_eq!(out.stdout, Vec::<u8>::new());
    }
}

#[test]
fn conflicting_duplicate_ids_reject_the_envelope() {
    let out = run(vec![
        observation("a", 100, "ns1.example.net"),
        observation("a", 200, "ns2.example.net"),
    ]);
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, Vec::<u8>::new());
}

#[test]
fn repeated_import_does_not_add_observations_or_findings() {
    let a = observation("a", 100, "ns1.example.net");
    assert_eq!(report(vec![a.clone()]), report(vec![a.clone(), a]));
}

#[test]
fn dns_record_order_case_and_trailing_dot_are_not_changes() {
    let a = observation("a", 100, "NS1.Example.NET.\nns2.example.net");
    let b = observation(
        "b",
        200,
        "ns2.example.net\nns1.example.net\nns1.example.net",
    );
    assert_eq!(report(vec![a, b])["findings"], json!([]));
}

#[test]
fn digest_changes_do_not_claim_repurposing() {
    let mut a = observation("a", 100, &"a".repeat(64));
    let mut b = observation("b", 200, &"b".repeat(64));
    for o in [&mut a, &mut b] {
        o["kind"] = json!("content_digest");
        o["scope"] = json!("https://example.com/");
    }
    let r = report(vec![a, b]);
    assert_eq!(r["findings"][0]["kind"], "content_digest_change");
    assert_eq!(r["ownership"], "unknown");
}

#[test]
fn invalid_hash_and_cross_host_content_scope_are_rejected() {
    for (scope, digest) in [
        ("https://example.com/", "not-a-hash".to_owned()),
        ("https://other.example/", "a".repeat(64)),
    ] {
        let mut a = observation("a", 100, &digest);
        a["kind"] = json!("content_digest");
        a["scope"] = json!(scope);
        assert_eq!(run(vec![a]).status.code(), Some(65));
    }
}

#[test]
fn unsupported_observation_fields_are_rejected() {
    let mut a = observation("a", 100, "ns1.example.net");
    a["trusted"] = json!(true);
    assert_eq!(run(vec![a]).status.code(), Some(65));
}

#[test]
fn registration_status_change_does_not_establish_availability() {
    let mut a = observation("a", 100, "active");
    let mut b = observation("b", 200, "redemptionPeriod");
    for o in [&mut a, &mut b] {
        o["kind"] = json!("registration_status");
        o["scope"] = json!("registry-domain-status");
    }
    let r = report(vec![a, b]);
    assert_eq!(r["findings"][0]["kind"], "registration_status_change");
    assert_eq!(r["availability"], "unknown");
}

#[test]
fn output_path_alias_cannot_overwrite_observations() {
    let dir = std::env::temp_dir().join(format!("hse-lifecycle-alias-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let input = dir.join("input.json");
    let bytes =
        serde_json::to_vec(&json!({"schema_version":1,"domain":"example.com","observations":[]}))
            .unwrap();
    fs::write(&input, &bytes).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .current_dir(&dir)
        .args([
            "domain-lifecycle",
            "analyze",
            "input.json",
            "--as-of",
            "1000",
            "--output",
            "./input.json",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert_eq!(fs::read(input).unwrap(), bytes);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn equivalent_ipv6_notation_does_not_create_an_infrastructure_change() {
    let mut a = observation("a", 100, "2001:0db8:0000:0000:0000:0000:0000:0001");
    let mut b = observation("b", 200, "2001:db8::1");
    a["scope"] = json!("AAAA");
    b["scope"] = json!("AAAA");
    assert_eq!(report(vec![a, b])["findings"], json!([]));
}

#[test]
fn evidence_removal_withdraws_the_dependent_change() {
    let a = observation("a", 100, "ns1.example.net");
    let b = observation("b", 200, "ns2.example.net");
    assert_eq!(
        report(vec![a, b.clone()])["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report(vec![b])["findings"], json!([]));
}

#[test]
fn observation_count_is_bounded_before_deduplication() {
    let out = run(vec![observation("a", 100, "ns1.example.net"); 4097]);
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, Vec::<u8>::new());
}

#[test]
fn classification_change_does_not_assert_stale_reputation() {
    let mut a = observation("a", 100, "food");
    let mut b = observation("b", 200, "personal");
    for o in [&mut a, &mut b] {
        o["kind"] = json!("category");
        o["scope"] = json!("vendor:taxonomy-v1");
    }
    let r = report(vec![a, b]);
    assert_eq!(r["findings"][0]["kind"], "classification_change");
    assert_eq!(r["availability"], "unknown");
}

#[test]
fn malformed_dot_hosts_cannot_be_normalized_into_the_target() {
    for host in [
        ".example.com",
        "example.com..",
        "example.com .",
        "example.com. .",
    ] {
        let mut a = observation("a", 100, "ns1.example.net");
        a["host"] = json!(host);
        assert_eq!(run(vec![a]).status.code(), Some(65));
    }
    let mut a = observation("a", 100, &"a".repeat(64));
    a["kind"] = json!("content_digest");
    a["scope"] = json!("https://.example.com/");
    assert_eq!(run(vec![a]).status.code(), Some(65));
}

#[test]
fn blank_dns_lines_are_not_infrastructure_changes() {
    let a = observation("a", 100, "ns1.example.net\n\nns2.example.net");
    let b = observation("b", 200, "ns1.example.net\nns2.example.net");
    assert_eq!(report(vec![a, b])["findings"], json!([]));
}

#[test]
fn malformed_nameserver_and_mx_records_are_not_successful_evidence() {
    for (scope, value) in [
        ("NS", "not a domain"),
        ("NS", ".example.net"),
        ("MX", "invalid mail.example.net"),
        ("MX", "10 mail.example.net extra"),
    ] {
        let mut a = observation("a", 100, value);
        a["scope"] = json!(scope);
        assert_eq!(run(vec![a]).status.code(), Some(65));
    }
}
