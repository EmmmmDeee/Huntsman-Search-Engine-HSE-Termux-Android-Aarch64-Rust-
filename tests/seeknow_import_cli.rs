//! `seeknow import` reads a bulk export offline: no key, no request, no credential in its output.
use std::process::Command;

#[test]
fn seeknow_import_needs_no_key_and_never_prints_a_credential() {
    let dir = std::env::temp_dir().join(format!("hse-seeknow-import-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("export.json");
    std::fs::write(
        &path,
        r#"{"id":"cli-test","results":[{"target":"dubai","type":"username","total":2,"rows":[
            {"_source":"Dataset A","username":"dubai","email":"owner@example.com","password":"never-printed"},
            {"_source":"Dataset B","field_4":"Dubai","email":"stranger@example.com"}]}]}"#,
    )
    .expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["seeknow", "import", path.to_str().expect("utf8"), "--json"])
        .env("HOME", &dir)
        .env_remove("HUNTSMAN_SEEKNOW_KEY")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("json");
    let entity_values: Vec<&str> = parsed["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .filter_map(|e| e["value"].as_str())
        .collect();
    // The owner is attributed; the stranger is not attributed to the searched handle...
    assert!(
        entity_values.contains(&"owner@example.com"),
        "{entity_values:?}"
    );
    assert!(
        !entity_values.contains(&"stranger@example.com"),
        "{entity_values:?}"
    );
    // ...but every row is preserved as a record, so the full dataset survives import.
    assert_eq!(parsed["record_count"].as_u64(), Some(2), "{text}");
    let records = parsed["records"].to_string();
    assert!(records.contains("owner@example.com") && records.contains("stranger@example.com"));
    // The credential value is never printed, in any section of the output.
    assert!(!text.contains("never-printed"), "{text}");
    let bad = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["seeknow", "import"])
        .env("HOME", &dir)
        .output()
        .expect("run");
    assert!(!bad.status.success());
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn repeated_target_blocks_do_not_lose_later_attributed_records() {
    // A bulk export can contain more than one result block for the same selector.
    // Both blocks are evidence, even if their canonical selector UID matches.
    let dir = std::env::temp_dir().join(format!(
        "hse-seeknow-repeated-blocks-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("dir");
    let path = dir.join("export.json");
    std::fs::write(
        &path,
        r#"{"id":"duplicate-target-fixture","results":[
            {"target":"sample_handle","type":"username","total":1,"rows":[
                {"_source":"Dataset A","username":"sample_handle","email":"first@example.test"}]},
            {"target":"sample_handle","type":"username","total":1,"rows":[
                {"_source":"Dataset B","username":"sample_handle","email":"second@example.test"}]}
        ]}"#,
    )
    .expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["seeknow", "import", path.to_str().expect("utf8"), "--json"])
        .env("HOME", &dir)
        .env_remove("HUNTSMAN_SEEKNOW_KEY")
        .output()
        .expect("run");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let values: Vec<&str> = parsed["entities"]
        .as_array()
        .expect("entities")
        .iter()
        .filter_map(|entity| entity["value"].as_str())
        .collect();
    assert!(values.contains(&"first@example.test"), "{values:?}");
    assert!(values.contains(&"second@example.test"), "{values:?}");
    assert_eq!(parsed["record_count"].as_u64(), Some(2));
    assert_eq!(parsed["outcomes"].as_array().expect("outcomes").len(), 2);
    std::fs::remove_dir_all(&dir).expect("cleanup");
}
