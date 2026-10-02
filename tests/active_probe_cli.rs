use std::process::Command;

#[test]
fn probe_binary_exposes_help_without_network() {
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-probe"))
        .arg("--help")
        .output()
        .expect("run huntsman-probe --help");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("authorized active web reconnaissance"));
    assert!(stdout.contains("--authorized"));
    assert!(stdout.contains("--max-requests"));
}

#[test]
fn probe_binary_refuses_active_network_without_explicit_authorization() {
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-probe"))
        .arg("https://example.com")
        .output()
        .expect("run huntsman-probe without authorization");
    assert_eq!(out.status.code(), Some(77));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("--authorized"));
}

#[test]
fn probe_binary_rejects_zero_request_budget_before_network() {
    let out = Command::new(env!("CARGO_BIN_EXE_huntsman-probe"))
        .args(["--authorized", "--max-requests", "0", "https://example.com"])
        .output()
        .expect("run huntsman-probe with zero budget");
    assert_eq!(out.status.code(), Some(64));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("max-requests"));
}
