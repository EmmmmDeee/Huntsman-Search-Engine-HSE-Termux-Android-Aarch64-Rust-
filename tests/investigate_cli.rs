use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_investigate")
}

#[test]
fn help_is_available() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("run investigate --help");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("usage: investigate"));
}

#[test]
fn offline_cli_executes_shared_runtime() {
    let output = Command::new(binary())
        .args(["ada@example.com", "example.com"])
        .output()
        .expect("run investigation");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("accepted=2"));
    assert!(stdout.contains("entities=2"));
    assert!(stdout.contains("termination=FixedPoint"));
    assert!(stdout.contains("truncated=false"));
}

#[test]
fn unsupported_only_input_fails_explicitly() {
    let output = Command::new(binary())
        .arg("not-a-supported-single-token")
        .output()
        .expect("run unsupported investigation");
    assert_eq!(output.status.code(), Some(65));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no actionable seeds"));
}
