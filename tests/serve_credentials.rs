//! Exit status of `serve` when a required credential is missing. Both cases are refused while the
//! configuration is checked, before anything is bound, so this needs no network.

use std::process::Command;

/// Runs `serve` with the given bind and token, returning the exit status and stderr.
fn serve(bind: &str, token: Option<&str>) -> (Option<i32>, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_huntsman-recon"));
    command
        .args(["serve", "--bind", bind])
        .env_remove("HSE_AUTH_TOKEN");
    if let Some(token) = token {
        command.env("HSE_AUTH_TOKEN", token);
    }
    let output = command.output().unwrap();
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn a_non_loopback_bind_without_a_token_exits_66() {
    let (code, stderr) = serve("0.0.0.0:18099", None);
    assert_eq!(code, Some(66), "{stderr}");
    assert!(
        stderr.contains("non-loopback serve bind requires HSE_AUTH_TOKEN"),
        "{stderr}"
    );
}

#[test]
fn a_blank_token_exits_66() {
    let (code, stderr) = serve("127.0.0.1:18099", Some("   "));
    assert_eq!(code, Some(66), "{stderr}");
    assert!(
        stderr.contains("HSE_AUTH_TOKEN must not be empty"),
        "{stderr}"
    );
}
