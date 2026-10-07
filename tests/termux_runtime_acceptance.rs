use std::fs;
use std::path::PathBuf;
use std::process::Command;

const HARNESS: &str = "scripts/termux-runtime-acceptance.sh";

#[test]
fn termux_runtime_harness_targets_current_binary_and_api_contract() {
    let text = fs::read_to_string(HARNESS).expect("Termux acceptance harness must exist");

    for required in [
        "command -v huntsman-recon",
        r#"ORIGINAL_PWD="$(pwd -P)""#,
        r#"HSE_BIN="$ORIGINAL_PWD/$HSE_BIN""#,
        r#"STATE_DIR="$(anchor_path "${HUNTSMAN_HOME:-$HOME/.huntsman}")""#,
        "HSE_ACCEPTANCE_TIMEOUT must be positive",
        "HSE_ACCEPTANCE_SERVER_TIMEOUT must be positive",
        "HSE_ACCEPTANCE_PORT must be in 1..65535",
        r#"cd "$WORK_DIR" &&"#,
        r#""$HSE_BIN" check"#,
        r#""$HSE_BIN" verify var/ledger.json"#,
        "unset HSE_AUTH_TOKEN",
        r#"exec "$HSE_BIN" serve --bind"#,
        "/api/health",
        "/api/modules",
        "/api/command",
        "TERMUX_RUNTIME_ACCEPTANCE",
        "server lifecycle pass=2 (restart)",
        "aarch64|arm64",
        "/data/data/com.termux/files/usr",
    ] {
        assert!(
            text.contains(required),
            "{HARNESS} must contain current runtime probe {required:?}"
        );
    }

    for stale in [
        "/api/v1/health",
        "/api/v1/modules",
        "command -v hse || true",
        "  cd \"$WORK_DIR\"\n  timeout",
    ] {
        assert!(
            !text.contains(stale),
            "{HARNESS} must not retain stale runtime probe {stale:?}"
        );
    }
}

#[test]
fn termux_runtime_harness_is_valid_bash() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("bash")
        .arg("-n")
        .arg(root.join(HARNESS))
        .status()
        .expect("bash must execute in CI");
    assert!(status.success(), "{HARNESS} must parse as bash");
}
