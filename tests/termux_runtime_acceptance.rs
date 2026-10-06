use std::fs;
use std::path::PathBuf;
use std::process::Command;

const HARNESS: &str = "scripts/termux-runtime-acceptance.sh";

#[test]
fn termux_runtime_harness_targets_current_binary_and_api_contract() {
    let text = fs::read_to_string(HARNESS).expect("Termux acceptance harness must exist");

    for required in [
        "command -v huntsman-recon",
        ""$HSE_BIN" check",
        ""$HSE_BIN" verify var/ledger.json",
        ""$HSE_BIN" serve --bind",
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

    for stale in ["/api/v1/health", "/api/v1/modules", "command -v hse || true"] {
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
