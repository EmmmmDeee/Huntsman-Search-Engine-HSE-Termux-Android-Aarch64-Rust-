use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn current_railway_image_builds_the_root_recon_crate() {
    let docker = fs::read_to_string("Dockerfile").expect("root Dockerfile must exist");

    for required in [
        "FROM rust:1.99-trixie AS builder",
        "FROM debian:trixie-slim AS runtime",
        "cargo build --release --locked --bin huntsman-recon",
        "COPY scripts/railway-entrypoint.sh /usr/local/bin/huntsman-entrypoint",
        "ENTRYPOINT [\"/usr/local/bin/huntsman-entrypoint\"]",
        "CMD [\"serve\"]",
        "/api/health",
    ] {
        assert!(
            docker.contains(required),
            "root Dockerfile must contain {required:?}"
        );
    }

    assert!(
        !docker.contains("legacy/hse-monolith"),
        "current Recon image must not silently build the legacy monolith"
    );
}

#[test]
fn railway_runtime_contract_is_current_and_shell_valid() {
    let entrypoint =
        fs::read_to_string("scripts/railway-entrypoint.sh").expect("Railway entrypoint");
    for required in [
        "RAILWAY_VOLUME_MOUNT_PATH",
        "HUNTSMAN_DATA_DIR",
        "HUNTSMAN_STARTUP_CHECK",
        "HSE_AUTH_TOKEN",
        "/dev/urandom",
        "huntsman-recon check",
        "huntsman-recon verify var/ledger.json",
        "exec gosu huntsman /usr/local/bin/huntsman-recon",
    ] {
        assert!(
            entrypoint.contains(required),
            "Railway entrypoint must contain {required:?}"
        );
    }

    let status = Command::new("sh")
        .args(["-n", "scripts/railway-entrypoint.sh"])
        .status()
        .expect("POSIX sh must execute in CI");
    assert!(
        status.success(),
        "Railway entrypoint must parse as POSIX sh"
    );

    let live_acceptance = fs::read_to_string("scripts/railway-live-acceptance.sh")
        .expect("Railway live acceptance harness");
    for required in [
        "HUNTSMAN_RAILWAY_URL",
        "HSE_AUTH_TOKEN",
        "/api/health",
        "/api/modules",
        "/api/command",
        "unauthenticated_modules=401",
        "authenticated_modules=200",
        "authenticated_command=200",
        "auth.headers",
        "unset HSE_AUTH_TOKEN",
        "-H \"@$auth_headers\"",
        "HSE_AUTH_TOKEN must not contain CR/LF",
        "allowed_proto='=https'",
        "--proto \"$allowed_proto\"",
    ] {
        assert!(
            live_acceptance.contains(required),
            "Railway live acceptance harness must contain {required:?}"
        );
    }

    assert!(
        !live_acceptance.contains("Authorization: Bearer $HSE_AUTH_TOKEN"),
        "Railway live acceptance must not place the bearer token directly in curl argv"
    );

    let rejected = Command::new("bash")
        .args(["scripts/railway-live-acceptance.sh"])
        .env("HUNTSMAN_RAILWAY_URL", "https://example.invalid")
        .env("HSE_AUTH_TOKEN", "bad\nheader")
        .output()
        .expect("Railway acceptance rejection path must execute");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("must not contain CR/LF"),
        "CR/LF token must be rejected before any request"
    );

    let status = Command::new("bash")
        .args(["-n", "scripts/railway-live-acceptance.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(
        status.success(),
        "Railway live acceptance harness must parse as bash"
    );
}

#[test]
fn railway_iac_contract_is_current_and_shell_valid() {
    let iac_validator =
        fs::read_to_string("scripts/validate-railway-iac.sh").expect("Railway IaC validator");
    for required in [
        "Node.js 22+ required",
        "railway\": \"3.12.0",
        "typescript\": \"5.9.3",
        "./node_modules/.bin/tsc -p tsconfig.json",
        ".railway/railway.ts",
    ] {
        assert!(
            iac_validator.contains(required),
            "Railway IaC validator must contain {required:?}"
        );
    }
    let status = Command::new("bash")
        .args(["-n", "scripts/validate-railway-iac.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(status.success(), "Railway IaC validator must parse as bash");

    let plan = fs::read_to_string("scripts/railway-iac-plan.sh").expect("Railway IaC plan wrapper");
    for required in ["railway config plan", "Railway CLI is required"] {
        assert!(
            plan.contains(required),
            "Railway plan wrapper must contain {required:?}"
        );
    }
    let status = Command::new("bash")
        .args(["-n", "scripts/railway-iac-plan.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(
        status.success(),
        "Railway IaC plan wrapper must parse as bash"
    );

    let iac = fs::read_to_string(".railway/railway.ts").expect("Railway IaC");
    for required in [
        "railway/iac",
        "export const partial = \"huntsman-recon\"",
        "healthcheck: \"/api/health\"",
        "HSE_AUTH_TOKEN: preserve()",
        "HUNTSMAN_STARTUP_CHECK: \"1\"",
        "branch: \"main\"",
    ] {
        assert!(
            iac.contains(required),
            "Railway IaC must contain {required:?}"
        );
    }

    assert!(
        !Path::new("railway.toml").exists() && !Path::new("railway.json").exists(),
        "new deployments must not regress to deprecated Railway Config as Code"
    );
}

#[test]
fn termux_installer_is_arm64_userland_and_self_accepting() {
    let device = fs::read_to_string("scripts/termux-device-acceptance.sh")
        .expect("Termux device acceptance");
    for required in [
        "aarch64|arm64",
        "/data/data/com.termux/files/usr",
        "timeout 30 \"$bin\" check",
        "timeout 30 \"$bin\" verify var/ledger.json",
        "termux-acceptance: PASS",
    ] {
        assert!(
            device.contains(required),
            "Termux device acceptance must contain {required:?}"
        );
    }
    let status = Command::new("bash")
        .args(["-n", "scripts/termux-device-acceptance.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(
        status.success(),
        "Termux device acceptance harness must parse as bash"
    );

    let installer = fs::read_to_string("install.sh").expect("Termux installer");
    for required in [
        "aarch64|arm64",
        "/data/data/com.termux/files/usr",
        "pkg update -y",
        "pkg install -y git rust clang curl coreutils",
        "rust-std-",
        "--root \"$TERMUX_PREFIX\"",
        "huntsman-recon",
        "timeout 30 \"$installed\" check",
        "timeout 30 \"$installed\" verify var/ledger.json",
        "chmod 0600 \"$ENV_FILE\"",
    ] {
        assert!(
            installer.contains(required),
            "Termux installer must contain {required:?}"
        );
    }

    for forbidden in ["sudo ", " su ", "pkg install -y proot"] {
        assert!(
            !installer.contains(forbidden),
            "Termux installer must remain no-root userland: {forbidden:?}"
        );
    }

    let status = Command::new("bash")
        .args(["-n", "install.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(status.success(), "Termux installer must parse as bash");
}
