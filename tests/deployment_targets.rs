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
