use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn current_container_image_builds_the_root_recon_crate() {
    let docker = fs::read_to_string("Dockerfile").expect("root Dockerfile must exist");

    for required in [
        "FROM rust:1.99-trixie@sha256:6ff07edce8775d0f64be7aba9197229407301bddf2054d62c27b541a6238a181 AS builder",
        "FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS runtime",
        "cargo build --release --locked --bin huntsman-recon",
        "COPY scripts/container-entrypoint.sh /usr/local/bin/huntsman-entrypoint",
        "ENTRYPOINT [\"/usr/local/bin/huntsman-entrypoint\"]",
        "CMD [\"serve\"]",
        "/api/health",
    ] {
        assert!(
            docker.contains(required),
            "root Dockerfile must contain {required:?}"
        );
    }

    for line in docker.lines().filter(|line| line.starts_with("FROM ")) {
        assert!(
            line.contains("@sha256:"),
            "every base image must be pinned by digest, not a tag alone: {line:?}"
        );
    }

    assert!(
        !docker.contains("legacy/hse-monolith"),
        "current Recon image must not silently build the legacy monolith"
    );
}

#[test]
fn container_runtime_contract_is_current_and_shell_valid() {
    let entrypoint =
        fs::read_to_string("scripts/container-entrypoint.sh").expect("container entrypoint");
    for required in [
        "HUNTSMAN_DATA_DIR",
        "HUNTSMAN_STARTUP_CHECK",
        "HSE_AUTH_TOKEN",
        "/dev/urandom",
        "HUNTSMAN_BIN=\"${HUNTSMAN_BIN:-/usr/local/bin/huntsman-recon}\"",
        "\"$HUNTSMAN_BIN\" check",
        "\"$HUNTSMAN_BIN\" verify var/ledger.json",
        "gosu huntsman \"$HUNTSMAN_BIN\" \"$@\" &",
        "trap 'kill -TERM \"$server\" 2>/dev/null || true' TERM INT HUP",
    ] {
        assert!(
            entrypoint.contains(required),
            "container entrypoint must contain {required:?}"
        );
    }

    let status = Command::new("sh")
        .args(["-n", "scripts/container-entrypoint.sh"])
        .status()
        .expect("POSIX sh must execute in CI");
    assert!(
        status.success(),
        "container entrypoint must parse as POSIX sh"
    );

    let live_acceptance = fs::read_to_string("scripts/container-live-acceptance.sh")
        .expect("container live acceptance harness");
    for required in [
        "HUNTSMAN_CONTAINER_URL",
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
            "container live acceptance harness must contain {required:?}"
        );
    }

    assert!(
        !live_acceptance.contains("Authorization: Bearer $HSE_AUTH_TOKEN"),
        "container live acceptance must not place the bearer token directly in curl argv"
    );

    let rejected = Command::new("bash")
        .args(["scripts/container-live-acceptance.sh"])
        .env("HUNTSMAN_CONTAINER_URL", "https://example.invalid")
        .env("HSE_AUTH_TOKEN", "bad\nheader")
        .output()
        .expect("container acceptance rejection path must execute");
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("must not contain CR/LF"),
        "CR/LF token must be rejected before any request"
    );

    let status = Command::new("bash")
        .args(["-n", "scripts/container-live-acceptance.sh"])
        .status()
        .expect("bash must execute in CI");
    assert!(
        status.success(),
        "container live acceptance harness must parse as bash"
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
        "readonly INSTALL_ROOT=\"${HUNTSMAN_INSTALL_ROOT:-$TERMUX_PREFIX}\"",
        "--root \"$INSTALL_ROOT\"",
        "huntsman-recon",
        "sha256sum -c --quiet \"$ASSET.sha256\"",
        "timeout 30 \"$1\" check",
        "timeout 30 \"$1\" verify var/ledger.json",
        "accept_binary \"$release_dir/$ASSET\"",
        "accept_binary \"$installed\"",
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

#[test]
fn container_docs_match_the_image_and_the_token_contract() {
    let install = fs::read_to_string("docs/INSTALL.md").expect("install guide");
    let container = fs::read_to_string("docs/CONTAINERS.md").expect("container guide");

    assert!(install.contains("CONTAINERS.md"));
    assert!(container.contains("provider-neutral"));
    assert!(container.contains("the secret itself is not printed"));
    assert!(
        container.contains("no managed hosting service")
            || container.contains("No managed hosting service")
    );
}

#[test]
fn retired_managed_hosting_files_are_absent_from_current_project() {
    for path in [
        ".railway/railway.ts",
        "docs/RAILWAY.md",
        "scripts/railway-entrypoint.sh",
        "scripts/railway-iac-plan.sh",
        "scripts/railway-live-acceptance.sh",
        "scripts/validate-railway-iac.sh",
        "tests/railway_entrypoint.rs",
    ] {
        assert!(!Path::new(path).exists(), "{path} must not remain deployed");
    }
    for path in [
        "src/cli/service.rs",
        "src/web_server.rs",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
        "Dockerfile",
        "scripts/container-entrypoint.sh",
    ] {
        let text = fs::read_to_string(path).expect("current source");
        assert!(
            !text.to_ascii_lowercase().contains("railway"),
            "{path} must not depend on a removed hosting provider"
        );
    }
}
