use std::fs;

const CI: &str = ".github/workflows/ci.yml";
const NDK_ACTION: &str = ".github/actions/setup-ndk-aarch64/action.yml";
const DOCKERFILE: &str = "Dockerfile";

#[test]
fn active_ndk_action_exports_aarch64_android_toolchain() {
    let action = fs::read_to_string(NDK_ACTION)
        .expect("active Android NDK setup action must exist at the repository root");

    for required in [
        "aarch64-linux-android",
        "ANDROID_NDK_LATEST_HOME",
        "CC_aarch64_linux_android",
        "AR_aarch64_linux_android",
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER",
        "CARGO_TARGET_AARCH64_LINUX_ANDROID_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384",
        "android-api",
        "24",
    ] {
        assert!(
            action.contains(required),
            "{NDK_ACTION} must contain {required:?}"
        );
    }
}

#[test]
fn ci_cross_builds_the_actual_termux_target() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");

    for required in [
        "android-aarch64:",
        "aarch64-linux-android",
        "./.github/actions/setup-ndk-aarch64",
        "cargo build --release --locked --target aarch64-linux-android",
        "HUNTSMAN_BUILD_SHA: ${{ github.sha }}",
        "llvm-readelf",
        "/system/bin/linker64",
        "[ $((align)) -ge 16384 ]",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}

/// The open flags that differ between `x86_64` and aarch64 are tested where Termux runs: the
/// library's tests, the no-follow and non-blocking opens among them, run as aarch64 code.
#[test]
fn ci_runs_the_library_tests_as_aarch64_code() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");
    for required in [
        "aarch64-tests:",
        "targets: aarch64-unknown-linux-gnu",
        "qemu-user",
        "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER: qemu-aarch64 -L /usr/aarch64-linux-gnu",
        "cargo test --locked --target aarch64-unknown-linux-gnu --lib",
        "cargo test --locked --target aarch64-unknown-linux-gnu -p xtask --bins",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
    let job = ci
        .split("  aarch64-tests:")
        .nth(1)
        .and_then(|rest| rest.split("\n  android-aarch64:").next())
        .expect("the aarch64 test job");
    // Only the tests emulation cannot judge are skipped; the open-flag tests never are.
    let skipped: Vec<&str> = job
        .split("--skip ")
        .skip(1)
        .filter_map(|rest| rest.split_whitespace().next())
        .collect();
    assert_eq!(
        skipped,
        [
            "quadratic_time",
            "http::tests::public_only_ignores_environment_proxy",
            "scan_store::tests::process_start_time_reads_past_a_name_holding_spaces_and_parentheses",
            "scan_service::tests::same_process_different_service_cannot_acknowledge_foreign_stop"
        ],
        "{job}"
    );
}

/// Devices with 16 KiB pages (Android 15 and later on recent hardware) refuse an ELF whose LOAD
/// segments are aligned to less. The action asks the linker for 16 KiB by name, and both
/// cross-builds refuse a binary that did not get it, so the published binary cannot silently
/// depend on the runner's NDK default (r28 links for 16 KiB, r27 for 4 KiB).
#[test]
fn the_android_binary_is_linked_and_checked_for_16_kib_pages() {
    let action = fs::read_to_string(NDK_ACTION).expect("NDK action");
    assert!(
        action.contains("max-page-size=16384"),
        "{NDK_ACTION} must link aarch64-linux-android for 16 KiB pages"
    );
    for (path, text) in [
        (CI, fs::read_to_string(CI).expect("ci workflow")),
        (
            ".github/workflows/release.yml",
            fs::read_to_string(".github/workflows/release.yml").expect("release workflow"),
        ),
    ] {
        for required in [
            "awk '$1 == \"LOAD\" { print $NF }'",
            "[ $((align)) -ge 16384 ]",
        ] {
            assert!(
                text.contains(required),
                "{path} must refuse a LOAD segment aligned below 16 KiB: {required}"
            );
        }
    }
}

#[test]
fn main_push_exposes_the_cross_built_binary_for_handset_testing() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");

    for required in [
        "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "huntsman-recon-aarch64-linux-android",
        "huntsman-recon-aarch64-linux-android.sha256",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}

#[test]
fn ci_and_container_builds_carry_exact_source_commit_provenance() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");
    let docker = fs::read_to_string(DOCKERFILE).expect("Dockerfile must be readable");
    assert!(ci.contains("--build-arg HUNTSMAN_BUILD_SHA=\"$GITHUB_SHA\""));
    assert!(docker.contains("ARG HUNTSMAN_BUILD_SHA=unknown"));
    assert!(docker.contains("HUNTSMAN_BUILD_SHA=${HUNTSMAN_BUILD_SHA}"));
}
