use std::fs;

const CI: &str = ".github/workflows/ci.yml";
const NDK_ACTION: &str = ".github/actions/setup-ndk-aarch64/action.yml";

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
        "HUNTSMAN_HIBP_NO_EMBED",
        "llvm-readelf",
        "/system/bin/linker64",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}

#[test]
fn main_push_exposes_both_cross_built_binaries_for_handset_testing() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");

    for required in [
        "actions/upload-artifact@v4",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "target/aarch64-linux-android/release/huntsman-recon",
        "target/aarch64-linux-android/release/huntsman-probe",
        "dist/huntsman-recon-aarch64-linux-android",
        "dist/huntsman-probe-aarch64-linux-android",
        "huntsman-recon-aarch64-linux-android.sha256",
        "huntsman-probe-aarch64-linux-android.sha256",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}
