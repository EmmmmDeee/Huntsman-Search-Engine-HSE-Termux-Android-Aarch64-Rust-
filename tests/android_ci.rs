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
fn ci_pins_every_external_action_to_an_immutable_commit() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");

    for line in ci.lines().map(str::trim) {
        let Some(action) = line.strip_prefix("- uses:") else {
            continue;
        };
        let action = action.split_whitespace().next().unwrap_or_default();
        if action.starts_with("./") {
            continue;
        }
        let (name, revision) = action.rsplit_once('@').unwrap_or_else(|| {
            panic!("external action {action:?} must name an immutable revision")
        });
        assert!(
            !name.is_empty(),
            "external action name must not be empty: {action:?}"
        );
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "external action {action:?} must be pinned to a full 40-hex commit SHA"
        );
    }
}

#[test]
fn main_push_exposes_the_cross_built_binary_for_handset_testing() {
    let ci = fs::read_to_string(CI).expect("active CI workflow must be readable");

    for required in [
        "actions/upload-artifact@",
        "if: github.event_name == 'push' && github.ref == 'refs/heads/main'",
        "huntsman-recon-aarch64-linux-android",
        "huntsman-recon-aarch64-linux-android.sha256",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}
