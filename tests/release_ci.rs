//! Contract for the live release workflow. GitHub only runs workflows under the
//! root `.github/workflows/`; the copy under `legacy/` is inert. Deleting the
//! root file (f0a1c64) silently stopped every main-channel pre-release.

use std::fs;

const RELEASE: &str = ".github/workflows/release.yml";
const SCAN: &str = ".github/scripts/scan-for-keys.sh";

fn release() -> String {
    fs::read_to_string(RELEASE)
        .expect("the live release workflow must exist at the repository root")
}

#[test]
fn main_pushes_publish_main_channel_pre_releases_only() {
    let wf = release();
    for required in [
        "branches:\n      - main",
        "workflow_dispatch:",
        "refs/heads/main",
        "main-${GITHUB_SHA:0:7}",
        "gh release create \"$TAG\"",
        "gh release create latest",
        "--prerelease --latest=false",
        "is NOT a pre-release; refusing",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
    assert_eq!(
        wf.matches("--prerelease --latest=false").count(),
        2,
        "both releases must be pre-releases that never become Latest"
    );
    for forbidden in ["tags:", "make_latest: true", "--latest=true", "--latest \\"] {
        assert!(
            !wf.contains(forbidden),
            "{RELEASE} must not contain {forbidden:?}"
        );
    }
}

#[test]
fn publishing_requires_release_build_and_zero_finding_key_scan() {
    let wf = release();
    for required in [
        "HSE_RELEASE: \"1\"",
        "HUNTSMAN_HIBP_NO_EMBED: \"1\"",
        "hibp_embedded_key.txt",
        "bash .github/scripts/scan-for-keys.sh dist",
        "grep -qx \"result: PASS (0 findings)\" key-scan-report.txt",
        "dist/key-scan-report.txt",
    ] {
        assert!(wf.contains(required), "{RELEASE} must contain {required:?}");
    }
    let scan = fs::read_to_string(SCAN).expect("key scanner must exist");
    assert!(
        scan.contains("value withheld"),
        "{SCAN} must never print values"
    );
    assert!(
        scan.contains("[ \"$hits\" -eq 0 ]"),
        "{SCAN} must fail on any finding"
    );
}
