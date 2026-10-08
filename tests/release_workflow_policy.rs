use std::fs;

const RELEASE: &str = ".github/workflows/release.yml";

#[test]
fn legacy_release_publication_is_serialized_and_never_cancelled() {
    let workflow = fs::read_to_string(RELEASE).expect("legacy release workflow");
    for required in [
        "branches:\n      - legacy-hse",
        "group: legacy-hse-release",
        "cancel-in-progress: false",
    ] {
        assert!(
            workflow.contains(required),
            "{RELEASE} must contain {required:?}"
        );
    }
    assert!(
        !workflow.contains("group: legacy-hse-release-${{ github.ref }}"),
        "branch and tag release runs must share one publication lane"
    );
    assert!(
        !workflow.contains("cancel-in-progress: true"),
        "an in-flight release must never be cancelled by a newer commit"
    );
}
