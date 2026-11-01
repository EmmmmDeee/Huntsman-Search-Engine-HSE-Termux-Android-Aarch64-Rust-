use std::fs;

const CI: &str = ".github/workflows/ci.yml";
const WORKFLOWS: &str = ".github/workflows";

/// All release and CI jobs stay on the pinned x86 runner, except the
/// explicitly reviewed native ARM64 SHA-256 performance measurement.
/// No `-latest` runner labels may silently change compilers or the NDK.
const RUNNER: &str = "ubuntu-24.04";
const ARM_BENCHMARK: &str = ".github/workflows/sha256-native-arm64-benchmark.yml";
const ARM_RUNNER: &str = "ubuntu-24.04-arm";

#[test]
fn main_pushes_must_have_a_merged_pr_association() {
    let ci = fs::read_to_string(CI).expect("CI workflow");
    for required in [
        "main-pr-origin:",
        "if: github.event_name == 'push'",
        "pull-requests: read",
        "commits/${GITHUB_SHA}/pulls",
        ".base.ref == \"main\" and .merged_at != null",
        "for attempt in 1 2 3 4 5 6 7 8 9 10",
        "[ \"$attempt\" -eq 10 ] || sleep 3",
        "could not verify merged pull request association",
        "reached main without an associated merged pull request after bounded retry",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
}

#[test]
fn self_hosted_container_has_executable_ci_acceptance() {
    let ci = fs::read_to_string(CI).expect("CI workflow");
    for required in [
        "container:",
        "Self-hosted container smoke test",
        "scripts/container-live-acceptance.sh",
        "scripts/container-build-retry.sh",
        "Dockerfile",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
    assert!(
        !ci.contains("railway"),
        "provider-specific jobs must be removed"
    );
}

#[test]
fn every_job_runs_on_the_pinned_runner_image() {
    let mut workflows: Vec<_> = fs::read_dir(WORKFLOWS)
        .expect("workflow directory")
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|ext| ext == "yml" || ext == "yaml")
        })
        .collect();
    workflows.sort();
    assert!(!workflows.is_empty(), "{WORKFLOWS} holds no workflow");
    for path in &workflows {
        let workflow = fs::read_to_string(path).expect("workflow");
        let runners: Vec<&str> = workflow
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("runs-on:"))
            .map(str::trim)
            .collect();
        assert!(!runners.is_empty(), "{} names no runner", path.display());
        // The benchmark requires an actual ARM64 CPU; every other job must
        // keep its reviewed x86 image, so performance measurement cannot alter
        // deployment, security, browser or release environments.
        let expected = if path == std::path::Path::new(ARM_BENCHMARK) {
            ARM_RUNNER
        } else {
            RUNNER
        };
        for runner in runners {
            assert_eq!(
                runner,
                expected,
                "{}: unexpected runner image; expected {expected}",
                path.display()
            );
        }
    }
}

#[test]
fn native_arm64_benchmark_is_read_only_and_scoped() {
    let workflow = fs::read_to_string(ARM_BENCHMARK).expect("native ARM64 benchmark");
    for required in [
        "runs-on: ubuntu-24.04-arm",
        "contents: read",
        "pull_request:",
        "workflow_dispatch:",
        "cargo test --locked --lib sha256::tests",
        "cargo run --release --locked --example sha256_arm64_bench",
    ] {
        assert!(workflow.contains(required), "ARM64 benchmark requires {required:?}");
    }
    assert!(!workflow.contains("push:"));
    assert!(!workflow.contains("pull-requests: write"));
}
