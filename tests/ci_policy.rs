use std::fs;

const CI: &str = ".github/workflows/ci.yml";
const WORKFLOWS: &str = ".github/workflows";

/// The runner image every job names. A `-latest` label moves to a new release on GitHub's
/// schedule, changing the compilers, the container runtime and the preinstalled Android NDK the
/// release binaries link against without a commit here. Moving to a new image is a reviewed
/// change: update this and every `runs-on:` together.
const RUNNER: &str = "ubuntu-24.04";

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
        "Dockerfile",
    ] {
        assert!(ci.contains(required), "{CI} must contain {required:?}");
    }
    assert!(!ci.contains("railway"), "provider-specific jobs must be removed");
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
        for runner in runners {
            assert_eq!(
                runner,
                RUNNER,
                "{}: every job must name the runner image {RUNNER}",
                path.display()
            );
        }
    }
}
