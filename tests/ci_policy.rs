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

#[test]
fn live_collector_smoke_is_manual_read_only_and_secret_free() {
    let path = format!("{WORKFLOWS}/live-collector-smoke.yml");
    let workflow = fs::read_to_string(&path).expect("live collector smoke workflow");
    let triggers: Vec<&str> = workflow
        .split("\non:\n")
        .nth(1)
        .and_then(|rest| rest.split("\n\n").next())
        .expect("an `on:` block")
        .lines()
        .map(str::trim)
        .collect();
    assert_eq!(
        triggers,
        ["workflow_dispatch:"],
        "{path}: manual dispatch only"
    );
    assert!(
        workflow.contains("permissions:\n  contents: read\n"),
        "{path}: read-only token"
    );
    for forbidden in ["secrets.", "uses:", ": write", "id-token:", "github_token"] {
        assert!(
            !workflow.to_ascii_lowercase().contains(forbidden),
            "{path} must not contain {forbidden:?}"
        );
    }
    let script = fs::read_to_string(".github/scripts/live-collector-smoke.sh").expect("script");
    assert!(
        script.contains("unset HIBP_API_KEY"),
        "the smoke unsets keys"
    );
    for module in [
        "github_user",
        "crates_io",
        "hacker_news",
        "lobsters",
        "docker_hub_user",
        "wikidata",
        "peeringdb",
    ] {
        assert!(
            script.contains(&format!("|{module}\"")),
            "no probe for {module}"
        );
    }
}

#[test]
fn live_smoke_verdict_requires_actual_source_success() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let out = std::env::temp_dir().join(format!("huntsman-smoke-{}-{nonce}", std::process::id()));
    fs::create_dir_all(&out).expect("output directory");

    for (probe, text) in [
        (
            "user-dtolnay",
            "github_user\tsuccess\t1\ncrates_io\tsuccess\t1\n",
        ),
        ("user-pg", "hacker_news\tsuccess\t1\n"),
        ("user-jcs", "lobsters\tsuccess\t1\n"),
        ("user-torvalds", "docker_hub_user\tsuccess\t1\n"),
        ("wikidata-q42", "wikidata\tsuccess\t1\n"),
        ("asn-13335", "peeringdb\tsuccess\t1\n"),
    ] {
        fs::write(out.join(format!("{probe}.out")), text).expect("fixture");
        fs::write(out.join(format!("{probe}.exit")), "0\n").expect("status");
    }

    let run = || {
        Command::new("bash")
            .arg(".github/scripts/live-collector-smoke.sh")
            .arg("unused-binary")
            .arg(&out)
            .output()
            .expect("Bash verdict")
    };
    let positive = run();
    assert!(
        positive.status.success(),
        "{}",
        String::from_utf8_lossy(&positive.stdout)
    );
    let verdict = fs::read_to_string(out.join("verdict.tsv")).expect("verdict");
    assert_eq!(
        verdict
            .lines()
            .filter(|row| row.contains("\tPASS\t"))
            .count(),
        7
    );

    // A success row cannot override a failed CLI process.
    fs::write(out.join("user-jcs.exit"), "1\n").expect("nonzero exit fixture");
    let nonzero = run();
    assert!(
        !nonzero.status.success(),
        "nonzero exit must invalidate success"
    );
    let verdict = fs::read_to_string(out.join("verdict.tsv")).expect("exit verdict");
    assert!(verdict.contains("lobsters\tuser-jcs\tFAIL\texit=1"));
    fs::write(out.join("user-jcs.exit"), "0\n").expect("restore success exit");

    fs::write(out.join("wikidata-q42.out"), "Q42 lookup failed\n").expect("negative wikidata");
    fs::write(out.join("asn-13335.out"), "PeeringDB unavailable\n").expect("negative peeringdb");
    let negative = run();
    assert!(!negative.status.success(), "false positives are not PASS");
    let verdict = fs::read_to_string(out.join("verdict.tsv")).expect("negative verdict");
    assert!(verdict.contains("wikidata\twikidata-q42\tFAIL\t"));
    assert!(verdict.contains("peeringdb\tasn-13335\tFAIL\t"));
    fs::write(
        out.join("wikidata-q42.out"),
        "other_wikidata\tsuccess\tQ42\nwikidata\tfailure\tQ42\n",
    )
    .expect("mismatched module/status fixture");
    let mismatched = run();
    assert!(
        !mismatched.status.success(),
        "wrong source/status must fail"
    );
    fs::remove_dir_all(&out).expect("remove fixture");
}
