#[path = "support/executable.rs"]
mod executable;

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

/// Every workflow file, and every composite action's `action.yml`.
fn workflow_and_action_files() -> Vec<std::path::PathBuf> {
    let yaml = |path: &std::path::Path| {
        path.extension()
            .is_some_and(|ext| ext == "yml" || ext == "yaml")
    };
    let mut files: Vec<_> = fs::read_dir(WORKFLOWS)
        .expect("workflow directory")
        .map(|entry| entry.expect("workflow entry").path())
        .filter(|path| yaml(path))
        .collect();
    for action in fs::read_dir(".github/actions").expect("actions directory") {
        let dir = action.expect("action entry").path();
        for name in ["action.yml", "action.yaml"] {
            if dir.join(name).is_file() {
                files.push(dir.join(name));
            }
        }
    }
    files.sort();
    files
}

/// One job of a workflow: from its `  <id>:` line to the next line indented two spaces that
/// starts another key.
fn job<'a>(workflow: &'a str, id: &str) -> &'a str {
    let start = workflow
        .find(&format!("\n  {id}:\n"))
        .unwrap_or_else(|| panic!("no job {id}"))
        + 1;
    let body = &workflow[start..];
    let end = body
        .match_indices("\n  ")
        .map(|(at, _)| at)
        .find(|&at| body[at + 3..].starts_with(|c: char| c.is_ascii_alphanumeric()))
        .unwrap_or(body.len());
    &body[..end]
}

/// On 2026-11-05 a runner's Ubuntu mirror trickled for fourteen minutes inside one package
/// install, and nothing bounded the step or its job, so the run waited for a person to cancel
/// it. apt runs only through the installer that bounds and retries each attempt, and the job
/// that runs it has a time limit.
#[test]
fn apt_runs_only_through_the_bounded_installer_in_a_job_with_a_time_limit() {
    for path in workflow_and_action_files() {
        let text = fs::read_to_string(&path).expect("workflow");
        for line in text.lines() {
            assert!(
                !line.contains("apt-get") && !line.contains("apt install"),
                "{}: install packages through scripts/apt-install-retry.sh, which bounds and \
                 retries each attempt: {}",
                path.display(),
                line.trim()
            );
        }
    }
    let ci = fs::read_to_string(CI).expect("CI workflow");
    let qemu = job(&ci, "aarch64-tests");
    assert!(
        qemu.contains(
            "run: bash scripts/apt-install-retry.sh gcc-aarch64-linux-gnu \
             libc6-dev-arm64-cross qemu-user"
        ),
        "the qemu job installs its toolchain through the bounded installer:\n{qemu}"
    );
    assert!(
        qemu.lines()
            .any(|line| line.starts_with("    timeout-minutes: ")),
        "the qemu job has a time limit:\n{qemu}"
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
    // The sweep reads every keyless networked module from the binary's own registry, and the web
    // server is exercised only on loopback (rootless, never a public bind).
    assert!(
        script.contains("\"$bin\" modules --json"),
        "sweep uses the module registry"
    );
    assert!(
        script.contains("serve --bind \"127.0.0.1:$port\""),
        "serve is exercised on loopback"
    );
    // The web UI is checked through the flows the page itself drives, not only its health.
    for flow in [
        "X-Huntsman-Lookup: 1",
        "/api/scans?target=",
        "/elements",
        "/export?format=csv",
        "web-ui-flow",
        "ui-content",
        "graph-dangling-edges",
    ] {
        assert!(script.contains(flow), "the UI smoke lacks {flow:?}");
    }
    for command in [
        "username ",
        "people ",
        "domain ",
        "ip ",
        "email ",
        "netblock ",
        "crypto ",
        "geocode ",
        "gleif ",
        "itunes ",
        "query ",
        "recon crtsh ",
        "recon dns ",
        "public-osint web ",
        "public-osint news ",
        "asn ",
        "wikidata ",
    ] {
        assert!(
            script.contains(&format!("|{command}")),
            "no sweep probe runs `{command}`"
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

/// A status token may carry digits (`upstream4xx`, `upstream5xx`); the sweep must read those
/// rows as the module's FAIL, never report the module as having printed no status at all.
#[test]
fn live_smoke_sweep_reads_status_tokens_with_digits() {
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("huntsman-sweep-{}-{nonce}", std::process::id()));
    let out = dir.join("out");
    fs::create_dir_all(&out).expect("output directory");
    let fake = dir.join("fake-binary");
    executable::write_executable(
        &fake,
        r#"#!/usr/bin/env bash
case "$1" in
  modules) printf '%s' '{"count":3,"modules":[
    {"name":"submd","network":true,"access":"keyless"},
    {"name":"common_crawl","network":true,"access":"keyless"},
    {"name":"crtsh","network":true,"access":"keyless"}]}' ;;
  domain) printf 'submd\tupstream4xx\tfound=none\tdetail=HTTP 429\n'
          printf 'common_crawl\tupstream5xx\tfound=none\n'
          printf 'crtsh\tsuccess\tfound=3\n' ;;
  serve) exit 0 ;;
esac
exit 0
"#,
        0o755,
    );

    Command::new("bash")
        .arg(".github/scripts/live-collector-smoke.sh")
        .arg(&fake)
        .arg(&out)
        .output()
        .expect("sweep");
    let sweep = fs::read_to_string(out.join("sweep.tsv")).expect("sweep table");
    let row = |module: &str| {
        sweep
            .lines()
            .find(|line| line.starts_with(&format!("{module}\t")))
            .unwrap_or_else(|| panic!("no {module} row in\n{sweep}"))
            .to_owned()
    };
    assert!(
        row("submd").starts_with("submd\tFAIL\tupstream4xx\t"),
        "{sweep}"
    );
    assert!(
        row("common_crawl").starts_with("common_crawl\tFAIL\tupstream5xx\t"),
        "{sweep}"
    );
    assert!(
        row("crtsh").starts_with("crtsh\tPASS\tsuccess\t"),
        "{sweep}"
    );
    assert!(sweep.contains("live-PASS: 1/3"), "{sweep}");
    fs::remove_dir_all(&dir).ok();
}
