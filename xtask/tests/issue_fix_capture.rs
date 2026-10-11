//! The issue-fix capture, `xtask issue-fix capture BASE OUT_DIR`. Each case of the shell self-check
//! (scripts/issue-fix/self-check.sh) that covers the capture is a test here, named after the
//! case's label, and the cases that the guard shares with the capture are checked for the capture
//! too. The output directory of each capture is outside the repository, so the capture never
//! sees its own output as a change.

mod common;

use std::path::Path;
use std::process::Command;

use common::{Repo, Scratch};

/// Runs `git ARGS` in DIR with no global configuration, for the clone and the apply.
fn git_in(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git must run")
}

/// The stderr of an output, as text.
fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn capture_round_trips_a_new_test_file_through_a_patch() {
    let repo = Repo::new("capture-round-trips-a-new-test-file-through-a-patch");
    let scratch = Scratch::new("capture-round-trip");
    let out = scratch.path().join("change-rt");
    repo.write("tests/issue_fix_1.rs", "#[test]\nfn t() {}\n");
    let output = repo.capture(&out.display().to_string());
    assert!(
        output.status.success(),
        "capture refused a changed tree: {}",
        stderr(&output)
    );
    let patch = out.join("change.patch");
    let size = std::fs::metadata(&patch)
        .expect("the patch must exist")
        .len();
    assert!(size > 0, "capture wrote no patch");
    let expected = format!(
        "capture: wrote {size} bytes to {}/change.patch\n",
        out.display()
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), expected);

    let clone = scratch.path().join("clone");
    let cloned = Command::new("git")
        .args(["clone", "-q"])
        .arg(repo.root())
        .arg(&clone)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git must run");
    assert!(cloned.status.success(), "{}", stderr(&cloned));
    let applied = git_in(&clone, &["apply", "--index", &patch.display().to_string()]);
    assert!(
        applied.status.success(),
        "the patch does not apply: {}",
        stderr(&applied)
    );
    assert!(
        clone.join("tests/issue_fix_1.rs").is_file(),
        "the captured patch does not reproduce the new test"
    );
}

#[test]
fn capture_refuses_an_unchanged_tree() {
    let repo = Repo::new("capture-refuses-an-unchanged-tree");
    let scratch = Scratch::new("capture-none");
    let out = scratch.path().join("change-none");
    let output = repo.capture(&out.display().to_string());
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    let expected = format!("capture: the agent left no changes against {}", repo.base());
    assert!(stderr(&output).contains(&expected), "{}", stderr(&output));
}

#[test]
fn capture_refuses_a_base_that_is_not_a_commit() {
    let repo = Repo::new("capture-refuses-a-base-that-is-not-a-commit");
    let scratch = Scratch::new("capture-bad-base");
    let out = scratch.path().join("change-bad");
    repo.write("tests/issue_fix_1.rs", "#[test]\nfn t() {}\n");
    let output = common::xtask(
        repo.root(),
        &[
            "issue-fix",
            "capture",
            "not-a-real-commit",
            &out.display().to_string(),
        ],
    );
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("git diff failed (exit 128) against not-a-real-commit"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn capture_is_a_usage_error_without_its_two_arguments() {
    let repo = Repo::new("capture-is-a-usage-error-without-its-two-arguments");
    let output = common::xtask(repo.root(), &["issue-fix", "capture", repo.base()]);
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
    let output = common::xtask(repo.root(), &["issue-fix", "capture"]);
    assert_eq!(output.status.code(), Some(64), "{}", stderr(&output));
}

#[test]
fn a_filter_named_by_gitattributes_does_not_run_during_the_capture() {
    let repo = Repo::new("a-filter-named-by-gitattributes-does-not-run-during-the-capture");
    let scratch = Scratch::new("filter-capture");
    let marker = scratch.path().join("filter-ran");
    let out = scratch.path().join("change-filter");
    let filter = format!("touch '{}'; cat", marker.display());
    // The control: a plain git add runs the filter, so the check below proves something.
    repo.git(&["config", "filter.evil.clean", &filter]);
    repo.write("src/.gitattributes", "*.rs filter=evil\n");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    repo.git(&["add", "src/lib.rs"]);
    assert!(marker.exists(), "the control did not run the filter");
    std::fs::remove_file(&marker).expect("the marker must be removed");
    repo.reset();
    repo.write("src/.gitattributes", "*.rs filter=evil\n");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    let output = repo.capture(&out.display().to_string());
    assert!(
        output.status.success(),
        "capture refused a plain edit under the filter: {}",
        stderr(&output)
    );
    assert!(!marker.exists(), "a filter ran during the capture");
}

#[test]
fn a_filter_in_info_attributes_and_a_fsmonitor_program_do_not_run_during_the_capture() {
    let repo = Repo::new("a-filter-in-info-attributes-and-a-fsmonitor-program-do-not-run-capture");
    let scratch = Scratch::new("info-capture");
    let info_marker = scratch.path().join("info-filter-ran");
    let fsmon_marker = scratch.path().join("fsmon-ran");
    let fsmon_script = scratch.path().join("fsmon.sh");
    let out = scratch.path().join("change-info");
    let fsmon_text = format!("#!/bin/sh\ntouch {}\nexit 0\n", fsmon_marker.display());
    std::fs::write(&fsmon_script, fsmon_text).expect("the program must be written");
    set_executable(&fsmon_script);
    let fsmon = fsmon_script.display().to_string();
    let filter = format!("touch '{}'; echo REPLACED", info_marker.display());

    repo.reset();
    repo.git(&["config", "filter.evil.clean", &filter]);
    repo.git(&["config", "core.fsmonitor", &fsmon]);
    std::fs::write(
        repo.root().join(".git/info/attributes"),
        "*.rs filter=evil\n",
    )
    .expect("attributes must be written");
    repo.write("src/lib.rs", "pub fn a() {}\npub fn b() {}\n");
    let output = repo.capture(&out.display().to_string());
    assert!(
        output.status.success(),
        "capture refused a plain edit: {}",
        stderr(&output)
    );
    assert!(
        !info_marker.exists() && !fsmon_marker.exists(),
        "a program in the agent's repository ran during the capture"
    );
    let patch = std::fs::read_to_string(out.join("change.patch")).expect("the patch must exist");
    assert!(
        patch.contains("pub fn b() {}"),
        "the patch does not carry the edit itself"
    );
    assert!(
        !patch.contains("REPLACED"),
        "the patch carries the output of a filter"
    );
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .expect("the program must exist")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).expect("the program must be made executable");
}
