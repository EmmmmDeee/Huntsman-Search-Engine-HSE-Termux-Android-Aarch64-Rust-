//! Behaviour of `xtask issue-fix publish`. Each case gets a bare remote whose main is a fixture base
//! commit, and a clone of it that publish runs in, as the workflow's publish job does. The patch is
//! made from the clone, the way capture makes one. Publish runs in DRY_RUN mode unless a case says
//! otherwise, and a fake gh records what a real pull request would be asked for.
//!
//! The path policy is the guard's rule set, which publish calls in-process. The cases that name its
//! refusal ("check-protected: refused") test that call. The guard is the other work package's, so
//! those cases are the first to fail while its port is missing.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const REPO: &str = "fixture/fixture";
const BRANCH: &str = "refs/heads/ai-fix/issue-42";

/// A directory that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("publish-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("the scratch directory can be made");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// One case: the bare remote, the clone publish runs in, the base commit, and the issue and change.
struct Case {
    _scratch: Scratch,
    bare: PathBuf,
    clone: PathBuf,
    base: String,
    issue: PathBuf,
    change: PathBuf,
}

/// Runs git with the machine's configuration kept out, and returns its trimmed standard output.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .output()
        .expect("git must run");
    assert!(
        output.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned()
}

fn write(root: &Path, name: &str, content: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().expect("a file has a parent")).expect("the parent directory");
    fs::write(path, content).expect("the fixture file can be written");
}

/// A base commit with the files the policy cares about, pushed to a bare remote as main, and cloned.
fn new_case(name: &str) -> Case {
    let scratch = Scratch::new(name);
    let root = scratch.path();
    let repo = root.join("repo");
    fs::create_dir_all(&repo).expect("the repository directory");
    git(&repo, &["init", "-q", "-b", "main"]);
    write(&repo, "Cargo.toml", "[package]\nname = \"fixture\"\n");
    write(&repo, "src/lib.rs", "pub fn a() {}\n");
    write(
        &repo,
        "src/tested.rs",
        "pub fn c() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn c_is_one() {\n        assert_eq!(super::c(), 1);\n    }\n}\n",
    );
    write(&repo, "tests/existing.rs", "use fixture::a;\n");
    write(&repo, "xtask/src/gate.rs", "fn main() {}\n");
    git(&repo, &["add", "-A"]);
    git(&repo, &["commit", "-q", "-m", "base"]);
    let base = git(&repo, &["rev-parse", "HEAD"]);

    let bare = root.join("remote.git");
    let clone = root.join("clone");
    git(root, &["init", "-q", "--bare", path_str(&bare)]);
    git(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    git(
        &repo,
        &["push", "-q", path_str(&bare), "HEAD:refs/heads/main"],
    );
    git(root, &["clone", "-q", path_str(&bare), path_str(&clone)]);

    let issue = root.join("issue.json");
    fs::write(
        &issue,
        r#"{"number": 42, "title": "dns: blank target", "body": "Steps: run recon dns on a blank target.", "state": "OPEN"}"#,
    )
    .expect("the issue can be written");
    let change = root.join("change");
    fs::create_dir_all(&change).expect("the change directory");
    Case {
        _scratch: scratch,
        bare,
        clone,
        base,
        issue,
        change,
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("the fixture paths are UTF-8")
}

/// Makes the change's patch from the clone, as capture does: the edit is staged and diffed against
/// the base, and the clone is reset afterwards.
fn make_patch(case: &Case, edit: impl FnOnce(&Path)) {
    edit(&case.clone);
    git(&case.clone, &["add", "-A"]);
    let output = Command::new("git")
        .args([
            "diff",
            "--cached",
            "--binary",
            "--full-index",
            "--no-ext-diff",
            "--no-textconv",
            case.base.as_str(),
            "--",
        ])
        .current_dir(&case.clone)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("git must run");
    assert!(output.status.success());
    fs::write(case.change.join("change.patch"), output.stdout).expect("the patch can be written");
    git(&case.clone, &["reset", "-q", "--hard", &case.base]);
    git(&case.clone, &["clean", "-fdq"]);
}

fn new_test_file(clone: &Path) {
    write(clone, "tests/issue_fix_42.rs", "#[test]\nfn t() {}\n");
}

/// The publish command for CASE, in the clone, with the environment the workflow sets: the repository,
/// the gated commit, the bare remote in place of origin, and a dry run.
fn publish_command(case: &Case) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
    command
        .args(["issue-fix", "publish"])
        .arg(&case.issue)
        .arg(&case.change)
        .current_dir(&case.clone)
        .env("REPO", REPO)
        .env("GATED_SHA", &case.base)
        .env("REMOTE_URL", &case.bare)
        .env("DRY_RUN", "1")
        .env_remove("PUSH_TOKEN")
        .env_remove("GH_TOKEN")
        .env_remove("HAS_PAT");
    command
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The commit at a ref of the bare remote, or None when the ref does not exist there.
fn remote_ref(case: &Case, name: &str) -> Option<String> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(&case.bare)
        .args(["rev-parse", "-q", "--verify", name])
        .output()
        .expect("git must run");
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// A `gh` that records its arguments in ARGS and its standard input in BODY, and exits with 0. Its
/// directory is put first on the PATH, so a publish that calls gh is seen.
fn fake_gh(dir: &Path) -> PathBuf {
    let bin = dir.join("gh-bin");
    fs::create_dir_all(&bin).expect("the fake bin directory");
    let gh = bin.join("gh");
    fs::write(
        &gh,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ARGS\"\ncat >> \"$BODY\"\n",
    )
    .expect("the fake gh can be written");
    fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).expect("the fake gh is executable");
    bin
}

// The cases below run before the policy, so they hold with or without the guard's port.

#[test]
fn publish_needs_the_repository() {
    let case = new_case("no-repo");
    make_patch(&case, new_test_file);
    let output = publish_command(&case)
        .env_remove("REPO")
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("publish: REPO must be set"),
        "{}",
        stderr(&output)
    );
    assert_eq!(remote_ref(&case, BRANCH), None);
}

#[test]
fn publish_needs_the_commit_the_gate_tested() {
    let case = new_case("no-gated");
    make_patch(&case, new_test_file);
    let output = publish_command(&case)
        .env_remove("GATED_SHA")
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("GATED_SHA must name the commit the gate tested"));
    assert_eq!(remote_ref(&case, BRANCH), None);
}

#[test]
fn publish_refuses_when_main_is_not_the_gated_commit() {
    let case = new_case("moved");
    make_patch(&case, new_test_file);
    let output = publish_command(&case)
        .env("GATED_SHA", "0123456789abcdef0123456789abcdef01234567")
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("the gate tested"),
        "{}",
        stderr(&output)
    );
    assert_eq!(remote_ref(&case, BRANCH), None);
}

#[test]
fn publish_never_overwrites_an_existing_remote_branch() {
    let case = new_case("existing");
    make_patch(&case, new_test_file);
    git(&case.bare, &["update-ref", BRANCH, &case.base]);
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("already exists"),
        "{}",
        stderr(&output)
    );
    assert_eq!(
        remote_ref(&case, BRANCH).as_deref(),
        Some(case.base.as_str())
    );
}

#[test]
fn publish_refuses_an_empty_patch() {
    let case = new_case("empty");
    fs::write(case.change.join("change.patch"), b"").expect("the empty patch");
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("there is no patch at"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn publish_refuses_a_patch_that_does_not_apply() {
    let case = new_case("garbage");
    fs::write(case.change.join("change.patch"), b"not a patch\n").expect("the patch");
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("the patch does not apply to"),
        "{}",
        stderr(&output)
    );
    assert_eq!(remote_ref(&case, BRANCH), None);
}

#[test]
fn publish_needs_a_push_token_to_push_to_origin() {
    let case = new_case("no-token");
    make_patch(&case, new_test_file);
    let output = publish_command(&case)
        .env_remove("REMOTE_URL")
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("PUSH_TOKEN must be set"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn publish_refuses_when_the_remote_cannot_be_read() {
    let case = new_case("unreadable-remote");
    make_patch(&case, new_test_file);
    let output = publish_command(&case)
        .env("REMOTE_URL", "/nonexistent/remote.git")
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("could not read the remote heads (exit 128)"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn publish_stops_when_a_local_branch_of_that_name_already_exists() {
    let case = new_case("local-branch");
    make_patch(&case, new_test_file);
    git(&case.clone, &["branch", "ai-fix/issue-42"]);
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("checkout -q -b ai-fix/issue-42"),
        "{}",
        stderr(&output)
    );
    assert_eq!(remote_ref(&case, BRANCH), None);
}

#[test]
fn a_non_numeric_issue_number_is_refused() {
    let case = new_case("number");
    make_patch(&case, new_test_file);
    fs::write(&case.issue, r#"{"number": "4x", "title": "t"}"#).expect("the issue");
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("publish: issue number is not numeric: 4x"));
}

#[test]
fn malformed_issue_json_is_a_usage_error() {
    let case = new_case("malformed");
    make_patch(&case, new_test_file);
    fs::write(&case.issue, "{").expect("the issue");
    let output = publish_command(&case).output().expect("xtask must run");
    assert_eq!(output.status.code(), Some(64));
}

#[test]
fn publish_needs_exactly_two_arguments() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "publish", "only-one"])
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(64));
}

// The cases below need the guard's port: publish checks the staged change with it before it commits.

#[test]
fn publish_pushes_the_branch_with_its_subject_and_stops_at_a_dry_run() {
    let case = new_case("push");
    make_patch(&case, new_test_file);
    let output = publish_command(&case).output().expect("xtask must run");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("publish: dry run pushed ai-fix/issue-42 and skipped the pull request"),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let subject = git(&case.bare, &["log", "-1", "--format=%s", BRANCH]);
    assert_eq!(subject, "Fix #42: dns: blank target");
}

#[test]
fn a_dry_run_makes_no_gh_call() {
    let case = new_case("dry-gh");
    make_patch(&case, new_test_file);
    let bin = fake_gh(case.change.parent().expect("the change has a parent"));
    let args = case.change.parent().expect("parent").join("gh-args.txt");
    let body = case.change.parent().expect("parent").join("gh-body.txt");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = publish_command(&case)
        .env("PATH", path)
        .env("ARGS", &args)
        .env("BODY", &body)
        .output()
        .expect("xtask must run");
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!args.exists(), "a dry run must not call gh");
}

#[test]
fn publish_opens_the_pull_request_with_its_body_on_standard_input() {
    let case = new_case("pr");
    make_patch(&case, new_test_file);
    fs::write(
        case.change.join("agent.json"),
        r#"{"result": "added the test"}"#,
    )
    .expect("agent output");
    let scratch = case.change.parent().expect("parent").to_path_buf();
    let bin = fake_gh(&scratch);
    let args = scratch.join("gh-args.txt");
    let body = scratch.join("gh-body.txt");
    let path = format!(
        "{}:{}",
        bin.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = publish_command(&case)
        .env_remove("DRY_RUN")
        .env("PATH", path)
        .env("ARGS", &args)
        .env("BODY", &body)
        .output()
        .expect("xtask must run");
    assert!(output.status.success(), "{}", stderr(&output));
    let args = fs::read_to_string(&args).expect("gh was called");
    assert_eq!(
        args.trim_end(),
        "pr create --repo fixture/fixture --base main --head ai-fix/issue-42 --title Fix #42: dns: blank target --body-file -"
    );
    let body = fs::read_to_string(&body).expect("the body was sent");
    assert!(
        body.starts_with("Closes #42\n\n## Model summary (unreviewed)\n\nadded the test\n\n"),
        "{body}"
    );
    assert!(
        body.contains("workflow token. GitHub does not start CI"),
        "{body}"
    );
    assert!(remote_ref(&case, BRANCH).is_some());
}

#[test]
fn publish_refuses_a_change_the_policy_refuses_and_pushes_nothing() {
    let case = new_case("policy");
    make_patch(&case, |clone| {
        write(clone, "tests/existing.rs", "use fixture::a; // weaker\n");
    });
    let output = publish_command(&case).output().expect("xtask must run");
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("check-protected: refused"),
        "{}",
        stderr(&output)
    );
    assert_eq!(remote_ref(&case, BRANCH), None);
}
