//! The Claude Code harness this repository ships: `.claude/settings.json`, the
//! hooks it registers, the subagent definitions, and the gate receipt that
//! the pre-push hook enforces (REQ-HARNESS-001).
//!
//! Every mechanism here failed silently before. The pre-push gate was
//! registered under `StopBeforePush`, which is not a Claude Code hook event,
//! so it never ran. The permission list sat under `allowlist`, which is not a
//! settings key, so nothing was allowed. The one subagent file had no
//! frontmatter, so it was skipped as documentation. Claude Code tolerates all
//! three. It drops the entry, keeps the rest of the file and says nothing in
//! a normal session. So nothing but these tests notices when one comes back.
//!
//! The receipt and hook tests drive the real scripts. `scripts/gate-receipt.sh`
//! is copied into a throwaway git repository, and `.claude/hooks/pre-push-gate.sh`
//! runs from this checkout on JSON shaped like Claude Code's `PreToolUse`
//! input.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

// ─── Fixture: a throwaway checkout that has the receipt script ──────────────

/// A git repository in a temp dir, isolated from the host's git config, with
/// `scripts/gate-receipt.sh` copied in so the hook treats it as an HSE
/// checkout.
struct Repo {
    dir: tempfile::TempDir,
    /// `HOME` for every command, outside the repository so nothing git or a
    /// test writes there can end up in a tree.
    home: tempfile::TempDir,
}

impl Repo {
    fn new() -> Self {
        Self::with_receipts(Self::bare())
    }

    /// An HSE-shaped checkout whose path contains spaces, as a real one can.
    fn spaced() -> Self {
        Self::with_receipts(Self::bare_in(
            tempfile::Builder::new()
                .prefix("hse repo with spaces ")
                .tempdir()
                .expect("temp dir"),
        ))
    }

    fn with_receipts(repo: Self) -> Self {
        let scripts = repo.path().join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        fs::copy(
            root().join("scripts/gate-receipt.sh"),
            scripts.join("gate-receipt.sh"),
        )
        .unwrap();
        assert!(
            is_executable(&scripts.join("gate-receipt.sh")),
            "scripts/gate-receipt.sh must be committed executable"
        );
        repo
    }

    /// A repository without the receipt script: not an HSE checkout, or one
    /// from before receipts existed.
    fn bare() -> Self {
        Self::bare_in(tempfile::tempdir().expect("temp dir"))
    }

    fn bare_in(dir: tempfile::TempDir) -> Self {
        let repo = Self {
            dir,
            home: tempfile::tempdir().expect("temp dir"),
        };
        repo.write("README.md", "fixture\n");
        repo.write(".gitignore", "ignored.txt\n");
        repo.git(&["init", "-q", "-b", "main"]);
        repo.commit_all("init");
        repo
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn home(&self) -> &Path {
        self.home.path()
    }

    fn write(&self, rel: &str, body: &str) {
        let p = self.path().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    /// Run a command in `dir` with the host's git configuration shut out, so
    /// a signing key or hook in the developer's global config cannot change
    /// the outcome.
    fn cmd(&self, program: &str, dir: &Path) -> Command {
        let mut c = Command::new(program);
        c.current_dir(dir)
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.home())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .env_remove("HSE_PUSH_GATE")
            // The hook reads the session's project directory; a test run
            // inside a Claude Code session inherits the real one.
            .env_remove("CLAUDE_PROJECT_DIR")
            .env_remove("GIT_DIR")
            .env_remove("GIT_INDEX_FILE")
            .env_remove("GIT_WORK_TREE");
        c
    }

    fn git_in(&self, dir: &Path, args: &[&str]) -> String {
        let out = self
            .cmd("git", dir)
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git must be installed");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn git(&self, args: &[&str]) -> String {
        self.git_in(self.path(), args)
    }

    fn commit_all(&self, msg: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", msg]);
    }

    fn tree_of(&self, rev: &str) -> String {
        self.git(&["rev-parse", &format!("{rev}^{{tree}}")])
    }

    /// `scripts/gate-receipt.sh <args>` run in `dir`.
    fn receipt_in(&self, dir: &Path, args: &[&str]) -> Output {
        self.cmd("bash", dir)
            .arg(self.path().join("scripts/gate-receipt.sh"))
            .args(args)
            .output()
            .expect("bash")
    }

    fn receipt(&self, args: &[&str]) -> Output {
        self.receipt_in(self.path(), args)
    }

    fn worktree_tree(&self) -> String {
        let out = self.receipt(&["tree"]);
        assert!(out.status.success(), "tree failed: {}", text(&out.stderr));
        text(&out.stdout).trim().to_string()
    }

    /// Record a passing quick gate for the tree the working tree has now.
    fn record_pass(&self) {
        let tree = self.worktree_tree();
        let out = self.receipt(&["record", "quick", &tree, "3", "0", "1"]);
        assert!(out.status.success(), "record failed: {}", text(&out.stderr));
        assert!(
            text(&out.stdout).contains("recorded for tree"),
            "a clean pass must record a receipt, got: {}",
            text(&out.stdout)
        );
    }

    /// The pre-push hook, run as Claude Code runs it: from `cwd`, with the
    /// `PreToolUse` JSON on stdin.
    fn hook_with(&self, cwd: &Path, command: &str, gate_env: Option<&str>) -> Output {
        self.hook_described(cwd, command, "push it", gate_env)
    }

    /// [`Self::hook_with`] with a chosen `description`, so a test can make the
    /// JSON larger than a pipe buffer. The write is strict (`unwrap`): a hook
    /// that exits without draining its stdin closes the pipe under the writer,
    /// and that must fail here rather than pass by luck of scheduling.
    fn hook_described(
        &self,
        cwd: &Path,
        command: &str,
        description: &str,
        gate_env: Option<&str>,
    ) -> Output {
        self.hook_full(cwd, command, description, gate_env, None)
    }

    /// The hook as a session whose project is `project` (`CLAUDE_PROJECT_DIR`)
    /// runs it, from `cwd`.
    fn hook_in_project(&self, cwd: &Path, command: &str, project: &Path) -> Output {
        self.hook_full(cwd, command, "push it", None, Some(project))
    }

    fn hook_full(
        &self,
        cwd: &Path,
        command: &str,
        description: &str,
        gate_env: Option<&str>,
        project: Option<&Path>,
    ) -> Output {
        use std::io::Write;
        let input = serde_json::json!({
            "session_id": "test",
            "cwd": cwd,
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": command, "description": description },
        });
        let mut c = self.cmd("bash", cwd);
        c.arg(root().join(".claude/hooks/pre-push-gate.sh"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(v) = gate_env {
            c.env("HSE_PUSH_GATE", v);
        }
        if let Some(p) = project {
            c.env("CLAUDE_PROJECT_DIR", p);
        }
        let mut child = c.spawn().expect("bash");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn hook(&self, command: &str) -> Output {
        self.hook_with(self.path(), command, None)
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

#[track_caller]
fn assert_blocked(out: &Output, what: &str) {
    assert_eq!(
        code(out),
        2,
        "{what}: expected the push to be refused (exit 2)\nstderr: {}",
        text(&out.stderr)
    );
    assert!(
        text(&out.stderr).contains("scripts/gate.sh --quick"),
        "{what}: the refusal must name the command that fixes it\nstderr: {}",
        text(&out.stderr)
    );
}

#[track_caller]
fn assert_allowed(out: &Output, what: &str) {
    assert_eq!(
        code(out),
        0,
        "{what}: expected the command to pass the hook\nstderr: {}",
        text(&out.stderr)
    );
}

// ─── scripts/gate-receipt.sh ────────────────────────────────────────────────

#[test]
fn the_tree_of_a_clean_checkout_is_its_head_tree() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    assert_eq!(repo.worktree_tree(), repo.tree_of("HEAD"));
}

/// REQ-HARNESS-005. git re-hashes a file whose stat data looks unchanged only
/// when the file is "racily clean": its mtime is not older than the index
/// file's own mtime. `tree` worked on a copy of the index, and a plain `cp`
/// gave the copy a fresh mtime. So a file rewritten at the same size in the
/// same timestamp tick as the last index write was re-hashed by `git commit`
/// but not by the receipt, and the receipt named a tree nobody committed. It
/// failed 2 runs in 12 of this suite by chance. This recreates that stat state
/// on purpose: same size, mtime restored, ctime ignored, index as old as the
/// file.
#[test]
fn the_tree_matches_what_git_commits_for_a_racily_clean_file() {
    let repo = Repo::new();
    repo.git(&["config", "core.trustctime", "false"]);
    let readme = repo.path().join("README.md");
    // A fixed time well in the past. If the file's mtime shares a tick with
    // the index write below, git "smudges" the entry (zeroes its recorded
    // size) and every later read re-hashes it, which hides the defect. An old
    // mtime rules that out, so the outcome no longer depends on timing.
    let then = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_600_000_000);
    let set_mtime = |p: &Path| {
        fs::File::options()
            .write(true)
            .open(p)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(then))
            .unwrap();
    };
    set_mtime(&readme);
    repo.commit_all("add the receipt script");

    // Same byte count as "fixture\n", so size cannot give the change away.
    fs::write(&readme, "checked\n").unwrap();
    set_mtime(&readme);
    set_mtime(&repo.path().join(".git/index"));

    let tree = repo.worktree_tree();
    repo.commit_all("what git commits");
    assert_eq!(
        repo.git(&["show", "HEAD:README.md"]),
        "checked",
        "precondition: git itself saw the change"
    );
    assert_eq!(
        tree,
        repo.tree_of("HEAD"),
        "the receipt's tree must be the tree git commits"
    );
}

#[test]
fn the_tree_is_what_committing_everything_would_record_and_the_index_is_untouched() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    repo.write("README.md", "edited\n");
    repo.write("new.txt", "untracked, not ignored\n");
    repo.write("ignored.txt", "ignored\n");
    let status_before = repo.git(&["status", "--porcelain"]);

    let tree = repo.worktree_tree();

    assert_ne!(tree, repo.tree_of("HEAD"), "edits must change the tree");
    assert_eq!(
        repo.git(&["status", "--porcelain"]),
        status_before,
        "computing the tree must not stage anything in the real index"
    );
    assert_eq!(repo.git(&["diff", "--cached", "--name-only"]), "");

    repo.commit_all("everything");
    assert_eq!(
        tree,
        repo.tree_of("HEAD"),
        "the gate's tree must equal the tree of the commit made from what it checked"
    );
}

#[test]
fn a_receipt_is_written_only_for_a_clean_pass_on_an_unchanged_tree() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    let tree = repo.worktree_tree();

    for (args, why) in [
        (["2", "1", "0"], "check(s) failed"),
        (["0", "0", "4"], "no check executed"),
    ] {
        let out = repo.receipt(&["record", "quick", &tree, args[0], args[1], args[2]]);
        assert!(out.status.success(), "record reports, it does not fail");
        assert!(
            text(&out.stdout).contains(why),
            "expected '{why}', got: {}",
            text(&out.stdout)
        );
        assert_eq!(code(&repo.receipt(&["check"])), 1, "{why}: no receipt");
    }

    let out = repo.receipt(&["record", "quick", "", "3", "0", "0"]);
    assert!(text(&out.stdout).contains("could not be read when the gate started"));
    assert_eq!(code(&repo.receipt(&["check"])), 1);

    // The tree moves while the gate runs: the checks saw neither tree whole.
    repo.write("README.md", "edited mid-run\n");
    let out = repo.receipt(&["record", "quick", &tree, "3", "0", "0"]);
    assert!(
        text(&out.stdout).contains("the tree changed while the gate ran"),
        "got: {}",
        text(&out.stdout)
    );
    assert_eq!(code(&repo.receipt(&["check"])), 1);
    repo.write("README.md", "fixture\n");

    let out = repo.receipt(&["record", "sloppy", &tree, "3", "0", "0"]);
    assert_eq!(code(&out), 2, "an unknown gate mode is a usage error");
    let out = repo.receipt(&["record", "quick", &tree, "three", "0", "0"]);
    assert_eq!(code(&out), 2, "a non-numeric count is a usage error");

    repo.record_pass();
    let out = repo.receipt(&["check"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("passed the quick gate"));
}

#[test]
fn a_receipt_covers_its_tree_and_nothing_else() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    repo.write("README.md", "checked\n");
    repo.record_pass();
    repo.commit_all("the commit the gate checked");
    assert!(repo.receipt(&["check", "HEAD"]).status.success());

    // An amend that changes content is a new tree.
    repo.write("README.md", "changed after the gate\n");
    repo.git(&["commit", "-q", "-a", "--amend", "--no-edit"]);
    assert_eq!(code(&repo.receipt(&["check", "HEAD"])), 1);

    // A commit that changes nothing keeps the tree, so the receipt holds.
    repo.record_pass();
    repo.git(&["commit", "-q", "--allow-empty", "-m", "empty"]);
    assert!(repo.receipt(&["check", "HEAD"]).status.success());

    assert_eq!(
        code(&repo.receipt(&["check", "no-such-ref"])),
        3,
        "an unresolvable revision is its own outcome"
    );
}

#[test]
fn a_receipt_file_that_does_not_name_its_tree_is_not_a_receipt() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    let dir = PathBuf::from(text(&repo.receipt(&["dir"]).stdout).trim());
    let tree = repo.tree_of("HEAD");
    fs::create_dir_all(&dir).unwrap();

    fs::write(dir.join(&tree), "").unwrap();
    assert_eq!(code(&repo.receipt(&["check"])), 1, "an empty file");
    fs::write(dir.join(&tree), "tree=0000\nmode=quick\n").unwrap();
    assert_eq!(code(&repo.receipt(&["check"])), 1, "another tree's receipt");
}

#[test]
fn every_worktree_of_a_clone_shares_its_receipts() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    repo.record_pass();

    let other = repo.home().join("wt");
    repo.git(&["worktree", "add", "-q", "--detach", other.to_str().unwrap()]);
    let out = repo.receipt_in(&other, &["check", "HEAD"]);
    assert!(
        out.status.success(),
        "a receipt recorded in one worktree must be found from another: {}",
        text(&out.stderr)
    );
    assert_eq!(
        text(&repo.receipt_in(&other, &["dir"]).stdout),
        text(&repo.receipt(&["dir"]).stdout),
        "one receipt directory per clone"
    );
}

// ─── .claude/hooks/pre-push-gate.sh ─────────────────────────────────────────

#[test]
fn a_push_is_refused_until_the_gate_has_passed_on_its_tree() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");

    assert_blocked(&repo.hook("git push -u origin main"), "no receipt");
    repo.record_pass();
    assert_allowed(&repo.hook("git push -u origin main"), "receipt for HEAD");

    repo.write("README.md", "unchecked\n");
    repo.commit_all("a commit the gate never saw");
    assert_blocked(&repo.hook("git push"), "a new commit is a new tree");
}

#[test]
fn a_command_that_is_not_a_push_is_never_blocked() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    // A branch that exists here and has no receipt: if a deletion were read as
    // sending it, the hook would refuse.
    repo.git(&["branch", "old-branch"]);
    for command in [
        "git status",
        "git commit -m \"push it\"",
        "git log --grep push",
        "echo git push",
        "git push --dry-run",
        "git push -n origin main",
        "git push origin --delete old-branch",
        "git push origin :old-branch",
        "cargo test --test push",
    ] {
        assert_allowed(&repo.hook(command), command);
    }
}

#[test]
fn a_push_is_found_however_the_command_line_reaches_it() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    let elsewhere = repo.home().to_path_buf();
    let at = repo.path().display().to_string();
    let hook_from = |cwd: &Path, command: &str| repo.hook_with(cwd, command, None);

    assert_blocked(
        &hook_from(&elsewhere, &format!("cd {at} && git push")),
        "cd &&",
    );
    assert_blocked(
        &hook_from(&elsewhere, &format!("(cd {at} && git push)")),
        "subshell",
    );
    assert_blocked(
        &hook_from(&elsewhere, &format!("cd '{at}'; git push")),
        "quoted cd",
    );
    assert_blocked(
        &hook_from(&elsewhere, &format!("git -C {at} push origin HEAD")),
        "git -C",
    );
    assert_blocked(&repo.hook("timeout 60 git push"), "timeout wrapper");
    assert_blocked(
        &repo.hook("FOO=1 git push 2>&1 | tail -5"),
        "env prefix + pipe",
    );
    assert_blocked(&repo.hook("git status\ngit push"), "second line");
    assert_blocked(&repo.hook("git -c push.default=current push"), "git -c");

    // The command's own environment is not the hook's: this is still refused.
    assert_blocked(&repo.hook("HSE_PUSH_GATE=off git push"), "inline bypass");
    // Claude Code's environment is: a person turned the gate off.
    assert_allowed(
        &repo.hook_with(repo.path(), "git push", Some("off")),
        "HSE_PUSH_GATE=off in the hook environment",
    );
}

/// REQ-HARNESS-003 (review finding on PR #651). The command was split on
/// whitespace after the JSON was decoded, so quotes were not shell syntax:
/// `cd '/path with spaces' && git push` resolved to a directory that does not
/// exist, and the push went through unchecked. The hook now lexes quotes and
/// escapes as the shell does.
#[test]
fn a_push_is_found_through_quotes_and_paths_with_spaces() {
    let repo = Repo::spaced();
    repo.commit_all("add the receipt script");
    let at = repo.path().display().to_string();
    assert!(
        at.contains(' '),
        "the fixture's path must contain spaces: {at}"
    );
    let elsewhere = repo.home().to_path_buf();
    let escaped = at.replace(' ', "\\ ");
    let forms = [
        format!("cd '{at}' && git push"),
        format!("cd \"{at}\" && git push"),
        format!("cd {escaped} && git push"),
        format!("git -C '{at}' push origin main"),
    ];
    for f in &forms {
        assert_blocked(&repo.hook_with(&elsewhere, f, None), f);
    }
    // With a receipt they pass, so the refusals above came from resolving
    // this repository, not from failing to resolve anything.
    repo.record_pass();
    for f in &forms {
        assert_allowed(&repo.hook_with(&elsewhere, f, None), f);
    }
}

/// REQ-HARNESS-003. A directory or refspec the shell only knows at run time
/// cannot be checked here. Guessing let such a push through; in an HSE session
/// it is refused, with the reason. HEAD carries a receipt throughout, so every
/// refusal below is about what cannot be known, not a missing receipt.
#[test]
fn a_push_the_hook_cannot_resolve_is_refused_in_an_hse_session() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    repo.record_pass();
    let elsewhere = repo.home().to_path_buf();

    for command in [
        "git push origin \"$BRANCH\"",
        "git push -u origin \"$(git branch --show-current)\"",
        "git push origin `git branch --show-current`",
    ] {
        let out = repo.hook(command);
        assert_blocked(&out, command);
        assert!(
            text(&out.stderr).contains("only known at run time"),
            "{command}: the refusal says why: {}",
            text(&out.stderr)
        );
    }

    // A run-time directory, from a session whose project is this checkout.
    for command in ["cd \"$REPO\" && git push", "git -C \"$REPO\" push"] {
        let out = repo.hook_in_project(&elsewhere, command, repo.path());
        assert_blocked(&out, command);
        assert!(text(&out.stderr).contains("cannot tell which repository"));
    }
    // The same command from a session that is not about HSE is none of the
    // hook's business.
    assert_allowed(
        &repo.hook_with(&elsewhere, "cd \"$REPO\" && git push", None),
        "not an HSE session",
    );

    // A quote left open: refuse rather than guess.
    let out = repo.hook("git push 'origin");
    assert_blocked(&out, "unbalanced quote");
    assert!(text(&out.stderr).contains("a quote is left open"));

    // `$` inside single quotes is a literal, not an expansion.
    assert_allowed(
        &repo.hook("git push origin '$not-a-var'"),
        "single-quoted $",
    );
}

/// REQ-HARNESS-003. A heredoc's body is text fed to a command, never commands.
/// The first lexer read it as commands, so a commit message or an inline script
/// became unbalanced quotes and stray `push` words, and the live hook refused
/// ordinary work in this repository's own session.
#[test]
fn a_heredoc_body_is_text_not_commands() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    for command in [
        "python3 - <<'EOF'\ns = 'git push the '''odd\" thing'\nEOF\ngit status",
        "git commit -F - <<'MSG'\nWhy we never git push blind\nit's 'unbalanced\nMSG",
        "cat <<-EOF\n\tgit push\n\tEOF\necho done",
        "cat <<\"E O F\"\ngit push\nE O F",
        "cat <<A <<'B'\ngit push\nA\n'x\nB\ntrue",
        "git commit -m \"a; git push\" && git status",
    ] {
        assert_allowed(&repo.hook(command), command);
    }
    // A push on a line after the heredoc is still a push, and a here-string
    // (`<<<`) is not a heredoc.
    assert_blocked(
        &repo.hook("cat <<'EOF'\n'x\nEOF\ngit push"),
        "push after a heredoc",
    );
    assert_blocked(&repo.hook("git push <<< 'yes'"), "here-string");
}

/// REQ-HARNESS-003 (review finding on PR #651). `gate.sh` ignored the receipt
/// command's exit status, so a receipt that could not be stored still ended in
/// a passing gate, and the push hook then refused a tree the gate called good.
/// A storage failure exits non-zero, and gate.sh counts it as a failure.
#[test]
fn a_receipt_that_cannot_be_stored_is_a_failure() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    let dir = PathBuf::from(text(&repo.receipt(&["dir"]).stdout).trim());
    // A file where the directory should be: unwritable even for root.
    fs::write(&dir, "not a directory").unwrap();
    let tree = repo.worktree_tree();
    let out = repo.receipt(&["record", "quick", &tree, "3", "0", "0"]);
    assert!(
        !out.status.success(),
        "a receipt that was not stored must not exit 0\nstdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );
    assert_eq!(code(&repo.receipt(&["check"])), 1, "and none exists");
}

#[test]
fn the_ref_a_push_sends_is_the_one_that_needs_the_receipt() {
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    repo.record_pass(); // main's tree passed.

    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("README.md", "feature work\n");
    repo.commit_all("feature");

    assert_allowed(&repo.hook("git push origin main"), "main passed");
    assert_allowed(&repo.hook("git push origin HEAD~1:main"), "HEAD~1 is main");
    assert_blocked(
        &repo.hook("git push origin feature"),
        "feature did not pass",
    );
    assert_blocked(&repo.hook("git push origin feature:main"), "src:dst");
    assert_blocked(&repo.hook("git push --force origin +feature"), "forced");
    assert_blocked(&repo.hook("git push"), "no refspec pushes HEAD");
    assert_blocked(
        &repo.hook("git push origin main feature"),
        "one of two refs",
    );
}

#[test]
fn the_hook_drains_its_stdin_before_any_exit() {
    // Claude Code writes the hook JSON to the hook's stdin. The bypass used to
    // `exit 0` before reading it, closing the pipe under the writer: the write
    // then failed with EPIPE, but only when the hook happened to be scheduled
    // first, so it passed CI once and failed under load. A payload larger than
    // a pipe buffer (64 KiB on Linux) removes the luck: the writer blocks until
    // the reader drains, so a hook that exits without reading fails the write
    // every time.
    let repo = Repo::new();
    repo.commit_all("add the receipt script");
    let big = "x".repeat(256 * 1024);

    // Early exit: the person's bypass.
    let out = repo.hook_described(repo.path(), "git push", &big, Some("off"));
    assert_allowed(&out, "bypass with a large payload");

    // Early exit: not a push.
    let out = repo.hook_described(repo.path(), "git status", &big, None);
    assert_allowed(&out, "non-push with a large payload");

    // The full path still decides correctly on a large payload.
    let out = repo.hook_described(repo.path(), "git push", &big, None);
    assert_blocked(&out, "push without a receipt, large payload");
}

#[test]
fn the_workflow_lint_counts_only_manifests_git_tracks() {
    // `scripts/check_workflows.py` checks that gate.sh's audit skip-list covers
    // audit.yml's `**/Cargo.{toml,lock}` filter. It expanded that glob by
    // walking the filesystem, excluding only `target/`, so it also found the
    // manifests inside an ignored nested checkout. The `hse-falsifier` subagent
    // creates one by design (`.claude/worktrees/agent-*/`). The lint then
    // reported paths CI can never see as missing, and failed the gate
    // (REQ-GATE-005). A path filter matches only what a commit changes, which is
    // tracked files, so the glob is now expanded over `git ls-files`.
    let has_yaml = Command::new("python3")
        .args(["-c", "import yaml"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !has_yaml {
        // Same stance as gate.sh's `workflow files` SKIP: CI is the authority.
        eprintln!("SKIP: python3 with pyyaml is not available on this host");
        return;
    }

    let repo = Repo::bare();
    let copy = |rel: &str| {
        let dst = repo.path().join(rel);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::copy(root().join(rel), &dst).unwrap_or_else(|e| panic!("copy {rel}: {e}"));
    };
    for rel in [
        ".gitignore",
        "scripts/gate.sh",
        "scripts/check_workflows.py",
    ] {
        copy(rel);
    }
    for entry in fs::read_dir(root().join(".github/workflows")).unwrap() {
        let name = entry.unwrap().file_name().to_string_lossy().into_owned();
        copy(&format!(".github/workflows/{name}"));
    }
    for crate_dir in ["", "fuzz/", "hse-core/", "wasm-ui/"] {
        copy(&format!("{crate_dir}Cargo.toml"));
        copy(&format!("{crate_dir}Cargo.lock"));
    }
    // A Claude Code worktree: a full nested copy of the manifests, in a
    // directory the repository ignores. It exists before anything is staged,
    // as it does in a real session.
    let nested = ".claude/worktrees/agent-test";
    for crate_dir in ["", "fuzz/", "hse-core/"] {
        repo.write(&format!("{nested}/{crate_dir}Cargo.toml"), "[package]\n");
        repo.write(&format!("{nested}/{crate_dir}Cargo.lock"), "version = 4\n");
    }
    repo.commit_all("fixture: the lint, its inputs, and an ignored worktree");
    assert!(
        !repo.git(&["ls-files"]).contains(nested),
        "the fixture's worktree must be ignored, as `.claude/worktrees/` is here"
    );

    let lint = || {
        repo.cmd("python3", repo.path())
            .arg("scripts/check_workflows.py")
            .output()
            .expect("python3")
    };
    let out = lint();
    assert!(
        out.status.success(),
        "an ignored nested worktree's manifests are not paths CI can see, so \
         the lint must not ask gate.sh to list them\nstdout: {}\nstderr: {}",
        text(&out.stdout),
        text(&out.stderr)
    );

    // The other direction: the lint exists to catch a NEW crate gate.sh does
    // not list yet, and must still do so before the crate is staged. An
    // untracked, not-ignored manifest is a path the next commit carries.
    repo.write("newcrate/Cargo.toml", "[package]\n");
    let out = lint();
    // The lint reports its problems on stderr.
    assert!(
        !out.status.success() && text(&out.stderr).contains("newcrate/Cargo.toml"),
        "an unstaged new crate must still be flagged, or the fix traded one \
         silent omission for another\nstderr: {}",
        text(&out.stderr)
    );
}

#[test]
fn a_checkout_without_gate_receipts_is_not_policed() {
    let repo = Repo::bare();
    assert_allowed(&repo.hook("git push"), "no scripts/gate-receipt.sh");
    let not_a_repo = tempfile::tempdir().unwrap();
    assert_allowed(
        &repo.hook_with(not_a_repo.path(), "git push", None),
        "not a git checkout",
    );
}

// ─── .githooks/pre-push: every push, not only a Claude Code session's ───────

impl Repo {
    /// Install this checkout's git pre-push hook into the fixture, point
    /// `core.hooksPath` at it, and add a bare repository as `origin`.
    fn with_git_hook_and_remote(&self) -> PathBuf {
        let hooks = self.path().join(".githooks");
        fs::create_dir_all(&hooks).unwrap();
        fs::copy(root().join(".githooks/pre-push"), hooks.join("pre-push")).unwrap();
        assert!(
            is_executable(&hooks.join("pre-push")),
            ".githooks/pre-push must be committed executable, or git skips it"
        );
        self.git(&["config", "core.hooksPath", ".githooks"]);
        let remote = self.home().join("remote.git");
        self.git_in(
            self.home(),
            &["init", "-q", "--bare", remote.to_str().unwrap()],
        );
        self.git(&["remote", "add", "origin", remote.to_str().unwrap()]);
        remote
    }

    /// A real `git push` with `args`, run the way a person runs it.
    fn push(&self, args: &[&str], gate_env: Option<&str>) -> Output {
        let mut c = self.cmd("git", self.path());
        c.args(["-c", "commit.gpgsign=false", "push"]).args(args);
        if let Some(v) = gate_env {
            c.env("HSE_PUSH_GATE", v);
        }
        c.output().expect("git")
    }

    /// The commit `branch` points at in the bare remote, if it exists.
    fn remote_head(&self, remote: &Path, branch: &str) -> Option<String> {
        let out = self
            .cmd("git", self.path())
            .args([
                "--git-dir",
                remote.to_str().unwrap(),
                "rev-parse",
                "--verify",
                "--quiet",
            ])
            .arg(format!("refs/heads/{branch}"))
            .output()
            .expect("git");
        out.status
            .success()
            .then(|| text(&out.stdout).trim().to_string())
    }
}

/// REQ-HARNESS-004. The receipt check guarded only pushes a Claude Code session
/// issued; a person pushing from a terminal went through nothing. git runs
/// `.githooks/pre-push` for every push from a clone configured for it, and this
/// drives a real push to a real (bare) remote, so git itself invokes the hook.
#[test]
fn a_real_git_push_is_refused_until_the_gate_has_passed() {
    let repo = Repo::new();
    let remote = repo.with_git_hook_and_remote();
    repo.commit_all("fixture with the receipt script and the git hook");

    let out = repo.push(&["-q", "origin", "main"], None);
    assert!(!out.status.success(), "a push with no receipt must fail");
    assert!(
        text(&out.stderr).contains("scripts/gate.sh --quick"),
        "the refusal names the fix: {}",
        text(&out.stderr)
    );
    assert_eq!(
        repo.remote_head(&remote, "main"),
        None,
        "nothing reached the remote"
    );

    repo.record_pass();
    let out = repo.push(&["-q", "origin", "main"], None);
    assert!(
        out.status.success(),
        "a gated commit pushes: {}",
        text(&out.stderr)
    );
    let pushed = repo.git(&["rev-parse", "HEAD"]);
    assert_eq!(
        repo.remote_head(&remote, "main").as_deref(),
        Some(pushed.as_str())
    );

    // A branch at the same commit carries the same tree, so it may go too;
    // deleting it afterwards sends nothing, so it is never checked.
    repo.git(&["branch", "old"]);
    assert!(repo.push(&["-q", "origin", "old"], None).status.success());
    let out = repo.push(&["-q", "origin", "--delete", "old"], None);
    assert!(
        out.status.success(),
        "a deletion sends nothing: {}",
        text(&out.stderr)
    );

    // A new commit is a new tree.
    repo.write("README.md", "changed after the gate\n");
    repo.commit_all("unchecked");
    assert!(!repo.push(&["-q", "origin", "main"], None).status.success());
    assert_eq!(
        repo.remote_head(&remote, "main").as_deref(),
        Some(pushed.as_str()),
        "the refused commit did not reach the remote"
    );

    // The pusher's own, deliberate way past it.
    assert!(
        repo.push(&["-q", "origin", "main"], Some("off"))
            .status
            .success()
    );
}

/// REQ-HARNESS-004. git hands the hook one line per ref; each is checked on
/// its own commit, a deletion (all-zero sha) is skipped, and the refusal names
/// exactly the refs without a receipt.
#[test]
fn the_git_hook_checks_each_ref_it_is_handed() {
    let repo = Repo::new();
    repo.with_git_hook_and_remote();
    repo.commit_all("gated");
    repo.record_pass();
    let gated = repo.git(&["rev-parse", "HEAD"]);
    repo.write("README.md", "ungated\n");
    repo.commit_all("ungated");
    let ungated = repo.git(&["rev-parse", "HEAD"]);
    let zero = "0".repeat(40);

    let run = |stdin: String| {
        use std::io::Write;
        let mut child = repo
            .cmd("bash", repo.path())
            .arg(repo.path().join(".githooks/pre-push"))
            .args(["origin", "unused-url"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("bash");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };

    let out = run(format!(
        "refs/heads/a {gated} refs/heads/a {zero}\n\
         refs/heads/b {ungated} refs/heads/b {zero}\n\
         (delete) {zero} refs/heads/c {gated}\n\
         refs/heads/d {ungated} refs/heads/d {zero}\n"
    ));
    assert_eq!(code(&out), 1);
    let err = text(&out.stderr);
    assert!(
        err.contains("refs/heads/b ->")
            && err.contains("refs/heads/d ->")
            && !err.contains("refs/heads/a ->"),
        "every ref without a receipt is named, and only those: {err}"
    );

    let out = run(format!(
        "refs/heads/a {gated} refs/heads/a {zero}\n(delete) {zero} refs/heads/c {gated}\n"
    ));
    assert_eq!(code(&out), 0, "{}", text(&out.stderr));
}

/// REQ-HARNESS-004. `scripts/setup-dev.sh` turns the hook on by pointing
/// `core.hooksPath` at `.githooks`. That setting replaces `.git/hooks`, so it
/// is only written where it cannot disable anything of the developer's own.
#[test]
fn setup_dev_enables_the_repo_hooks_only_where_that_is_safe() {
    let configure = |repo: &Repo| -> (String, String) {
        let out = repo
            .cmd("bash", repo.path())
            .arg("-c")
            .arg(format!(
                "source '{}' && configure_git_hooks",
                root().join("scripts/setup-dev.sh").display()
            ))
            .output()
            .expect("bash");
        assert!(out.status.success(), "{}", text(&out.stderr));
        let got = repo
            .cmd("git", repo.path())
            .args(["config", "--get", "core.hooksPath"])
            .output()
            .expect("git");
        (text(&got.stdout).trim().to_string(), text(&out.stderr))
    };
    let with_hooks_dir = || {
        let repo = Repo::bare();
        repo.write(".githooks/pre-push", "#!/bin/sh\n");
        repo
    };

    let fresh = with_hooks_dir();
    assert_eq!(
        configure(&fresh).0,
        ".githooks",
        "a fresh clone is switched on"
    );
    assert_eq!(
        configure(&fresh).0,
        ".githooks",
        "and re-running changes nothing"
    );

    let custom = with_hooks_dir();
    custom.git(&["config", "core.hooksPath", "my-hooks"]);
    let (value, warning) = configure(&custom);
    assert_eq!(value, "my-hooks", "a developer's own hooksPath is kept");
    assert!(
        warning.contains("git config core.hooksPath .githooks"),
        "{warning}"
    );

    let own = with_hooks_dir();
    let hook = own.path().join(".git/hooks/pre-commit");
    fs::write(&hook, "#!/bin/sh\n").unwrap();
    let (value, warning) = configure(&own);
    assert_eq!(value, "", "hooks already in .git/hooks are not disabled");
    assert!(warning.contains("pre-commit"), "{warning}");

    let older = Repo::bare();
    assert_eq!(
        configure(&older).0,
        "",
        "a checkout without .githooks is left alone"
    );

    // The function above only matters if setup runs it, and before the
    // `--deps-only` exit: that is the path a Claude Code cloud session takes
    // (.claude/hooks/session-start.sh).
    let setup = read("scripts/setup-dev.sh");
    let main_body = setup
        .split("\nmain() {")
        .nth(1)
        .and_then(|b| b.split("\n}").next())
        .expect("setup-dev.sh defines main()");
    let call = main_body
        .find("configure_git_hooks")
        .expect("main() must call configure_git_hooks");
    let deps_exit = main_body
        .find("if [ \"$DEPS_ONLY\" = \"1\" ]")
        .expect("main() has the --deps-only exit");
    assert!(
        call < deps_exit,
        "configure_git_hooks must run before the --deps-only exit"
    );
}

// ─── .claude/settings.json and .claude/agents ───────────────────────────────

/// Claude Code's hook events. An entry under any other name is dropped with
/// only a warning, which is how the pre-push gate spent its life as
/// `StopBeforePush`. Source: https://code.claude.com/docs/en/hooks.
const HOOK_EVENTS: &[&str] = &[
    "SessionStart",
    "Setup",
    "UserPromptSubmit",
    "UserPromptExpansion",
    "PreToolUse",
    "PermissionRequest",
    "PermissionDenied",
    "PostToolUse",
    "PostToolUseFailure",
    "PostToolBatch",
    "Notification",
    "MessageDisplay",
    "SubagentStart",
    "SubagentStop",
    "TaskCreated",
    "TaskCompleted",
    "Stop",
    "StopFailure",
    "TeammateIdle",
    "InstructionsLoaded",
    "ConfigChange",
    "CwdChanged",
    "DirectoryAdded",
    "FileChanged",
    "WorktreeCreate",
    "WorktreeRemove",
    "PreCompact",
    "PostCompact",
    "PreModelSwitch",
    "PostModelSwitch",
    "Elicitation",
    "ElicitationResult",
    "SessionEnd",
];

/// The settings keys this file may use. Deliberately short: a key outside it
/// (`keybindings`, `reasoning_effort`, `allowlist` all lived here, none of
/// them settings) has to be looked up and added on purpose.
const TOP_LEVEL_KEYS: &[&str] = &["$schema", "permissions", "hooks", "env"];
const PERMISSION_KEYS: &[&str] = &["allow", "ask", "deny", "defaultMode"];

fn settings() -> serde_json::Value {
    serde_json::from_str(&read(".claude/settings.json"))
        .expect(".claude/settings.json must be JSON")
}

/// Every hook handler as (event, matcher, handler).
fn hook_handlers(s: &serde_json::Value) -> Vec<(String, String, serde_json::Value)> {
    let mut out = Vec::new();
    for (event, groups) in s["hooks"].as_object().expect("hooks is an object") {
        for group in groups.as_array().expect("an event holds a list") {
            let matcher = group["matcher"].as_str().unwrap_or("").to_string();
            for h in group["hooks"].as_array().expect("a group holds `hooks`") {
                out.push((event.clone(), matcher.clone(), h.clone()));
            }
        }
    }
    out
}

/// The repository script a hook command runs: the text after
/// `$CLAUDE_PROJECT_DIR`, however it is quoted.
fn hook_script(command: &str) -> Option<PathBuf> {
    let rest = command.split("$CLAUDE_PROJECT_DIR").nth(1)?;
    let rest = rest.trim_start_matches(['"', '}']);
    let rel = rest.split_whitespace().next()?.trim_matches('"');
    Some(root().join(rel.trim_start_matches('/')))
}

#[test]
fn settings_use_only_real_keys_and_hook_events() {
    let s = settings();
    for key in s.as_object().unwrap().keys() {
        assert!(
            TOP_LEVEL_KEYS.contains(&key.as_str()),
            "`{key}` in .claude/settings.json is not a key this file uses; check \
             https://code.claude.com/docs/en/settings and add it to TOP_LEVEL_KEYS \
             only if Claude Code reads it"
        );
    }
    for key in s["permissions"].as_object().unwrap().keys() {
        assert!(
            PERMISSION_KEYS.contains(&key.as_str()),
            "`permissions.{key}` is not a permissions key"
        );
    }
    for (event, _, handler) in hook_handlers(&s) {
        assert!(
            HOOK_EVENTS.contains(&event.as_str()),
            "`{event}` is not a Claude Code hook event; its hooks would never run"
        );
        assert_eq!(
            handler["type"], "command",
            "{event}: only command hooks here"
        );
        let command = handler["command"]
            .as_str()
            .expect("a command hook has a command");
        let script = hook_script(command).unwrap_or_else(|| {
            panic!("{event}: `{command}` must run a script under $CLAUDE_PROJECT_DIR")
        });
        assert!(
            is_executable(&script),
            "{event}: {} must exist and be executable",
            script.display()
        );
    }
}

#[test]
fn the_push_gate_runs_before_every_git_command() {
    let s = settings();
    let wired = hook_handlers(&s).into_iter().any(|(event, matcher, h)| {
        event == "PreToolUse"
            && matcher.split('|').any(|m| m == "Bash")
            && h["command"]
                .as_str()
                .is_some_and(|c| c.ends_with("/.claude/hooks/pre-push-gate.sh"))
            && h["if"].as_str().is_none_or(|cond| cond == "Bash(git *)")
    });
    assert!(
        wired,
        "the pre-push gate must be a PreToolUse hook on Bash, filtered at most to git commands"
    );
}

#[test]
fn every_subagent_definition_loads() {
    let dir = root().join(".claude/agents");
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "md") {
            continue;
        }
        let body = fs::read_to_string(&path).unwrap();
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        // Claude Code only reads frontmatter that opens on line 1; anything
        // else is documentation and the agent does not exist.
        let Some((front, _)) = body
            .strip_prefix("---\n")
            .and_then(|b| b.split_once("\n---\n"))
        else {
            panic!("{file}: frontmatter must open on the first line");
        };
        let field = |key: &str| {
            front
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key}:")))
                .map(|v| v.trim().to_string())
        };
        let name = field("name").unwrap_or_else(|| panic!("{file}: no `name`"));
        assert!(
            !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !name.starts_with('-'),
            "{file}: `name: {name}` must be lowercase letters, digits and hyphens"
        );
        assert_eq!(
            format!("{name}.md"),
            file,
            "an agent's file is named after it, so the two cannot disagree"
        );
        assert!(
            field("description").is_some_and(|d| !d.is_empty()),
            "{file}: no `description`, so Claude Code skips the agent"
        );
        names.push(name);
    }
    assert!(
        names.iter().any(|n| n == "hse-falsifier"),
        "the independent reviewer must be defined, found {names:?}"
    );
}

#[test]
fn the_gate_records_a_receipt_for_the_tree_it_read_before_its_first_check() {
    // The receipt tests above drive gate-receipt.sh directly. That proves
    // something only if gate.sh calls it as they assume. It must read the tree
    // before any check runs, and hand over its real counters once, after the
    // last check.
    let gate = read("scripts/gate.sh");
    let code_lines: Vec<(usize, &str)> = gate
        .lines()
        .enumerate()
        .filter(|(_, l)| !l.trim_start().starts_with('#'))
        .collect();
    let line_of = |needle: &str| {
        code_lines
            .iter()
            .filter(|(_, l)| l.contains(needle))
            .map(|(i, _)| *i)
            .collect::<Vec<_>>()
    };
    let tree_read = line_of("GATE_TREE=\"$(scripts/gate-receipt.sh tree");
    let record = line_of(
        "scripts/gate-receipt.sh record \"$GATE_MODE\" \"$GATE_TREE\" \"${#PASS[@]}\" \"${#FAIL[@]}\" \"${#SKIP[@]}\"",
    );
    let checks: Vec<usize> = code_lines
        .iter()
        .filter(|(_, l)| {
            let t = l.trim_start();
            t.starts_with("run \"") || t.contains("&& run \"") || t.starts_with("skip \"")
        })
        .map(|(i, _)| *i)
        .collect();
    assert_eq!(
        tree_read.len(),
        1,
        "gate.sh must read the tree exactly once"
    );
    assert_eq!(record.len(), 1, "gate.sh must record exactly once");
    assert!(
        tree_read[0] < *checks.iter().min().unwrap(),
        "the tree must be read before the first check"
    );
    assert!(
        record[0] > *checks.iter().max().unwrap(),
        "the receipt must be recorded after the last check"
    );
    let verdict = line_of("if [ \"${#FAIL[@]}\" -gt 0 ]; then");
    assert!(
        verdict.iter().any(|v| *v > record[0]),
        "the receipt is recorded before the verdict exits"
    );
    // A receipt that could not be stored must reach the verdict: the call is
    // the condition of an `if !` whose body adds to FAIL (REQ-HARNESS-003).
    let lines: Vec<&str> = gate.lines().collect();
    let call = lines[record[0]].trim_start();
    assert!(
        call.starts_with("if ! scripts/gate-receipt.sh record "),
        "the record call's exit status must be checked: {call}"
    );
    assert!(
        lines[record[0] + 1..]
            .iter()
            .take(3)
            .any(|l| l.trim_start().starts_with("FAIL+=(")),
        "a failed record must count as a gate failure"
    );
}
