//! `scripts/lifecycle.sh sync` commits verified work to a review branch without pushing `main`,
//! and CANONICAL.md promises that it refuses secret-looking paths. Each test runs the real script
//! against a local bare remote; the source tree on `main` must never change during sync.
//! Unix only: the script is bash.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

struct Sandbox {
    root: PathBuf,
    work: PathBuf,
    origin: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("huntsman-lifecycle-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let work = root.join("work");
        let origin = root.join("origin.git");
        fs::create_dir_all(work.join("scripts")).unwrap();
        fs::create_dir_all(root.join("home")).unwrap();
        let sandbox = Self { root, work, origin };
        sandbox.git_in(
            &sandbox.root,
            &["init", "-q", "--bare", "-b", "main", "origin.git"],
        );
        sandbox.git(&["init", "-q", "-b", "main"]);
        for (key, value) in [
            ("user.name", "Test"),
            ("user.email", "test@example.invalid"),
            ("commit.gpgsign", "false"),
        ] {
            sandbox.git(&["config", key, value]);
        }
        let origin = sandbox.origin.display().to_string();
        sandbox.git(&["remote", "add", "origin", &origin]);
        fs::copy(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/lifecycle.sh"),
            sandbox.work.join("scripts/lifecycle.sh"),
        )
        .unwrap();
        sandbox.write("README.md", "scratch\n");
        sandbox.commit_and_push("initial");
        sandbox
    }

    fn command(&self, program: &str, dir: &Path) -> Command {
        let mut command = Command::new(program);
        command
            .current_dir(dir)
            .env("HOME", self.root.join("home"))
            .env("HUNTSMAN_HOME", self.root.join("state"))
            // lifecycle.sh builds into an inherited CARGO_TARGET_DIR before its own default, so
            // a developer's target dir would receive the mock build's stub binary.
            .env("CARGO_TARGET_DIR", self.root.join("target"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0");
        command
    }

    fn git_in(&self, dir: &Path, args: &[&str]) -> Output {
        let output = self.command("git", dir).args(args).output().unwrap();
        assert!(output.status.success(), "git {args:?} failed");
        output
    }

    fn git(&self, args: &[&str]) -> Output {
        self.git_in(&self.work, args)
    }

    fn commit_and_push(&self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", message]);
        self.git(&["push", "-q", "origin", "main"]);
    }

    fn head(&self) -> String {
        let output = self.git(&["rev-parse", "HEAD"]);
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn write(&self, relative: &str, body: &str) {
        let path = self.work.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    // Use a deterministic cargo stub: these tests exercise lifecycle publication
    // decisions without compiling Rust in a disposable scratch repository.
    fn run_with_mock_cargo(&self, mode: &str, test_exit: u8) -> Output {
        self.run_with_mock_cargo_mutation(mode, test_exit, "none")
    }

    fn run_with_mock_cargo_mutation(&self, mode: &str, test_exit: u8, mutation: &str) -> Output {
        use std::os::unix::fs::PermissionsExt;

        let mock_bin = self.root.join("mock-bin");
        fs::create_dir_all(&mock_bin).unwrap();
        let mock_cargo = mock_bin.join("cargo");
        fs::write(
            &mock_cargo,
            format!(
                r#"#!/bin/sh
case "$1" in
build)
  mkdir -p "$CARGO_TARGET_DIR/debug" || exit 99
  printf '#!/bin/sh\nexit 0\n' > "$CARGO_TARGET_DIR/debug/huntsman-recon" || exit 99
  chmod 755 "$CARGO_TARGET_DIR/debug/huntsman-recon" || exit 99
  ;;
test)
  case "$HUNTSMAN_TEST_MUTATE" in
    file) printf 'unexpected\n' >> docs/pending.md ;;
    secret) mkdir -p deploy && printf 'fake\n' > deploy/.env ;;
    *) ;;
  esac
  exit {test_exit}
  ;;
*) exit 99 ;;
esac
"#
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&mock_cargo).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&mock_cargo, permissions).unwrap();

        let mut path = std::ffi::OsString::from(mock_bin.as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        self.command("bash", &self.work)
            .env("PATH", path)
            .env("HUNTSMAN_TEST_MUTATE", mutation)
            .args(["scripts/lifecycle.sh", mode])
            .output()
            .unwrap()
    }

    fn sync(&self) -> Output {
        self.command("bash", &self.work)
            .args(["scripts/lifecycle.sh", "sync"])
            .output()
            .unwrap()
    }

    /// The files on a remote ref, names unquoted.
    fn remote_files(&self, reference: &str) -> Vec<String> {
        let output = self
            .command("git", &self.root)
            .arg("--git-dir")
            .arg(&self.origin)
            .args(["ls-tree", "-r", "-z", "--name-only", reference])
            .output()
            .unwrap();
        assert!(output.status.success());
        let mut names: Vec<String> = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
            .map(|name| String::from_utf8(name.to_vec()).unwrap())
            .collect();
        names.sort();
        names
    }

    fn pushed(&self) -> Vec<String> {
        self.remote_files("main")
    }

    fn staged(&self) -> Vec<String> {
        self.remote_files(&format!("refs/heads/lifecycle/{}", self.head()))
    }

    fn review_branch_exists(&self) -> bool {
        self.command("git", &self.root)
            .arg("--git-dir")
            .arg(&self.origin)
            .args([
                "show-ref",
                "--verify",
                "--quiet",
                &format!("refs/heads/lifecycle/{}", self.head()),
            ])
            .output()
            .expect("check remote review ref")
            .status
            .success()
    }

    /// Runs the sync and asserts that it stopped for `reason`, committed nothing and pushed nothing.
    fn assert_stopped(&self, reason: &str) {
        let head = self.head();
        let pushed = self.pushed();
        let output = self.sync();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "the sync went ahead although it should have stopped: {reason}"
        );
        assert!(
            stderr.contains(reason),
            "the sync stopped for another reason: {stderr}"
        );
        assert_eq!(self.head(), head, "a commit was made");
        assert_eq!(self.pushed(), pushed, "the remote changed");
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

const REFUSED: &str = "refusing to commit secret-looking path";

#[test]
fn a_secret_inside_an_untracked_directory_is_refused() {
    // `git status --porcelain` lists an untracked directory as one entry, `deploy/`, and
    // `git add -A` then takes every file in it.
    let sandbox = Sandbox::new("directory");
    sandbox.write("deploy/.env", "API_KEY=not-a-real-key\n");
    sandbox.write("notes.txt", "ordinary\n");
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_secret_whose_name_has_a_space_is_refused() {
    // Porcelain quotes such a name, so the closing quote hides the `.pem` suffix.
    let sandbox = Sandbox::new("space");
    sandbox.write("my key.pem", "not a real key\n");
    sandbox.write("notes.txt", "ordinary\n");
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_secret_whose_name_is_not_ascii_is_refused() {
    // Porcelain writes such a name as a quoted octal escape.
    let sandbox = Sandbox::new("non-ascii");
    sandbox.write("café.pem", "not a real key\n");
    sandbox.write("notes.txt", "ordinary\n");
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_file_in_a_top_level_keys_directory_is_refused() {
    // The pattern `*/keys/*` needs a directory above `keys`.
    let sandbox = Sandbox::new("keys");
    sandbox.write("keys/provider.txt", "not a real key\n");
    sandbox.write("notes.txt", "ordinary\n");
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_secret_that_is_already_staged_is_refused() {
    // A staged file is neither untracked nor modified, but `git commit` takes it.
    let sandbox = Sandbox::new("staged");
    sandbox.write("deploy.env", "API_KEY=not-a-real-key\n");
    sandbox.git(&["add", "deploy.env"]);
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_tracked_secret_looking_file_that_changes_is_refused() {
    let sandbox = Sandbox::new("tracked");
    sandbox.write("example.env", "API_KEY=\n");
    sandbox.commit_and_push("track an example");
    sandbox.write("example.env", "API_KEY=not-a-real-key\n");
    sandbox.assert_stopped(REFUSED);
}

#[test]
fn a_listing_that_fails_stops_the_sync() {
    // The guard must fail closed: with no list of changed paths there is nothing to check.
    let sandbox = Sandbox::new("listing");
    sandbox.write("notes.txt", "ordinary\n");
    fs::write(sandbox.work.join(".git/index"), "not an index").unwrap();
    sandbox.assert_stopped("could not list the changed paths");
}

#[test]
fn ordinary_changes_are_committed_to_a_review_branch_without_pushing_main() {
    let sandbox = Sandbox::new("ordinary");
    let before = sandbox.head();
    let main_before = sandbox.pushed();
    sandbox.write("notes.txt", "ordinary\n");
    sandbox.write("docs/guide.md", "also ordinary\n");
    let output = sandbox.run_with_mock_cargo("sync", 0);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("test ok"),
        "sync skipped tests"
    );
    assert_ne!(sandbox.head(), before, "nothing was committed");
    assert_eq!(
        sandbox.pushed(),
        main_before,
        "direct sync changed remote main"
    );
    assert_eq!(
        sandbox.staged(),
        [
            "README.md",
            "docs/guide.md",
            "notes.txt",
            "scripts/lifecycle.sh"
        ]
    );
    let state = fs::read_to_string(sandbox.root.join("state/lifecycle-state")).unwrap();
    assert!(state.contains("phase=sync\nstatus=pending\n"), "{state}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("open a pull request to main"),
        "review is required before integration"
    );
}

#[test]
fn repeating_a_clean_sync_does_not_create_an_empty_review_branch() {
    let sandbox = Sandbox::new("repeat");
    let initial = sandbox.head();
    let main_before = sandbox.pushed();
    for _ in 0..2 {
        let output = sandbox.run_with_mock_cargo("sync", 0);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(sandbox.head(), initial, "clean sync must not commit");
        assert_eq!(sandbox.pushed(), main_before, "sync must not push main");
        assert!(
            !sandbox.review_branch_exists(),
            "clean main must not generate a redundant review branch"
        );
        let state = fs::read_to_string(sandbox.root.join("state/lifecycle-state")).unwrap();
        assert!(state.contains("phase=sync\nstatus=ok\n"), "{state}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("already on main"),
            "a clean checkout should report remote acceptance"
        );
    }
}

#[test]
fn direct_sync_with_failed_tests_never_commits_or_pushes() {
    let sandbox = Sandbox::new("direct-sync-failed-tests");
    sandbox.write("docs/pending.md", "must not be published\n");
    let previous_head = sandbox.head();
    let previous_remote = sandbox.pushed();
    let output = sandbox.run_with_mock_cargo("sync", 1);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!output.status.success(), "sync bypassed failed tests");
    assert!(stderr.contains("tests failed with exit 1"), "{stderr}");
    assert_eq!(
        sandbox.head(),
        previous_head,
        "sync made an unverified commit"
    );
    assert_eq!(
        sandbox.pushed(),
        previous_remote,
        "sync pushed unverified work"
    );
    let state = fs::read_to_string(sandbox.root.join("state/lifecycle-state")).unwrap();
    assert!(state.contains("phase=test\nstatus=failed\n"), "{state}");
}

#[test]
fn direct_sync_does_not_trust_a_previous_success_state() {
    let sandbox = Sandbox::new("direct-sync-stale-state");
    sandbox.write("docs/pending.md", "not verified in this process\n");
    let state_dir = sandbox.root.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        state_dir.join("lifecycle-state"),
        "updated=old\nrevision=old\nphase=sync\nstatus=ok\ndetail=old\n",
    )
    .unwrap();
    let before = sandbox.head();
    let output = sandbox.run_with_mock_cargo("sync", 1);
    assert!(
        !output.status.success(),
        "stale receipt bypassed verification"
    );
    assert_eq!(sandbox.head(), before);
}

#[test]
fn direct_sync_refuses_changes_made_by_a_successful_test_command() {
    let sandbox = Sandbox::new("mutated-after-check");
    sandbox.write("docs/pending.md", "verified before tests\n");
    let before = sandbox.head();
    let remote_before = sandbox.pushed();
    let output = sandbox.run_with_mock_cargo_mutation("sync", 0, "file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "mutated source was accepted");
    assert!(
        stderr.contains("worktree changed during verification"),
        "{stderr}"
    );
    assert_eq!(sandbox.head(), before, "unverified changes were committed");
    assert_eq!(sandbox.pushed(), remote_before, "remote main was mutated");
}

#[test]
fn all_refuses_changes_made_during_its_test_phase() {
    let sandbox = Sandbox::new("all-mutated-after-check");
    sandbox.write("docs/pending.md", "verified before tests\n");
    let before = sandbox.head();
    let remote_before = sandbox.pushed();
    let output = sandbox.run_with_mock_cargo_mutation("all", 0, "file");
    assert!(!output.status.success(), "all published a changed worktree");
    assert_eq!(sandbox.head(), before, "unverified changes were committed");
    assert_eq!(sandbox.pushed(), remote_before, "remote main was mutated");
}

#[test]
fn direct_sync_refuses_a_secret_path_created_during_tests() {
    let sandbox = Sandbox::new("new-secret-after-check");
    sandbox.write("docs/pending.md", "ordinary change\n");
    let before = sandbox.head();
    let remote_before = sandbox.pushed();
    let output = sandbox.run_with_mock_cargo_mutation("sync", 0, "secret");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(REFUSED),
        "secret introduced during tests was not refused"
    );
    assert_eq!(sandbox.head(), before);
    assert_eq!(sandbox.pushed(), remote_before);
}

#[test]
fn direct_sync_keeps_the_original_index_when_tests_fail() {
    let sandbox = Sandbox::new("index-preservation");
    sandbox.write("docs/staged.md", "staged only\n");
    sandbox.git(&["add", "docs/staged.md"]);
    let staged_before = sandbox.git(&["write-tree"]).stdout;
    let before = sandbox.head();
    let output = sandbox.run_with_mock_cargo("sync", 1);
    assert!(!output.status.success());
    assert_eq!(sandbox.git(&["write-tree"]).stdout, staged_before);
    assert_eq!(sandbox.head(), before);
}

#[test]
fn direct_sync_refuses_a_commit_hook_that_modifies_staged_content() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new("hook-mutates-commit");
    sandbox.write("docs/pending.md", "original\n");
    let hook = sandbox.work.join(".git/hooks/pre-commit");
    fs::write(
        &hook,
        "#!/bin/sh\nprintf 'unexpected\n' >> docs/pending.md\ngit add -A\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&hook).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&hook, permissions).unwrap();
    let before = sandbox.head();
    let remote_before = sandbox.pushed();
    let output = sandbox.run_with_mock_cargo("sync", 0);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "unexpected commit was published");
    assert!(
        stderr.contains("committed tree differs from verified tree"),
        "{stderr}"
    );
    assert_ne!(sandbox.head(), before, "hook never executed");
    assert_eq!(
        sandbox.pushed(),
        remote_before,
        "unverified commit was pushed"
    );
}

#[test]
fn an_interrupted_test_run_never_commits_or_pushes_main() {
    let sandbox = Sandbox::new("interrupted-test");
    sandbox.write("docs/pending.md", "not verified yet\n");
    let previous_head = sandbox.head();
    let previous_remote = sandbox.pushed();

    // Exercise the real 'all' lifecycle without building Rust in the scratch clone.
    // The stub succeeds at build/check but simulates cargo test killed by SIGKILL
    // (shell exit status 128 + 9). Incomplete tests must be a hard release gate.
    let output = sandbox.run_with_mock_cargo("all", 137);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "test exit 137 should fail the lifecycle: {stderr}"
    );
    // Inside the sandbox's target directory, in the checkout's own directory there.
    let checkouts = sandbox.root.join("target").join("checkouts");
    assert!(
        fs::read_dir(&checkouts).is_ok_and(|mut dirs| {
            dirs.any(|dir| dir.is_ok_and(|dir| dir.path().join("debug/huntsman-recon").exists()))
        }),
        "the mock build must write its stub inside the sandbox, never an inherited target dir"
    );
    assert!(
        stderr.contains("tests interrupted (exit 137); refusing sync"),
        "unexpected failure: {stderr}"
    );
    assert_eq!(
        sandbox.head(),
        previous_head,
        "local changes were committed"
    );
    assert_eq!(
        sandbox.pushed(),
        previous_remote,
        "remote main was modified"
    );

    let state = fs::read_to_string(sandbox.root.join("state/lifecycle-state")).unwrap();
    assert!(
        state.contains("phase=test\nstatus=failed\n"),
        "interrupted tests must be recorded as failed: {state}"
    );
    assert!(state.contains("tests incomplete"), "{state}");
}

#[test]
fn each_checkout_runs_the_binary_built_from_it_even_when_another_built_last() {
    use std::os::unix::fs::PermissionsExt;

    // Two checkouts on one device (two clones, or worktrees) share HOME, and so the lifecycle's
    // default build cache, or a CARGO_TARGET_DIR both export. Cargo would reuse one checkout's
    // build as fresh for the other, so each builds into a directory of its own, and `run` builds
    // before it runs: neither ever runs the binary the other built.
    let first = Sandbox::new("cache-first");
    let second = Sandbox::new("cache-second");
    let mock_bin = first.root.join("mock-bin-cache");
    fs::create_dir_all(&mock_bin).unwrap();
    let mock_cargo = mock_bin.join("cargo");
    fs::write(
        &mock_cargo,
        r#"#!/bin/sh
[ "$1" = build ] || exit 99
printf '%s|%s\n' "$CARGO_TARGET_DIR" "$CARGO_BUILD_BUILD_DIR" >> "$HOME/target-dirs"
mkdir -p "$CARGO_TARGET_DIR/debug" || exit 99
printf '#!/bin/sh\nprintf "built from %%s\\n" "%s"\n' "$PWD" > "$CARGO_TARGET_DIR/debug/huntsman-recon" || exit 99
chmod 755 "$CARGO_TARGET_DIR/debug/huntsman-recon"
"#,
    )
    .unwrap();
    let mut permissions = fs::metadata(&mock_cargo).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&mock_cargo, permissions).unwrap();
    let mut path = std::ffi::OsString::from(mock_bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());

    let shared = first.root.join("shared-target");
    for (home, target, cache) in [
        (
            first.root.join("home"),
            None,
            first.root.join("home/.cache/huntsman-recon-checkouts"),
        ),
        (
            second.root.join("home"),
            Some(&shared),
            shared.join("checkouts"),
        ),
    ] {
        let lifecycle = |sandbox: &Sandbox, mode: &str| {
            let mut command = sandbox.command("bash", &sandbox.work);
            command
                .env_remove("CARGO_TARGET_DIR")
                .env("HOME", &home)
                .env("PATH", &path);
            if let Some(target) = target {
                command.env("CARGO_TARGET_DIR", target);
            }
            let output = command
                .args(["scripts/lifecycle.sh", mode])
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{mode}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8_lossy(&output.stdout).into_owned()
        };
        lifecycle(&first, "build");
        lifecycle(&second, "build");
        let ran = lifecycle(&first, "run");
        assert!(
            ran.contains(&format!("built from {}", first.work.display())),
            "run did not run the binary built from its own checkout: {ran}"
        );
        assert!(
            !ran.contains(&format!("built from {}", second.work.display())),
            "run ran the other checkout's binary: {ran}"
        );
        let dirs = fs::read_to_string(home.join("target-dirs")).unwrap();
        let dirs: Vec<(&str, &str)> = dirs
            .lines()
            .map(|line| line.split_once('|').unwrap())
            .collect();
        assert_eq!(dirs.len(), 3, "run built before it ran: {dirs:?}");
        assert!(
            dirs.iter()
                .all(|(target, build)| target == build && Path::new(target).starts_with(&cache)),
            "{dirs:?}"
        );
        assert_eq!(dirs[0], dirs[2], "one checkout, one directory");
        assert_ne!(dirs[0], dirs[1], "two checkouts, two directories");
    }
}

/// A checkout at `dir` holding only the lifecycle script, and in `mock_bin` a `cargo` whose builds
/// log the directory they were given.
fn lone_checkout(dir: &Path, mock_bin: &Path) {
    use std::os::unix::fs::PermissionsExt;

    fs::create_dir_all(dir.join("scripts")).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/lifecycle.sh"),
        dir.join("scripts/lifecycle.sh"),
    )
    .unwrap();
    fs::create_dir_all(mock_bin).unwrap();
    let cargo = mock_bin.join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\n[ \"$1\" = build ] || exit 99\nprintf '%s\\n' \"$CARGO_TARGET_DIR\" >> \"$HOME/target-dirs\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&cargo).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&cargo, permissions).unwrap();
}

#[test]
fn a_checkout_named_with_a_colon_builds_where_cargo_accepts_the_path() {
    // Cargo joins the build directory into LD_LIBRARY_PATH, which a `:` in it would break.
    let root =
        std::env::temp_dir().join(format!("huntsman-lifecycle-{}-colon", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let checkout = root.join("wt:fix one");
    let mock_bin = root.join("mock-bin");
    lone_checkout(&checkout, &mock_bin);
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let mut path = std::ffi::OsString::from(mock_bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    let output = Command::new("bash")
        .current_dir(&checkout)
        .env_remove("CARGO_TARGET_DIR")
        .env("HOME", &home)
        .env("HUNTSMAN_HOME", root.join("state"))
        .env("PATH", path)
        .args(["scripts/lifecycle.sh", "build"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let dirs = fs::read_to_string(home.join("target-dirs")).unwrap();
    let name = Path::new(dirs.trim())
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    assert!(name.starts_with("wt_fix_one-"), "{name}");
    assert!(
        name.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')),
        "{name}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn without_cksum_the_lifecycle_refuses_instead_of_sharing_a_cache() {
    // Without the checksum, same-named checkouts would share one cache again.
    let root =
        std::env::temp_dir().join(format!("huntsman-lifecycle-{}-nocksum", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let checkout = root.join("huntsman");
    let mock_bin = root.join("mock-bin");
    lone_checkout(&checkout, &mock_bin);
    let which = |tool: &str| {
        let found = Command::new("sh")
            .args(["-c", &format!("command -v {tool}")])
            .output()
            .unwrap();
        PathBuf::from(String::from_utf8(found.stdout).unwrap().trim())
    };
    for tool in ["dirname", "mkdir", "chmod", "date", "tee"] {
        std::os::unix::fs::symlink(which(tool), mock_bin.join(tool)).unwrap();
    }
    let home = root.join("home");
    fs::create_dir_all(&home).unwrap();
    let output = Command::new(which("bash"))
        .current_dir(&checkout)
        .env_remove("CARGO_TARGET_DIR")
        .env("HOME", &home)
        .env("HUNTSMAN_HOME", root.join("state"))
        .env("PATH", &mock_bin)
        .args(["scripts/lifecycle.sh", "build"])
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(
        stderr.contains("cannot name this checkout's build directory"),
        "{stderr}"
    );
    assert!(!home.join("target-dirs").exists(), "a build ran: {stderr}");
    let _ = fs::remove_dir_all(&root);
}
