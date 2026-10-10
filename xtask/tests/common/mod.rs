//! The fixture that the issue-fix guard and capture tests share. Each test works in a git
//! repository of its own, in a unique directory under the system temporary directory, and the
//! directory is removed when the test ends. The base commit holds the fixture of
//! scripts/issue-fix/self-check.sh, so the cases read the same as the shell cases did.

#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// The files of the base commit: the fixture of scripts/issue-fix/self-check.sh.
const FIXTURE: &[(&str, &str)] = &[
    ("src/lib.rs", "pub fn a() {}\n"),
    (
        "src/tested.rs",
        "pub fn c() -> u8 {\n    1\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn c_is_one() {\n        assert_eq!(super::c(), 1);\n    }\n}\n",
    ),
    ("src/tests.rs", "pub fn t() -> u8 {\n    1\n}\n"),
    (
        "src/parent.rs",
        "pub fn p() -> u8 {\n    2\n}\n\n#[cfg(test)]\nmod helpers;\n",
    ),
    (
        "src/parent/helpers.rs",
        "fn helper() -> u8 {\n    2\n}\n\n#[test]\nfn p_is_two() {\n    assert_eq!(super::p(), helper());\n}\n",
    ),
    (
        "src/odd.rs",
        "pub fn o() -> u8 {\n    3\n}\n\n#[cfg(test)]\n#[path = \"odd_dir/check.rs\"]\nmod check;\n",
    ),
    (
        "src/odd_dir/check.rs",
        "#[test]\nfn o_is_three() {\n    assert_eq!(super::o(), 3);\n}\n",
    ),
    (
        "src/inner.rs",
        "#![cfg(test)]\n\n#[test]\nfn inner_is_four() {\n    assert_eq!(4, 4);\n}\n",
    ),
    (
        "src/spaced.rs",
        "pub fn s() -> u8 {\n    2\n}\n\n# [test]\nfn s_is_two() {\n    assert_eq!(s(), 2);\n}\n",
    ),
    (
        "src/nul.rs",
        "pub fn n() -> u8 {\n    3\n}\n\n// a NUL byte follows: \0\n#[test]\nfn n_is_three() {\n    assert_eq!(n(), 3);\n}\n",
    ),
    (
        "src/attr.rs",
        "pub fn at() -> u8 {\n    5\n}\n\n#[test]\nfn at_is_five() {\n    assert_eq!(at(), 5);\n}\n",
    ),
    (
        "src/normal.rs",
        "pub fn nm() -> u8 {\n    6\n}\n\n#[test]\nfn nm_is_six() {\n    assert_eq!(nm(), 6);\n}\n",
    ),
    ("tests/existing.rs", "use fixture::a;\n"),
    (".github/workflows/ci.yml", "name: ci\n"),
    ("xtask/src/gate.rs", "fn main() {}\n"),
    ("Cargo.toml", "[package]\nname = \"fixture\"\n"),
];

/// A git repository for one test, removed when the test ends.
pub struct Repo {
    root: PathBuf,
    base: String,
}

impl Repo {
    /// A repository whose one commit is the base commit and holds the fixture.
    pub fn new(label: &str) -> Self {
        Self::with_files(label, &[])
    }

    /// A repository whose base commit holds the fixture and the EXTRA files, each given as its
    /// path and its contents.
    pub fn with_files(label: &str, extra: &[(&str, &str)]) -> Self {
        let root = unique_dir(label);
        fs::create_dir_all(&root).expect("the test directory must be created");
        let mut repo = Self {
            root,
            base: String::new(),
        };
        repo.git(&["init", "-q"]);
        for (path, contents) in FIXTURE.iter().chain(extra) {
            repo.write(path, contents);
        }
        repo.commit_all("base");
        repo
    }

    /// The directory of the repository.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The commit that the guard and the capture are run against.
    pub fn base(&self) -> &str {
        &self.base
    }

    /// Stages every change, commits it, and makes that commit the base.
    pub fn commit_all(&mut self, message: &str) {
        self.git(&["add", "-A"]);
        self.git(&[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-qm",
            message,
        ]);
        self.base = self.rev("HEAD");
    }

    /// The full object name of SPEC.
    pub fn rev(&self, spec: &str) -> String {
        let output = self.git(&["rev-parse", spec]);
        String::from_utf8(output.stdout)
            .expect("a revision is UTF-8")
            .trim()
            .to_owned()
    }

    /// Runs `git ARGS` in the repository, isolated from the global configuration, and asserts
    /// that it succeeds.
    pub fn git(&self, args: &[&str]) -> Output {
        let output = self.git_status(args);
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Runs `git ARGS` in the repository and returns the output, whatever its status.
    pub fn git_status(&self, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(&self.root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .expect("git must run")
    }

    /// Writes CONTENTS to PATH, which is relative to the repository, creating its directories.
    pub fn write(&self, path: &str, contents: &str) {
        self.write_bytes(path, contents.as_bytes());
    }

    /// Writes BYTES to PATH, which is relative to the repository, creating its directories.
    pub fn write_bytes(&self, path: &str, bytes: &[u8]) {
        let target = self.root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).expect("the parent directory must be created");
        }
        fs::write(&target, bytes).expect("the file must be written");
    }

    /// The text of PATH, which is relative to the repository.
    pub fn read(&self, path: &str) -> String {
        fs::read_to_string(self.root.join(path)).expect("the file must be read")
    }

    /// Replaces line LINE (1-based) of PATH with TEXT, as `sed -i 'NRs/.*/TEXT/'` does.
    pub fn set_line(&self, path: &str, line: usize, text: &str) {
        let contents = self.read(path);
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        let slot = lines
            .get_mut(line - 1)
            .expect("the line must exist in the fixture");
        *slot = text.to_owned();
        self.write(path, &with_newline(&lines));
    }

    /// Inserts TEXT after line LINE (1-based) of PATH, as `sed -i 'Na TEXT'` does.
    pub fn insert_after(&self, path: &str, line: usize, text: &str) {
        let contents = self.read(path);
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        lines.insert(line, text.to_owned());
        self.write(path, &with_newline(&lines));
    }

    /// Replaces every OLD in PATH with NEW, as `sed -i 's/OLD/NEW/g'` does.
    pub fn replace(&self, path: &str, old: &str, new: &str) {
        let contents = self.read(path);
        assert!(contents.contains(old), "{old:?} must be in {path}");
        self.write(path, &contents.replace(old, new));
    }

    /// Appends TEXT to PATH, as `>>` does.
    pub fn append(&self, path: &str, text: &str) {
        let mut contents = self.read(path);
        contents.push_str(text);
        self.write(path, &contents);
    }

    /// Stages PATH, which is relative to the repository.
    pub fn add(&self, path: &str) {
        self.git(&["add", path]);
    }

    /// Removes PATH from the index and the working tree.
    pub fn remove(&self, path: &str) {
        self.git(&["rm", "-q", path]);
    }

    /// Renames FROM to TO with git.
    pub fn rename(&self, from: &str, to: &str) {
        self.git(&["mv", from, to]);
    }

    /// Creates a symbolic link at PATH that points at TARGET.
    pub fn symlink(&self, target: &str, path: &str) {
        let link = self.root.join(path);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent).expect("the parent directory must be created");
        }
        symlink(target, link).expect("the link must be created");
    }

    /// Undoes every change: untracked files are removed and the base commit is restored.
    pub fn reset(&self) {
        self.git(&["clean", "-fdq"]);
        self.git(&["reset", "-q", "--hard", &self.base]);
    }

    /// Runs the guard of this build against the base commit, in the repository.
    pub fn guard(&self) -> Output {
        xtask(&self.root, &["issue-fix", "guard", &self.base])
    }

    /// Runs the capture of this build against the base commit, writing into OUT, which is
    /// relative to the repository.
    pub fn capture(&self, out: &str) -> Output {
        xtask(&self.root, &["issue-fix", "capture", &self.base, out])
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        // The test has finished, so a directory that is already gone is not a failure.
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// An empty directory for one test, removed when the test ends.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// An empty directory that no other test uses.
    pub fn new(label: &str) -> Self {
        let path = unique_dir(label);
        fs::create_dir_all(&path).expect("the scratch directory must be created");
        Self { path }
    }

    /// The directory.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Runs this build of xtask with ARGS in DIR, in an environment that carries no global git
/// configuration.
pub fn xtask(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .expect("xtask must run")
}

/// The lines joined with a newline at the end, as a text file is written.
fn with_newline(lines: &[String]) -> String {
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// A directory name that no other test uses: the label, the process, the time, and a counter.
fn unique_dir(label: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let safe: String = label
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let counter = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "xtask-issue-fix-{safe}-{}-{stamp}-{counter}",
        std::process::id()
    ))
}
