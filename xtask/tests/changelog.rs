//! The changelog fragments: `check` validates them, `assemble` moves them to the top of their
//! section under `[Unreleased]` and deletes them, `render` prints the same and writes nothing.
//! Each test works in a directory of its own under the system temporary directory.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static NEXT: AtomicUsize = AtomicUsize::new(0);

const CHANGELOG: &str = "# Changelog\n\nAn intro paragraph.\n\n## [Unreleased]\n\n\
### Added\n\n- An older addition.\n\n### Changed\n\n- An older change.\n\n\
## [0.1.0] - 2026-01-01\n\n### Fixed\n\n- An old fix.\n";

struct Dir(PathBuf);

impl Dir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let root = std::env::temp_dir().join(format!(
            "xtask-changelog-{label}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(root.join("changelog.d")).expect("create the fragments directory");
        fs::write(root.join("CHANGELOG.md"), CHANGELOG).expect("write the changelog");
        fs::write(root.join("changelog.d/README.md"), "# Fragments\n").expect("write the readme");
        Self(root)
    }

    fn fragment(&self, name: &str, body: &str) {
        fs::write(self.0.join("changelog.d").join(name), body).expect("write a fragment");
    }

    fn changelog(&self) -> String {
        fs::read_to_string(self.0.join("CHANGELOG.md")).expect("read the changelog")
    }

    fn fragment_names(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.0.join("changelog.d"))
            .expect("list the fragments")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    fn run(&self, command: &str) -> Output {
        xtask(&["changelog", command, "--root"], &self.0)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn xtask(args: &[&str], root: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .arg(root)
        .output()
        .expect("xtask must run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn assemble_puts_each_fragment_at_the_top_of_its_section_and_creates_a_missing_one() {
    let dir = Dir::new("assemble");
    dir.fragment("b-topic.changed.md", "- The second change.\n");
    dir.fragment(
        "a-topic.changed.md",
        "- The first change,\n  continued on a second line.\n",
    );
    dir.fragment("zz.fixed.md", "- A fix.\n");
    dir.fragment("k.security.md", "- A patch.\n");
    dir.fragment("n.added.md", "- A new thing.\n\n- Another new thing.\n");

    let out = dir.run("assemble");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("assembled 5 fragment(s)"),
        "{}",
        text(&out.stdout)
    );
    let expected = "# Changelog\n\nAn intro paragraph.\n\n## [Unreleased]\n\n\
### Added\n\n- A new thing.\n\n- Another new thing.\n- An older addition.\n\n\
### Changed\n\n- The first change,\n  continued on a second line.\n- The second change.\n\
- An older change.\n\n### Fixed\n\n- A fix.\n\n### Security\n\n- A patch.\n\n\
## [0.1.0] - 2026-01-01\n\n### Fixed\n\n- An old fix.\n";
    assert_eq!(dir.changelog(), expected);
    assert_eq!(dir.fragment_names(), ["README.md"]);

    let again = dir.run("assemble");
    assert!(again.status.success(), "{}", text(&again.stderr));
    assert!(
        text(&again.stdout).contains("no fragments"),
        "{}",
        text(&again.stdout)
    );
    assert_eq!(dir.changelog(), expected);
}

#[test]
fn a_section_the_block_lacks_goes_before_the_first_later_section() {
    let dir = Dir::new("order");
    fs::write(
        dir.0.join("CHANGELOG.md"),
        "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n- An old fix.\n",
    )
    .expect("write");
    dir.fragment("x.removed.md", "- Gone.\n");
    dir.fragment("y.security.md", "- Patched.\n");
    let out = dir.run("assemble");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        dir.changelog(),
        "# Changelog\n\n## [Unreleased]\n\n### Removed\n\n- Gone.\n\n### Fixed\n\n- An old fix.\n\n\
### Security\n\n- Patched.\n"
    );
}

#[test]
fn render_prints_the_assembled_changelog_and_writes_nothing() {
    let dir = Dir::new("render");
    dir.fragment("t.changed.md", "- Rendered.\n");
    let out = dir.run("render");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let shown = text(&out.stdout);
    assert!(
        shown.contains("### Changed\n\n- Rendered.\n- An older change.\n"),
        "{shown}"
    );
    assert_eq!(dir.changelog(), CHANGELOG);
    assert_eq!(dir.fragment_names(), ["README.md", "t.changed.md"]);
}

#[test]
fn check_counts_valid_fragments_and_refuses_each_malformed_one() {
    let dir = Dir::new("check");
    dir.fragment("one.added.md", "- One.\n");
    dir.fragment("two-2.fixed.md", "- Two.\n  More.\n");
    let out = dir.run("check");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("2 fragment(s) valid"),
        "{}",
        text(&out.stdout)
    );

    for (name, body) in [
        ("Bad.changed.md", "- Upper-case slug.\n"),
        ("bad.unknown.md", "- Unknown section.\n"),
        ("bad.md", "- No section.\n"),
        ("bad.changed.txt", "- Not markdown.\n"),
        ("bad-line.changed.md", "Not a bullet.\n"),
        ("bad-empty.changed.md", ""),
        ("bad-blank.changed.md", "- \n"),
        ("bad-newline.changed.md", "- No final newline"),
    ] {
        dir.fragment(name, body);
        let out = dir.run("check");
        assert_eq!(out.status.code(), Some(1), "{name}: {}", text(&out.stderr));
        assert!(
            text(&out.stderr).contains(name),
            "{name}: {}",
            text(&out.stderr)
        );
        fs::remove_file(dir.0.join("changelog.d").join(name)).expect("remove");
    }
    assert_eq!(dir.changelog(), CHANGELOG);
}

#[test]
fn check_refuses_a_changelog_without_the_unreleased_heading() {
    let dir = Dir::new("heading");
    fs::write(dir.0.join("CHANGELOG.md"), "# Changelog\n\n## [0.1.0]\n").expect("write");
    let out = dir.run("check");
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("[Unreleased]"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn a_missing_fragments_directory_holds_no_fragments() {
    let dir = Dir::new("missing");
    fs::remove_dir_all(dir.0.join("changelog.d")).expect("remove");
    let out = dir.run("check");
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("0 fragment(s) valid"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn the_command_needs_one_of_its_three_verbs() {
    let dir = Dir::new("usage");
    assert_eq!(dir.run("publish").status.code(), Some(64));
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["changelog"])
        .output()
        .expect("xtask must run");
    assert_eq!(out.status.code(), Some(64));
}
