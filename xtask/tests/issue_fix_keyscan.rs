//! Behaviour of `xtask issue-fix key-scan`, and of the model step's scan block that runs it. The
//! block is read from the workflow file and run in a git tree the way the model step runs it: the
//! same listing, the same environment, and the same redaction of the model output. These cases are
//! the ones the offline self-check covered before the scan was ported.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const KEY: &str = "fixture~~~model~key";
const WORKFLOW: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../.github/workflows/issue-fix.yml"
);
const DOCS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/ISSUE_FIX.md");
const REFUSAL: &str = "the model key, or an encoding of it, is in";

/// The forms of the fixture key that the scan must find, as Python's base64 module writes them. The
/// stream rows put the key at each alignment inside a longer base64 stream, with a prefix of 0 to 3
/// bytes and the first 0 to 3 characters cut.
const FORMS: &[(&str, &str)] = &[
    ("literal", "fixture~~~model~key"),
    ("hex", "666978747572657e7e7e6d6f64656c7e6b6579"),
    ("hex-upper", "666978747572657E7E7E6D6F64656C7E6B6579"),
    ("base64", "Zml4dHVyZX5+fm1vZGVsfmtleQ=="),
    ("base64url", "Zml4dHVyZX5-fm1vZGVsfmtleQ=="),
    (
        "assignment",
        "ANTHROPIC_API_KEY=Zml4dHVyZX5+fm1vZGVsfmtleQ==",
    ),
    ("stream-prefix0-cut0", "Zml4dHVyZX5+fm1vZGVsfmtleXRhaWw="),
    ("stream-prefix1-cut0", "eGZpeHR1cmV+fn5tb2RlbH5rZXl0YWls"),
    (
        "stream-prefix2-cut0",
        "eHhmaXh0dXJlfn5+bW9kZWx+a2V5dGFpbA==",
    ),
    (
        "stream-prefix3-cut0",
        "eHh4Zml4dHVyZX5+fm1vZGVsfmtleXRhaWw=",
    ),
    ("stream-prefix3-cut1", "Hh4Zml4dHVyZX5+fm1vZGVsfmtleXRhaWw="),
    ("stream-prefix3-cut2", "h4Zml4dHVyZX5+fm1vZGVsfmtleXRhaWw="),
    ("stream-prefix3-cut3", "4Zml4dHVyZX5+fm1vZGVsfmtleXRhaWw="),
];

/// A directory that is removed when the test ends.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("keyscan-{name}-{}", std::process::id()));
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

/// A git command with the configuration of the machine kept out, so the listing is the same everywhere.
fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.com")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.com")
        .status()
        .expect("git must run");
    assert!(status.success(), "git {args:?} failed in {}", dir.display());
}

/// A git tree with the given files, none of them committed, so each is untracked and listed.
fn tree(root: &Path, files: &[(&str, &[u8])]) -> PathBuf {
    let dir = root.join("tree");
    fs::create_dir_all(&dir).expect("the tree directory can be made");
    git(&dir, &["init", "-q"]);
    for (name, content) in files {
        let path = dir.join(name);
        fs::create_dir_all(path.parent().expect("a file has a parent")).expect("parent directory");
        fs::write(&path, content).expect("the fixture file can be written");
    }
    dir
}

/// The key-scan block of the model step: from `scan_status=0` through the `exit "$status"` line, with
/// the step's indentation removed. The test runs what CI runs, so a change to the step is tested here.
fn scan_block() -> String {
    let workflow = fs::read_to_string(WORKFLOW).expect("the issue-fix workflow exists");
    let mut block = Vec::new();
    let mut inside = false;
    for line in workflow.lines() {
        if line == "          scan_status=0" {
            inside = true;
        }
        if inside {
            block.push(line.strip_prefix("          ").unwrap_or(line));
        }
        if inside && line == "          exit \"$status\"" {
            break;
        }
    }
    let text = block.join("\n") + "\n";
    assert!(
        text.contains("\"$RUNNER_TEMP/trusted-xtask\" issue-fix key-scan \"$RUNNER_TEMP/change/agent.json\" \"$RUNNER_TEMP/scan-paths\""),
        "the model step must run the trusted key scan:\n{text}"
    );
    text
}

/// The outcome of the scan block in TREE: its status, its standard error, and the model output after
/// the block redacted it.
struct Outcome {
    status: i32,
    /// Standard output and standard error together, as the step's log holds them.
    log: String,
    agent: String,
}

/// Runs the scan block in TREE as the model step does. The model output is copied to the runner's
/// change directory, the trusted binary is linked as `trusted-xtask`, and the key is in the
/// environment only when KEY is Some.
fn run_block(name: &str, tree: &Path, key: Option<&str>, agent: &str) -> Outcome {
    let runner = Scratch::new(&format!("runner-{name}"));
    fs::create_dir_all(runner.path().join("change")).expect("the change directory can be made");
    fs::write(runner.path().join("change/agent.json"), agent)
        .expect("the model output can be written");
    symlink(
        env!("CARGO_BIN_EXE_xtask"),
        runner.path().join("trusted-xtask"),
    )
    .expect("the trusted binary can be linked");
    let block = runner.path().join("block.sh");
    fs::write(&block, scan_block()).expect("the block can be written");

    let mut command = Command::new("bash");
    command
        .args(["--noprofile", "--norc", "-eo", "pipefail"])
        .arg(&block)
        .current_dir(tree)
        .env("RUNNER_TEMP", runner.path())
        .env("status", "0")
        .env_remove("ANTHROPIC_API_KEY")
        .stdin(std::process::Stdio::null());
    if let Some(key) = key {
        command.env("ANTHROPIC_API_KEY", key);
    }
    let output: Output = command.output().expect("bash must run the scan block");
    let agent = fs::read_to_string(runner.path().join("change/agent.json"))
        .expect("the model output is still there");
    Outcome {
        status: output.status.code().unwrap_or(-1),
        log: format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
        agent,
    }
}

#[test]
fn the_scan_refuses_each_form_of_the_key_in_a_source_file() {
    let scratch = Scratch::new("forms");
    for (name, value) in FORMS {
        let dir = tree(
            scratch.path(),
            &[(
                "src/lib.rs",
                format!("pub fn a() {{}} // {value}\n").as_bytes(),
            )],
        );
        let outcome = run_block(name, &dir, Some(KEY), "{\"result\": \"ok\"}\n");
        assert_eq!(
            outcome.status, 1,
            "the {name} form must refuse: {}",
            outcome.log
        );
        assert!(
            outcome.log.contains(REFUSAL) && outcome.log.contains("src/lib.rs"),
            "the {name} form must name the file: {}",
            outcome.log
        );
        fs::remove_dir_all(&dir).expect("the tree can be removed");
    }
}

/// The unpadded base64 forms of the key: the standard and the URL-safe alphabet, and the key after a
/// one-byte prefix. Each is the last thing in its run, so the run's final group has no padding.
#[test]
fn unpadded_base64_of_the_key_at_the_end_of_a_run_is_refused() {
    let scratch = Scratch::new("unpadded");
    for (name, value) in [
        ("unpadded-standard", "Zml4dHVyZX5+fm1vZGVsfmtleQ"),
        ("unpadded-url-safe", "Zml4dHVyZX5-fm1vZGVsfmtleQ"),
        ("unpadded-after-prefix", "eGZpeHR1cmV+fn5tb2RlbH5rZXk"),
    ] {
        let dir = tree(
            scratch.path(),
            &[(
                "src/lib.rs",
                format!("pub const X: &str = \"{value}\";\n").as_bytes(),
            )],
        );
        let outcome = run_block(name, &dir, Some(KEY), "{\"result\": \"ok\"}\n");
        assert_eq!(
            outcome.status, 1,
            "the {name} form must refuse: {}",
            outcome.log
        );
        assert!(
            outcome.log.contains(REFUSAL) && outcome.log.contains("src/lib.rs"),
            "the {name} form must name the file: {}",
            outcome.log
        );
        fs::remove_dir_all(&dir).expect("the tree can be removed");
    }
}

#[test]
fn a_clean_tree_passes_and_its_model_output_loses_every_form_of_the_key() {
    let scratch = Scratch::new("clean");
    let dir = tree(
        scratch.path(),
        &[
            ("src/lib.rs", b"pub fn a() {}\n"),
            (".gitignore", b"target/\n"),
            ("target/build.log", KEY.as_bytes()),
        ],
    );
    let agent = format!(
        "{{\"result\": \"literal {KEY}, base64 Zml4dHVyZX5+fm1vZGVsfmtleQ==, hex 666978747572657E7E7E6D6F64656C7E6B6579, and sk-ant-abc123\"}}\n"
    );
    let outcome = run_block("clean", &dir, Some(KEY), &agent);
    assert_eq!(outcome.status, 0, "a clean tree must pass: {}", outcome.log);
    for form in [KEY, "Zml4dHVyZX5", "666978747572", "sk-ant-"] {
        assert!(
            !outcome.agent.contains(form),
            "{form} survived the redaction: {}",
            outcome.agent
        );
    }
    assert!(outcome.agent.contains("[redacted]"));
}

#[test]
fn a_key_in_an_untracked_file_is_refused() {
    let scratch = Scratch::new("untracked");
    let dir = tree(
        scratch.path(),
        &[
            ("src/lib.rs", b"pub fn a() {}\n"),
            ("tests/issue_fix_9.rs", format!("// {KEY}\n").as_bytes()),
        ],
    );
    let outcome = run_block("untracked", &dir, Some(KEY), "{\"result\": \"ok\"}\n");
    assert_eq!(outcome.status, 1);
    assert!(
        outcome.log.contains("tests/issue_fix_9.rs"),
        "{}",
        outcome.log
    );
}

#[test]
fn a_target_directory_that_a_nested_gitignore_re_includes_is_read() {
    let scratch = Scratch::new("nested");
    let dir = tree(
        scratch.path(),
        &[
            (".gitignore", b"target/\n"),
            ("src/.gitignore", b"!target/\n"),
            ("src/lib.rs", b"pub fn a() {}\n"),
            ("src/target/leak.txt", KEY.as_bytes()),
        ],
    );
    let outcome = run_block("nested", &dir, Some(KEY), "{\"result\": \"ok\"}\n");
    assert_eq!(
        outcome.status, 1,
        "the re-included target/ must be read: {}",
        outcome.log
    );
    assert!(
        outcome.log.contains("src/target/leak.txt"),
        "{}",
        outcome.log
    );
}

#[test]
fn a_file_name_that_carries_the_key_is_refused_and_the_name_is_not_printed() {
    let scratch = Scratch::new("name");
    let dir = tree(scratch.path(), &[("src/lib.rs", b"pub fn a() {}\n")]);
    fs::write(dir.join("src").join(format!("{KEY}.rs")), b"x\n").expect("the named file");
    let outcome = run_block("name", &dir, Some(KEY), "{\"result\": \"ok\"}\n");
    assert_eq!(outcome.status, 1);
    assert!(
        outcome.log.contains("the file name of entry 1"),
        "{}",
        outcome.log
    );
    assert!(
        !outcome.log.contains(KEY),
        "the name was printed: {}",
        outcome.log
    );
}

#[test]
fn a_symbolic_link_whose_target_carries_the_key_is_refused() {
    let scratch = Scratch::new("link");
    let dir = tree(scratch.path(), &[("src/lib.rs", b"pub fn a() {}\n")]);
    symlink(KEY, dir.join("src/link.rs")).expect("the link can be made");
    let outcome = run_block("link", &dir, Some(KEY), "{\"result\": \"ok\"}\n");
    assert_eq!(outcome.status, 1);
    assert!(outcome.log.contains("src/link.rs"), "{}", outcome.log);
}

#[test]
fn an_unset_or_short_key_refuses_the_scan() {
    let scratch = Scratch::new("short");
    let dir = tree(scratch.path(), &[("src/lib.rs", b"pub fn a() {}\n")]);
    for key in [None, Some("abc")] {
        let outcome = run_block("short", &dir, key, "{\"result\": \"ok\"}\n");
        assert_eq!(outcome.status, 1, "key {key:?}");
        assert!(
            outcome.log.contains("unset or too short"),
            "{}",
            outcome.log
        );
    }
}

#[test]
fn a_tree_that_cannot_be_listed_is_refused() {
    let scratch = Scratch::new("unlistable");
    let dir = scratch.path().join("plain");
    fs::create_dir_all(dir.join("src")).expect("the directory can be made");
    fs::write(dir.join("src/lib.rs"), b"pub fn a() {}\n").expect("the file can be written");
    let outcome = run_block("unlistable", &dir, Some(KEY), "{\"result\": \"ok\"}\n");
    assert_eq!(outcome.status, 1);
    assert!(
        outcome.log.contains("cannot list the files"),
        "{}",
        outcome.log
    );
}

#[test]
fn a_refused_change_still_has_its_model_output_redacted() {
    let scratch = Scratch::new("refused-output");
    let dir = tree(scratch.path(), &[("src/leak.txt", KEY.as_bytes())]);
    let agent = format!("{{\"result\": \"{KEY}\"}}\n");
    let outcome = run_block("refused-output", &dir, Some(KEY), &agent);
    assert_eq!(outcome.status, 1);
    assert!(
        !outcome.agent.contains(KEY),
        "the refused output kept the key: {}",
        outcome.agent
    );
}

#[test]
fn a_file_that_cannot_be_read_is_reported_and_refused() {
    let scratch = Scratch::new("unreadable");
    let listing = scratch.path().join("paths.bin");
    fs::write(&listing, b"/proc/self/mem\0").expect("the listing can be written");
    let agent = scratch.path().join("agent.json");
    fs::write(&agent, b"{\"result\": \"ok\"}\n").expect("the output can be written");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "key-scan"])
        .arg(&agent)
        .arg(&listing)
        .env("ANTHROPIC_API_KEY", KEY)
        .output()
        .expect("xtask must run");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr.contains("::error::cannot read /proc/self/mem: Input/output error"),
        "{stderr}"
    );
    assert!(stderr.contains("is in /proc/self/mem"), "{stderr}");
}

#[test]
fn a_key_that_is_not_utf_8_is_refused_even_when_nothing_is_listed() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let scratch = Scratch::new("not-utf8");
    let listing = scratch.path().join("paths.bin");
    fs::write(&listing, b"").expect("the listing can be written");
    let agent = scratch.path().join("agent.json");
    fs::write(&agent, b"{\"result\": \"ok\"}\n").expect("the output can be written");
    let key = OsStr::from_bytes(b"model\xffkey-bytes");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "key-scan"])
        .arg(&agent)
        .arg(&listing)
        .env("ANTHROPIC_API_KEY", key)
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("the model key is not UTF-8"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn entries_that_are_not_files_or_links_are_skipped() {
    let scratch = Scratch::new("skipped");
    fs::create_dir_all(scratch.path().join("src")).expect("the directory can be made");
    let listing = scratch.path().join("paths.bin");
    fs::write(&listing, b"src\0absent.rs\0").expect("the listing can be written");
    let agent = scratch.path().join("agent.json");
    fs::write(&agent, b"{\"result\": \"ok\"}\n").expect("the output can be written");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "key-scan"])
        .arg(&agent)
        .arg(&listing)
        .current_dir(scratch.path())
        .env("ANTHROPIC_API_KEY", KEY)
        .output()
        .expect("xtask must run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn a_missing_listing_is_an_error_and_a_missing_model_output_is_left_alone() {
    let scratch = Scratch::new("missing");
    let agent = scratch.path().join("agent.json");
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "key-scan"])
        .arg(&agent)
        .arg(scratch.path().join("no-listing.bin"))
        .env("ANTHROPIC_API_KEY", KEY)
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("issue-fix key-scan: "),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !agent.exists(),
        "a model output that was not there must not be created"
    );
}

/// The text with each line's comment marker and indentation removed, and the lines joined by spaces, so
/// a sentence that the source breaks across lines can be searched for as one.
fn prose(text: &str) -> String {
    text.lines()
        .map(|line| line.trim().trim_start_matches('#').trim())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The trust notes of the key scan must describe what is enforced. The scanner is a copy in
/// RUNNER_TEMP, and code that the model's cargo commands run can overwrite it, so no note may say
/// that the model cannot change it.
#[test]
fn the_trust_note_does_not_say_the_model_cannot_change_the_scanner() {
    let workflow = prose(&fs::read_to_string(WORKFLOW).expect("the issue-fix workflow exists"));
    let docs = prose(&fs::read_to_string(DOCS).expect("the issue-fix document exists"));
    assert!(
        !workflow.contains("so the model cannot change it"),
        "the workflow's scan note says the model cannot change the scanner"
    );
    assert!(
        !docs.contains("which the model cannot write"),
        "the document's key scan note says the model cannot write the scanner"
    );
    assert!(
        workflow.contains("can overwrite it"),
        "the workflow's scan note must say that the scanner copy can be overwritten"
    );
    assert!(
        docs.contains("can overwrite it"),
        "the document's key scan note must say that the scanner copy can be overwritten"
    );
}

/// The build step's note on the checking tools must not say that the model never writes them or
/// cannot reach them. The copy in RUNNER_TEMP is writable by code that the model's cargo commands run.
#[test]
fn the_build_step_does_not_say_the_model_cannot_reach_the_checking_tools() {
    let workflow = prose(&fs::read_to_string(WORKFLOW).expect("the issue-fix workflow exists"));
    assert!(
        !workflow.contains("never written by the model"),
        "the build step says the model never writes the checking tools"
    );
    assert!(
        !workflow.contains("cannot reach it through the checkout"),
        "the build step says the model cannot reach the checking tools through the checkout"
    );
}

#[test]
fn the_wrong_number_of_arguments_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["issue-fix", "key-scan", "only-one"])
        .output()
        .expect("xtask must run");
    assert_eq!(output.status.code(), Some(64));
}
