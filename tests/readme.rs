//! The README is a claim about the binary. Each claim here is checked against a run,
//! so a stale example, an undocumented command, or a wrong exit code fails the build.

use std::collections::BTreeSet;
use std::fs;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn readme() -> String {
    fs::read_to_string(root().join("README.md")).unwrap()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("huntsman-readme-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Shell-style split: double quotes group, an unquoted `#` after whitespace starts a comment.
fn shell_words(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let (mut quoted, mut in_word, mut prev_space) = (false, false, true);
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                in_word = true;
            }
            '#' if !quoted && prev_space => break,
            c if c.is_whitespace() && !quoted => {
                if in_word {
                    words.push(std::mem::take(&mut word));
                    in_word = false;
                }
            }
            c => {
                word.push(c);
                in_word = true;
            }
        }
        prev_space = c.is_whitespace() && !quoted;
    }
    assert!(!quoted, "unbalanced quote in README line: {line}");
    if in_word {
        words.push(word);
    }
    words
}

/// Argument lists of every `cargo run -- …` line in the README.
fn readme_examples() -> Vec<Vec<String>> {
    let examples: Vec<Vec<String>> = readme()
        .lines()
        .filter_map(|l| l.strip_prefix("cargo run -- "))
        .map(shell_words)
        .collect();
    assert!(
        !examples.is_empty(),
        "README has no `cargo run --` examples"
    );
    examples
}

fn usage_subcommands() -> BTreeSet<String> {
    let out = bin().arg("no-such-command").output().unwrap();
    let stderr = String::from_utf8(out.stderr).unwrap();
    let usage = stderr
        .lines()
        .find_map(|l| l.strip_prefix("usage: huntsman-recon ["))
        .and_then(|l| l.strip_suffix(']'))
        .unwrap_or_else(|| panic!("no usage line in {stderr:?}"));
    usage
        .split(" | ")
        .map(|alt| alt.split_whitespace().next().unwrap().to_owned())
        .collect()
}

/// Internet examples: a URL argument, any `email`/`username`/`query` lookup, `serve`, or any
/// `hibp` lookup (`hibp help` is offline). Provider-specific tests cover these separately.
fn is_network(args: &[String]) -> bool {
    args.iter()
        .any(|a| a.starts_with("https://") || a.starts_with("http://"))
        || args.first().is_some_and(|a| a == "email")
        || args.first().is_some_and(|a| a == "username")
        || args.first().is_some_and(|a| a == "query")
        || args.first().is_some_and(|a| a == "serve")
        || (args.first().is_some_and(|a| a == "hibp") && args.get(1).is_some_and(|a| a != "help"))
}

#[test]
fn every_command_has_an_example_and_every_example_is_a_command() {
    let documented: BTreeSet<String> = readme_examples()
        .into_iter()
        .map(|a| a[0].clone())
        .collect();
    assert_eq!(documented, usage_subcommands());
}

/// Runs the examples in README order in a scratch directory holding a copy of `docs/`
/// and a mode-600 `keys.env`. Examples that need the internet are excluded: the
/// fetch layer is proven against a local server in `tests/http_local.rs`.
#[test]
fn readme_examples_run_as_written() {
    let dir = scratch("examples");
    fs::create_dir_all(dir.join("docs")).unwrap();
    for entry in fs::read_dir(root().join("docs")).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            fs::copy(&path, dir.join("docs").join(path.file_name().unwrap())).unwrap();
        }
    }
    let keys = dir.join("keys.env");
    fs::write(&keys, "EXAMPLE_KEY=k3y-8f2a91\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&keys, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut ran = 0;
    for args in readme_examples().iter().filter(|a| !is_network(a)) {
        let out = bin().args(args).current_dir(&dir).output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "`{}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            !out.stdout.is_empty(),
            "`{}` printed nothing",
            args.join(" ")
        );
        ran += 1;
    }
    assert!(ran >= 10, "only {ran} examples ran");
    let _ = fs::remove_dir_all(&dir);
}

fn code(out: &Output) -> u8 {
    u8::try_from(out.status.code().expect("exited")).unwrap()
}

/// One offline run per documented exit code, each producing that code.
fn observed_exit_code(documented: u8) -> Option<u8> {
    let out = match documented {
        64 => bin().arg("no-such-command").output(),
        65 => bin().args(["geo", "91,0", "0,0"]).output(),
        66 => bin()
            .args(["search", "port", "/nonexistent/huntsman-readme"])
            .output(),
        69 => {
            let port = TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port();
            bin()
                .args([
                    "fetch",
                    &format!("http://127.0.0.1:{port}/"),
                    "--allow-private",
                ])
                .output()
        }
        74 => {
            let dir = scratch("ioerr");
            fs::create_dir_all(dir.join("var/navigator.json")).unwrap();
            let out = bin().arg("check").current_dir(&dir).output();
            let _ = fs::remove_dir_all(&dir);
            out
        }
        77 => bin().args(["fetch", "http://127.0.0.1:1/"]).output(),
        _ => return None,
    };
    Some(code(&out.unwrap()))
}

/// `Exit codes: 64 usage, 65 …, 77 ….` → the leading numbers.
fn documented_exit_codes(readme: &str) -> Vec<u8> {
    let line = readme
        .lines()
        .find_map(|l| l.strip_prefix("Exit codes: "))
        .expect("README has an `Exit codes:` line");
    let list = &line[..line.find(". ").unwrap_or(line.len())];
    list.split(", ")
        .map(|item| {
            item.split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or_else(|| panic!("exit-code item without a number: {item:?}"))
        })
        .collect()
}

#[test]
fn every_documented_exit_code_is_observed() {
    let documented = documented_exit_codes(&readme());
    assert!(!documented.is_empty(), "README documents no exit code");
    for want in &documented {
        assert_eq!(
            observed_exit_code(*want),
            Some(*want),
            "README documents exit {want}"
        );
    }
    let defined: BTreeSet<u8> = main_source()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("const EX_"))
        .filter_map(|l| l.split('=').nth(1))
        .map(|n| n.trim().trim_end_matches(';').parse().unwrap())
        .collect();
    assert_eq!(
        documented.iter().copied().collect::<BTreeSet<u8>>(),
        defined,
        "README exit codes differ from the EX_* constants in src/main.rs"
    );
}

fn main_source() -> String {
    fs::read_to_string(root().join("src/main.rs")).unwrap()
}

/// Gate codes passed to `gate(N, …)` in `src/main.rs`.
fn gate_codes(source: &str) -> BTreeSet<u8> {
    source
        .split("gate(")
        .skip(1)
        .filter_map(|rest| rest.trim_start().split(',').next()?.trim().parse().ok())
        .collect()
}

#[test]
fn documented_gate_range_matches_the_gates() {
    let readme = readme();
    let claim = readme
        .split("`check` uses ")
        .nth(1)
        .and_then(|rest| rest.split_whitespace().next())
        .expect("README states the `check` gate range");
    let (lo, hi) = claim.split_once('–').expect("range written as LO–HI");
    let range: BTreeSet<u8> = (lo.parse().unwrap()..=hi.parse().unwrap()).collect();
    assert_eq!(range, gate_codes(&main_source()));
}

#[test]
fn parsers_hold_on_known_inputs() {
    assert_eq!(
        shell_words(r#"search "brisbane port" docs/   # comment"#),
        ["search", "brisbane port", "docs/"]
    );
    assert_eq!(
        shell_words(r#"classify 200 "<html># not a comment</html>""#),
        ["classify", "200", "<html># not a comment</html>"]
    );
    assert_eq!(
        documented_exit_codes("Exit codes: 64 usage, 65 bad data. `check` uses 2–3."),
        [64, 65]
    );
    assert_eq!(
        gate_codes("gate(2, a)?; gate(\n 11,\n b)?; fn gate(code: u8"),
        BTreeSet::from([2, 11])
    );
}
