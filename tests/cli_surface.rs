//! One command surface. `cli::run` dispatches each command word; `--help` lists it with a
//! summary, the usage line names it, and `COMMAND --help` prints that command's own help. A word
//! the dispatcher accepts that one of them leaves out is a command no one can find, and
//! `tests/readme.rs` only ties the usage line to the README.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::EX_USAGE;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

/// The command words `cli::run` matches, read from its dispatch.
fn dispatched() -> BTreeSet<String> {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli/mod.rs"))
        .expect("src/cli/mod.rs");
    let dispatch = source
        .split("match remaining.next().as_deref() {")
        .nth(1)
        .expect("cli::run dispatches on the first argument");
    let words: BTreeSet<String> = dispatch
        .split("Some(\"")
        .skip(1)
        .filter_map(|rest| rest.split('"').next())
        .map(str::to_owned)
        .collect();
    assert!(words.len() > 20, "dispatch parse found only {words:?}");
    words
}

fn general_help() -> String {
    let out = bin().arg("--help").output().unwrap();
    assert!(out.status.success());
    String::from_utf8(out.stdout).unwrap()
}

/// The command words in `--help`'s `Commands:` list.
fn listed(help: &str) -> BTreeSet<String> {
    help.split("Commands:\n")
        .nth(1)
        .expect("--help has a Commands: list")
        .lines()
        .take_while(|line| !line.trim().is_empty())
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

/// The command words in the usage line.
fn in_usage(help: &str) -> BTreeSet<String> {
    let usage = help
        .lines()
        .find_map(|line| line.strip_prefix("usage: huntsman-recon ["))
        .and_then(|line| line.strip_suffix(']'))
        .expect("--help ends with the usage line");
    usage
        .split(" | ")
        .filter_map(|alternative| alternative.split_whitespace().next())
        .map(str::to_owned)
        .collect()
}

#[test]
fn help_lists_every_command_the_binary_dispatches_and_no_other() {
    assert_eq!(listed(&general_help()), dispatched());
}

#[test]
fn the_usage_line_names_every_command_the_binary_dispatches_and_no_other() {
    assert_eq!(in_usage(&general_help()), dispatched());
}

#[test]
fn every_command_has_help_of_its_own() {
    let general = general_help();
    for command in dispatched() {
        let out = bin().args([&command, "--help"]).output().unwrap();
        assert!(out.status.success(), "{command} --help");
        let text = String::from_utf8(out.stdout).unwrap();
        assert_ne!(
            text.trim(),
            general.trim(),
            "{command} --help prints the general help instead of its own"
        );
        assert!(
            text.contains(&command),
            "{command} --help does not name the command:\n{text}"
        );
    }
}

#[test]
fn scan_help_and_usage_name_every_kind_and_the_batch_save_directory() {
    let general = general_help();
    let out = bin().args(["scan", "--help"]).output().unwrap();
    let scan_help = String::from_utf8(out.stdout).unwrap();
    for text in [&general, &scan_help] {
        for needed in [
            "people|email|exposure|username|phone|domain",
            "--save-dir DIR",
        ] {
            assert!(text.contains(needed), "missing {needed:?} in:\n{text}");
        }
    }
}

/// With no command the binary does nothing unasked. It used to run `check`, which writes
/// `var/*.json` into whatever directory the user happens to be in.
#[test]
fn no_command_prints_the_help_to_stderr_and_writes_nothing() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli-surface-no-command");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    let out = bin().current_dir(&dir).output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert_eq!(stderr.trim_end(), general_help().trim_end());
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "wrote into {dir:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// Every dispatched command is handed all of its arguments. An arm that takes only the next one or
/// two leaves the rest unread, and the command then runs on part of what was typed.
#[test]
fn every_command_is_handed_all_of_its_arguments() {
    let source = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli/mod.rs"))
        .expect("src/cli/mod.rs");
    let dispatch = source
        .split("match remaining.next().as_deref() {")
        .nth(1)
        .expect("cli::run dispatches on the first argument");
    let dispatch = &dispatch[..dispatch.find("\n    }\n").expect("end of the dispatch")];
    assert!(
        !dispatch.contains("remaining.next()"),
        "a dispatch arm reads single arguments, so the rest are dropped:\n{dispatch}"
    );
}

/// A command that takes a fixed number of arguments refuses one more, before it reads or writes
/// anything, instead of running on the ones it expected.
#[test]
fn fixed_arity_commands_refuse_an_extra_argument() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("cli-surface-extra-argument");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for args in [
        &["check", "extra"][..],
        &["geo", "-27.4698,153.0251", "-33.8688,151.2093", "extra"][..],
        &["geohash", "-27.4698,153.0251", "9", "extra"][..],
        &["coarsen", "-27.4698,153.0251", "extra"][..],
        &["search", "brisbane port", ".", "extra"][..],
        &["verify", "ledger.json", "extra"][..],
        &["keys", "keys.env", "extra"][..],
    ] {
        let out = bin().args(args).current_dir(&dir).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "", "{args:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .starts_with(&format!("usage: huntsman-recon {}", args[0])),
            "{args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 0, "wrote into {dir:?}");
    let _ = fs::remove_dir_all(&dir);
}

/// A command whose last argument is free text takes the rest of the line, as `query` and
/// `investigate` do, so an unquoted name, ABN or response body means what it means quoted.
#[test]
fn free_text_commands_take_the_rest_of_the_line() {
    for (unquoted, quoted) in [
        (
            &["sources", "Ada", "Lovelace"][..],
            &["sources", "Ada Lovelace"][..],
        ),
        (
            &["id", "53", "004", "085", "616"][..],
            &["id", "53 004 085 616"][..],
        ),
        (
            &[
                "classify",
                "200",
                "<html>just",
                "a",
                "moment",
                "cloudflare</html>",
            ][..],
            &["classify", "200", "<html>just a moment cloudflare</html>"][..],
        ),
    ] {
        let split = bin().args(unquoted).output().unwrap();
        let whole = bin().args(quoted).output().unwrap();
        assert_eq!(whole.status.code(), Some(0), "{quoted:?}");
        assert_eq!(split.status.code(), whole.status.code(), "{unquoted:?}");
        assert_eq!(
            String::from_utf8_lossy(&split.stdout),
            String::from_utf8_lossy(&whole.stdout),
            "{unquoted:?}"
        );
    }
}
