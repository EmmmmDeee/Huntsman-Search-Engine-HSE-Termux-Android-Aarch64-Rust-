//! Tests write the programs they run (fake `gh`, `cargo`, `docker`, sensor shims, git hooks) only
//! through `tests/support/executable.rs`. Writing one from the test process races a sibling test
//! thread's fork: the child holds the write descriptor until it execs, and running the program
//! meanwhile fails with ETXTBSY ("Text file busy"). That failed `xtask/tests/issue_fix_report.rs`
//! intermittently (issue #1590). This file checks the helper and refuses any other way of setting
//! an execute bit in a test source.

#[path = "support/executable.rs"]
mod executable;
#[allow(dead_code)]
#[path = "support/rust_code.rs"]
mod rust_code;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "executable-policy-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory");
    dir
}

#[test]
fn a_written_program_holds_its_body_and_mode_and_runs() {
    let dir = scratch("runs");
    let program = dir.join("with space");
    write_and_check(&program, "#!/bin/sh\nprintf ran\n", 0o700, b"ran");
    // Writing again replaces the body instead of appending to it, and sets the new mode.
    write_and_check(
        &program,
        "#!/bin/sh\nprintf 'ran again'\n",
        0o750,
        b"ran again",
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn write_and_check(program: &Path, body: &str, mode: u32, expected: &[u8]) {
    executable::write_executable(program, body, mode);
    let written = std::fs::metadata(program).expect("the program exists");
    assert_eq!(written.permissions().mode() & 0o777, mode);
    let output = Command::new(program).output().expect("the program runs");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, expected);
}

#[test]
#[should_panic(expected = "must be written with mode 755")]
fn a_program_that_cannot_be_written_is_a_named_failure() {
    let dir = scratch("missing-parent");
    executable::write_executable(&dir.join("absent/gh"), "#!/bin/sh\n", 0o755);
}

/// The race this helper removes, run on purpose: threads write programs and run them at once,
/// each start forking while other threads write. With an in-process `fs::write` and `chmod`, a
/// run of this size fails with "Text file busy" (measured: 1 run in 400 of the five report
/// tests). Every program here must start.
#[test]
fn programs_written_while_other_threads_start_processes_always_run() {
    let dir = scratch("race");
    let threads: Vec<_> = (0..8)
        .map(|thread| {
            let dir = dir.clone();
            std::thread::spawn(move || {
                for round in 0..40 {
                    let program = dir.join(format!("p-{thread}-{round}"));
                    executable::write_executable(
                        &program,
                        format!("#!/bin/sh\nprintf {thread}-{round}\n"),
                        0o755,
                    );
                    let output = Command::new(&program).output().unwrap_or_else(|error| {
                        panic!("{} must start: {error}", program.display())
                    });
                    assert_eq!(output.stdout, format!("{thread}-{round}").as_bytes());
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("every program started and ran");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the test directory can be read") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name != "fixtures") {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// The `0o…` literals passed to `from_mode(…)`, `set_mode(…)` or `.mode(…)` in SOURCE that set
/// any execute bit.
fn execute_bit_modes(source: &str) -> Vec<String> {
    let toks = rust_code::tokens(&rust_code::strip_non_code(source));
    let mut found = Vec::new();
    for (i, tok) in toks.iter().enumerate() {
        let call = match tok.as_str() {
            "from_mode" | "set_mode" => true,
            "mode" => i > 0 && toks[i - 1] == ".",
            _ => false,
        };
        if !call || rust_code::tok(&toks, i + 1) != "(" {
            continue;
        }
        let end = rust_code::skip_group(&toks, i + 1);
        for arg in &toks[i + 2..end - 1] {
            let Some(digits) = arg.strip_prefix("0o") else {
                continue;
            };
            let digits = digits.replace('_', "");
            let Ok(mode) = u32::from_str_radix(&digits, 8) else {
                continue;
            };
            if mode & 0o111 != 0 {
                found.push(format!("{tok}({arg})"));
            }
        }
    }
    found
}

#[test]
fn the_policy_reads_each_way_a_mode_is_set() {
    let refused = execute_bit_modes(
        "fs::set_permissions(&p, fs::Permissions::from_mode(0o755));\n\
         perms.set_mode(0o7_00);\n\
         builder.mode(0o750);\n\
         set_mode(&p, 0o711);\n\
         std::fs::Permissions::from_mode(\n    0o700,\n);",
    );
    assert_eq!(
        refused,
        [
            "from_mode(0o755)",
            "set_mode(0o7_00)",
            "mode(0o750)",
            "set_mode(0o711)",
            "from_mode(0o700)"
        ]
    );
    let allowed = execute_bit_modes(
        "fs::Permissions::from_mode(0o600);\n\
         assert_eq!(meta.permissions().mode() & 0o777, 0o755);\n\
         assert_eq!(mode(&dir), 0o700);\n\
         // from_mode(0o755) in a comment\n\
         let s = \"set_mode(0o755)\";",
    );
    assert!(allowed.is_empty(), "{allowed:?}");
}

#[test]
fn no_test_sets_an_execute_bit_except_through_the_shared_writer() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("tests"), &mut files);
    rust_files(&root.join("xtask/tests"), &mut files);
    assert!(
        files
            .iter()
            .any(|f| f.ends_with("xtask/tests/issue_fix_report.rs")),
        "the scan must cover the xtask tests"
    );
    let mut refused = Vec::new();
    for file in &files {
        let source = std::fs::read_to_string(file).expect("a test source is UTF-8");
        for call in execute_bit_modes(&source) {
            refused.push(format!(
                "{}: {call}",
                file.strip_prefix(root).unwrap_or(file).display()
            ));
        }
    }
    assert!(
        refused.is_empty(),
        "a test makes a file executable itself, which races a parallel test's fork into \
         \"Text file busy\"; write it with executable::write_executable \
         (#[path = \"support/executable.rs\"] mod executable;) instead:\n{}",
        refused.join("\n")
    );
}
