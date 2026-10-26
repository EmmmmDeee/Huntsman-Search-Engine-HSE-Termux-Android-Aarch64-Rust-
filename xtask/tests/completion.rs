//! The adaptive register must cover the entire Git index without changing runtime source.
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask process")
}

#[test]
fn generated_tree_contains_every_tracked_path_and_is_repeatable() {
    let one = xtask(&["completion", "print"]);
    let two = xtask(&["completion", "print"]);
    assert!(one.status.success(), "{one:?}");
    assert!(two.status.success(), "{two:?}");
    assert_eq!(
        one.stdout, two.stdout,
        "same Git index must be deterministic"
    );
    let document = String::from_utf8(one.stdout).expect("UTF-8 document");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root");
    let paths = Command::new("git")
        .args(["ls-files", "-z", "--cached"])
        .current_dir(root)
        .output()
        .expect("git ls-files");
    assert!(paths.status.success(), "{paths:?}");
    for raw in paths
        .stdout
        .split(|byte| *byte == 0)
        .filter(|p| !p.is_empty())
    {
        let path = std::str::from_utf8(raw).expect("UTF-8 tracked path");
        let basename = path.rsplit('/').next().expect("basename");
        assert!(
            document.contains(basename),
            "tracked path is absent from adaptive tree: {path}"
        );
    }
    assert!(document.contains("## Dependency-ordered implementation queue"));
    assert!(document.contains("docs/completion/handset-evidence.md"));
    assert!(document.contains("[P:PROPOSED]"));
}

#[test]
fn written_report_matches_print_mode() {
    let written = xtask(&["completion", "write"]);
    assert!(written.status.success(), "{written:?}");
    let checked = xtask(&["completion", "check"]);
    assert!(checked.status.success(), "{checked:?}");
    let printed = xtask(&["completion", "print"]);
    assert!(printed.status.success(), "{printed:?}");
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repository root");
    let file = fs::read(root.join("target/completion/IMPLEMENTATION_REGISTER.md"))
        .expect("generated register");
    assert_eq!(file, printed.stdout);
}

#[test]
fn unsupported_operations_are_usage_errors() {
    let result = xtask(&["completion", "unsafe-apply"]);
    assert_eq!(result.status.code(), Some(64), "{result:?}");
}
