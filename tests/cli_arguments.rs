//! A bad argument is a usage error, exit 64, with the usage line on stderr and nothing on
//! stdout: an argument that is not UTF-8 (a file name from Android's shared storage can be),
//! and `--help` after a word that is not a command.

use std::process::Command;

use huntsman_recon::exit::EX_USAGE;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[cfg(unix)]
#[test]
fn an_argument_that_is_not_utf8_is_a_usage_error_not_a_panic() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let out = bin()
        .arg("search")
        .arg(OsStr::from_bytes(b"caf\xe9"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.starts_with("argument 2 is not valid UTF-8 (4 bytes)"),
        "{stderr}"
    );
    assert!(stderr.contains("usage: huntsman-recon ["), "{stderr}");
    // The bytes are not echoed: an argument can be a selector.
    assert!(!out.stderr.windows(4).any(|w| w == b"caf\xe9"));
}

#[test]
fn help_after_a_word_that_is_not_a_command_is_the_unknown_command_error() {
    let out = bin().args(["scna", "--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{out:?}");
    assert_eq!(String::from_utf8_lossy(&out.stdout), "");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.starts_with("unknown command: scna\n"), "{stderr}");
    assert!(stderr.contains("usage: huntsman-recon ["), "{stderr}");
    // A real command's help is unchanged.
    let out = bin().args(["scan", "-h"]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("scan SELECTOR"));
}

#[test]
fn a_scan_value_flag_refuses_a_repeat_or_a_missing_value_by_name() {
    let refusals: [(&[&str], &str); 8] = [
        (&["jane", "-k"], "scan -k/--kind needs a value"),
        (
            &["jane", "-k", "person", "-k", "domain"],
            "scan accepts only one -k/--kind",
        ),
        (
            &["--input-file", "--save-dir"],
            "scan --input-file needs a file path",
        ),
        (
            &["jane", "--save-dir", "a", "--save-dir", "b"],
            "scan accepts only one --save-dir",
        ),
        (
            &["--recurse", "jane", "--max-generations"],
            "scan --max-generations needs a value",
        ),
        (
            &["--recurse", "jane", "--max-generations", "x"],
            "scan --max-generations needs a non-negative integer",
        ),
        (
            &[
                "--recurse",
                "jane",
                "--expand-floor",
                "0.5",
                "--expand-floor",
                "0.6",
            ],
            "scan accepts only one --expand-floor",
        ),
        (
            &["--recurse", "jane", "--expand-floor"],
            "scan --expand-floor needs a value",
        ),
    ];
    for (args, message) in refusals {
        let out = bin().arg("scan").args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(i32::from(EX_USAGE)), "{args:?}");
        assert_eq!(String::from_utf8_lossy(&out.stdout), "", "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(stderr.lines().next(), Some(message), "{args:?}");
    }
}
