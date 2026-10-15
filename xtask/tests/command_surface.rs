//! xtask runs the commands it names. A command whose port had not landed used to print "is not
//! implemented yet" and exit 70, which advertised work nobody could run. Those placeholders are
//! gone, and their live authority stays in `scripts/` and `.github/scripts/`, which CI calls
//! directly. A removed name must now be a usage error, the same as any unknown command.

use std::process::Command;

fn xtask(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

#[test]
fn the_help_advertises_no_placeholder() {
    let (code, help) = xtask(&["--help"]);
    assert_eq!(code, Some(0), "{help}");
    assert!(!help.contains("not implemented"), "{help}");
    for group in ["ops ...", "release ..."] {
        assert!(
            !help.contains(group),
            "the help still lists `{group}`:\n{help}"
        );
    }
}

#[test]
fn a_removed_placeholder_is_a_usage_error_not_a_stub() {
    for args in [
        &["ops", "railway"][..],
        &["ops", "cleanup-prereleases"],
        &["release", "promote"],
        &["release", "scan-keys"],
        &["dual-pass", "plan"],
        &["dual-pass", "red-class"],
        &["dual-pass", "run"],
        &["dual-pass", "publish"],
    ] {
        let (code, text) = xtask(args);
        assert_eq!(
            code,
            Some(64),
            "xtask {args:?} must be a usage error:\n{text}"
        );
        assert!(!text.contains("not implemented"), "xtask {args:?}:\n{text}");
    }
}
