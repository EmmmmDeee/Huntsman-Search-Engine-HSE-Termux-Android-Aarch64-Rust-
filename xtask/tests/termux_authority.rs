//! The Termux installer, the handset acceptance harness and the lifecycle script are shell that
//! runs on a phone with no checkout, so xtask cannot be their authority. xtask must not advertise
//! a command for any of them that only reports it is not implemented.

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
fn xtask_has_no_placeholder_for_a_termux_script() {
    let (_, help) = xtask(&["--help"]);
    assert!(!help.contains("install ..."), "{help}");
    assert!(!help.contains("Termux"), "{help}");
    for args in [
        &["install", "termux"][..],
        &["ops", "termux-acceptance"],
        &["ops", "lifecycle"],
        &["release", "install-check"],
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
