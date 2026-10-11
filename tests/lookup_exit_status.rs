//! Exit status of the identifier lookup commands when their argument is rejected. Every case fails
//! while the arguments are parsed, before any request is made, so this needs no network.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

fn status_of(args: &[&str]) -> Option<i32> {
    bin().args(args).output().unwrap().status.code()
}

#[test]
fn a_malformed_value_exits_65_for_each_identifier_command() {
    assert_eq!(status_of(&["email", "not-an-email"]), Some(65));
    assert_eq!(status_of(&["username", "../root"]), Some(65));
    assert_eq!(status_of(&["username", "username"]), Some(65));
    assert_eq!(status_of(&["phone", "12"]), Some(65));
}

#[test]
fn a_usage_error_exits_64_for_each_identifier_command() {
    assert_eq!(status_of(&["email"]), Some(64));
    assert_eq!(status_of(&["username"]), Some(64));
    assert_eq!(status_of(&["phone"]), Some(64));
    assert_eq!(status_of(&["phone", "0412345678", "--bogus"]), Some(64));
}

#[test]
fn echoed_option_text_never_changes_the_status() {
    // An unknown option whose text contains a value phrase is a usage error, not a data error.
    assert_eq!(status_of(&["email", "--invalid email address"]), Some(64));
    assert_eq!(status_of(&["username", "--username selector"]), Some(64));
    assert_eq!(
        status_of(&["phone", "0412345678", "--unknown international"]),
        Some(64)
    );
}
