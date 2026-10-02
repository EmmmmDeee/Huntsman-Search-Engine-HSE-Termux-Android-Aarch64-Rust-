//! Acceptance tests for declarative source routing.

use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
}

#[test]
fn sources_routes_a_domain_through_multiple_source_classes() {
    let out = bin().args(["sources", "example.com"]).output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=domain confidence=0.750 routes="),
        "{stdout}"
    );
    assert!(
        stdout.contains("source=google_site execution=search_url access=public"),
        "{stdout}"
    );
    assert!(
        stdout.contains("source=wayback execution=search_url access=public"),
        "{stdout}"
    );
    assert!(
        stdout.contains("source=whois execution=search_url access=public"),
        "{stdout}"
    );
    assert!(
        stdout.contains("https://web.archive.org/web/*/example.com/*"),
        "{stdout}"
    );
}

#[test]
fn sources_percent_encodes_human_queries() {
    let out = bin().args(["sources", "Ada Lovelace"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.starts_with("kind=person confidence=0.500 routes="),
        "{stdout}"
    );
    assert!(stdout.contains("Ada%20Lovelace"), "{stdout}");
    assert!(!stdout.contains("Ada Lovelace"), "{stdout}");
}

#[test]
fn sources_refuses_unactionable_residual_text() {
    let out = bin().args(["sources", "x"]).output().unwrap();
    assert_eq!(out.status.code(), Some(65));
    assert_eq!(out.stdout, [] as [u8; 0]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("no actionable source routes"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
