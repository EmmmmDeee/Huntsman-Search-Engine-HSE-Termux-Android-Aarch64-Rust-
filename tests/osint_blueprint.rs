//! The committed blueprint document is the one Huntsman generates from its entries, so the
//! Word file cannot drift from the code it describes.

use std::process::Command;

const COMMITTED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/OSINT_APK_BLUEPRINT.docx");

#[test]
fn the_committed_blueprint_is_the_one_huntsman_generates() {
    let committed = std::fs::read(COMMITTED).expect("docs/OSINT_APK_BLUEPRINT.docx");
    assert!(
        committed == huntsman_recon::osint_blueprint::docx(),
        "docs/OSINT_APK_BLUEPRINT.docx is stale: regenerate it with \
         `cargo run -- blueprint --docx docs/OSINT_APK_BLUEPRINT.docx`"
    );
}

#[test]
fn the_cli_writes_the_same_document_and_lists_every_app() {
    let bin = env!("CARGO_BIN_EXE_huntsman-recon");
    let docx = Command::new(bin)
        .args(["blueprint", "--docx", "-"])
        .output()
        .unwrap();
    assert_eq!(docx.status.code(), Some(0));
    assert_eq!(docx.stdout, huntsman_recon::osint_blueprint::docx());
    let text = Command::new(bin).arg("blueprint").output().unwrap();
    let text = String::from_utf8(text.stdout).unwrap();
    for entry in huntsman_recon::osint_blueprint::ENTRIES {
        assert!(text.contains(entry.app), "{}", entry.app);
    }
    let json = Command::new(bin)
        .args(["blueprint", "--json"])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
    assert_eq!(
        json["count"],
        huntsman_recon::osint_blueprint::ENTRIES.len()
    );
    let bad = Command::new(bin)
        .args(["blueprint", "--pdf"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(64));
}
