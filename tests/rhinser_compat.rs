//! End-to-end offline CLI acceptance for the Rhinser compatibility surface.

use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .output()
        .expect("binary executable")
}

#[test]
fn all_catalogue_entries_are_accessible_without_network() {
    let output = run(&["osint", "catalog", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let categories = value["categories"].as_array().unwrap();
    assert_eq!(categories.len(), 11);
    assert_eq!(
        categories
            .iter()
            .map(|category| category["tools"].as_array().unwrap().len())
            .sum::<usize>(),
        83
    );
    let search = run(&["osint", "catalog", "--find", "unclaimed money"]);
    assert!(search.status.success());
    assert!(String::from_utf8_lossy(&search.stdout).contains("lead_only_unverified"));
    let template = run(&[
        "osint",
        "catalog",
        "--query",
        "emailosint",
        "abc+test@example.org",
    ]);
    assert!(template.status.success());
    assert_eq!(
        String::from_utf8_lossy(&template.stdout).trim(),
        "https://emailosint.com/?q=abc%2Btest%40example.org"
    );
}

#[test]
fn workspace_roundtrip_and_nfc_are_read_only() {
    let path = std::env::temp_dir().join(format!(
        "huntsman-rhinser-casebook-{}-{}.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let filename = path.to_str().expect("UTF-8 temp path");
    let _ = std::fs::remove_file(&path);
    assert!(
        run(&["osint", "workspace", filename, "init"])
            .status
            .success()
    );
    assert!(
        run(&[
            "osint",
            "workspace",
            filename,
            "case",
            "case-1",
            "Example case"
        ])
        .status
        .success()
    );
    assert!(
        run(&[
            "osint",
            "workspace",
            filename,
            "note",
            "case-1",
            "Check archives"
        ])
        .status
        .success()
    );
    assert!(
        run(&["osint", "workspace", filename, "bookmark", "t0343"])
            .status
            .success()
    );
    assert!(
        run(&["osint", "workspace", filename, "search", "archives"])
            .status
            .success()
    );
    let shown = run(&["osint", "workspace", filename, "show"]);
    assert!(shown.status.success());
    let v: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(v["cases"][0]["id"], "case-1");
    assert_eq!(v["cases"][0]["notes"][0]["text"], "Check archives");
    assert_eq!(v["bookmarks"][0], "t0343");
    assert_eq!(v["search_history"][0], "archives");
    let invalid = run(&[
        "osint",
        "workspace",
        filename,
        "lead",
        "case-1",
        "bad",
        "https://u:pw@example.org/",
        "bad",
    ]);
    assert!(!invalid.status.success());
    let nfc = run(&["osint", "nfc", "apdu", "00A40400023F00"]);
    assert!(
        nfc.status.success(),
        "{}",
        String::from_utf8_lossy(&nfc.stderr)
    );
    assert!(String::from_utf8_lossy(&nfc.stdout).contains("\"data_bytes\": 2"));
    std::fs::remove_file(path).unwrap();
}


#[test]
fn rhinser_sources_are_accessible_from_the_analysis_web_view() {
    let page = include_str!("../src/web_ui.html");
    for marker in [
        "id=\"rhinser-sources-panel\"",
        "id=\"rhinser-source-category\"",
        "id=\"rhinser-source-search\"",
        "id=\"rhinser-source-list\"",
        "api('/api/rhinser/catalog')",
        "else if(v==='analyze')loadRhinserCatalog();",
        "link.rel='noopener noreferrer'",
        "link.referrerPolicy='no-referrer'",
    ] {
        assert!(page.contains(marker), "missing Rhinser Web UI integration: {marker}");
    }
}
