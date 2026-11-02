//! Acceptance for top-level commands no other integration test invoked: `case-check`, `exif`,
//! `docmeta` and `public-osint`. Every case here is offline: `public-osint` is only exercised on
//! its usage paths, which return before any request.

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use huntsman_recon::exit::{EX_DATAERR, EX_UNAVAILABLE, EX_USAGE};

fn run(dir: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .current_dir(dir)
        .env("HOME", dir)
        .env("HUNTSMAN_HOME", dir.join(".huntsman"))
        .output()
        .expect("run huntsman-recon")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn scratch(tag: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("untested-cli-{tag}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const PNG_NO_EXIF: &[u8] = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\x00IEND\xaeB`\x82";

#[test]
fn every_command_documents_itself_and_refuses_missing_arguments() {
    let dir = scratch("usage");
    for (command, usage) in [
        ("case-check", "case-check CASE-JSON ORIGINAL-ADVERT-TEXT"),
        ("exif", "exif IMAGE-FILE"),
        ("docmeta", "docmeta FILE"),
        (
            "public-osint",
            "public-osint news|notices|web|dossier QUERY...",
        ),
    ] {
        let help = run(&dir, &[command, "--help"]);
        assert!(help.status.success(), "{command} --help: {help:?}");
        assert!(
            text(&help.stdout).contains(usage),
            "{command}: {}",
            text(&help.stdout)
        );
        let bare = run(&dir, &[command]);
        assert_eq!(
            bare.status.code(),
            Some(i32::from(EX_USAGE)),
            "{command} without arguments"
        );
    }
    let unknown = run(&dir, &["public-osint", "bogus", "query"]);
    assert_eq!(unknown.status.code(), Some(i32::from(EX_USAGE)));
}

#[test]
fn exif_reports_a_png_without_exif_cleanly_and_refuses_a_non_image() {
    let dir = scratch("exif");
    fs::write(dir.join("a.png"), PNG_NO_EXIF).unwrap();
    fs::write(dir.join("a.txt"), "plain text").unwrap();
    let ok = run(&dir, &["exif", "a.png"]);
    assert!(ok.status.success(), "{ok:?}");
    let out = text(&ok.stdout);
    assert!(
        out.contains("PNG image a.png with no EXIF metadata"),
        "{out}"
    );
    assert!(out.contains("attribute\tformat\tPNG"), "{out}");
    let bad = run(&dir, &["exif", "a.txt"]);
    assert_eq!(bad.status.code(), Some(i32::from(EX_UNAVAILABLE)));
    assert!(text(&bad.stderr).contains("not a JPEG, TIFF, WebP or PNG image"));
}

#[test]
fn docmeta_reads_pdf_info_fields() {
    let dir = scratch("docmeta");
    fs::write(
        dir.join("a.pdf"),
        "%PDF-1.4\n1 0 obj << /Title (Huntsman probe) /Author (Tester) >> endobj\ntrailer << /Info 1 0 R >>\n%%EOF\n",
    )
    .unwrap();
    let ok = run(&dir, &["docmeta", "a.pdf"]);
    assert!(ok.status.success(), "{ok:?}");
    let out = text(&ok.stdout);
    assert!(
        out.contains("attribute\tinfo:Title\tHuntsman probe"),
        "{out}"
    );
    assert!(out.contains("attribute\tinfo:Author\tTester"), "{out}");
    assert!(out.contains("attribute\tformat\tPDF 1.4"), "{out}");
}

#[test]
fn case_check_refuses_malformed_or_missing_case_json() {
    let dir = scratch("case-check");
    fs::write(dir.join("bad.json"), "not json").unwrap();
    fs::write(dir.join("ad.txt"), "advert").unwrap();
    let bad = run(&dir, &["case-check", "bad.json", "ad.txt"]);
    assert_eq!(bad.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(text(&bad.stderr).contains("invalid case JSON"), "{bad:?}");
    let missing = run(&dir, &["case-check", "missing.json", "ad.txt"]);
    assert_eq!(missing.status.code(), Some(i32::from(EX_DATAERR)));
    assert!(
        text(&missing.stderr).contains("cannot open case input"),
        "{missing:?}"
    );
}
