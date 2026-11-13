//! Exercise the production CLI on a synthetic dossier. Real case data stays private.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use huntsman_recon::sha256::{hex32, sha256};

fn run(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .env("HOME", home)
        .env_remove("HUNTSMAN_DOSSIER_PATH")
        .arg("dossier")
        .args(args)
        .output()
        .unwrap()
}

fn scratch() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("dossier-cli");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(dir.join("bundle")).unwrap();
    dir
}

fn write_member(bundle: &Path, manifest: &mut String, file: &str, content: &[u8]) {
    fs::write(bundle.join(file), content).unwrap();
    writeln!(manifest, "{}  {file}", hex32(&sha256(content))).unwrap();
}

#[test]
fn verifies_then_installs_exact_bytes_once_and_keeps_a_different_register() {
    let home = scratch();
    let bundle = home.join("bundle");
    let dir = bundle.to_str().unwrap();
    let mut manifest = String::new();
    let document = br#"{
      "sources":[{"id":"S01","title":"Local source"}],
      "claims":[],"cross_source_correlation":[],"uncertainties":[],"hypotheses":[],"actions":[],
      "audit_changes_2026_10_24":[],"media_manifest":[],"binary_verification_2026_10_24":{}
    }"#;
    for (file, body) in [
        ("register.json", document.as_slice()),
        ("index.html", b"<article id='S01'></article>"),
        ("binary_verification.json", b"{}"),
        ("sources.csv", b"id,title\nS01,Local source\n"),
        ("claims.csv", b"id\n"),
        ("cross_source_correlation.csv", b"id\n"),
        ("uncertainties.csv", b"id\n"),
        ("hypotheses.csv", b"id\n"),
        ("actions.csv", b"id\n"),
        ("audit_changes_2026_10_24.csv", b"change\n"),
        ("media_manifest.csv", b"filename\n"),
    ] {
        write_member(&bundle, &mut manifest, file, body);
    }
    fs::write(bundle.join("SHA256SUMS.txt"), &manifest).unwrap();
    let installed = home.join(".huntsman/dossier/register.json");
    let check = run(&home, &["verify", dir]);
    assert!(
        check.status.success(),
        "{}",
        String::from_utf8_lossy(&check.stderr)
    );
    assert!(!installed.exists());
    let report: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(report["indexed_records"], 1);
    assert_eq!(report["verified_csv_tables"], 8);

    for _ in 0..2 {
        let install = run(&home, &["install", dir]);
        assert!(
            install.status.success(),
            "{}",
            String::from_utf8_lossy(&install.stderr)
        );
        assert_eq!(fs::read(&installed).unwrap(), document);
    }
    let check = run(&home, &["check"]);
    let installed_report: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    assert_eq!(
        installed_report["register_sha256"],
        report["register_sha256"]
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&installed).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    let other = document.strip_suffix(b"}").unwrap();
    fs::write(&installed, other).unwrap();
    let refused = run(&home, &["install", dir]);
    assert!(!refused.status.success());
    assert_eq!(fs::read(&installed).unwrap(), other);

    fs::write(bundle.join("sources.csv"), b"id,title\nS01,Changed\n").unwrap();
    let refused = run(&home, &["install", dir]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("checksum mismatch"));
    assert_eq!(fs::read(&installed).unwrap(), other);
    fs::remove_dir_all(home).unwrap();
}
