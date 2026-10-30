//! End-to-end CLI acceptance for offline multi-APK container inventory.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_DATAERR, EX_NOINPUT};

fn zip(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut central = Vec::new();
    for &(name, bytes) in parts {
        let at = u32::try_from(data.len()).expect("fixture offset");
        let name_len = u16::try_from(name.len()).expect("fixture name");
        let size = u32::try_from(bytes.len()).expect("fixture size");
        let crc = crc32fast::hash(bytes);
        let mut local = [0_u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[14..18].copy_from_slice(&crc.to_le_bytes());
        local[18..22].copy_from_slice(&size.to_le_bytes());
        local[22..26].copy_from_slice(&size.to_le_bytes());
        local[26..28].copy_from_slice(&name_len.to_le_bytes());
        data.extend_from_slice(&local);
        data.extend_from_slice(name.as_bytes());
        data.extend_from_slice(bytes);

        let mut entry = [0_u8; 46];
        entry[..4].copy_from_slice(b"PK\x01\x02");
        entry[16..20].copy_from_slice(&crc.to_le_bytes());
        entry[20..24].copy_from_slice(&size.to_le_bytes());
        entry[24..28].copy_from_slice(&size.to_le_bytes());
        entry[28..30].copy_from_slice(&name_len.to_le_bytes());
        entry[42..46].copy_from_slice(&at.to_le_bytes());
        central.extend_from_slice(&entry);
        central.extend_from_slice(name.as_bytes());
    }
    let start = u32::try_from(data.len()).expect("directory offset");
    let size = u32::try_from(central.len()).expect("directory size");
    data.extend_from_slice(&central);
    let mut end = [0_u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&u16::try_from(parts.len()).expect("count").to_le_bytes());
    end[10..12].copy_from_slice(&u16::try_from(parts.len()).expect("count").to_le_bytes());
    end[12..16].copy_from_slice(&size.to_le_bytes());
    end[16..20].copy_from_slice(&start.to_le_bytes());
    data.extend_from_slice(&end);
    data
}

fn path(suffix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "huntsman-apk-set-{}-{suffix}.apks",
        std::process::id()
    ))
}

fn invoke(file: &PathBuf) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(["apk", "set"])
        .arg(file)
        .arg("--json")
        .output()
        .expect("invoke huntsman-recon")
}

#[test]
fn apk_set_cli_preserves_hashes_and_explicit_uncertainty() {
    let inner = zip(&[("AndroidManifest.xml", b"untrusted manifest")]);
    let outer = zip(&[("base.apk", &inner), ("toc.pb", b"untrusted")]);
    let file = path("valid");
    fs::write(&file, &outer).expect("write fixture");
    let output = invoke(&file);
    fs::remove_file(&file).expect("remove fixture");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("valid JSON");
    assert_eq!(report["format_hint_unverified"], "apks");
    assert_eq!(report["apk_members"].as_array().map(Vec::len), Some(1));
    assert_eq!(report["package_consistency"], "unverified");
    assert_eq!(
        report["apk_members"][0]["sha256"],
        huntsman_recon::sha256::hex32(&huntsman_recon::sha256::sha256(&inner))
    );
    assert_eq!(
        report["apk_members"][0]["role_hint_unverified"],
        "base_filename_hint"
    );
    assert_eq!(report["entities"].as_array().map(Vec::len), Some(2));
}

#[test]
fn apk_set_cli_refuses_corruption_and_missing_file() {
    let file = path("bad");
    let _ = fs::remove_file(&file);
    assert_eq!(invoke(&file).status.code(), Some(i32::from(EX_NOINPUT)));
    fs::write(&file, b"not a ZIP").expect("write invalid fixture");
    let output = invoke(&file);
    fs::remove_file(&file).expect("remove fixture");
    assert_eq!(output.status.code(), Some(i32::from(EX_DATAERR)));
}
