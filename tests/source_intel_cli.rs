//! End-to-end proof that offline APK source discovery reaches the shipped binary.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use huntsman_recon::exit::{EX_NOINPUT, EX_USAGE};

fn zip(parts: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut central = Vec::new();
    for &(name, payload) in parts {
        let at = u32::try_from(bytes.len()).unwrap();
        let size = u32::try_from(payload.len()).unwrap();
        let name_size = u16::try_from(name.len()).unwrap();
        let crc = crc32fast::hash(payload);
        let mut local = [0_u8; 30];
        local[..4].copy_from_slice(b"PK\x03\x04");
        local[14..18].copy_from_slice(&crc.to_le_bytes());
        local[18..22].copy_from_slice(&size.to_le_bytes());
        local[22..26].copy_from_slice(&size.to_le_bytes());
        local[26..28].copy_from_slice(&name_size.to_le_bytes());
        bytes.extend_from_slice(&local);
        bytes.extend_from_slice(name.as_bytes());
        bytes.extend_from_slice(payload);
        let mut entry = [0_u8; 46];
        entry[..4].copy_from_slice(b"PK\x01\x02");
        entry[16..20].copy_from_slice(&crc.to_le_bytes());
        entry[20..24].copy_from_slice(&size.to_le_bytes());
        entry[24..28].copy_from_slice(&size.to_le_bytes());
        entry[28..30].copy_from_slice(&name_size.to_le_bytes());
        entry[42..46].copy_from_slice(&at.to_le_bytes());
        central.extend_from_slice(&entry);
        central.extend_from_slice(name.as_bytes());
    }
    let start = u32::try_from(bytes.len()).unwrap();
    let directory_size = u32::try_from(central.len()).unwrap();
    bytes.extend_from_slice(&central);
    let mut end = [0_u8; 22];
    end[..4].copy_from_slice(b"PK\x05\x06");
    end[8..10].copy_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
    end[10..12].copy_from_slice(&u16::try_from(parts.len()).unwrap().to_le_bytes());
    end[12..16].copy_from_slice(&directory_size.to_le_bytes());
    end[16..20].copy_from_slice(&start.to_le_bytes());
    bytes.extend_from_slice(&end);
    bytes
}

fn dex(url: &str) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x70];
    bytes[..8].copy_from_slice(b"dex\n035\0");
    bytes[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
    bytes[56..60].copy_from_slice(&1_u32.to_le_bytes());
    bytes[60..64].copy_from_slice(&0x70_u32.to_le_bytes());
    let string_offset = 0x74_u32;
    bytes.extend_from_slice(&string_offset.to_le_bytes());
    bytes.push(u8::try_from(url.len()).unwrap());
    bytes.extend_from_slice(url.as_bytes());
    bytes.push(0);
    bytes
}

fn file() -> PathBuf {
    std::env::temp_dir().join(format!("hse-source-intel-{}.apk", std::process::id()))
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_huntsman-recon"))
        .args(args)
        .output()
        .expect("invoke huntsman-recon")
}

#[test]
fn source_intel_apk_cli_is_offline_evidence_scoped_and_preserves_original_apk_output() {
    let test_apk = zip(&[
        ("AndroidManifest.xml", b"unverified manifest bytes"),
        ("classes.dex", &dex("https://api.github.com/v1/items?token=PRIVATE")),
    ]);
    let path = file();
    fs::write(&path, &test_apk).expect("write fixture");
    let target = path.to_str().expect("UTF-8 test temp path");
    let original = run(&["apk", target, "--json"]);
    let first = run(&["source-intel", "apk", target, "--json"]);
    let second = run(&["source-intel", "apk", target, "--json"]);
    fs::remove_file(&path).expect("remove fixture");
    assert!(original.status.success(), "{}", String::from_utf8_lossy(&original.stderr));
    assert!(first.status.success(), "{}", String::from_utf8_lossy(&first.stderr));
    assert_eq!(first.stdout, second.stdout, "offline report must be deterministic");
    assert_eq!(first.stderr, second.stderr);
    assert!(!first.stdout.windows(b"PRIVATE".len()).any(|w| w == b"PRIVATE"));
    let source: serde_json::Value = serde_json::from_slice(&first.stdout).expect("JSON");
    let apk: serde_json::Value = serde_json::from_slice(&original.stdout).expect("APK JSON");
    assert_eq!(source["schema"], "huntsman.source-candidates/1");
    assert_eq!(source["artifact_sha256"], apk["inventory"]["sha256"]);
    assert_eq!(source["candidates"][0]["endpoint"], "https://api.github.com/v1/items");
    assert_eq!(source["candidates"][0]["method"], serde_json::Value::Null);
    assert_eq!(source["candidates"][0]["access"], "unknown");
    assert_eq!(source["candidates"][0]["operational_status"], "not_tested");
    assert_eq!(source["candidates"][0]["evidence"]["byte_range"], serde_json::Value::Null);
}

#[test]
fn source_intel_cli_refuses_missing_file_and_unsupported_modes() {
    let missing = format!("missing-source-intel-fixture-{}.apk", std::process::id());
    let output = run(&["source-intel", "apk", &missing, "--json"]);
    assert_eq!(output.status.code(), Some(i32::from(EX_NOINPUT)));
    let output = run(&["source-intel", "apk", &missing]);
    assert_eq!(output.status.code(), Some(i32::from(EX_USAGE)));
    let help = run(&["source-intel", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("source-intel apk FILE --json"));
}
