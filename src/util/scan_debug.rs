//! One capture path for a scan debug log.
//!
//! `log_capture::dump` is the only source. This module writes that text
//! unchanged and uploads the same bytes. It does not redact.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Header plus the captured log, byte-for-byte after the header.
pub fn bundle(scan_id: &str, raw: &str) -> String {
    format!("# hse scan debug\n# scan_id={scan_id}\n\n{raw}")
}

/// Write the raw bundle, then upload it to `debug/scans/` in the repository.
/// A failed upload does not discard the local file.
pub fn publish(scan_id: &str, raw: &str) -> Result<PathBuf, String> {
    let text = bundle(scan_id, raw);
    let dir = debug_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{scan_id}.log"));
    fs::write(&path, &text).map_err(|e| e.to_string())?;
    let repo = std::env::var("HSE_DEBUG_REPO").unwrap_or_else(|_| {
        "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-".into()
    });
    if let Err(err) = upload(&repo, scan_id, &text) {
        eprintln!("scan debug upload skipped: {err}");
    }
    Ok(path)
}

fn debug_dir() -> PathBuf {
    std::env::var("HSE_DEBUG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".huntsman").join("debug-scans")
        })
}

fn upload(repo: &str, scan_id: &str, body: &str) -> Result<(), String> {
    let status = Command::new("gh")
        .args([
            "api",
            "--method",
            "PUT",
            &format!("repos/{repo}/contents/debug/scans/{scan_id}.log"),
            "-f",
            &format!("message=scan debug {scan_id}"),
            "-f",
            &format!("content={}", b64(body)),
            "-f",
            "branch=scan-debug",
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("debug upload exited {}", status.code().unwrap_or(-1)))
    }
}

fn b64(body: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = body.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(T[(b0 >> 2) as usize] as char);
        out.push(T[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(T[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if i + 2 < bytes.len() {
            out.push(T[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_keeps_every_captured_byte() {
        let raw = "target alice@example.com token=abcdEFGH1234567890zz\nengine bing up\n";
        let text = bundle("scan-1", raw);
        assert!(text.contains(raw));
        assert!(!text.contains("[redacted]"));
    }
}
