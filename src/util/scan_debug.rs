//! One capture path for a scan debug log.
//!
//! `log_capture::dump` is the log body. This module adds the runtime record
//! around it and uploads both unchanged. It does not redact the scan log.
//! The upload token is not copied into the bundle.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Header, runtime record, host probes, then the captured log byte for byte.
pub fn bundle(scan_id: &str, raw: &str) -> String {
    let mut out = String::new();
    out.push_str("# hse scan debug\n");
    out.push_str(&format!("# scan_id={scan_id}\n"));
    out.push_str(&format!("# version={}\n", crate::VERSION));
    out.push_str(&format!("# unix={}\n", unix_now()));
    out.push_str(&format!("# cwd={}\n", cwd()));
    out.push_str("# args=");
    out.push_str(&args());
    out.push('\n');
    out.push_str("# runtime\n");
    out.push_str(&runtime_env());
    out.push_str("# host\n");
    out.push_str(&probe("uname", &["-a"]));
    out.push_str(&probe("rustc", &["--version"]));
    out.push_str("\n# log\n");
    out.push_str(raw);
    if !raw.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn cwd() -> String {
    env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| String::new())
}

fn args() -> String {
    env::args().collect::<Vec<_>>().join(" ")
}

fn runtime_env() -> String {
    const KEYS: &[&str] = &[
        "PREFIX",
        "HSE_REF",
        "HSE_REQUIRE_SHA",
        "HUNTSMAN_REV",
        "HUNTSMAN_HOME",
        "RUST_LOG",
        "HSE_DEBUG_REPO",
        "HSE_DEBUG_DIR",
    ];
    let mut out = String::new();
    for key in KEYS {
        if let Ok(value) = env::var(key) {
            out.push_str(key);
            out.push('=');
            out.push_str(&value);
            out.push('\n');
        }
    }
    out
}

fn probe(cmd: &str, args: &[&str]) -> String {
    match Command::new(cmd).args(args).output() {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout);
            format!("{cmd}={}\n", text.trim())
        }
        _ => format!("{cmd}=\n"),
    }
}

/// Write the raw bundle, then upload it to `debug/scans/` in the repository.
/// A failed upload does not discard the local file.
pub fn publish(scan_id: &str, raw: &str) -> Result<PathBuf, String> {
    let text = bundle(scan_id, raw);
    let dir = debug_dir();
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{scan_id}.log"));
    fs::write(&path, &text).map_err(|e| e.to_string())?;
    let repo = env::var("HSE_DEBUG_REPO").unwrap_or_else(|_| {
        "EmmmmDeee/Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust-".into()
    });
    if let Err(err) = upload(&repo, scan_id, &text) {
        eprintln!("scan debug upload skipped: {err}");
    }
    Ok(path)
}

fn debug_dir() -> PathBuf {
    env::var("HSE_DEBUG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = env::var("HOME").unwrap_or_else(|_| ".".into());
            PathBuf::from(home).join(".huntsman").join("debug-scans")
        })
}

fn upload(repo: &str, scan_id: &str, body: &str) -> Result<(), String> {
    let token = env::var("GH_TOKEN")
        .or_else(|_| env::var("GITHUB_TOKEN"))
        .map_err(|_| "GH_TOKEN is not set".to_string())?;
    put(&token, repo, &format!("debug/scans/{scan_id}.log"), body)?;
    put(&token, repo, "debug/scans/latest.log", body)?;
    Ok(())
}

fn put(token: &str, repo: &str, path: &str, body: &str) -> Result<(), String> {
    let sha = existing_sha(token, repo, path);
    let mut payload = format!(
        "{{\"message\":\"scan debug\",\"content\":\"{}\",\"branch\":\"scan-debug\"",
        b64(body)
    );
    if let Some(sha) = sha {
        payload.push_str(&format!(",\"sha\":\"{sha}\""));
    }
    payload.push('}');
    let status = Command::new("curl")
        .args([
            "-fsS",
            "-X",
            "PUT",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "-H",
            "Content-Type: application/json",
            "--data",
            &payload,
            &format!("https://api.github.com/repos/{repo}/contents/{path}"),
        ])
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "upload of {path} exited {}",
            status.code().unwrap_or(-1)
        ))
    }
}

fn existing_sha(token: &str, repo: &str, path: &str) -> Option<String> {
    let output = Command::new("curl")
        .args([
            "-fsS",
            "-H",
            "Accept: application/vnd.github+json",
            "-H",
            &format!("Authorization: Bearer {token}"),
            &format!("https://api.github.com/repos/{repo}/contents/{path}?ref=scan-debug"),
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let key = "\"sha\":\"";
    let start = text.find(key)? + key.len();
    let end = text[start..].find('"')? + start;
    Some(text[start..end].to_string())
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
        assert!(text.contains("scan_id=scan-1"));
        assert!(text.contains("# version="));
        assert!(text.contains("# host"));
        assert!(text.contains(raw));
        assert!(!text.contains("[redacted]"));
    }
}
