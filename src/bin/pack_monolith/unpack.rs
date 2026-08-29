//! Unpacking (round-trip extraction and verification).

use std::collections::HashSet;
use std::path::Path;

use base64::Engine;

use crate::entry::sha256_hex;
use crate::format_util::{TempDir, commas_int, py_list_repr};
use crate::gitinfo::git_tracked_files;
use crate::{BEGIN, BEGIN_B64, END, END_B64};

/// Like Python's `readlines()`: each element keeps its trailing `\n` except
/// possibly the last, if the file doesn't end in one.
fn read_lines_keepends(path: &Path) -> Result<Vec<String>, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut lines = Vec::new();
    let mut rest = raw.as_str();
    while let Some(idx) = rest.find('\n') {
        lines.push(rest[..=idx].to_string());
        rest = &rest[idx + 1..];
    }
    if !rest.is_empty() {
        lines.push(rest.to_string());
    }
    Ok(lines)
}

/// Reconstruct the tree under `dest`. Returns `[(path, sha256), ...]`.
pub fn unpack(mono_path: &Path, dest: &Path) -> Result<Vec<(String, String)>, String> {
    let lines = read_lines_keepends(mono_path)?;
    let begin_b64_prefix = format!("{BEGIN_B64} ");
    let end_b64_prefix = format!("{END_B64} ");
    let begin_prefix = format!("{BEGIN} ");
    let end_prefix = format!("{END} ");

    let mut restored: Vec<(String, String)> = Vec::new();
    let mut i = 0usize;
    let mut expected_sha: Option<String> = None;
    let mut expected_eof_nl = true;
    while i < lines.len() {
        let line = lines[i].clone();
        if let Some(rest) = line.strip_prefix("### sha256   : ") {
            expected_sha = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("### eof-newline : ") {
            expected_eof_nl = rest.trim() == "true";
        }

        if let Some(rest) = line.strip_prefix(&begin_b64_prefix) {
            let path = rest.trim_end_matches('\n').to_string();
            i += 1;
            let mut buf = String::new();
            while !lines[i].starts_with(&end_b64_prefix) {
                buf.push_str(lines[i].trim_end_matches('\n'));
                i += 1;
            }
            let data = base64::engine::general_purpose::STANDARD
                .decode(&buf)
                .map_err(|e| format!("base64 decode of {path}: {e}"))?;
            write_restored(dest, &path, &data, &mut restored, expected_sha.as_deref())?;
            expected_sha = None;
            expected_eof_nl = true;
        } else if let Some(rest) = line.strip_prefix(&begin_prefix) {
            let path = rest.trim_end_matches('\n').to_string();
            i += 1;
            let start = i;
            while !lines[i].starts_with(&end_prefix) {
                i += 1;
            }
            let mut body = lines[start..i].concat();
            if !expected_eof_nl && body.ends_with('\n') {
                body.pop();
            }
            write_restored(
                dest,
                &path,
                body.as_bytes(),
                &mut restored,
                expected_sha.as_deref(),
            )?;
            expected_sha = None;
            expected_eof_nl = true;
        }
        i += 1;
    }
    Ok(restored)
}

fn write_restored(
    dest: &Path,
    path: &str,
    data: &[u8],
    acc: &mut Vec<(String, String)>,
    expected_sha: Option<&str>,
) -> Result<(), String> {
    let got = sha256_hex(data);
    if let Some(exp) = expected_sha
        && !exp.is_empty()
        && got != exp
    {
        return Err(format!(
            "FATAL: sha mismatch on extract for {path}: expected {}, got {}",
            &exp[..exp.len().min(12)],
            &got[..got.len().min(12)]
        ));
    }
    let full = dest.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("creating {}: {e}", parent.display()))?;
    }
    std::fs::write(&full, data).map_err(|e| format!("writing {}: {e}", full.display()))?;
    acc.push((path.to_string(), got));
    Ok(())
}

/// Pack-independent check: unpack to a temp dir and diff vs. the work tree.
/// Returns the process exit code (0 ok, 1 failed) matching the Python
/// original's return value.
pub fn verify(root: &Path, mono_path: &Path) -> Result<i32, String> {
    let tmp = TempDir::new("hse-pack-monolith-verify")?;
    let restored = unpack(mono_path, tmp.path())?;

    let root_str = root
        .to_str()
        .ok_or_else(|| "repo root is not valid UTF-8".to_string())?;
    let mono_abs = crate::format_util::abspath(mono_path)?;
    let mono_rel = crate::format_util::relpath_under(root, &mono_abs);
    let tracked: HashSet<String> = git_tracked_files(root_str)?
        .into_iter()
        .filter(|p| *p != mono_rel)
        .collect();
    let got: HashSet<String> = restored.iter().map(|(p, _)| p.clone()).collect();

    let missing: Vec<String> = tracked.difference(&got).cloned().collect();
    let extra: Vec<String> = got.difference(&tracked).cloned().collect();
    let mut mismatch: Vec<String> = Vec::new();
    for (p, sha) in &restored {
        let data = std::fs::read(root.join(p)).map_err(|e| format!("reading {p}: {e}"))?;
        if sha256_hex(&data) != *sha {
            mismatch.push(p.clone());
        }
    }
    let ok = missing.is_empty() && extra.is_empty() && mismatch.is_empty();

    println!(
        "[verify] restored {} files; tracked {}",
        commas_int(got.len() as u64),
        commas_int(tracked.len() as u64)
    );
    if !missing.is_empty() {
        let mut sorted = missing.clone();
        sorted.sort();
        sorted.truncate(10);
        println!(
            "[verify] MISSING ({}): {}",
            missing.len(),
            py_list_repr(&sorted)
        );
    }
    if !extra.is_empty() {
        let mut sorted = extra.clone();
        sorted.sort();
        sorted.truncate(10);
        println!(
            "[verify] EXTRA ({}): {}",
            extra.len(),
            py_list_repr(&sorted)
        );
    }
    if !mismatch.is_empty() {
        let mut sorted = mismatch.clone();
        sorted.sort();
        sorted.truncate(10);
        println!(
            "[verify] CONTENT MISMATCH ({}): {}",
            mismatch.len(),
            py_list_repr(&sorted)
        );
    }
    println!(
        "[verify] {}",
        if ok {
            "OK — byte-exact, 100% capture"
        } else {
            "FAILED"
        }
    );
    Ok(if ok { 0 } else { 1 })
}
