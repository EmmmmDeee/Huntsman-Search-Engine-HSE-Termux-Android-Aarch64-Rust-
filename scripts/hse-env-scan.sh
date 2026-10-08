#!/data/data/com.termux/files/usr/bin/bash
(
set -uo pipefail
TIMEOUT="${HSE_TIMEOUT:-120}"
MAX_RETRIES="${HSE_MAX_RETRIES:-3}"
MAX_INPUT="${HSE_MAX_INPUT:-268435456}"
TMPDIR="${TMPDIR:-/tmp}"
HOME="${HOME:-$TMPDIR}"
WORKDIR="$(mktemp -d "${TMPDIR}/hse.XXXXXX")" || exit 1
BIN="${WORKDIR}/engine"
cleanup() {
  if [[ -n "${WORKDIR:-}" && -d "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
printf 'WARN: libc and rustls crates not satisfiable because stdin rustc cannot link external crates; std only\n' >&2
printf 'WARN: exec not used so the EXIT trap can purge WORKDIR\n' >&2
has() { command -v "$1" >/dev/null 2>&1; }
ensure_rust() {
  if has rustc; then return 0; fi
  if ! has pkg; then printf 'phase: rust-missing-no-pkg\n' >&2; return 1; fi
  local attempt=0
  while [[ "${attempt}" -lt "${MAX_RETRIES}" ]]; do
    if timeout "${TIMEOUT}" pkg install -y rust && has rustc; then return 0; fi
    attempt=$((attempt + 1))
    sleep "${attempt}"
  done
  return 1
}
ROOT="${1:-${HSE_ROOT:-${HOME}/hse}}"
INCLUDE_TEST="${HSE_INCLUDE_TEST:-0}"
INCLUDE_EXAMPLE="${HSE_INCLUDE_EXAMPLE:-0}"
INCLUDE_COMMENT="${HSE_INCLUDE_COMMENT:-0}"
INCLUDE_DOCS="${HSE_INCLUDE_DOCS:-0}"
if [[ ! -d "${ROOT}" ]]; then printf 'phase: root-missing %s\n' "${ROOT}" >&2; exit 2; fi
if ! ensure_rust; then exit 1; fi
HOST_TRIPLE="$(rustc -vV 2>/dev/null | awk '/^host:/ {print $2; exit}')"
if [[ "${HOST_TRIPLE}" != "aarch64-linux-android" ]]; then
  printf 'WARN: aarch64-linux-android not selected because rustc host is %s\n' "${HOST_TRIPLE:-unknown}" >&2
fi
if ! timeout "${TIMEOUT}" rustc -O --edition 2021 -o "${BIN}" - <<'RUST_BEGIN'
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
struct Guard { path: String }
impl Drop for Guard { fn drop(&mut self) { let _ = fs::write(format!("{}/engine.ran", self.path), b"1"); } }
fn main() { process::exit(run()); }
struct Hit { name: String, value: String, path: String, line: usize, origin: &'static str, comment: bool, assigned: bool }
fn run() -> i32 {
    let workdir = env::var("HSE_WORKDIR").unwrap_or_default();
    let _guard = Guard { path: workdir };
    let root = env::var("HSE_ROOT").unwrap_or_default();
    if root.is_empty() { eprintln!("phase: missing-root"); return 2; }
    let include_test = flag("HSE_INCLUDE_TEST");
    let include_example = flag("HSE_INCLUDE_EXAMPLE");
    let include_comment = flag("HSE_INCLUDE_COMMENT");
    let include_docs = flag("HSE_INCLUDE_DOCS");
    eprintln!("phase: sense");
    let mut files_read = 0u64; let mut bytes_read = 0u64; let mut raw_hits = 0u64;
    let mut skipped_hidden = 0u64; let mut skipped_dir = 0u64; let mut skipped_binary = 0u64;
    let mut skipped_depth = 0u64; let mut skipped_large = 0u64; let mut skipped_other = 0u64;
    let mut hits = Vec::new();
    let mut stack = vec![(PathBuf::from(&root), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > 24 { skipped_depth += 1; continue; }
        let Ok(rd) = fs::read_dir(&dir) else { skipped_other += 1; continue; };
        for ent in rd.flatten() {
            let name_s = ent.file_name().to_string_lossy().to_string();
            if name_s.starts_with('.') && !is_env_file(&name_s) { skipped_hidden += 1; continue; }
            if name_s == "target" || name_s == "node_modules" || name_s == ".git" { skipped_dir += 1; continue; }
            let path = ent.path();
            let Ok(ft) = ent.file_type() else { skipped_other += 1; continue; };
            if ft.is_dir() { stack.push((path, depth + 1)); continue; }
            if !ft.is_file() { skipped_other += 1; continue; }
            let Ok(meta) = ent.metadata() else { skipped_other += 1; continue; };
            if meta.len() > 2_000_000 { skipped_large += 1; continue; }
            if !textish(&path) { skipped_binary += 1; continue; }
            let Ok(data) = fs::read(&path) else { skipped_other += 1; continue; };
            if data.iter().take(800).any(|&b| b == 0) { skipped_binary += 1; continue; }
            files_read += 1; bytes_read += data.len() as u64;
            scan_file(&path, &data, &mut hits, &mut raw_hits);
        }
    }
    eprintln!("phase: decide");
    let mut kept: BTreeMap<String, Agg> = BTreeMap::new();
    let mut dropped_test = 0u64; let mut dropped_example = 0u64; let mut dropped_comment = 0u64; let mut dropped_docs = 0u64;
    for hit in hits {
        if hit.comment && !include_comment { dropped_comment += 1; continue; }
        if hit.origin == "test" && !include_test { dropped_test += 1; continue; }
        if hit.origin == "example" && !include_example { dropped_example += 1; continue; }
        if hit.origin == "docs" && !include_docs { dropped_docs += 1; continue; }
        let agg = kept.entry(hit.name.clone()).or_insert_with(Agg::default);
        agg.count += 1;
        if hit.origin == "production" && agg.first_production.is_empty() { agg.first_production = format!("{}:{}", hit.path, hit.line); }
        if agg.first_any.is_empty() { agg.first_any = format!("{}:{}", hit.path, hit.line); }
        agg.assigned |= hit.assigned;
        if !hit.value.is_empty() && (agg.value.is_empty() || hit.origin == "production") { agg.value = hit.value.clone(); }
        if !agg.origins.iter().any(|o| o == hit.origin) { agg.origins.push(hit.origin.to_string()); agg.origins.sort(); }
    }
    eprintln!("phase: report");
    let mut emitted = 0u64;
    let mut stdout = io::stdout();
    for (name, agg) in &kept {
        let loc = if agg.first_production.is_empty() { agg.first_any.clone() } else { agg.first_production.clone() };
        let confidence = if !agg.first_production.is_empty() && agg.assigned { "high" } else if !agg.first_production.is_empty() { "medium" } else { "low" };
        let line = format!("{{\"type\":\"HUNTSMAN_ENV_VAR\",\"name\":\"{}\",\"value\":\"{}\",\"count\":{},\"location\":\"{}\",\"origins\":\"{}\",\"confidence\":\"{}\"}}\n", json_escape(name), json_escape(&agg.value), agg.count, json_escape(&loc), json_escape(&agg.origins.join(",")), confidence);
        if stdout.write_all(line.as_bytes()).is_err() { return 1; }
        emitted += 1;
    }
    let _ = stdout.flush();
    eprintln!("[engine] summary: files_read={files_read}, bytes_read={bytes_read}, raw_hits={raw_hits}, emitted={emitted}, dropped=[test={dropped_test}, example={dropped_example}, comment={dropped_comment}, docs={dropped_docs}], filters=[test={}, example={}, comment={}, docs={}], redaction=off, budgets_hit=false, skipped=[hidden={skipped_hidden}, ignored_dir={skipped_dir}, binary={skipped_binary}, depth_limit={skipped_depth}, not_regular_file={skipped_other}, too_large={skipped_large}]", !include_test, !include_example, !include_comment, !include_docs);
    0
}
struct Agg { count: u64, first_production: String, first_any: String, origins: Vec<String>, assigned: bool, value: String }
impl Default for Agg { fn default() -> Self { Self { count: 0, first_production: String::new(), first_any: String::new(), origins: Vec::new(), assigned: false, value: String::new() } } }
fn flag(key: &str) -> bool { matches!(env::var(key).unwrap_or_default().as_str(), "1" | "true" | "yes") }
fn is_env_file(name: &str) -> bool { name == ".env" || name == ".env.example" || name.starts_with(".env.") }
fn textish(path: &Path) -> bool { let s = path.to_string_lossy().to_ascii_lowercase(); s.ends_with(".rs") || s.ends_with(".sh") || s.ends_with(".md") || s.ends_with(".txt") || s.ends_with(".toml") || s.ends_with(".example") || s.ends_with(".env") || s.ends_with(".json") || s.ends_with(".yml") || s.ends_with(".yaml") }
fn scan_file(path: &Path, data: &[u8], hits: &mut Vec<Hit>, raw: &mut u64) {
    let text = String::from_utf8_lossy(data);
    let path_s = path.to_string_lossy().to_string();
    let origin = classify(&path_s);
    for (idx, line) in text.split('\n').enumerate() {
        let comment = is_comment(line, &path_s);
        let bytes = line.as_bytes();
        let mut i = 0;
        while i + 10 < bytes.len() {
            if bytes[i..].starts_with(b"HUNTSMAN_") {
                let start = i; i += 9;
                while i < bytes.len() && (bytes[i].is_ascii_uppercase() || bytes[i].is_ascii_digit() || bytes[i] == b'_') { i += 1; }
                if i - start < 12 { continue; }
                let name = line[start..i].to_string();
                let assigned = i < bytes.len() && bytes[i] == b'=';
                let value = if assigned { take_value(line, i + 1) } else { String::new() };
                hits.push(Hit { name, value, path: path_s.clone(), line: idx + 1, origin, comment, assigned });
                *raw += 1;
            } else { i += 1; }
        }
    }
}
fn take_value(line: &str, start: usize) -> String {
    let rest = line[start..].trim_start();
    if rest.is_empty() { return String::new(); }
    let b = rest.as_bytes();
    if b[0] == b'"' || b[0] == b'\'' {
        let q = b[0] as char; let mut out = String::new(); let mut chars = rest[1..].chars();
        while let Some(c) = chars.next() { if c == '\\' { if let Some(n) = chars.next() { out.push(n); } continue; } if c == q { break; } out.push(c); }
        return out;
    }
    rest.split_whitespace().next().unwrap_or("").to_string()
}
fn classify(path: &str) -> &'static str {
    let p = path.replace('\\', "/");
    if p.ends_with(".env.example") || p.contains("/fixtures/") { return "example"; }
    if p.contains("/tests/") || p.ends_with("_tests.rs") || p.contains("/tests.rs") { return "test"; }
    if p.contains("/docs/") || p.ends_with(".md") { return "docs"; }
    "production"
}
fn is_comment(line: &str, path: &str) -> bool {
    let t = line.trim_start();
    if path.ends_with(".rs") { return t.starts_with("//") || t.starts_with("/*") || t.starts_with('*'); }
    if path.ends_with(".sh") || path.ends_with(".example") || path.ends_with(".env") { return t.starts_with('#'); }
    false
}
fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() { match c { '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"), '\n' => out.push_str("\\n"), c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)), c => out.push(c), } }
    out
}
RUST_BEGIN
then
  printf 'phase: compile-failed\n' >&2
  exit 1
fi
printf 'phase: execute\n' >&2
HSE_ROOT="${ROOT}" HSE_WORKDIR="${WORKDIR}" HSE_HOME="${HOME}" HSE_TMPDIR="${TMPDIR}" HSE_INCLUDE_TEST="${INCLUDE_TEST}" HSE_INCLUDE_EXAMPLE="${INCLUDE_EXAMPLE}" HSE_INCLUDE_COMMENT="${INCLUDE_COMMENT}" HSE_INCLUDE_DOCS="${INCLUDE_DOCS}" timeout "${TIMEOUT}" "${BIN}"
child=$?
if [[ "${child}" -eq 124 ]]; then child=1; fi
exit "${child}"
)
