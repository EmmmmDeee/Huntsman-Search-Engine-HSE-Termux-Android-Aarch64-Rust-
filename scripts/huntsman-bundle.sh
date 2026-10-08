#!/data/data/com.termux/files/usr/bin/bash
(
set -uo pipefail
export DEBIAN_FRONTEND=noninteractive
WORKDIR="${HOME}/.cache/huntsman_instant_v6"
BUNDLE_DIR="${WORKDIR}/bundles"
mkdir -p "${BUNDLE_DIR}"
log_info() { printf '[INFO] %s\n' "$*" >&2; }
log_ok() { printf '[OK] %s\n' "$*" >&2; }
log_err() { printf '[ERR] %s\n' "$*" >&2; }
has() { command -v "$1" >/dev/null 2>&1; }
ensure() {
  local pkg="$1" bin="$2"
  if has "${bin}"; then
    return 0
  fi
  if ! has pkg; then
    log_err "missing ${pkg} and pkg is not available"
    return 1
  fi
  log_info "installing ${pkg}"
  if ! timeout 180 pkg install -y "${pkg}"; then
    log_err "pkg install ${pkg} failed"
    return 1
  fi
  has "${bin}"
}
ensure git git || exit 1
ensure rust rustc || exit 1
REPO_ROOT=""
if [[ -f Cargo.toml ]]; then
  REPO_ROOT="$(pwd)"
elif [[ -f "${HOME}/hse/Cargo.toml" ]]; then
  REPO_ROOT="${HOME}/hse"
else
  found="$(find "${HOME}" -maxdepth 3 -name Cargo.toml -type f 2>/dev/null | head -n 1 || true)"
  if [[ -n "${found}" ]]; then
    REPO_ROOT="$(dirname "${found}")"
  else
    log_err "no Cargo.toml under ${HOME}; not cloning"
    exit 2
  fi
fi
cd "${REPO_ROOT}"
log_ok "workspace ${REPO_ROOT}"
BIN="${WORKDIR}/engine"
log_info "compiling bundle engine"
if ! timeout 120 rustc -O --edition 2021 -o "${BIN}" - << 'RUST_BEGIN'
use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_FILE_BYTES: u64 = 512 * 1024;
const CHUNK_LIMIT: usize = 400 * 1024;
const SKIP_DIRS: &[&str] = &[
    ".git", ".github", "target", "legacy", "var", "node_modules", "__pycache__", ".venv",
    "venv", ".idea", ".vscode", ".railway",
];
const SKIP_EXTS: &[&str] = &[
    "lock", "png", "jpg", "jpeg", "gif", "ico", "svg", "zip", "tar", "gz", "7z", "pdf",
    "exe", "so", "bin", "o", "pyc", "rlib",
];
const PRIORITY: &[&str] = &[
    "Cargo.toml", "ARCHITECTURE.md", "RULE.md", "README.md", "src/lib.rs", "src/main.rs",
];

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let root_str = env::var("ROOT").unwrap_or_else(|_| ".".to_string());
    let work_dir_str = env::var("WORKDIR").unwrap_or_else(|_| "/tmp".to_string());
    let action = env::var("ACTION").unwrap_or_else(|_| "push".to_string());
    let root = PathBuf::from(&root_str);
    let bundle_dir = Path::new(&work_dir_str).join("bundles");
    if fs::create_dir_all(&bundle_dir).is_err() {
        eprintln!("[ERR] cannot create {}", bundle_dir.display());
        return 1;
    }
    if action == "pull" {
        return pull(&root);
    }
    push(&root, &bundle_dir)
}

fn push(root: &Path, bundle_dir: &Path) -> i32 {
    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort_by(|a, b| {
        let pa = priority_val(a);
        let pb = priority_val(b);
        if pa != pb { pa.cmp(&pb) } else { a.cmp(b) }
    });
    let repo_name = root.file_name().and_then(|n| n.to_str()).unwrap_or("repo");
    let mut chunk_idx = 1usize;
    let mut current_bytes = 0usize;
    let mut current: Option<File> = None;
    let mut part1 = String::new();
    let mut written = 0usize;
    for path in files {
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let content = match fs::read(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        if content.contains(&0) {
            continue;
        }
        let text = String::from_utf8_lossy(&content);
        let banner = format!("### File: `{rel}`\n```{ext}\n");
        let footer = "\n```\n\n";
        let payload = banner.len() + text.len() + footer.len();
        if current.is_none() || current_bytes + payload > CHUNK_LIMIT {
            let cname = format!("notebooklm_bundle_part_{chunk_idx:02}.md");
            let cpath = bundle_dir.join(&cname);
            let header = format!("# Bundle: {repo_name} (Part {chunk_idx:02})\n\n");
            match File::create(&cpath) {
                Ok(mut f) => {
                    if f.write_all(header.as_bytes()).is_err() {
                        eprintln!("[ERR] write header {}", cpath.display());
                        return 1;
                    }
                    current = Some(f);
                    current_bytes = header.len();
                    if chunk_idx == 1 {
                        part1.push_str(&header);
                    }
                    println!("[+] wrote {}", cpath.display());
                    chunk_idx += 1;
                }
                Err(_) => {
                    eprintln!("[ERR] create chunk failed");
                    return 1;
                }
            }
        }
        if let Some(f) = current.as_mut() {
            let _ = f.write_all(banner.as_bytes());
            let _ = f.write_all(text.as_bytes());
            let _ = f.write_all(footer.as_bytes());
            current_bytes += payload;
            written += 1;
            if chunk_idx == 2 {
                part1.push_str(&banner);
                part1.push_str(&text);
                part1.push_str(footer);
            }
        }
    }
    if part1.is_empty() {
        eprintln!("[ERR] no files bundled");
        return 1;
    }
    if set_clipboard(&part1) {
        println!("[+] part 01 copied to clipboard ({} bytes)", part1.len());
    } else {
        println!("[!] clipboard copy failed; parts remain in {}", bundle_dir.display());
    }
    println!("[+] files={written} parts={} dir={}", chunk_idx - 1, bundle_dir.display());
    0
}

fn pull(root: &Path) -> i32 {
    let clip = get_clipboard();
    if clip.is_empty() {
        eprintln!("[ERR] clipboard empty");
        return 1;
    }
    let mut applied = 0u32;
    let mut start = 0usize;
    while let Some(idx) = clip[start..].find("### File: `") {
        let fstart = start + idx + 11;
        let Some(fend) = clip[fstart..].find('`') else { break; };
        let path_str = &clip[fstart..fstart + fend];
        let rem = &clip[fstart + fend..];
        let Some(cstart) = rem.find("```") else { break; };
        let after = &rem[cstart + 3..];
        let Some(nl) = after.find('\n') else { break; };
        let code_text = &after[nl + 1..];
        let Some(cend) = code_text.find("\n```") else { break; };
        let code = &code_text[..cend];
        let rel = Path::new(path_str);
        if rel.is_absolute() || rel.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
            eprintln!("[ERR] refused path {path_str}");
            return 1;
        }
        let dest = root.join(rel);
        if let Some(parent) = dest.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if fs::write(&dest, code).is_ok() {
            println!("[+] applied {}", dest.display());
            applied += 1;
        }
        start = fstart + 11;
    }
    if applied == 0 {
        eprintln!("[ERR] no file blocks applied");
        return 1;
    }
    0
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return; };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') && name != ".env" && name != ".env.example" {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue; };
        if meta.is_dir() {
            if !SKIP_DIRS.contains(&name) {
                walk(&path, files);
            }
        } else if meta.is_file() {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if SKIP_EXTS.contains(&ext.to_ascii_lowercase().as_str()) {
                    continue;
                }
            }
            if meta.len() <= MAX_FILE_BYTES {
                files.push(path);
            }
        }
    }
}

fn priority_val(p: &Path) -> usize {
    let s = p.to_string_lossy();
    PRIORITY.iter().position(|&x| s.ends_with(x)).unwrap_or(PRIORITY.len())
}

fn set_clipboard(text: &str) -> bool {
    let Ok(mut child) = Command::new("termux-clipboard-set").stdin(Stdio::piped()).spawn() else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

fn get_clipboard() -> String {
    Command::new("termux-clipboard-get")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default()
}
RUST_BEGIN
then
  log_err "compile failed"
  exit 1
fi
ACTION="${1:-push}"
ROOT="${REPO_ROOT}" WORKDIR="${WORKDIR}" ACTION="${ACTION}" "${BIN}"
child=$?
if [[ "${child}" -ne 0 ]]; then
  exit "${child}"
fi
if [[ "${ACTION}" == "push" ]] && has termux-open-url; then
  termux-open-url "https://notebooklm.google.com" || true
fi
log_ok "parts in ${BUNDLE_DIR}; clipboard holds part 01 only"
)
