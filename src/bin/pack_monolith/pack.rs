//! Ported logic for the `pack-monolith` tool: classify every git-tracked file
//! into the crate's architectural layers, order them topologically, and emit
//! (or reconstruct) the loss-less single-file monolith.
//!
//! This is a faithful port of the former `scripts/pack_monolith.py` — the
//! record format (sentinels, `### key : value` metablocks, `eof-newline`
//! handling, base64 76-column wrapping, the `path\0sha\0` tree-digest) is
//! byte-compatible with what that script produced and consumed, so a monolith
//! written by either side round-trips through the other. The only intentional
//! divergence is the artifact's self-reference: the `generator` line and the
//! FORMAT SPECIFICATION's "reference unpacker" now name this Rust binary,
//! because that is the tool an operator actually runs.
//!
//! Determinism is preserved: the output is a pure function of the working tree
//! (no wall-clock, no randomness), so the same commit always yields the same
//! bytes.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use base64::Engine as _;
use sha2::{Digest, Sha256};

/// Format-version tag written into (and, in principle, checked out of) the
/// monolith banner. Bump only on an incompatible record-format change.
pub const PACKER_VERSION: &str = "1";
/// Default artifact name when `-o` is not given.
pub const DEFAULT_OUTPUT: &str = "HSE_MONOLITH.glm5.txt";

// Per-file payload delimiters. Guaranteed (and re-checked at pack time) never
// to occur at the start of a line inside any file's content, so a parser splits
// records unambiguously by scanning for them at column 0.
const BEGIN: &str = "@@HSE-BEGIN@@"; // text payload (UTF-8 verbatim)
const END: &str = "@@HSE-END@@";
const BEGIN_B64: &str = "@@HSE-BEGIN-B64@@"; // binary payload (base64, 76-col wrapped)
const END_B64: &str = "@@HSE-END-B64@@";
const SENTINELS: [&str; 4] = [BEGIN, END, BEGIN_B64, END_B64];

const RULE: &str = "====================================================================================================";
const THIN: &str = "----------------------------------------------------------------------------------------------------";

/// `(rank, label, human description)` for every architectural layer, in strict
/// dependency order — the linearisation of the DAG `tests/architecture.rs`
/// enforces. Lower rank == earlier == fewer dependencies. Kept in sync with
/// [`classify_layer`], which assigns these ranks.
const LAYER_RANKS: [(u32, &str, &str); 19] = [
    (
        0,
        "build",
        "Build & dependency foundation (manifest, lockfile, build script, lints)",
    ),
    (
        1,
        "util",
        "src/util — leaf utilities; no intra-crate deps above this layer",
    ),
    (
        2,
        "core",
        "src/core — engine, entities, correlation; uses util, defines ports",
    ),
    (
        3,
        "storage",
        "src/storage — persistence implementing core's StoragePort",
    ),
    (
        4,
        "modules",
        "src/modules — OSINT collectors; use core+util, never engine/storage",
    ),
    (
        5,
        "api",
        "src/api — HTTP/axum surface over core (via ports, not storage)",
    ),
    (
        6,
        "cli",
        "src/cli — command-line orchestration wiring all layers",
    ),
    (7, "audit", "src/audit — cross-cutting audit trail"),
    (8, "selftest", "src/selftest — built-in self-test harness"),
    (
        9,
        "crate-root",
        "Crate roots — lib.rs/main.rs declare & depend on every module above",
    ),
    (
        10,
        "web",
        "src/web — static SPA assets served by the api layer",
    ),
    (
        11,
        "src-other",
        "src/* — remaining source not otherwise classified",
    ),
    (
        12,
        "tests",
        "tests/ — integration & architecture tests (depend on whole crate)",
    ),
    (13, "benches", "benches/ — performance benchmarks"),
    (14, "scripts", "scripts/ — developer & CI shell tooling"),
    (15, "ci", ".github/ — CI/CD workflow definitions"),
    (
        16,
        "proptest",
        "proptest-regressions/ — recorded property-test seeds",
    ),
    (17, "meta", ".claude/ — agent & tooling configuration"),
    (
        18,
        "docs",
        "docs/ & root prose — design docs, READMEs, analyses, license",
    ),
];

/// Explicit head-of-file order for a few foundation files; everything else is
/// ordered structurally (see [`sort_key`]). Returns `None` for unlisted paths.
fn explicit_order(path: &str) -> Option<u32> {
    Some(match path {
        "Cargo.toml" => 0,
        "Cargo.lock" => 1,
        "build.rs" => 2,
        "rust-toolchain.toml" | "rust-toolchain" => 3,
        "deny.toml" => 4,
        ".cargo/config.toml" => 5,
        ".gitignore" => 9,
        _ => return None,
    })
}

/// Return `(rank, label)` for `path`'s architectural layer.
///
/// Only the crate-root build files are "foundation". A per-module `build.rs`
/// (e.g. `src/modules/photon/build.rs`) belongs WITH its module and falls
/// through to the `modules` layer, so a module stays contiguous.
fn classify_layer(path: &str) -> (u32, &'static str) {
    if explicit_order(path).is_some() || path.starts_with(".cargo/") {
        return (0, "build");
    }
    for (prefix, rank, label) in [
        ("src/util/", 1, "util"),
        ("src/core/", 2, "core"),
        ("src/storage/", 3, "storage"),
        ("src/modules/", 4, "modules"),
        ("src/api/", 5, "api"),
        ("src/cli/", 6, "cli"),
        ("src/audit/", 7, "audit"),
        ("src/selftest/", 8, "selftest"),
    ] {
        if path.starts_with(prefix) {
            return (rank, label);
        }
    }
    if matches!(
        path,
        "src/lib.rs" | "src/lib_tests.rs" | "src/main.rs" | "src/main_tests.rs"
    ) {
        return (9, "crate-root");
    }
    for (prefix, rank, label) in [
        ("src/web/", 10, "web"),
        ("src/", 11, "src-other"),
        ("tests/", 12, "tests"),
        ("benches/", 13, "benches"),
        ("scripts/", 14, "scripts"),
        (".github/", 15, "ci"),
        ("proptest-regressions/", 16, "proptest"),
        (".claude/", 17, "meta"),
    ] {
        if path.starts_with(prefix) {
            return (rank, label);
        }
    }
    (18, "docs")
}

/// One component of a structural sort key. A file component sorts before a
/// directory component at the same position (marker 0 < 1), so a directory's
/// own files precede its sub-directories; within the files, `mod.rs` leads.
/// Mirrors the Python `module_token_key`'s heterogeneous tuple ordering.
#[derive(PartialEq, Eq)]
enum Tok {
    /// A file leaf: `mod_flag` is 0 for `mod.rs` (sorts first), else 1.
    File { mod_flag: u8, name: String },
    /// A directory component.
    Dir { name: String },
}

impl Ord for Tok {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        use std::cmp::Ordering::{Greater, Less};
        match (self, other) {
            (Tok::File { .. }, Tok::Dir { .. }) => Less,
            (Tok::Dir { .. }, Tok::File { .. }) => Greater,
            (
                Tok::File {
                    mod_flag: a,
                    name: na,
                },
                Tok::File {
                    mod_flag: b,
                    name: nb,
                },
            ) => (a, na).cmp(&(b, nb)),
            (Tok::Dir { name: a }, Tok::Dir { name: b }) => a.cmp(b),
        }
    }
}

impl PartialOrd for Tok {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Structural token key: directory components (marker 1) followed by the file
/// component (marker 0). `Vec<Tok>` compares lexicographically, so a shorter
/// key that is a prefix of another sorts first — matching Python's tuple rules.
fn module_token_key(path: &str) -> Vec<Tok> {
    let parts: Vec<&str> = path.split('/').collect();
    let mut key = Vec::with_capacity(parts.len());
    for d in &parts[..parts.len() - 1] {
        key.push(Tok::Dir {
            name: (*d).to_string(),
        });
    }
    let fname = parts[parts.len() - 1];
    key.push(Tok::File {
        mod_flag: u8::from(fname != "mod.rs"),
        name: fname.to_string(),
    });
    key
}

/// The total order files are emitted in: layer rank, then the foundation-file
/// explicit order, then the structural token key.
fn sort_key(path: &str) -> (u32, u32, Vec<Tok>) {
    let (rank, _label) = classify_layer(path);
    (
        rank,
        explicit_order(path).unwrap_or(10_000),
        module_token_key(path),
    )
}

/// Provenance hint so the reader knows non-authored / generated files.
fn category_note(path: &str) -> &'static str {
    if path.starts_with("src/web/vendor/") {
        "vendored third-party asset (not HSE-authored)"
    } else if path == "Cargo.lock" {
        "generated dependency lockfile"
    } else if path.starts_with("proptest-regressions/") {
        "generated property-test regression seeds"
    } else if path.ends_with(".der") {
        "binary test fixture (DER certificate)"
    } else if path.starts_with("src/web/") {
        "hand-rolled SPA front-end asset"
    } else {
        ""
    }
}

/// Syntax-highlight language tag for the agent, by file extension.
fn lang_for(path: &str, is_bin: bool) -> &'static str {
    if is_bin {
        return "binary";
    }
    let base = path.rsplit('/').next().unwrap_or(path);
    let ext = if base.starts_with('.') && !base[1..].contains('.') {
        &base[1..]
    } else {
        base.rsplit_once('.').map_or("", |(_, e)| e)
    };
    match ext.to_ascii_lowercase().as_str() {
        "rs" => "rust",
        "toml" | "lock" => "toml",
        "md" => "markdown",
        "txt" => "text",
        "sh" => "bash",
        "yml" | "yaml" => "yaml",
        "json" => "json",
        "js" => "javascript",
        "css" => "css",
        "html" => "html",
        "der" => "binary",
        "py" => "python",
        "gitignore" => "gitignore",
        _ => "text",
    }
}

/// A file is binary if it has a NUL byte or is not valid UTF-8.
fn is_binary(data: &[u8]) -> bool {
    data.contains(&0) || std::str::from_utf8(data).is_err()
}

/// One packed file: its bytes plus the derived metadata a record carries.
struct Entry {
    path: String,
    data: Vec<u8>,
    is_binary: bool,
    sha256: String,
    eof_newline: bool,
    lines: usize,
    rank: u32,
    label: &'static str,
    note: &'static str,
}

impl Entry {
    fn new(path: String, data: Vec<u8>) -> Self {
        let bin = is_binary(&data);
        let sha256 = hex::encode(Sha256::digest(&data));
        let eof_newline = data.last().is_none_or(|&b| b == b'\n');
        // Line count: newlines, plus one for a final line with no trailing "\n".
        let lines = if bin {
            0
        } else {
            data.iter().filter(|&&b| b == b'\n').count()
                + usize::from(!data.is_empty() && !eof_newline)
        };
        let (rank, label) = classify_layer(&path);
        let note = category_note(&path);
        Self {
            path,
            data,
            is_binary: bin,
            sha256,
            eof_newline,
            lines,
            rank,
            label,
            note,
        }
    }
}

// --------------------------------------------------------------------------- //
// Git plumbing                                                                 //
// --------------------------------------------------------------------------- //

fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("running git {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(out.stdout)
}

/// Repository root (`git rev-parse --show-toplevel`).
pub fn repo_root() -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd: {e}"))?;
    let out = git(&cwd, &["rev-parse", "--show-toplevel"])?;
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

fn git_tracked_files(root: &Path) -> Result<Vec<String>, String> {
    let out = git(root, &["ls-files", "-z"])?;
    Ok(String::from_utf8_lossy(&out)
        .split('\0')
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect())
}

/// Reduce a remote URL to its `owner/repo` slug, dropping any embedded
/// credentials or local-proxy host (the sandbox rewrites origin through a
/// `local_proxy@127.0.0.1:PORT` URL we must not bake into the artifact).
fn sanitize_remote(url: &str) -> String {
    let mut u = url;
    if let Some((_, rest)) = u.split_once("://") {
        u = rest;
    }
    if let Some((_, rest)) = u.rsplit_once('@') {
        u = rest;
    }
    if let Some((_, rest)) = u.split_once("/git/") {
        u = rest;
    }
    let u = u.strip_suffix(".git").unwrap_or(u);
    if u.is_empty() {
        "(unknown)".to_string()
    } else {
        u.to_string()
    }
}

struct GitInfo {
    commit: String,
    branch: String,
    date: String,
    subject: String,
    remote: String,
}

fn git_info(root: &Path) -> GitInfo {
    let g = |args: &[&str]| {
        git(root, args).map_or_else(
            |_| "(unknown)".to_string(),
            |o| String::from_utf8_lossy(&o).trim().to_string(),
        )
    };
    GitInfo {
        commit: g(&["rev-parse", "HEAD"]),
        branch: g(&["rev-parse", "--abbrev-ref", "HEAD"]),
        date: g(&["log", "-1", "--format=%cd", "--date=iso-strict"]),
        subject: g(&["log", "-1", "--format=%s"]),
        remote: sanitize_remote(&g(&["config", "--get", "remote.origin.url"])),
    }
}

// --------------------------------------------------------------------------- //
// Rendering helpers                                                            //
// --------------------------------------------------------------------------- //

/// Group a non-negative integer with thousands separators (`1234` → `1,234`),
/// matching Python's `f"{n:,}"`.
fn commas(n: u64) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (len - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// One-decimal, thousands-grouped float, matching Python's `f"{f:,.1f}"`.
fn commas_f1(f: f64) -> String {
    let s = format!("{f:.1}");
    let (int_part, frac) = s.split_once('.').unwrap_or((s.as_str(), "0"));
    let neg = int_part.starts_with('-');
    let digits = int_part.trim_start_matches('-').parse::<u64>().unwrap_or(0);
    format!("{}{}.{frac}", if neg { "-" } else { "" }, commas(digits))
}

/// Human-readable byte size, matching the Python `human()` exactly.
fn human(n: u64) -> String {
    let mut f = n as f64;
    for unit in ["B", "KiB", "MiB", "GiB"] {
        if f < 1024.0 || unit == "GiB" {
            return if unit == "B" {
                format!("{} B", commas(n))
            } else {
                format!("{} {unit}", commas_f1(f))
            };
        }
        f /= 1024.0;
    }
    format!("{n} B")
}

/// SHA-256 over `path\0filesha256\0` for every record, in order — the
/// whole-tree fingerprint.
fn tree_digest(entries: &[Entry]) -> String {
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.path.as_bytes());
        h.update([0]);
        h.update(e.sha256.as_bytes());
        h.update([0]);
    }
    hex::encode(h.finalize())
}

#[derive(Default)]
struct TreeNode {
    children: BTreeMap<String, TreeNode>,
}

/// ASCII directory tree (dirs first, then files, each lexical) for navigation.
fn render_tree(paths: &[String]) -> Vec<String> {
    let mut root = TreeNode::default();
    for p in paths {
        let mut node = &mut root;
        for part in p.split('/') {
            node = node.children.entry(part.to_string()).or_default();
        }
    }
    let mut lines = vec![".".to_string()];
    walk(&root, "", &mut lines);
    lines
}

fn walk(node: &TreeNode, prefix: &str, lines: &mut Vec<String>) {
    let mut items: Vec<(&String, &TreeNode)> = node.children.iter().collect();
    // Directories (non-empty) before files (empty), each already lexical.
    items.sort_by(|a, b| (a.1.children.is_empty(), a.0).cmp(&(b.1.children.is_empty(), b.0)));
    let n = items.len();
    for (i, (name, child)) in items.into_iter().enumerate() {
        let last = i == n - 1;
        let branch = if last { "`-- " } else { "|-- " };
        let is_dir = !child.children.is_empty();
        lines.push(format!(
            "{prefix}{branch}{name}{}",
            if is_dir { "/" } else { "" }
        ));
        if is_dir {
            walk(
                child,
                &format!("{prefix}{}", if last { "    " } else { "|   " }),
                lines,
            );
        }
    }
}

// --------------------------------------------------------------------------- //
// Packing                                                                      //
// --------------------------------------------------------------------------- //

fn build_entries(root: &Path, exclude: &str) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for path in git_tracked_files(root)? {
        if path == exclude {
            continue;
        }
        let data = std::fs::read(root.join(&path)).map_err(|e| format!("reading {path}: {e}"))?;
        entries.push(Entry::new(path, data));
    }
    entries.sort_by_key(|e| sort_key(&e.path));
    Ok(entries)
}

fn assert_no_sentinel_collision(entries: &[Entry]) -> Result<(), String> {
    for e in entries {
        if e.is_binary {
            continue;
        }
        // Safe: non-binary means valid UTF-8.
        let text = std::str::from_utf8(&e.data).unwrap_or("");
        for ln in text.split('\n') {
            if SENTINELS.iter().any(|s| ln.starts_with(s)) {
                let head: String = ln.chars().take(60).collect();
                return Err(format!(
                    "sentinel collision in {}: {head:?}\n       A file's content begins a \
                     line with a reserved @@HSE-...@@ marker; choose a different sentinel.",
                    e.path
                ));
            }
        }
    }
    Ok(())
}

/// One BODY record: the `----` rule, the `### key : value` metablock, and the
/// sentinel-delimited payload (text verbatim, or base64 76-col for binary).
/// Shared by [`pack_to_string`] and the round-trip test so the emit and parse
/// sides can never drift.
fn body_record(e: &Entry, index: usize, total: usize) -> String {
    let mut o = String::new();
    o.push_str(THIN);
    o.push('\n');
    o.push_str(&format!("### file     : {index} / {total}\n"));
    o.push_str(&format!("### path     : {}\n", e.path));
    o.push_str(&format!("### layer    : {}  (rank {})\n", e.label, e.rank));
    o.push_str(&format!(
        "### lang     : {}\n",
        lang_for(&e.path, e.is_binary)
    ));
    o.push_str(&format!("### bytes    : {}\n", e.data.len()));
    o.push_str(&format!("### lines    : {}\n", e.lines));
    o.push_str(&format!("### sha256   : {}\n", e.sha256));
    o.push_str(&format!(
        "### encoding : {}\n",
        if e.is_binary { "base64" } else { "utf-8" }
    ));
    if !e.is_binary {
        o.push_str(&format!(
            "### eof-newline : {}\n",
            if e.eof_newline { "true" } else { "false" }
        ));
    }
    if !e.note.is_empty() {
        o.push_str(&format!("### note     : {}\n", e.note));
    }
    o.push_str(THIN);
    o.push('\n');
    if e.is_binary {
        o.push_str(&format!("{BEGIN_B64} {}\n", e.path));
        let b64 = base64::engine::general_purpose::STANDARD.encode(&e.data);
        let mut j = 0;
        while j < b64.len() {
            let end = (j + 76).min(b64.len());
            o.push_str(&b64[j..end]);
            o.push('\n');
            j = end;
        }
        o.push_str(&format!("{END_B64} {}\n\n", e.path));
    } else {
        o.push_str(&format!("{BEGIN} {}\n", e.path));
        o.push_str(std::str::from_utf8(&e.data).unwrap_or(""));
        if !e.eof_newline {
            o.push('\n'); // separator only; flagged by eof-newline:false
        }
        o.push_str(&format!("{END} {}\n\n", e.path));
    }
    o
}

/// Pack `root`'s tracked tree into a monolith string. `out_rel` is the
/// artifact's own repo-relative path, excluded from its own capture.
pub fn pack_to_string(root: &Path, out_rel: &str) -> Result<(String, usize, String), String> {
    let entries = build_entries(root, out_rel)?;
    assert_no_sentinel_collision(&entries)?;

    let info = git_info(root);
    let total_bytes: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
    let total_lines: usize = entries.iter().map(|e| e.lines).sum();
    let n_binary = entries.iter().filter(|e| e.is_binary).count();
    let digest = tree_digest(&entries);

    let mut o = String::new();
    // ---- Banner ----------------------------------------------------------- //
    o.push_str(RULE);
    o.push('\n');
    o.push_str("  HSE :: HUNTSMAN SEARCH ENGINE  --  MONOLITHIC CODEBASE SNAPSHOT\n");
    o.push_str(
        "  Topologically ordered, loss-less, single-file capture of the entire repository.\n",
    );
    o.push_str("  Designed for whole-repo ingestion by an LLM agent (GLM 5.2 Agent compatible).\n");
    o.push_str(RULE);
    o.push_str("\n\n");

    o.push_str(&format!("packer-version : {PACKER_VERSION}\n"));
    o.push_str("generator      : src/bin/pack_monolith (cargo run --bin pack-monolith; deterministic; pure function of the tree)\n");
    o.push_str(&format!("repository     : {}\n", info.remote));
    o.push_str(&format!("branch         : {}\n", info.branch));
    o.push_str(&format!("commit         : {}\n", info.commit));
    o.push_str(&format!("commit-date    : {}\n", info.date));
    o.push_str(&format!("commit-subject : {}\n", info.subject));
    o.push_str(&format!(
        "files          : {}  ({n_binary} binary, {} text)\n",
        commas(entries.len() as u64),
        commas((entries.len() - n_binary) as u64)
    ));
    o.push_str(&format!(
        "total-bytes    : {}  ({})\n",
        commas(total_bytes),
        human(total_bytes)
    ));
    o.push_str(&format!(
        "total-lines    : {}\n",
        commas(total_lines as u64)
    ));
    o.push_str(&format!("tree-digest    : sha256:{digest}\n"));
    o.push_str(
        "                 (sha256 over `path\\0filesha256\\0` for every record, in order)\n\n",
    );

    // ---- Format spec ------------------------------------------------------ //
    o.push_str(THIN);
    o.push('\n');
    o.push_str("FORMAT SPECIFICATION  (read this first)\n");
    o.push_str(THIN);
    o.push('\n');
    o.push_str(&format_spec());
    o.push('\n');

    // ---- Topology --------------------------------------------------------- //
    o.push_str(THIN);
    o.push('\n');
    o.push_str("TOPOLOGY  (layers in dependency order; files are emitted in exactly this order)\n");
    o.push_str(THIN);
    o.push('\n');
    let mut present: BTreeMap<&str, usize> = BTreeMap::new();
    for e in &entries {
        *present.entry(e.label).or_insert(0) += 1;
    }
    for (rank, label, desc) in LAYER_RANKS {
        if let Some(&count) = present.get(label) {
            o.push_str(&format!(
                "  [{rank:2}] {label:<11} {count:>4} files  -- {desc}\n"
            ));
        }
    }
    o.push_str("\n  Rule: every dependency edge points to an EARLIER layer. Crate roots\n");
    o.push_str("  (lib.rs/main.rs) declare all modules and so are emitted AFTER them;\n");
    o.push_str("  tests/benches depend on the whole crate and follow the roots.\n\n");

    // ---- Directory tree --------------------------------------------------- //
    o.push_str(THIN);
    o.push('\n');
    o.push_str("DIRECTORY TREE  (lexical; full repository layout)\n");
    o.push_str(THIN);
    o.push('\n');
    let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    for line in render_tree(&paths) {
        o.push_str(&line);
        o.push('\n');
    }
    o.push('\n');

    // ---- Manifest --------------------------------------------------------- //
    o.push_str(THIN);
    o.push('\n');
    o.push_str("FILE MANIFEST  (emission order == topological order; seek by index or path)\n");
    o.push_str(THIN);
    o.push('\n');
    o.push_str(&format!(
        "  {:>4}  {:<11} {:>7} {:>9}  {:<12} path\n",
        "#", "layer", "lines", "bytes", "sha256"
    ));
    for (i, e) in entries.iter().enumerate() {
        let flag = if e.is_binary { "B" } else { " " };
        o.push_str(&format!(
            "  {:>4}{flag} {:<11} {:>7} {:>9}  {} {}\n",
            i + 1,
            e.label,
            e.lines,
            e.data.len(),
            &e.sha256[..12],
            e.path
        ));
    }
    o.push('\n');

    // ---- Body ------------------------------------------------------------- //
    o.push_str(RULE);
    o.push('\n');
    o.push_str("BODY  --  FILE CONTENTS (topological order)\n");
    o.push_str(RULE);
    o.push_str("\n\n");
    let n = entries.len();
    for (i, e) in entries.iter().enumerate() {
        o.push_str(&body_record(e, i + 1, n));
    }

    // ---- Footer ----------------------------------------------------------- //
    o.push_str(RULE);
    o.push('\n');
    o.push_str("END OF MONOLITH\n");
    o.push_str(&format!(
        "  records     : {}\n",
        commas(entries.len() as u64)
    ));
    o.push_str(&format!(
        "  total-bytes : {} ({})\n",
        commas(total_bytes),
        human(total_bytes)
    ));
    o.push_str(&format!("  total-lines : {}\n", commas(total_lines as u64)));
    o.push_str(&format!("  tree-digest : sha256:{digest}\n"));
    o.push_str(&format!("  commit      : {}\n", info.commit));
    o.push_str(RULE);
    o.push('\n');

    Ok((o, entries.len(), digest))
}

fn format_spec() -> String {
    format!(
        "\
This file is a loss-less concatenation of every git-tracked file in the repo,
in dependency-topological order. It is line-oriented UTF-8. Structure:

    monolith := BANNER  SPEC  TOPOLOGY  TREE  MANIFEST  BODY  FOOTER
    BODY     := record*
    record   := metablock  payload
    metablock:= (\"### \" <key> \" : \" <value> \"\\n\")+        # human-readable, parseable
    payload  := text_payload | base64_payload

    text_payload   := \"{BEGIN} \" <path> \"\\n\"  <bytes...>  \"\\n{END} \" <path> \"\\n\"
    base64_payload := \"{BEGIN_B64} \" <path> \"\\n\" <base64 76-col> \"\\n{END_B64} \" <path> \"\\n\"

EXTRACTING ONE FILE
  1. Find the line that is exactly:  `{BEGIN} <path>`   (or the B64 variant).
  2. The file content is every byte AFTER that line's terminating newline, up to
     (and not including) the newline that immediately precedes the matching
     `{END} <path>` line.
  3. If the record's `meta` shows `eof-newline : false`, drop that single trailing
     separator newline (the original file did not end in one).
  4. For B64 records, base64-decode the enclosed block to recover raw bytes.

GUARANTEES
  * The `{BEGIN}` / `{END}` sentinels never appear at the start of any line
    inside file content (verified at pack time), so records split unambiguously.
  * Each record's `### sha256` is the SHA-256 of the ORIGINAL file bytes; verify
    after decoding. The `tree-digest` above fingerprints the whole set.
  * Order is topological: a layer always appears after the layers it depends on
    (see TOPOLOGY). The MANIFEST lists every record with its byte offset cue.

REFERENCE UNPACKER (Rust; reconstructs the byte-exact tree):
    cargo run --bin pack-monolith -- --unpack <this-file> <destdir>
"
    )
}

// --------------------------------------------------------------------------- //
// Unpacking                                                                    //
// --------------------------------------------------------------------------- //

/// Reconstruct the tree encoded in `mono` under `dest`. Returns
/// `[(path, sha256), ...]` for every restored file.
pub fn unpack(mono: &str, dest: &Path) -> Result<Vec<(String, String)>, String> {
    // Split retaining the trailing '\n' on each line, like Python readlines().
    let lines: Vec<&str> = mono.split_inclusive('\n').collect();
    let mut restored = Vec::new();
    let mut i = 0;
    let mut expected_sha: Option<String> = None;
    let mut expected_eof_nl = true;

    while i < lines.len() {
        let line = lines[i];
        if let Some(rest) = line.strip_prefix("### sha256   : ") {
            expected_sha = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("### eof-newline : ") {
            expected_eof_nl = rest.trim() == "true";
        }

        if let Some(rest) = line.strip_prefix(&format!("{BEGIN_B64} ")) {
            let path = rest.trim_end_matches('\n').to_string();
            i += 1;
            let mut buf = String::new();
            while i < lines.len() && !lines[i].starts_with(&format!("{END_B64} ")) {
                buf.push_str(lines[i].trim_end_matches('\n'));
                i += 1;
            }
            let data = base64::engine::general_purpose::STANDARD
                .decode(buf.as_bytes())
                .map_err(|e| format!("base64 decode for {path}: {e}"))?;
            write_file(dest, &path, &data, &mut restored, expected_sha.as_deref())?;
            expected_sha = None;
            expected_eof_nl = true;
        } else if let Some(rest) = line.strip_prefix(&format!("{BEGIN} ")) {
            let path = rest.trim_end_matches('\n').to_string();
            i += 1;
            let start = i;
            while i < lines.len() && !lines[i].starts_with(&format!("{END} ")) {
                i += 1;
            }
            let mut body: String = lines[start..i].concat();
            if !expected_eof_nl && body.ends_with('\n') {
                body.pop();
            }
            write_file(
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

fn write_file(
    dest: &Path,
    path: &str,
    data: &[u8],
    acc: &mut Vec<(String, String)>,
    expected_sha: Option<&str>,
) -> Result<(), String> {
    let got = hex::encode(Sha256::digest(data));
    if let Some(exp) = expected_sha
        && got != exp
    {
        return Err(format!(
            "sha mismatch on extract for {path}: expected {}, got {}",
            &exp[..exp.len().min(12)],
            &got[..12]
        ));
    }
    let full = dest.join(path);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    std::fs::write(&full, data).map_err(|e| format!("writing {}: {e}", full.display()))?;
    acc.push((path.to_string(), got));
    Ok(())
}

/// Pack-independent round-trip check: unpack `mono_path` to a temp dir and diff
/// the result against the working tree. Returns `Ok(true)` on a byte-exact,
/// complete match.
pub fn verify(root: &Path, mono: &str, mono_rel: &str) -> Result<bool, String> {
    let tmp = std::env::temp_dir().join(format!("hse-monolith-verify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let restored = unpack(mono, &tmp)?;

    let tracked: std::collections::BTreeSet<String> = git_tracked_files(root)?
        .into_iter()
        .filter(|p| p != mono_rel)
        .collect();
    let got: std::collections::BTreeSet<String> = restored.iter().map(|(p, _)| p.clone()).collect();

    let missing: Vec<&String> = tracked.difference(&got).collect();
    let extra: Vec<&String> = got.difference(&tracked).collect();
    let mut mismatch = Vec::new();
    for (p, sha) in &restored {
        let live = std::fs::read(root.join(p)).map_err(|e| format!("reading {p}: {e}"))?;
        if &hex::encode(Sha256::digest(&live)) != sha {
            mismatch.push(p.clone());
        }
    }
    let _ = std::fs::remove_dir_all(&tmp);

    let ok = missing.is_empty() && extra.is_empty() && mismatch.is_empty();
    println!(
        "[verify] restored {} files; tracked {}",
        commas(got.len() as u64),
        commas(tracked.len() as u64)
    );
    if !missing.is_empty() {
        println!(
            "[verify] MISSING ({}): {:?}",
            missing.len(),
            &missing[..missing.len().min(10)]
        );
    }
    if !extra.is_empty() {
        println!(
            "[verify] EXTRA ({}): {:?}",
            extra.len(),
            &extra[..extra.len().min(10)]
        );
    }
    if !mismatch.is_empty() {
        println!(
            "[verify] CONTENT MISMATCH ({}): {:?}",
            mismatch.len(),
            &mismatch[..mismatch.len().min(10)]
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
    Ok(ok)
}

#[cfg(test)]
mod tests {
    include!("pack_tests.rs");
}
