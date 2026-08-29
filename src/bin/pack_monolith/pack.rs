//! Packing: build the file list, then write the monolith
//! (banner / format spec / topology / tree / manifest / body / footer).

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use base64::Engine;

use crate::entry::{Entry, lang_for};
use crate::format_util::{abspath, commas_int, human, relpath_under};
use crate::gitinfo::{git_info, git_tracked_files};
use crate::topology::{LAYER_RANKS, sort_key};
use crate::tree::render_tree;
use crate::{BEGIN, BEGIN_B64, END, END_B64, PACKER_VERSION, SENTINELS};

pub fn build_entries(root: &str, exclude: &HashSet<String>) -> Result<Vec<Entry>, String> {
    let mut entries = Vec::new();
    for path in git_tracked_files(root)? {
        if exclude.contains(&path) {
            continue;
        }
        let data = std::fs::read(Path::new(root).join(&path))
            .map_err(|e| format!("reading {path}: {e}"))?;
        entries.push(Entry::new(path, data));
    }
    entries.sort_by_key(|e| sort_key(&e.path));
    Ok(entries)
}

/// Fails closed rather than emitting a monolith an unpacker could misparse.
/// A file's content is scanned line-by-line (`str::lines`, i.e. split on
/// `\n`) for a line starting with one of the reserved `@@HSE-...@@` markers.
pub fn assert_no_sentinel_collision(entries: &[Entry]) -> Result<(), String> {
    for e in entries {
        if e.is_binary {
            continue;
        }
        let text = std::str::from_utf8(&e.data)
            .map_err(|_| format!("{}: not valid UTF-8 despite is_binary == false", e.path))?;
        for ln in text.lines() {
            if SENTINELS.iter().any(|s| ln.starts_with(s)) {
                let truncated: String = ln.chars().take(60).collect();
                return Err(format!(
                    "FATAL: sentinel collision in {}: {truncated:?}\n       A file's content \
                     begins a line with a reserved @@HSE-...@@ marker; choose a different \
                     sentinel.",
                    e.path
                ));
            }
        }
    }
    Ok(())
}

pub fn tree_digest(entries: &[Entry]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.path.as_bytes());
        h.update([0u8]);
        h.update(e.sha256.as_bytes());
        h.update([0u8]);
    }
    hex::encode(h.finalize())
}

pub fn pack(root: &str, out_path: &Path) -> Result<(), String> {
    let root_abs = abspath(Path::new(root))?;
    let out_abs = abspath(out_path)?;
    let rel_out = relpath_under(&root_abs, &out_abs);
    let mut exclude = HashSet::new();
    exclude.insert(rel_out);

    let entries = build_entries(root, &exclude)?;
    assert_no_sentinel_collision(&entries)?;

    let info = git_info(Path::new(root))?;
    let total_bytes: u64 = entries.iter().map(|e| e.data.len() as u64).sum();
    let total_lines: u64 = entries.iter().map(|e| e.lines as u64).sum();
    let n_binary = entries.iter().filter(|e| e.is_binary).count();
    let digest = tree_digest(&entries);

    let file = std::fs::File::create(out_path)
        .map_err(|e| format!("creating {}: {e}", out_path.display()))?;
    let mut o = std::io::BufWriter::new(file);
    write_monolith(
        &mut o,
        &entries,
        &info,
        total_bytes,
        total_lines,
        n_binary,
        &digest,
    )
    .map_err(|e| format!("writing {}: {e}", out_path.display()))?;
    o.flush()
        .map_err(|e| format!("writing {}: {e}", out_path.display()))?;

    let art_size = std::fs::metadata(out_path).map_or(0, |m| m.len());
    println!(
        "[pack] {} files  ->  {}",
        commas_int(entries.len() as u64),
        out_path.display()
    );
    println!(
        "[pack] source bytes : {} ({})",
        commas_int(total_bytes),
        human(total_bytes)
    );
    println!(
        "[pack] artifact size: {} ({})",
        commas_int(art_size),
        human(art_size)
    );
    println!("[pack] tree-digest  : sha256:{digest}");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_monolith(
    o: &mut impl Write,
    entries: &[Entry],
    info: &crate::gitinfo::GitInfo,
    total_bytes: u64,
    total_lines: u64,
    n_binary: usize,
    digest: &str,
) -> std::io::Result<()> {
    let rule = "=".repeat(100);
    let thin = "-".repeat(100);

    // ---- Banner ---------------------------------------------------------
    writeln!(o, "{rule}")?;
    writeln!(
        o,
        "  HSE :: HUNTSMAN SEARCH ENGINE  --  MONOLITHIC CODEBASE SNAPSHOT"
    )?;
    writeln!(
        o,
        "  Topologically ordered, loss-less, single-file capture of the entire repository."
    )?;
    writeln!(
        o,
        "  Designed for whole-repo ingestion by an LLM agent (GLM 5.2 Agent compatible)."
    )?;
    writeln!(o, "{rule}\n")?;

    writeln!(o, "packer-version : {PACKER_VERSION}")?;
    writeln!(
        o,
        "generator      : pack-monolith (deterministic; pure function of the tree)"
    )?;
    writeln!(o, "repository     : {}", info.remote)?;
    writeln!(o, "branch         : {}", info.branch)?;
    writeln!(o, "commit         : {}", info.commit)?;
    writeln!(o, "commit-date    : {}", info.date)?;
    writeln!(o, "commit-subject : {}", info.subject)?;
    writeln!(
        o,
        "files          : {}  ({n_binary} binary, {} text)",
        commas_int(entries.len() as u64),
        entries.len() - n_binary
    )?;
    writeln!(
        o,
        "total-bytes    : {}  ({})",
        commas_int(total_bytes),
        human(total_bytes)
    )?;
    writeln!(o, "total-lines    : {}", commas_int(total_lines))?;
    writeln!(o, "tree-digest    : sha256:{digest}")?;
    writeln!(
        o,
        "                 (sha256 over `path\\0filesha256\\0` for every record, in order)\n"
    )?;

    // ---- Format spec ------------------------------------------------------
    writeln!(o, "{thin}")?;
    writeln!(o, "FORMAT SPECIFICATION  (read this first)")?;
    writeln!(o, "{thin}")?;
    writeln!(
        o,
        "This file is a loss-less concatenation of every git-tracked file in the repo,"
    )?;
    writeln!(
        o,
        "in dependency-topological order. It is line-oriented UTF-8. Structure:\n"
    )?;
    writeln!(
        o,
        "    monolith := BANNER  SPEC  TOPOLOGY  TREE  MANIFEST  BODY  FOOTER"
    )?;
    writeln!(o, "    BODY     := record*")?;
    writeln!(o, "    record   := metablock  payload")?;
    writeln!(
        o,
        "    metablock:= (\"### \" <key> \" : \" <value> \"\\n\")+        # human-readable, parseable"
    )?;
    writeln!(o, "    payload  := text_payload | base64_payload\n")?;
    writeln!(
        o,
        "    text_payload   := \"{BEGIN} \" <path> \"\\n\"  <bytes...>  \"\\n{END} \" <path> \"\\n\""
    )?;
    writeln!(
        o,
        "    base64_payload := \"{BEGIN_B64} \" <path> \"\\n\" <base64 76-col> \"\\n{END_B64} \" <path> \"\\n\"\n"
    )?;
    writeln!(o, "EXTRACTING ONE FILE")?;
    writeln!(
        o,
        "  1. Find the line that is exactly:  `{BEGIN} <path>`   (or the B64 variant)."
    )?;
    writeln!(
        o,
        "  2. The file content is every byte AFTER that line's terminating newline, up to"
    )?;
    writeln!(
        o,
        "     (and not including) the newline that immediately precedes the matching"
    )?;
    writeln!(o, "     `{END} <path>` line.")?;
    writeln!(
        o,
        "  3. If the record's `meta` shows `eof-newline : false`, drop that single trailing"
    )?;
    writeln!(
        o,
        "     separator newline (the original file did not end in one)."
    )?;
    writeln!(
        o,
        "  4. For B64 records, base64-decode the enclosed block to recover raw bytes.\n"
    )?;
    writeln!(o, "GUARANTEES")?;
    writeln!(
        o,
        "  * The `{BEGIN}` / `{END}` sentinels never appear at the start of any line"
    )?;
    writeln!(
        o,
        "    inside file content (verified at pack time), so records split unambiguously."
    )?;
    writeln!(
        o,
        "  * Each record's `### sha256` is the SHA-256 of the ORIGINAL file bytes; verify"
    )?;
    writeln!(
        o,
        "    after decoding. The `tree-digest` above fingerprints the whole set."
    )?;
    writeln!(
        o,
        "  * Order is topological: a layer always appears after the layers it depends on"
    )?;
    writeln!(
        o,
        "    (see TOPOLOGY). The MANIFEST lists every record with its byte offset cue.\n"
    )?;
    writeln!(o, "REFERENCE UNPACKER (reconstructs the byte-exact tree):")?;
    writeln!(
        o,
        "    cargo run --bin pack-monolith -- --unpack <this-file> <destdir>\n"
    )?;

    // ---- Topology -----------------------------------------------------
    writeln!(o, "{thin}")?;
    writeln!(
        o,
        "TOPOLOGY  (layers in dependency order; files are emitted in exactly this order)"
    )?;
    writeln!(o, "{thin}")?;
    let mut present: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for e in entries {
        *present.entry(e.label).or_insert(0) += 1;
    }
    for &(rank, label, desc) in LAYER_RANKS {
        if let Some(&count) = present.get(label) {
            writeln!(o, "  [{rank:2}] {label:<11} {count:>4} files  -- {desc}")?;
        }
    }
    writeln!(
        o,
        "\n  Rule: every dependency edge points to an EARLIER layer. Crate roots"
    )?;
    writeln!(
        o,
        "  (lib.rs/main.rs) declare all modules and so are emitted AFTER them;"
    )?;
    writeln!(
        o,
        "  tests/benches depend on the whole crate and follow the roots.\n"
    )?;

    // ---- Directory tree -------------------------------------------------
    writeln!(o, "{thin}")?;
    writeln!(o, "DIRECTORY TREE  (lexical; full repository layout)")?;
    writeln!(o, "{thin}")?;
    let paths: Vec<String> = entries.iter().map(|e| e.path.clone()).collect();
    for line in render_tree(&paths) {
        writeln!(o, "{line}")?;
    }
    writeln!(o)?;

    // ---- Manifest ---------------------------------------------------------
    writeln!(o, "{thin}")?;
    writeln!(
        o,
        "FILE MANIFEST  (emission order == topological order; seek by index or path)"
    )?;
    writeln!(o, "{thin}")?;
    writeln!(
        o,
        "  {:>4}  {:<11} {:>7} {:>9}  {:<12} path",
        "#", "layer", "lines", "bytes", "sha256"
    )?;
    for (i, e) in entries.iter().enumerate() {
        let flag = if e.is_binary { "B" } else { " " };
        writeln!(
            o,
            "  {:>4}{flag} {:<11} {:>7} {:>9}  {} {}",
            i + 1,
            e.label,
            e.lines,
            e.data.len(),
            &e.sha256[..12],
            e.path
        )?;
    }
    writeln!(o)?;

    // ---- Body -----------------------------------------------------------
    writeln!(o, "{rule}")?;
    writeln!(o, "BODY  --  FILE CONTENTS (topological order)")?;
    writeln!(o, "{rule}\n")?;
    let n = entries.len();
    for (idx, e) in entries.iter().enumerate() {
        let i = idx + 1;
        writeln!(o, "{thin}")?;
        writeln!(o, "### file     : {i} / {n}")?;
        writeln!(o, "### path     : {}", e.path)?;
        writeln!(o, "### layer    : {}  (rank {})", e.label, e.rank)?;
        writeln!(o, "### lang     : {}", lang_for(&e.path, e.is_binary))?;
        writeln!(o, "### bytes    : {}", e.data.len())?;
        writeln!(o, "### lines    : {}", e.lines)?;
        writeln!(o, "### sha256   : {}", e.sha256)?;
        writeln!(
            o,
            "### encoding : {}",
            if e.is_binary { "base64" } else { "utf-8" }
        )?;
        if !e.is_binary {
            writeln!(
                o,
                "### eof-newline : {}",
                if e.eof_newline { "true" } else { "false" }
            )?;
        }
        if !e.note.is_empty() {
            writeln!(o, "### note     : {}", e.note)?;
        }
        writeln!(o, "{thin}")?;
        if e.is_binary {
            writeln!(o, "{BEGIN_B64} {}", e.path)?;
            let b64 = base64::engine::general_purpose::STANDARD.encode(&e.data);
            let bytes = b64.as_bytes();
            for chunk in bytes.chunks(76) {
                o.write_all(chunk)?;
                writeln!(o)?;
            }
            writeln!(o, "{END_B64} {}\n", e.path)?;
        } else {
            writeln!(o, "{BEGIN} {}", e.path)?;
            // `assert_no_sentinel_collision` already proved this decodes.
            o.write_all(&e.data)?;
            if !e.eof_newline {
                writeln!(o)?;
            }
            writeln!(o, "{END} {}\n", e.path)?;
        }
    }

    // ---- Footer -----------------------------------------------------------
    writeln!(o, "{rule}")?;
    writeln!(o, "END OF MONOLITH")?;
    writeln!(o, "  records     : {}", commas_int(entries.len() as u64))?;
    writeln!(
        o,
        "  total-bytes : {} ({})",
        commas_int(total_bytes),
        human(total_bytes)
    )?;
    writeln!(o, "  total-lines : {}", commas_int(total_lines))?;
    writeln!(o, "  tree-digest : sha256:{digest}")?;
    writeln!(o, "  commit      : {}", info.commit)?;
    writeln!(o, "{rule}")?;
    Ok(())
}
