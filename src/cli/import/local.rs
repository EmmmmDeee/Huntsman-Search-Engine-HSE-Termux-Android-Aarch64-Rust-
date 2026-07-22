//! Local-storage scrape: import an entire on-device directory tree — the HSE
//! installation's own scan exports, dossiers, stealer/victim logs, breach
//! compilations and debug bundles — into one correlated scan. Every artifact is
//! parsed by the exact same content-based dispatcher the single-file `hse import`
//! and the web upload use, so the three can never drift. Fully offline: it reads
//! local files only and performs no network I/O of its own, so it works on a
//! Termux install with no connectivity. Shared helpers live in `super`.

use super::*;
use crate::core::entity::Entity;

/// Maximum directory depth a scrape descends — bounds a pathological or symlink
/// tree so it can't wander unboundedly.
const MAX_DIR_DEPTH: usize = 8;
/// Maximum number of candidate files a single scrape will import — a backstop so
/// pointing at a huge tree can't exhaust memory.
const MAX_FILES: usize = 2000;
/// Per-file size cap, mirroring the single-file import limit (`MAX_IMPORT_BYTES`)
/// so both paths enforce the same bound.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// True for files that never carry importable OSINT text — build artifacts,
/// media, archives and binary stores — so a scrape skips them without reading.
/// `read_to_string` also rejects any non-UTF-8 file, so this is an optimisation
/// that avoids slurping large binaries, not the only guard.
fn is_skippable_file(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if matches!(lower.as_str(), "cargo.lock" | "cargo.toml") {
        return true;
    }
    matches!(
        lower.rsplit('.').next().unwrap_or(""),
        "rs" | "so"
            | "rlib"
            | "rmeta"
            | "o"
            | "a"
            | "bin"
            | "exe"
            | "dll"
            | "dylib"
            | "png"
            | "jpg"
            | "jpeg"
            | "gif"
            | "webp"
            | "ico"
            | "pdf"
            | "mp3"
            | "mp4"
            | "wav"
            | "zip"
            | "gz"
            | "xz"
            | "zst"
            | "bz2"
            | "tar"
            | "7z"
            | "wasm"
            | "class"
            | "jar"
            | "sqlite"
            | "db"
            | "wal"
            | "shm"
            | "ttf"
            | "woff"
            | "woff2"
    )
}

/// True for directory names never worth descending into during a scrape: hidden
/// directories (`.git`, `.cargo`, …) and heavy build/dependency trees. The
/// build/dependency names are matched case-insensitively (mirroring
/// [`is_skippable_file`]) so a mixed-case `Target/` or `NODE_MODULES/` — which a
/// case-insensitive Android/exFAT storage volume can surface — is skipped too.
fn is_skippable_dir(name: &str) -> bool {
    name.starts_with('.')
        || matches!(
            name.to_ascii_lowercase().as_str(),
            "target" | "node_modules"
        )
}

/// Enumerate candidate importable files under `root`, bounded by depth/count/size
/// and returned in a fully deterministic order (final sort by path) — so a scrape
/// of the same tree always visits the same files in the same order. Determinism
/// by construction; no network, no mutation.
pub(super) fn collect_importable_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out: Vec<std::path::PathBuf> = Vec::new();
    let mut stack: Vec<(std::path::PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DIR_DEPTH || out.len() >= MAX_FILES {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if !is_skippable_dir(name) {
                    stack.push((path, depth + 1));
                }
            } else if file_type.is_file()
                && !is_skippable_file(name)
                && let Ok(meta) = entry.metadata()
                && meta.len() > 0
                && meta.len() <= MAX_FILE_BYTES
            {
                out.push(path);
            }
        }
    }
    out.sort();
    out.truncate(MAX_FILES);
    out
}

/// Walk `root`, import every recognised artifact through the shared upload
/// dispatcher, and return the aggregated, cross-file-deduplicated entities plus
/// `(files_scanned, files_imported)`. This is the pure core — NO persistence and
/// no network of its own — so it is unit-testable against a temp tree. A file
/// that is unreadable (binary / non-UTF-8), unrecognised, or empty contributes
/// nothing and is not counted as imported.
pub(super) async fn import_local_dir_entities(
    root: &std::path::Path,
    sid: &str,
) -> (Vec<Entity>, usize, usize) {
    let files = collect_importable_files(root);
    let scanned = files.len();
    let mut all: Vec<Entity> = Vec::new();
    let mut imported = 0usize;
    for path in files {
        let Ok(body) = std::fs::read_to_string(&path) else {
            continue; // binary / non-UTF-8 — skip
        };
        if let Ok((ents, _label)) = entities_from_upload(&body, sid).await
            && !ents.is_empty()
        {
            imported += 1;
            all.extend(ents);
        }
    }
    // Fold entities that recur across files — the same email in a dossier and a
    // scan export — merging their evidence rather than dropping, exactly as the
    // single-file path finalises. Preserves cross-account reuse signals (AU-047).
    deduplicate_by_uid(&mut all);
    (all, scanned, imported)
}

/// CLI entry: scrape a local directory tree into one persisted scan, then report.
/// Reached from [`super::cmd_import`] when its path is a directory rather than a
/// file, so `hse import <dir>` ingests the whole installation's on-device data.
pub(super) async fn cmd_import_local_dir(root: &str, output: &str) -> Result<()> {
    note(output, format!("Scraping local storage under {root} ..."));
    let sid = format!("import-local-{}", crate::core::entity::unix_now());
    let (entities, scanned, imported) =
        import_local_dir_entities(std::path::Path::new(root), &sid).await;
    note(
        output,
        format!(
            "  {imported}/{scanned} file(s) yielded {} aggregated entities",
            entities.len()
        ),
    );
    persist_and_report(&sid, &entities, output).await;
    render_import_entities(&entities, output);
    Ok(())
}
