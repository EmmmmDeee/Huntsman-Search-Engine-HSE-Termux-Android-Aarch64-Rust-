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
/// Per-file size cap: the single-file import limit itself, not a copy of it.
///
/// This was a second `16 * 1024 * 1024` literal whose doc comment asserted it
/// "mirrors `MAX_IMPORT_BYTES` so both paths enforce the same bound" — a claim
/// nothing checked. `MAX_IMPORT_BYTES` is `pub(crate)` precisely so callers share
/// it (`cli::ingest` already does), and it is in scope here through `use super::*`,
/// so the two can now only move together.
const MAX_FILE_BYTES: u64 = MAX_IMPORT_BYTES;

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

/// Enumerate candidate importable files under `root`, bounded by depth/count/size.
///
/// Deterministic in BOTH senses, which the count bound makes two separate claims: the returned
/// order is fixed (final sort by path), and — because each directory's entries are sorted before
/// the traversal acts on them — the SUBSET selected when the `MAX_FILES` budget is exhausted is
/// fixed too. Sorting only at the end would leave the latter decided by `read_dir` order. No
/// network, no mutation.
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
        // Collect this directory's entries and sort before acting on them.
        //
        // The closing `out.sort()` fixes the ORDER of whatever was collected, but it cannot fix
        // WHICH files were collected: the `out.len() >= MAX_FILES` check above abandons a whole
        // directory once the budget is hit, so on a tree with more than `MAX_FILES` eligible files
        // the chosen subset was decided by `read_dir` order plus DFS stack order. Sorting here
        // makes the traversal itself order-independent, so the same tree yields the same subset —
        // which is what this function's contract already claimed.
        let mut dirs: Vec<std::path::PathBuf> = Vec::new();
        let mut files: Vec<std::path::PathBuf> = Vec::new();
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if !is_skippable_dir(name) {
                    dirs.push(path);
                }
            } else if file_type.is_file()
                && !is_skippable_file(name)
                && let Ok(meta) = entry.metadata()
                && meta.len() > 0
                && meta.len() <= MAX_FILE_BYTES
            {
                files.push(path);
            }
        }
        files.sort();
        out.extend(files);
        // The stack is LIFO, so push in reverse to pop in ascending path order.
        dirs.sort();
        for d in dirs.into_iter().rev() {
            stack.push((d, depth + 1));
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
/// Scrape a tree into one aggregated entity set, plus the RF sightings any
/// wardriving capture in it carried.
///
/// The sightings ride alongside rather than inside the entity vector because
/// they are a different grain: the entities are deduplicated to one node per
/// device, while a sighting per observation is exactly what must NOT be
/// collapsed — the repeats are the movement track.
pub(super) async fn import_local_dir_entities(
    root: &std::path::Path,
    sid: &str,
) -> (Vec<Entity>, usize, usize, Vec<crate::core::rf::RfSighting>) {
    let files = collect_importable_files(root);
    let scanned = files.len();
    let mut all: Vec<Entity> = Vec::new();
    let mut sightings: Vec<crate::core::rf::RfSighting> = Vec::new();
    let mut imported = 0usize;
    for path in files {
        let Ok(body) = tokio::fs::read_to_string(&path).await else {
            continue; // binary / non-UTF-8 — skip
        };
        if let Ok((ents, label)) = entities_from_upload(&body, sid).await
            && !ents.is_empty()
        {
            imported += 1;
            all.extend(ents);
            // Keyed off the label the shared dispatcher already resolved, so
            // this cannot disagree with which parser actually ran.
            if label == "kml" {
                sightings.extend(super::kml::rf_sightings(&body));
            }
        }
    }
    // Fold entities that recur across files — the same email in a dossier and a
    // scan export — merging their evidence rather than dropping, exactly as the
    // single-file path finalises. Preserves cross-account reuse signals (AU-047).
    deduplicate_by_uid(&mut all);
    (all, scanned, imported, sightings)
}

/// CLI entry: scrape a local directory tree into one persisted scan, then report.
/// Reached from [`super::cmd_import`] when its path is a directory rather than a
/// file, so `hse import <dir>` ingests the whole installation's on-device data.
pub(super) async fn cmd_import_local_dir(root: &str, output: &str) -> Result<()> {
    note(output, format!("Scraping local storage under {root} ..."));
    let sid = format!("import-local-{}", crate::core::entity::unix_now());
    let (entities, scanned, imported, sightings) =
        import_local_dir_entities(std::path::Path::new(root), &sid).await;
    note(
        output,
        format!(
            "  {imported}/{scanned} file(s) yielded {} aggregated entities",
            entities.len()
        ),
    );
    persist_and_report(&sid, &entities, output).await;
    super::persist_rf_sightings_best_effort(&sid, &sightings, output).await;
    render_import_entities(&entities, output);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `collect_importable_files` bounds the walk at `MAX_FILES`, abandoning a whole directory once
    /// the budget is hit. That makes WHICH files survive a traversal-order decision, not just an
    /// ordering one — and the closing `out.sort()` cannot recover a file that was never collected.
    ///
    /// Builds a tree wider than the budget across several sibling directories, so the cut lands
    /// mid-traversal, and asserts the selected SET is exactly the lexicographic prefix. Under the
    /// old code the set was whatever `read_dir` happened to yield first.
    #[test]
    fn the_file_budget_selects_a_deterministic_subset_not_a_traversal_order_one() {
        let root = tempfile::tempdir().expect("tempdir");
        // 30 directories x 100 files = 3000 eligible files, comfortably over MAX_FILES (2000).
        for d in 0..30 {
            let dir = root.path().join(format!("d{d:02}"));
            std::fs::create_dir(&dir).expect("mkdir");
            for f in 0..100 {
                std::fs::write(dir.join(format!("f{f:03}.txt")), b"x").expect("write");
            }
        }

        let got = collect_importable_files(root.path());
        assert_eq!(got.len(), MAX_FILES, "the budget is still enforced");

        // The expected set: every eligible path, sorted, truncated to the budget. This is the only
        // subset that does not depend on the order the filesystem enumerated directories in.
        let mut all: Vec<std::path::PathBuf> = Vec::new();
        for d in 0..30 {
            for f in 0..100 {
                all.push(
                    root.path()
                        .join(format!("d{d:02}"))
                        .join(format!("f{f:03}.txt")),
                );
            }
        }
        all.sort();
        all.truncate(MAX_FILES);
        assert_eq!(got, all, "the budget must cut the lexicographic prefix");

        // Corroboration from a second angle: repeated walks of one tree agree.
        assert_eq!(
            collect_importable_files(root.path()),
            got,
            "the same tree must yield the same subset on every walk"
        );
    }
}
