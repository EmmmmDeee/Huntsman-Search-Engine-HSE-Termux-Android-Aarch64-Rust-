//! `hse diff` — compare two scans and report what each found that the other
//! didn't, what they share, and which common entities were re-scored.
//!
//! Each side is either a **scan id** in the store (or `latest`) or a path to a
//! **JSON entity snapshot** written by `hse export --format json`. The file
//! form enables time-series monitoring that a bare scan id cannot: a scan id is
//! the deterministic `SHA-256(kind:value)`, so re-scanning a target overwrites
//! its row — but snapshot the graph now, re-scan later, then
//! `hse diff snapshot.json latest` to see what changed. Scan-id↔scan-id diffs
//! serve link analysis (shared infrastructure / identity surface between two
//! targets).

use crate::core::diff::{ScanDiff, diff_entities};
use crate::core::entity::Entity;
use crate::core::error::{Error, Result};
use crate::default_db_path;
use crate::storage::Store;

/// Resolve a scan id, accepting `latest` (most-recent completed scan) and
/// erroring on an unknown id so a typo can't silently diff against nothing.
fn resolve(store: &Store, raw: &str) -> Result<String> {
    if raw == "latest" {
        return store
            .latest_completed_scan()?
            .map(|s| s.id)
            .ok_or_else(|| Error::Other("no completed scans in store".into()));
    }
    if store.get_scan(raw)?.is_none() {
        return Err(Error::Other(format!("scan {raw} not found")));
    }
    Ok(raw.to_string())
}

/// Load one side of the diff: a JSON entity snapshot if `arg` is a file on
/// disk, otherwise the entities of a resolved scan id.
fn load_side(store: &Store, arg: &str) -> Result<Vec<Entity>> {
    if std::path::Path::new(arg).is_file() {
        let body =
            std::fs::read_to_string(arg).map_err(|e| Error::Other(format!("read {arg}: {e}")))?;
        return serde_json::from_str(&body)
            .map_err(|e| Error::Other(format!("{arg} is not a JSON entity snapshot: {e}")));
    }
    let sid = resolve(store, arg)?;
    store.entities_for_scan(&sid)
}

pub(super) fn cmd_diff(from: String, to: String, format: String) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let baseline = load_side(&store, &from)?;
    let later = load_side(&store, &to)?;
    let d = diff_entities(&baseline, &later);

    match format.to_lowercase().as_str() {
        "json" => {
            let body = serde_json::to_string_pretty(&d)
                .map_err(|e| Error::Other(format!("json serialise: {e}")))?;
            println!("{body}");
        }
        "text" => print_text(&from, &to, &d),
        other => {
            return Err(Error::Other(format!(
                "unknown --format '{other}'. Valid: text, json"
            )));
        }
    }
    Ok(())
}

/// Short, greppable label for a diff side (scan ids are 64-char SHA-256 hex).
fn label(s: &str) -> String {
    if s.chars().count() > 16 {
        format!("{}…", s.chars().take(16).collect::<String>())
    } else {
        s.to_string()
    }
}

fn print_text(from: &str, to: &str, d: &ScanDiff) {
    println!("Scan diff  {}  →  {}", label(from), label(to));
    println!("  {}", d.summary());
    if !d.added.is_empty() {
        println!("\n+ Added ({}):", d.added.len());
        for e in &d.added {
            println!(
                "  + {:<12} {}  (C_eff {:.2})",
                e.kind, e.value, e.c_effective
            );
        }
    }
    if !d.removed.is_empty() {
        println!("\n- Removed ({}):", d.removed.len());
        for e in &d.removed {
            println!(
                "  - {:<12} {}  (C_eff {:.2})",
                e.kind, e.value, e.c_effective
            );
        }
    }
    if !d.confidence_shifts.is_empty() {
        println!("\n~ Re-scored ({}):", d.confidence_shifts.len());
        for s in &d.confidence_shifts {
            println!(
                "  ~ {:<12} {}  ({:.2} → {:.2})",
                s.kind, s.value, s.before, s.after
            );
        }
    }
    if d.is_empty() {
        println!("\n  (no entity changes)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::EntityKind;

    #[test]
    fn label_truncates_long_ids_keeps_short_args() {
        assert_eq!(label("0123456789abcdef0123"), "0123456789abcdef…");
        assert_eq!(label("snapshot.json"), "snapshot.json");
        assert_eq!(label(""), "");
    }

    #[test]
    fn resolve_errors_on_unknown_scan() {
        let store = Store::open(":memory:").unwrap();
        let err = resolve(&store, "deadbeef").unwrap_err();
        assert!(
            err.to_string().contains("deadbeef"),
            "error should name the missing scan: {err}"
        );
    }

    #[test]
    fn resolve_latest_errors_when_store_empty() {
        let store = Store::open(":memory:").unwrap();
        assert!(resolve(&store, "latest").is_err());
    }

    #[test]
    fn load_side_reads_json_entity_snapshot_file() {
        let store = Store::open(":memory:").unwrap();
        let ents = vec![Entity::new(EntityKind::Email, "a@b.com", 0.8, "s")];
        let json = serde_json::to_string(&ents).unwrap();
        let path = std::env::temp_dir().join(format!(
            "hse-diff-snap-{}-{}.json",
            std::process::id(),
            "load"
        ));
        std::fs::write(&path, json).unwrap();
        let loaded = load_side(&store, path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].value, "a@b.com");
        let _ = std::fs::remove_file(&path);
    }
}
