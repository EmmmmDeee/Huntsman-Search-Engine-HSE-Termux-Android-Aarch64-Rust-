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

/// One loaded diff side: its entities, plus the resolved scan id when the side
/// was a store scan (`None` when it was a JSON snapshot file). The id lets
/// `cmd_diff` detect the "diff a scan against itself" footgun.
struct Side {
    entities: Vec<Entity>,
    scan_id: Option<String>,
}

/// Load one side of the diff: a JSON entity snapshot if `arg` is a file on
/// disk, otherwise the entities of a resolved scan id.
fn load_side(store: &Store, arg: &str) -> Result<Side> {
    if std::path::Path::new(arg).is_file() {
        let body =
            std::fs::read_to_string(arg).map_err(|e| Error::Other(format!("read {arg}: {e}")))?;
        let entities = serde_json::from_str(&body)
            .map_err(|e| Error::Other(format!("{arg} is not a JSON entity snapshot: {e}")))?;
        return Ok(Side {
            entities,
            scan_id: None,
        });
    }
    let sid = super::resolve_scan_id(store, arg)?;
    let entities = store.entities_for_scan(&sid)?;
    Ok(Side {
        entities,
        scan_id: Some(sid),
    })
}

pub(super) fn cmd_diff(from: String, to: String, format: String) -> Result<()> {
    let store = Store::open(&default_db_path())?;
    let a = load_side(&store, &from)?;
    let b = load_side(&store, &to)?;

    // Footgun guard: diffing a scan against itself (the same target resolved on
    // both sides — common when an operator expects "what changed since I last
    // scanned" but scan ids are the deterministic SHA-256(kind:value), so a
    // re-scan overwrites rather than creating a second row). The diff is
    // trivially empty; point them at the snapshot-file workflow that actually
    // captures change over time. Only when neither side was a snapshot file.
    if let (Some(ida), Some(idb)) = (a.scan_id.as_deref(), b.scan_id.as_deref())
        && ida == idb
    {
        eprintln!(
            "note: both sides resolve to the same scan ({}…) — diffing it against \
             itself, so there are no changes.\n      Scan ids are deterministic \
             (SHA-256 of kind+value), so re-scanning a target overwrites its row \
             rather than making a second one.\n      For time-series monitoring, \
             snapshot first then diff the file:\n        hse export --scan-id {} \
             --format json --out before.json\n        # ... re-scan the target \
             later ...\n        hse diff before.json {}",
            &ida[..ida.len().min(12)],
            ida,
            ida,
        );
    }

    let d = diff_entities(&a.entities, &b.entities);

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
        let err = crate::cli::resolve_scan_id(&store, "deadbeef").unwrap_err();
        assert!(
            err.to_string().contains("deadbeef"),
            "error should name the missing scan: {err}"
        );
    }

    #[test]
    fn resolve_latest_errors_when_store_empty() {
        let store = Store::open(":memory:").unwrap();
        assert!(crate::cli::resolve_scan_id(&store, "latest").is_err());
    }

    #[test]
    fn load_side_tags_store_scans_with_their_id_for_self_diff_guard() {
        // A store-scan side carries its resolved id; two sides resolving to the
        // same id is what `cmd_diff` detects as a self-diff. Seed a scan and
        // confirm both the id is set and it round-trips equal for the same arg.
        use crate::core::scan::{Scan, Target, TargetKind};
        let store = Store::open(":memory:").unwrap();
        let scan = Scan::new("scan-x", Target::new(TargetKind::Domain, "example.com"));
        store.upsert_scan(&scan).unwrap();
        store
            .upsert_entity(&Entity::new(
                EntityKind::Domain,
                "example.com",
                0.9,
                "scan-x",
            ))
            .unwrap();

        let a = load_side(&store, "scan-x").unwrap();
        let b = load_side(&store, "scan-x").unwrap();
        assert_eq!(a.scan_id.as_deref(), Some("scan-x"));
        assert_eq!(a.scan_id, b.scan_id, "same arg → same id → self-diff");
        assert_eq!(a.entities.len(), 1);
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
        assert_eq!(loaded.entities.len(), 1);
        assert_eq!(loaded.entities[0].value, "a@b.com");
        // A snapshot-file side carries no scan id (so it's never flagged as a
        // same-scan self-diff).
        assert!(loaded.scan_id.is_none());
        let _ = std::fs::remove_file(&path);
    }
}
