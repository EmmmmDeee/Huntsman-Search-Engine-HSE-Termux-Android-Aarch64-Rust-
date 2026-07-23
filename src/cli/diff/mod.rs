//! `hse diff` — compare two scans and report what each found that the other
//! didn't, what they share, and which common entities were re-scored.
//!
//! Each side is either a **scan id** in the store (or `latest`) or a path to a
//! **JSON entity snapshot** written by `hse export --format json`. The file
//! form enables time-series monitoring that a bare scan id cannot: every scan
//! gets a fresh unique id (timestamp + counter, never re-used), so re-scanning a
//! target creates a separate row — but snapshot the graph now, re-scan later,
//! then `hse diff snapshot.json latest` to see what changed. Scan-id↔scan-id diffs
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
///
/// Both branches must yield the SAME confirmed-footprint view: a snapshot
/// file was itself written by `hse export --format json`, which already
/// drops quarantined `candidate` rows (the breach co-occurrence "strangers" —
/// non-subject PII) via `confirmed_entities`. The scan-id branch strips the
/// identical tag here so the two sides stay comparable. Without this, a
/// `candidate` entity would leak as non-subject PII into the diff output, AND
/// (for the documented `hse export … ; hse diff snapshot.json latest`
/// workflow) every `candidate` entity on the live scan side would show up as
/// spuriously "added" on every re-scan even when nothing about the target
/// changed — corrupting the very "what changed" signal this command exists to
/// produce.
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
    let mut entities = store.entities_for_scan(&sid)?;
    entities.retain(|e| !e.has_tag(crate::core::tags::CANDIDATE));
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
             itself, so there are no changes.\n      For time-series monitoring, \
             snapshot first then diff the file to capture what changed between scans:\n        \
             hse export --scan-id {} --format json --out before.json\n        \
             # ... re-scan the target later ...\n        hse diff before.json latest",
            &ida[..ida.len().min(12)],
            ida,
        );
        return Err(Error::Other("both sides resolve to the same scan".into()));
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
    include!("tests.rs");
}
