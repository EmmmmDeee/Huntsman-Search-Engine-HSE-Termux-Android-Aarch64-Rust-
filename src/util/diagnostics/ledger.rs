//! Cross-scan ledger — persists rolling module statistics.

use std::collections::HashMap;
use std::path::PathBuf;

use super::types::ModulePerformance;

fn ledger_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".huntsman")
        .join("module_stats.json")
}

pub(super) fn persist_ledger(modules: &[ModulePerformance], kinds: &HashMap<String, usize>) {
    use super::types::{LedgerEntry, ModuleLedger};
    let path = ledger_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut ledger: ModuleLedger = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    ledger.total_scans = ledger.total_scans.saturating_add(1);
    ledger.last_updated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    for m in modules {
        let entry: &mut LedgerEntry = ledger.per_module.entry(m.name.clone()).or_default();
        entry.scans_present = entry.scans_present.saturating_add(1);
        entry.total_entities = entry
            .total_entities
            .saturating_add(m.entities_emitted as u64);
        // Deliberately NOT `if m.entities_emitted == 0 { zero_yield_scans += 1 }`
        // here: `modules` is always `ScanDiagnostics::modules_by_yield`, which is
        // built exclusively from emitted entities' evidence sources (see
        // `analyse()`) — a module only ever enters that list WITH `entities_emitted
        // >= 1`, immediately on insertion. A module that ran and found nothing is
        // absent from `modules`, never present with a zero, so that condition was
        // unreachable dead code (the exact PROBLEM_TREE T2.13/T2.14 pattern,
        // rediscovered here in the ledger). Zero-yield dispatches are tracked
        // separately by [`record_zero_yield_dispatches`], fed from the scan's own
        // `ModuleDone` events at the caller layer (`util` cannot reach event data
        // itself — no `StoragePort` access).
        entry.mean_entities_per_scan = entry.total_entities as f64 / entry.scans_present as f64;
        entry.zero_yield_rate = entry.zero_yield_scans as f64 / entry.scans_present as f64;
    }
    for (kind, n) in kinds {
        let counter = ledger.kind_distribution.entry(kind.clone()).or_default();
        *counter = counter.saturating_add(*n as u64);
    }

    if let Ok(s) = serde_json::to_string_pretty(&ledger) {
        // Atomic write (temp + fsync + rename), not a plain truncating write: an
        // OOM-kill mid-write — realistic on a low-RAM phone — would otherwise leave
        // a truncated module_stats.json, which the next read here (and the adaptive
        // scanner) discards via `unwrap_or_default()`, silently RESETTING the whole
        // accumulated self-optimization history. Atomic rename keeps the previous
        // valid ledger intact on a crash. Same durability the key pool / settings
        // use. Best-effort but never silent: a failure is logged, not dropped.
        if let Err(e) = crate::util::atomic_file::write(&path, s.as_bytes()) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to persist module-stats ledger — self-optimization history not updated this scan"
            );
        }
    }
}

/// Pure: bump `scans_present` + `zero_yield_scans` (and recompute the
/// derived rates) for every named module — no-op for a name not in
/// `zero_yield_modules`. Split out from the I/O wrapper below so the ledger
/// arithmetic is unit-testable without touching `$HOME`/the filesystem
/// (`std::env::set_var` is `unsafe` under Edition 2024's
/// `#![forbid(unsafe_code)]`, so a test cannot safely redirect
/// [`ledger_path`]'s `$HOME` lookup).
pub(super) fn apply_zero_yield_dispatches(
    ledger: &mut super::types::ModuleLedger,
    zero_yield_modules: &[String],
) {
    use super::types::LedgerEntry;
    for name in zero_yield_modules {
        let entry: &mut LedgerEntry = ledger.per_module.entry(name.clone()).or_default();
        entry.scans_present = entry.scans_present.saturating_add(1);
        entry.zero_yield_scans = entry.zero_yield_scans.saturating_add(1);
        entry.mean_entities_per_scan = entry.total_entities as f64 / entry.scans_present as f64;
        entry.zero_yield_rate = entry.zero_yield_scans as f64 / entry.scans_present as f64;
    }
}

/// Corrects the cross-scan ledger for modules that were dispatched this scan
/// but yielded nothing — invisible to [`persist_ledger`]'s entity-derived
/// `modules`, since a module only enters that list once it has emitted ≥1
/// entity (see the comment in `persist_ledger`'s loop above). Without this,
/// `LedgerEntry::zero_yield_rate` can never rise above 0.0 for any module,
/// which permanently empties `read_adaptive_routing`'s `recommended_skips` —
/// the `hse scan --adaptive` self-optimization flag silently never skips
/// anything, no matter how many scans accumulate (`PROBLEM_TREE`, discovery
/// pass). `zero_yield_modules` is the caller's already-deduped list from this
/// scan's own `ModuleDone` events (typically
/// [`crate::core::event::zero_yield_module_names`]) — `util` has no
/// `StoragePort` access to fetch events itself. A no-op for an empty slice
/// (skips the read/write round-trip entirely when nothing needs correcting).
pub fn record_zero_yield_dispatches(zero_yield_modules: &[String]) {
    if zero_yield_modules.is_empty() {
        return;
    }
    use super::types::ModuleLedger;
    let path = ledger_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut ledger: ModuleLedger = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    apply_zero_yield_dispatches(&mut ledger, zero_yield_modules);

    if let Ok(s) = serde_json::to_string_pretty(&ledger) {
        // Same atomic-write durability as `persist_ledger` above.
        if let Err(e) = crate::util::atomic_file::write(&path, s.as_bytes()) {
            tracing::warn!(
                error = %e,
                path = %path.display(),
                "failed to record zero-yield dispatches — adaptive-routing history not updated this scan"
            );
        }
    }
}
