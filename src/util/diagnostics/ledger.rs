//! Cross-scan ledger — persists rolling module statistics.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};

use super::types::ModulePerformance;

/// Serializes the ledger's read-modify-write across concurrent scan
/// completions. `persist_ledger` reads the whole ledger, accumulates this
/// scan's deltas, and writes it back; two `serve` scans finishing at once
/// would otherwise interleave read/read/write/write and lose one scan's
/// accumulation (a lost-update race). `atomic_file::write` gives crash
/// durability — it does NOT serialize concurrent accumulators, which is what
/// this guard adds. Held across the entire read+accumulate+write below.
static LEDGER_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn ledger_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".huntsman")
        .join("module_stats.json")
}

pub(super) fn persist_ledger(modules: &[ModulePerformance], kinds: &HashMap<String, usize>) {
    use super::types::{LedgerEntry, ModuleLedger};
    // Hold the lock for the whole read-modify-write so overlapping scan
    // completions apply their deltas sequentially. Recover from a poisoned lock
    // (a prior panic while holding it): the guarded data is just `()`, so the
    // in-progress ledger state is unaffected and continuing is safe.
    let _guard = LEDGER_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if m.entities_emitted == 0 {
            entry.zero_yield_scans = entry.zero_yield_scans.saturating_add(1);
        }
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
