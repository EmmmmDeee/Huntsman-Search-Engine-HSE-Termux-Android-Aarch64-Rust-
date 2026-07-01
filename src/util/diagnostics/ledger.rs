//! Cross-scan ledger — persists rolling module statistics.

use std::collections::BTreeMap;
use std::path::PathBuf;

use super::types::ModulePerformance;

fn ledger_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home)
        .join(".huntsman")
        .join("module_stats.json")
}

/// Pure ledger mutation — no I/O, so it's directly unit-testable. Bumps
/// `scans_present` for every module in `modules` (yield-bearing, from
/// `ScanDiagnostics::modules_by_yield`) **and** every name in
/// `zero_yield_modules` — modules that ran and finished this scan but
/// emitted zero entities, so they are structurally absent from `modules`
/// (built only from emitted entities' evidence; see
/// `analyse::zero_yield_module_names`). Before this split, a module's
/// `zero_yield_scans`/`zero_yield_rate` could never be observed: the ledger
/// only ever saw the scans a module SUCCEEDED in, so a module that failed
/// every single scan would show a perfect `zero_yield_rate: 0.0` (no data,
/// not "never fails") — silently disabling
/// `AdaptiveRouting::recommended_skips` (`zero_yield_rate ≥ 0.80`), the same
/// unreachable-premise class `PROBLEM_TREE` T2.13/T2.14 already found and
/// fixed in the ROI/60s hints (`PROBLEM_TREE` T2.15).
fn update_ledger(
    ledger: &mut super::types::ModuleLedger,
    modules: &[ModulePerformance],
    zero_yield_modules: &[String],
    kinds: &BTreeMap<String, usize>,
) {
    use super::types::LedgerEntry;

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
        entry.mean_entities_per_scan = entry.total_entities as f64 / entry.scans_present as f64;
        entry.zero_yield_rate = entry.zero_yield_scans as f64 / entry.scans_present as f64;
    }
    for name in zero_yield_modules {
        let entry: &mut LedgerEntry = ledger.per_module.entry(name.clone()).or_default();
        entry.scans_present = entry.scans_present.saturating_add(1);
        entry.zero_yield_scans = entry.zero_yield_scans.saturating_add(1);
        entry.mean_entities_per_scan = entry.total_entities as f64 / entry.scans_present as f64;
        entry.zero_yield_rate = entry.zero_yield_scans as f64 / entry.scans_present as f64;
    }
    for (kind, n) in kinds {
        let counter = ledger.kind_distribution.entry(kind.clone()).or_default();
        *counter = counter.saturating_add(*n as u64);
    }
}

/// Persist one scan's module stats to the cross-scan ledger
/// (`$HOME/.huntsman/module_stats.json`). Callers pass `modules` and `kinds`
/// straight from a computed `ScanDiagnostics` (`modules_by_yield` /
/// `entity_kind_counts`); `zero_yield_modules` — modules that ran and
/// finished this scan but are absent from `modules_by_yield` — comes from
/// [`super::zero_yield_module_names`]. Deliberately NOT called from
/// `analyse()` itself any more (unlike before `PROBLEM_TREE` T2.15):
/// `analyse` is a pure function with no `StoragePort` access to read the
/// scan's own events, and folding this unconditional file write into it
/// made every one of its 13 unit tests silently mutate the real on-disk
/// ledger too.
pub fn persist_ledger(
    modules: &[ModulePerformance],
    zero_yield_modules: &[String],
    kinds: &BTreeMap<String, usize>,
) {
    use super::types::ModuleLedger;
    let path = ledger_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut ledger: ModuleLedger = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    update_ledger(&mut ledger, modules, zero_yield_modules, kinds);

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

#[cfg(test)]
mod tests {
    use super::super::types::ModuleLedger;
    use super::ModulePerformance;
    use super::update_ledger;
    use std::collections::BTreeMap;

    /// The core of the fix: before `update_ledger` took a separate
    /// `zero_yield_modules` list, a module absent from `modules` (every
    /// zero-yield module, by construction — see `analyse::
    /// zero_yield_module_names`) never got a ledger entry AT ALL, so it could
    /// never accumulate a `zero_yield_scans` count. This proves it now does.
    #[test]
    fn zero_yield_module_is_tracked_even_though_absent_from_modules_by_yield() {
        let mut ledger = ModuleLedger::default();
        update_ledger(&mut ledger, &[], &["shodan".to_string()], &BTreeMap::new());

        let entry = ledger.per_module.get("shodan").expect("entry must exist");
        assert_eq!(entry.scans_present, 1);
        assert_eq!(entry.zero_yield_scans, 1);
        assert_eq!(entry.total_entities, 0);
        assert!((entry.zero_yield_rate - 1.0).abs() < f64::EPSILON);
        assert!((entry.mean_entities_per_scan - 0.0).abs() < f64::EPSILON);
    }

    /// A yield-bearing module and a zero-yield module in the SAME scan must
    /// be tracked independently — neither list interferes with the other.
    #[test]
    fn yield_bearing_and_zero_yield_modules_are_independent() {
        let mut ledger = ModuleLedger::default();
        let bing = ModulePerformance {
            name: "bing".to_string(),
            entities_emitted: 5,
            ..Default::default()
        };
        update_ledger(
            &mut ledger,
            &[bing],
            &["shodan".to_string()],
            &BTreeMap::new(),
        );

        let bing_entry = ledger.per_module.get("bing").expect("bing must exist");
        assert_eq!(bing_entry.scans_present, 1);
        assert_eq!(bing_entry.zero_yield_scans, 0);
        assert_eq!(bing_entry.total_entities, 5);

        let shodan_entry = ledger.per_module.get("shodan").expect("shodan must exist");
        assert_eq!(shodan_entry.scans_present, 1);
        assert_eq!(shodan_entry.zero_yield_scans, 1);
        assert_eq!(shodan_entry.total_entities, 0);
    }

    /// A module that fails EVERY scan must accumulate a `zero_yield_rate` of
    /// 1.0 over repeated scans — the exact signal
    /// `AdaptiveRouting::recommended_skips` (`≥ 0.80` over `≥ 5` scans) reads.
    /// Before this fix, `zero_yield_rate` could structurally never be
    /// anything but its `Default` (0.0) for such a module, since it never
    /// received a ledger entry to compute a rate against.
    #[test]
    fn consistently_zero_yield_module_reaches_full_zero_yield_rate() {
        let mut ledger = ModuleLedger::default();
        for _ in 0..5 {
            update_ledger(
                &mut ledger,
                &[],
                &["dead_module".to_string()],
                &BTreeMap::new(),
            );
        }
        let entry = ledger.per_module.get("dead_module").unwrap();
        assert_eq!(entry.scans_present, 5);
        assert_eq!(entry.zero_yield_scans, 5);
        assert!((entry.zero_yield_rate - 1.0).abs() < f64::EPSILON);
    }

    /// Kind distribution accumulation is untouched by the split.
    #[test]
    fn kind_distribution_still_accumulates() {
        let mut ledger = ModuleLedger::default();
        let mut kinds = BTreeMap::new();
        kinds.insert("email".to_string(), 3usize);
        update_ledger(&mut ledger, &[], &[], &kinds);
        update_ledger(&mut ledger, &[], &[], &kinds);
        assert_eq!(ledger.kind_distribution.get("email"), Some(&6));
        assert_eq!(ledger.total_scans, 2);
    }
}
