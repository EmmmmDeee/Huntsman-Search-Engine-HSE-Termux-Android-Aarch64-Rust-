//! Event-sourced optimization hints — signals `analyse()` cannot compute
//! because it is pure over an entity set: a module that ran and found
//! nothing never appears in `modules_by_yield` (built exclusively from
//! emitted entities' evidence), so it is absent, not present-at-zero, and
//! `analyse()` has no `StoragePort` access to ask what was dispatched.
//!
//! `PROBLEM_TREE.md` T2.13 found and removed two now-unreachable hints that
//! tried to compute this inside `analyse()`. T2.14 reinstates both correctly,
//! at the CALLER layer (which already holds `StoragePort` and fetches this
//! scan's events for other purposes): a caller calls
//! [`append_event_sourced_hints`] after `analyse()`, passing the events it
//! already has, to enrich `ScanDiagnostics::optimization_hints` in place.

use std::collections::HashMap;

use crate::core::event::{Event, EventKind};
use crate::core::module::ModuleCost;

use super::types::ScanDiagnostics;

/// Distinct module names that were actually **dispatched** this scan — a
/// `ModuleDone` or `ModuleError` event (the module was attempted), NOT
/// `ModuleSkipped` (a gate excluded it before it ever ran: wrong target
/// kind, `--exclude`, circuit-open, needs-key). Sorted + deduped, so a
/// module counted once regardless of how many events it produced (a
/// `ModuleDone` can be followed by a later `ModuleError` on retry paths, or
/// vice versa). Pure and deterministic.
fn dispatched_module_names(events: &[Event]) -> Vec<String> {
    let mut names: Vec<String> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::ModuleDone { module, .. } | EventKind::ModuleError { module, .. } => {
                Some(module.clone())
            }
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Distinct module names with a `ModuleDone { found: 0, .. }` event this
/// scan — modules that ran to completion and yielded nothing. Sorted +
/// deduped. Pure and deterministic.
fn zero_yield_module_names(events: &[Event]) -> Vec<String> {
    let mut names: Vec<String> = events
        .iter()
        .filter_map(|ev| match &ev.kind {
            EventKind::ModuleDone { module, found: 0 } => Some(module.clone()),
            _ => None,
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Names of `KeyGated`/`Paid` modules that ran and finished with **zero**
/// entities this scan — the set the dossier's "ROI" hint warns about
/// spending a budgeted API call for nothing. The shared, single-sourced
/// version of what was previously a `cli`-only private helper: `api`-surfaced
/// diagnostics and the CLI JSON/dossier views must agree on this list, not
/// maintain independent copies that can drift.
#[must_use]
pub fn keyed_or_paid_zero_yield_modules(
    events: &[Event],
    cost_by_module: &HashMap<String, ModuleCost>,
) -> Vec<String> {
    zero_yield_module_names(events)
        .into_iter()
        .filter(|m| {
            matches!(
                cost_by_module.get(m.as_str()),
                Some(ModuleCost::KeyGated | ModuleCost::Paid)
            )
        })
        .collect()
}

/// Wall-time threshold (ms) above which a zero-yield keyed/paid module is
/// worth flagging as a scan-level time-and-budget cost, not just a per-module
/// ROI note. Matches the dead hint T2.13 removed ("scan exceeded 60s with a
/// zero-yield module").
const SLOW_SCAN_MS: u64 = 60_000;

/// Append the two event-sourced hints T2.13 removed as unreachable dead code,
/// now correctly computed from `events` (this scan's own `ModuleDone` /
/// `ModuleError` / `ModuleSkipped` record) rather than from `analyse()`'s
/// entity-only view:
///
/// 1. **Scan-level, cost-gated**: when the scan's wall time exceeded
///    [`SLOW_SCAN_MS`] AND at least one `KeyGated`/`Paid` module yielded
///    nothing, one hint names the count — an actionable "this run spent both
///    time and budget for no return" signal. Cost-gated (mirrors the
///    dossier's existing ROI hint) so the common case — a handful of free
///    modules legitimately finding nothing — never fires it.
/// 2. **Per-module, noise-bounded**: when ANY module (of any cost tier) was
///    zero-yield, exactly ONE summary line reports "N of M dispatched
///    modules found nothing for this target kind" — never one line per
///    module. A realistic scan dispatches dozens of modules that legitimately
///    find nothing for a given target kind; enumerating each would flood the
///    hints list, so this is a bounded count, the noise-safe design T2.14
///    settled on.
///
/// No-op when `events` yields no dispatched modules (nothing to report).
/// Idempotent to call twice with the same events (hints only ever append,
/// but calling this function itself twice would duplicate — callers invoke
/// it exactly once per `analyse()` result, as the doc example shows).
pub fn append_event_sourced_hints(
    diag: &mut ScanDiagnostics,
    events: &[Event],
    cost_by_module: &HashMap<String, ModuleCost>,
) {
    let dispatched = dispatched_module_names(events);
    if dispatched.is_empty() {
        return;
    }
    let zero_yield = zero_yield_module_names(events);
    if zero_yield.is_empty() {
        return;
    }

    let wasted_keyed_or_paid = keyed_or_paid_zero_yield_modules(events, cost_by_module).len();
    if diag.wall_time_ms > SLOW_SCAN_MS && wasted_keyed_or_paid > 0 {
        diag.optimization_hints.push(format!(
            "scan took {:.1}s with {wasted_keyed_or_paid} keyed/paid module(s) yielding \
             nothing — excluding them would speed up future scans of this seed shape",
            diag.wall_time_ms as f64 / 1000.0
        ));
    }

    diag.optimization_hints.push(format!(
        "{} of {} dispatched modules found nothing for this target kind",
        zero_yield.len(),
        dispatched.len()
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(module: &str, found: usize) -> Event {
        Event {
            scan_id: "s".into(),
            ts: 0,
            kind: EventKind::ModuleDone {
                module: module.into(),
                found,
            },
        }
    }

    fn errored(module: &str) -> Event {
        Event {
            scan_id: "s".into(),
            ts: 0,
            kind: EventKind::ModuleError {
                module: module.into(),
                error: "boom".into(),
            },
        }
    }

    fn skipped(module: &str) -> Event {
        Event {
            scan_id: "s".into(),
            ts: 0,
            kind: EventKind::ModuleSkipped {
                module: module.into(),
                reason: "excluded".into(),
            },
        }
    }

    fn costs(pairs: &[(&str, ModuleCost)]) -> HashMap<String, ModuleCost> {
        pairs.iter().map(|(n, c)| ((*n).to_string(), *c)).collect()
    }

    fn diag(wall_time_ms: u64) -> ScanDiagnostics {
        ScanDiagnostics {
            scan_id: "s".into(),
            wall_time_ms,
            ..Default::default()
        }
    }

    #[test]
    fn dispatched_counts_done_and_error_not_skipped() {
        let events = vec![
            done("a", 3),
            errored("b"),
            skipped("c"),
            done("a", 0), // same module twice -> deduped
        ];
        assert_eq!(dispatched_module_names(&events), vec!["a", "b"]);
    }

    #[test]
    fn zero_yield_names_only_found_zero() {
        let events = vec![done("a", 0), done("b", 5), errored("c")];
        assert_eq!(zero_yield_module_names(&events), vec!["a"]);
    }

    #[test]
    fn keyed_or_paid_zero_yield_excludes_free() {
        let events = vec![done("free_mod", 0), done("key_mod", 0), done("paid_mod", 0)];
        let cost_by_module = costs(&[
            ("free_mod", ModuleCost::Free),
            ("key_mod", ModuleCost::KeyGated),
            ("paid_mod", ModuleCost::Paid),
        ]);
        let mut wasted = keyed_or_paid_zero_yield_modules(&events, &cost_by_module);
        wasted.sort();
        assert_eq!(wasted, vec!["key_mod", "paid_mod"]);
    }

    #[test]
    fn no_hints_when_nothing_dispatched() {
        let mut d = diag(120_000);
        append_event_sourced_hints(&mut d, &[], &HashMap::new());
        assert!(d.optimization_hints.is_empty());
    }

    #[test]
    fn no_hints_when_nothing_zero_yield() {
        let events = vec![done("a", 3), done("b", 7)];
        let mut d = diag(120_000);
        append_event_sourced_hints(&mut d, &events, &HashMap::new());
        assert!(
            d.optimization_hints.is_empty(),
            "every dispatched module found something — nothing to flag"
        );
    }

    #[test]
    fn slow_scan_hint_fires_only_when_over_threshold_and_cost_gated() {
        // Under the 60s threshold: the scan-level hint must NOT fire even
        // though a keyed module wasted budget — only the bounded summary does.
        let events = vec![done("key_mod", 0), done("free_mod", 3)];
        let cost_by_module = costs(&[
            ("key_mod", ModuleCost::KeyGated),
            ("free_mod", ModuleCost::Free),
        ]);
        let mut fast = diag(59_999);
        append_event_sourced_hints(&mut fast, &events, &cost_by_module);
        assert_eq!(fast.optimization_hints.len(), 1, "only the bounded summary");
        assert!(!fast.optimization_hints[0].contains("keyed/paid"));

        // Over the threshold WITH a keyed/paid zero-yield module: both hints fire.
        let mut slow = diag(90_000);
        append_event_sourced_hints(&mut slow, &events, &cost_by_module);
        assert_eq!(slow.optimization_hints.len(), 2);
        assert!(slow.optimization_hints[0].contains("90.0s"));
        assert!(slow.optimization_hints[0].contains("1 keyed/paid"));
        assert!(slow.optimization_hints[1].contains("1 of 2 dispatched"));
    }

    #[test]
    fn slow_scan_hint_does_not_fire_for_free_only_zero_yield() {
        // Over the threshold, but the ONLY zero-yield module is free: cost gate
        // must suppress the scan-level hint (free modules finding nothing is
        // expected, not a budget signal) — only the bounded summary fires.
        let events = vec![done("free_mod", 0), done("other", 4)];
        let cost_by_module = costs(&[("free_mod", ModuleCost::Free), ("other", ModuleCost::Free)]);
        let mut d = diag(90_000);
        append_event_sourced_hints(&mut d, &events, &cost_by_module);
        assert_eq!(
            d.optimization_hints.len(),
            1,
            "cost gate must suppress the scan-level hint"
        );
        assert!(d.optimization_hints[0].contains("1 of 2 dispatched"));
    }

    #[test]
    fn per_module_summary_is_one_bounded_line_regardless_of_zero_yield_count() {
        // Ten zero-yield modules must still produce exactly ONE summary line,
        // never one line per module (the noise T2.14 explicitly guards against).
        let mut events: Vec<Event> = (0..10).map(|i| done(&format!("m{i}"), 0)).collect();
        events.push(done("found_one", 2));
        let mut d = diag(1_000);
        append_event_sourced_hints(&mut d, &events, &HashMap::new());
        assert_eq!(d.optimization_hints.len(), 1);
        assert!(d.optimization_hints[0].contains("10 of 11 dispatched"));
    }

    #[test]
    fn appends_without_clobbering_existing_hints() {
        let events = vec![done("a", 0)];
        let mut d = diag(1_000);
        d.optimization_hints.push("pre-existing hint".into());
        append_event_sourced_hints(&mut d, &events, &HashMap::new());
        assert_eq!(d.optimization_hints.len(), 2);
        assert_eq!(d.optimization_hints[0], "pre-existing hint");
    }
}
