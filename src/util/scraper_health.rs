//! Per-source scraper health signal (`PROBLEM_TREE` T2.7 / `SOLUTION_TREE`
//! SOL-HEALTH-SIGNAL): derives `last_success_at` and a `consecutive_failures`
//! streak per module from the `ModuleDone`/`ModuleError` event log the engine
//! already persists across every scan — no new tracking table, since the
//! signal HSE needs already exists in `events`, just never aggregated across
//! scan boundaries. Pure over an event slice, so it is unit-testable without
//! a live `Store`; the live substrate is
//! [`crate::storage::Store::recent_module_outcome_events`].
//!
//! Scope of this slice: hard-failure detection only (a module that raised a
//! `ModuleError`, e.g. a request/parse panic path). A module that runs to
//! completion but silently returns fewer/zero results because a page layout
//! drifted (`ModuleDone { found: 0, .. }` on a source that used to yield) is
//! a real, related failure mode the original T2.7 sketch also names
//! ("parse-rate"), but distinguishing genuine zero-result targets from
//! silent parser breakage needs a per-source historical yield baseline this
//! slice does not build — tracked as the next SOL-HEALTH-SIGNAL increment
//! rather than guessed at here.

use std::collections::HashMap;

use crate::core::event::{Event, EventKind};

/// A source is flagged **drifted** once its current unbroken failure streak
/// reaches this many trailing `ModuleError` events with no intervening
/// success. Three strikes distinguishes a real break (endpoint down, layout
/// changed) from an isolated transient network blip that shouldn't page the
/// operator on a single timeout.
pub const DRIFTED_THRESHOLD: u32 = 3;

/// How many recent `ModuleDone`/`ModuleError` rows a health check pulls from
/// [`crate::storage::Store::recent_module_outcome_events`]. At ~162
/// registered modules, a single scan produces well under 162 such events
/// (most are skipped/gated per target kind, not dispatched), so 5,000 covers
/// dozens of recent scans' worth of outcomes — enough for a meaningful
/// per-source streak — without a manual diagnostic command pulling
/// unbounded history into memory.
pub const RECENT_EVENTS_WINDOW: usize = 5_000;

/// One module's rolling health, derived from the tail of its recent outcome
/// events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealth {
    pub module: String,
    /// Unix seconds of the most recent `ModuleDone` seen in the queried
    /// window. `None` means every outcome in the window was an error — the
    /// source may have last succeeded before the window's horizon, or never.
    pub last_success_at: Option<u64>,
    /// Consecutive `ModuleError` events immediately preceding the newest
    /// event for this module — the current unbroken failure streak. Reset to
    /// 0 the moment a success is seen walking backward from "now".
    pub consecutive_failures: u32,
    /// The most recent error message, present whenever `consecutive_failures
    /// > 0`.
    pub last_error: Option<String>,
}

impl SourceHealth {
    #[must_use]
    pub fn is_drifted(&self) -> bool {
        self.consecutive_failures >= DRIFTED_THRESHOLD
    }
}

/// Per-module accumulator while walking events newest-first. Not
/// constructible outside this module — purely an aggregation scratchpad.
struct Acc {
    last_success_at: Option<u64>,
    consecutive_failures: u32,
    last_error: Option<String>,
    /// Set once this module's newest `ModuleDone` has been seen; every
    /// earlier (older) event for the module is then irrelevant to its
    /// *current* streak and is ignored.
    resolved: bool,
}

/// Aggregate per-module health from a **newest-first** slice of
/// `ModuleDone`/`ModuleError` events, as returned by
/// [`crate::storage::Store::recent_module_outcome_events`]. Any other event
/// kind is silently ignored, so callers may pass a mixed slice safely.
///
/// Deterministic: one pass over the input, one running streak per module (a
/// `HashMap` only for the intra-function scratch — iteration order never
/// reaches the output), then a lexicographic sort by module name before
/// returning. Two calls over the same event set always produce the same
/// `Vec` in the same order.
#[must_use]
pub fn aggregate_source_health(events_newest_first: &[Event]) -> Vec<SourceHealth> {
    let mut by_module: HashMap<&str, Acc> = HashMap::new();

    for ev in events_newest_first {
        let (module, is_success, error) = match &ev.kind {
            EventKind::ModuleDone { module, .. } => (module.as_str(), true, None),
            EventKind::ModuleError { module, error } => {
                (module.as_str(), false, Some(error.as_str()))
            }
            _ => continue,
        };
        let acc = by_module.entry(module).or_insert(Acc {
            last_success_at: None,
            consecutive_failures: 0,
            last_error: None,
            resolved: false,
        });
        if acc.resolved {
            continue; // already found this module's newest success; older
            // events can't change its *current* streak.
        }
        if is_success {
            acc.last_success_at = Some(ev.ts);
            acc.resolved = true;
        } else {
            acc.consecutive_failures += 1;
            if acc.last_error.is_none() {
                acc.last_error = error.map(str::to_string);
            }
        }
    }

    let mut out: Vec<SourceHealth> = by_module
        .into_iter()
        .map(|(module, acc)| SourceHealth {
            module: module.to_string(),
            last_success_at: acc.last_success_at,
            consecutive_failures: acc.consecutive_failures,
            last_error: acc.last_error,
        })
        .collect();
    out.sort_by(|a, b| a.module.cmp(&b.module));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn done(scan: &str, ts: u64, module: &str) -> Event {
        Event {
            scan_id: scan.to_string(),
            ts,
            kind: EventKind::ModuleDone {
                module: module.to_string(),
                found: 1,
            },
        }
    }

    fn err(scan: &str, ts: u64, module: &str, msg: &str) -> Event {
        Event {
            scan_id: scan.to_string(),
            ts,
            kind: EventKind::ModuleError {
                module: module.to_string(),
                error: msg.to_string(),
            },
        }
    }

    #[test]
    fn healthy_module_has_no_failures_and_a_success_timestamp() {
        // Newest-first: most recent event is a success.
        let events = vec![
            done("s2", 200, "shodan"),
            err("s1", 100, "shodan", "timeout"),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].module, "shodan");
        assert_eq!(health[0].last_success_at, Some(200));
        assert_eq!(health[0].consecutive_failures, 0);
        assert!(!health[0].is_drifted());
    }

    #[test]
    fn trailing_failures_count_until_the_last_success_and_stop_there() {
        // Chronological: success, fail, fail, fail (newest). Newest-first order:
        let events = vec![
            err("s4", 400, "au_property", "parse error"),
            err("s3", 300, "au_property", "parse error"),
            err("s2", 200, "au_property", "parse error"),
            done("s1", 100, "au_property"),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].consecutive_failures, 3);
        assert_eq!(health[0].last_success_at, Some(100));
        assert_eq!(health[0].last_error.as_deref(), Some("parse error"));
        assert!(
            health[0].is_drifted(),
            "3 strikes reaches DRIFTED_THRESHOLD"
        );
    }

    #[test]
    fn two_strikes_is_not_yet_drifted() {
        let events = vec![
            err("s2", 200, "au_electoral", "http 500"),
            err("s1", 100, "au_electoral", "http 500"),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(health[0].consecutive_failures, 2);
        assert!(!health[0].is_drifted());
    }

    #[test]
    fn never_succeeded_in_window_reports_no_last_success() {
        let events = vec![
            err("s2", 200, "dead_source", "404"),
            err("s1", 100, "dead_source", "404"),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(health[0].last_success_at, None);
        assert_eq!(health[0].consecutive_failures, 2);
    }

    #[test]
    fn multiple_modules_are_tracked_independently_and_sorted_by_name() {
        let events = vec![
            done("s2", 200, "zoomeye"),
            err("s2", 200, "shodan", "timeout"),
            done("s1", 100, "shodan"),
        ];
        let health = aggregate_source_health(&events);
        let names: Vec<&str> = health.iter().map(|h| h.module.as_str()).collect();
        assert_eq!(
            names,
            vec!["shodan", "zoomeye"],
            "sorted, not insertion order"
        );
        let shodan = health.iter().find(|h| h.module == "shodan").unwrap();
        assert_eq!(shodan.consecutive_failures, 1);
        assert_eq!(shodan.last_success_at, Some(100));
    }

    #[test]
    fn non_outcome_events_are_ignored() {
        let events = vec![Event::new(
            "s1",
            EventKind::ModuleStart {
                module: "shodan".to_string(),
            },
        )];
        assert!(aggregate_source_health(&events).is_empty());
    }

    #[test]
    fn empty_input_yields_empty_output() {
        assert!(aggregate_source_health(&[]).is_empty());
    }
}
