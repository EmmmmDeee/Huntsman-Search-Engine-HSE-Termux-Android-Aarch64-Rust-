//! Per-source scraper health signal (`PROBLEM_TREE` T2.7 / `SOLUTION_TREE`
//! SOL-HEALTH-SIGNAL): derives `last_success_at` and a `consecutive_failures`
//! streak per module from the `ModuleDone`/`ModuleError` event log the engine
//! already persists across every scan — no new tracking table, since the
//! signal HSE needs already exists in `events`, just never aggregated across
//! scan boundaries. Pure over an event slice, so it is unit-testable without
//! a live `Store`; the live substrate is
//! [`crate::storage::Store::recent_module_outcome_events`].
//!
//! Two independent failure signals, both derived from the same event window:
//!
//! 1. **Hard failure** — a module that raised a `ModuleError` (a request/parse
//!    panic path). Flagged via [`SourceHealth::is_drifted`] /
//!    [`DRIFTED_THRESHOLD`].
//! 2. **Silent zero-yield ("parse-rate") drift** — a module that runs to
//!    *completion* but returns zero results, when it has previously yielded
//!    at least once in the window. The naive version of this check (any
//!    `found: 0`) would misfire on a source whose target genuinely has
//!    nothing to find — most modules are correctly silent on most seeds. The
//!    distinguishing signal is exactly the one the health-streak leg already
//!    validated for hard failures: not "did this happen once" but "did it
//!    happen unbroken over several trailing runs, for a source proven
//!    capable of yielding by its own history." Flagged via
//!    [`SourceHealth::is_yield_drifted`] / [`YIELD_DRIFT_THRESHOLD`] — same
//!    shape, same threshold rationale, deliberately not a fancier statistical
//!    baseline (average/median historical yield): that would require picking
//!    an arbitrary drop-percentage no real incident has yet justified, so a
//!    *partial* yield degradation (fewer, not zero, results) is left for a
//!    future increment if evidence of that failure mode appears.

use std::collections::HashMap;

use crate::core::event::{Event, EventKind};

/// A source is flagged **drifted** once its current unbroken failure streak
/// reaches this many trailing `ModuleError` events with no intervening
/// success. Three strikes distinguishes a real break (endpoint down, layout
/// changed) from an isolated transient network blip that shouldn't page the
/// operator on a single timeout.
pub const DRIFTED_THRESHOLD: u32 = 3;

/// A source is flagged **yield-drifted** once it has completed this many
/// trailing runs in a row with zero results, PROVIDED it has yielded at
/// least once somewhere in the window — a source that has never yielded is
/// not evidence of drift, just a target with nothing to find. Same
/// three-strikes rationale as [`DRIFTED_THRESHOLD`]: a single zero-result run
/// is unremarkable (many real seeds legitimately have nothing for a given
/// source), three in a row from a source proven capable of finding something
/// is a real signal a layout change silently broke extraction.
pub const YIELD_DRIFT_THRESHOLD: u32 = 3;

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
    /// True if at least one `ModuleDone` anywhere in the queried window
    /// yielded `found > 0` — the "this source is capable of finding
    /// something" evidence [`is_yield_drifted`](Self::is_yield_drifted)
    /// requires before zero-yield runs count as drift rather than a
    /// genuinely empty target.
    pub ever_yielded: bool,
    /// Consecutive `ModuleDone { found: 0, .. }` completions immediately
    /// preceding the newest `ModuleDone` for this module — `ModuleError`
    /// events are skipped (not counted, not resetting) since that failure
    /// mode is already covered by `consecutive_failures`. Reset the moment a
    /// non-zero-yield `ModuleDone` is seen walking backward from "now".
    pub consecutive_zero_yield: u32,
}

impl SourceHealth {
    #[must_use]
    pub fn is_drifted(&self) -> bool {
        self.consecutive_failures >= DRIFTED_THRESHOLD
    }

    /// True when this source has proven it can yield results (`ever_yielded`)
    /// but its last [`YIELD_DRIFT_THRESHOLD`]+ completions all silently
    /// returned zero — the "parse-rate" drift T2.7 named alongside hard
    /// failures: a module that runs to completion without erroring, but a
    /// page-layout change quietly broke its extraction.
    #[must_use]
    pub fn is_yield_drifted(&self) -> bool {
        self.ever_yielded && self.consecutive_zero_yield >= YIELD_DRIFT_THRESHOLD
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
    ever_yielded: bool,
    consecutive_zero_yield: u32,
    /// True until the first (newest-first) non-zero-yield `ModuleDone` is
    /// seen, at which point the zero-yield streak is finalised — scans the
    /// FULL window independently of `resolved` (which only gates the
    /// hard-failure streak above).
    zero_yield_streak_open: bool,
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
        let (module, is_success, error, found) = match &ev.kind {
            EventKind::ModuleDone { module, found } => (module.as_str(), true, None, Some(*found)),
            EventKind::ModuleError { module, error } => {
                (module.as_str(), false, Some(error.as_str()), None)
            }
            _ => continue,
        };
        let acc = by_module.entry(module).or_insert(Acc {
            last_success_at: None,
            consecutive_failures: 0,
            last_error: None,
            resolved: false,
            ever_yielded: false,
            consecutive_zero_yield: 0,
            zero_yield_streak_open: true,
        });

        // Yield-drift tracking scans the FULL window regardless of the
        // hard-failure streak's early resolution below.
        if let Some(found) = found {
            if found > 0 {
                acc.ever_yielded = true;
                acc.zero_yield_streak_open = false;
            } else if acc.zero_yield_streak_open {
                acc.consecutive_zero_yield += 1;
            }
        }

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
            ever_yielded: acc.ever_yielded,
            consecutive_zero_yield: acc.consecutive_zero_yield,
        })
        .collect();
    out.sort_by(|a, b| a.module.cmp(&b.module));
    out
}

/// The set of module names whose parser has **provably gone dead** — either
/// hard-drifted ([`SourceHealth::is_drifted`]: ≥[`DRIFTED_THRESHOLD`] trailing
/// errors) or yield-drifted ([`SourceHealth::is_yield_drifted`]: a proven-
/// capable source silently returning zero for ≥[`YIELD_DRIFT_THRESHOLD`] runs).
///
/// This is the signal **capability-aware dispatch** acts on: a scan skips these
/// modules so their dispatch slot goes to a source that still works — the
/// budget the scan needs to find more (the cross-scan, persisted counterpart of
/// the in-scan [`crate::core::engine`] circuit breaker). Pure over a health
/// slice, so it is unit-testable without a DB and shares one definition of
/// "dead" between the engine and any diagnostics that report the quarantine.
///
/// **Self-recovering by construction:** both drift predicates reset on the first
/// success walking back from "now", so once a quarantined module emits a single
/// healthy `ModuleDone` it drops out of this set on the very next scan — no
/// timer, no manual reset. Until then it stays skipped, which is the point.
#[must_use]
pub fn quarantined_modules(health: &[SourceHealth]) -> std::collections::HashSet<String> {
    health
        .iter()
        .filter(|h| h.is_drifted() || h.is_yield_drifted())
        .map(|h| h.module.clone())
        .collect()
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

    /// Like `done`, but with an explicit `found` count — for the yield-drift
    /// tests, which need to control zero-vs-nonzero yields precisely.
    fn done_found(scan: &str, ts: u64, module: &str, found: usize) -> Event {
        Event {
            scan_id: scan.to_string(),
            ts,
            kind: EventKind::ModuleDone {
                module: module.to_string(),
                found,
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
<<<<<<< HEAD
        let shodan = health.iter().find(|h| h.module == "shodan").expect("should succeed");
=======
        let shodan = health
            .iter()
            .find(|h| h.module == "shodan")
            .expect("should succeed");
>>>>>>> origin/main
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

    // ── Yield-drift ("parse-rate") tests ─────────────────────────────────

    #[test]
    fn a_source_that_has_never_yielded_is_not_yield_drifted() {
        // Every run is a genuine, legitimate zero — nothing distinguishes
        // this from a target that simply has nothing for this source.
        let events = vec![
            done_found("s3", 300, "au_property", 0),
            done_found("s2", 200, "au_property", 0),
            done_found("s1", 100, "au_property", 0),
        ];
        let health = aggregate_source_health(&events);
        assert!(!health[0].ever_yielded);
        assert_eq!(health[0].consecutive_zero_yield, 3);
        assert!(
            !health[0].is_yield_drifted(),
            "no prior yield anywhere in the window ⇒ not evidence of drift"
        );
    }

    #[test]
    fn a_source_proven_capable_that_goes_silent_is_yield_drifted() {
        // Newest-first: three trailing zero-yield runs, but an older run in
        // the same window DID find something — this source is proven
        // capable, so the silent zeros are real signal.
        let events = vec![
            done_found("s4", 400, "search_engines", 0),
            done_found("s3", 300, "search_engines", 0),
            done_found("s2", 200, "search_engines", 0),
            done_found("s1", 100, "search_engines", 12),
        ];
        let health = aggregate_source_health(&events);
        assert!(health[0].ever_yielded);
        assert_eq!(health[0].consecutive_zero_yield, 3);
        assert!(
            health[0].is_yield_drifted(),
            "3 trailing zero-yield runs from a source proven capable of finding results"
        );
    }

    #[test]
    fn two_trailing_zero_yields_is_not_yet_yield_drifted() {
        let events = vec![
            done_found("s3", 300, "search_engines", 0),
            done_found("s2", 200, "search_engines", 0),
            done_found("s1", 100, "search_engines", 5),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(health[0].consecutive_zero_yield, 2);
        assert!(!health[0].is_yield_drifted());
    }

    #[test]
    fn a_recent_nonzero_yield_closes_the_zero_streak_even_with_older_zeros() {
        // The module recovered: its newest run found results, even though
        // older runs in the window were zero. The trailing streak (counted
        // from "now" backward) must be 0, not inflated by older history.
        let events = vec![
            done_found("s4", 400, "search_engines", 7),
            done_found("s3", 300, "search_engines", 0),
            done_found("s2", 200, "search_engines", 0),
            done_found("s1", 100, "search_engines", 0),
        ];
        let health = aggregate_source_health(&events);
        assert!(health[0].ever_yielded);
        assert_eq!(
            health[0].consecutive_zero_yield, 0,
            "the newest run yielded, so the trailing streak is closed at 0"
        );
        assert!(!health[0].is_yield_drifted());
    }

    #[test]
    fn module_errors_are_skipped_not_counted_for_the_yield_streak() {
        // A ModuleError in between two zero-yield completions neither
        // extends nor breaks the zero-yield streak — that failure mode is
        // already covered by consecutive_failures.
        let events = vec![
            err("s4", 400, "search_engines", "timeout"),
            done_found("s3", 300, "search_engines", 0),
            done_found("s2", 200, "search_engines", 0),
            done_found("s1", 100, "search_engines", 9),
        ];
        let health = aggregate_source_health(&events);
        assert_eq!(
            health[0].consecutive_zero_yield, 2,
            "the interspersed error is skipped, not counted"
        );
        assert!(health[0].ever_yielded);
        assert!(!health[0].is_yield_drifted(), "only 2 trailing zero-yields");
    }

    #[test]
    fn quarantined_modules_collects_hard_and_yield_drift_only() {
        // hard-drifted (3 errors), yield-drifted (yield then 3 zeros), healthy,
        // and not-yet-drifted (2 errors) — only the two drifted ones quarantine.
        let events = vec![
            // hard_dead: 3 trailing errors → is_drifted
            err("s3", 330, "hard_dead", "500"),
            err("s2", 320, "hard_dead", "500"),
            err("s1", 310, "hard_dead", "500"),
            // parse_broken: 3 trailing zero-yields after a real yield → is_yield_drifted
            done_found("s4", 240, "parse_broken", 0),
            done_found("s3", 230, "parse_broken", 0),
            done_found("s2", 220, "parse_broken", 0),
            done_found("s1", 210, "parse_broken", 7),
            // healthy: newest is a success
            done("s1", 110, "healthy"),
            // borderline: only 2 errors → not drifted
            err("s2", 120, "borderline", "500"),
            err("s1", 115, "borderline", "500"),
        ];
        let q = quarantined_modules(&aggregate_source_health(&events));
        assert!(q.contains("hard_dead"), "hard-drift must quarantine");
        assert!(q.contains("parse_broken"), "yield-drift must quarantine");
        assert!(
            !q.contains("healthy"),
            "a healthy source is never quarantined"
        );
        assert!(
            !q.contains("borderline"),
            "2 failures is below the drift threshold"
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn quarantined_modules_is_empty_for_a_fresh_event_log() {
        // The invariant capability-aware dispatch relies on for zero behaviour
        // change on a fresh DB: no events → nothing quarantined.
        assert!(quarantined_modules(&aggregate_source_health(&[])).is_empty());
    }
}
