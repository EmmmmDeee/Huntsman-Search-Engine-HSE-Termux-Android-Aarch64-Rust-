//! Per-source drift aggregation over persisted module outcome events.

use std::collections::{HashMap, HashSet};

use crate::event::{Event, EventKind};

pub const DRIFTED_THRESHOLD: u32 = 3;
pub const YIELD_DRIFT_THRESHOLD: u32 = 3;
pub const RECENT_EVENTS_WINDOW: usize = 5_000;
pub const DRIFT_RETRY_TTL_SECS: u64 = 24 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHealth {
    pub module: String,
    pub last_success_at: Option<u64>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
    pub ever_yielded: bool,
    pub consecutive_zero_yield: u32,
    pub newest_event_at: u64,
}

impl SourceHealth {
    #[must_use]
    pub const fn is_drifted(&self) -> bool {
        self.consecutive_failures >= DRIFTED_THRESHOLD
    }

    #[must_use]
    pub fn quarantine_expired(&self, now: u64) -> bool {
        now.saturating_sub(self.newest_event_at) >= DRIFT_RETRY_TTL_SECS
    }

    #[must_use]
    pub const fn is_yield_drifted(&self) -> bool {
        self.ever_yielded && self.consecutive_zero_yield >= YIELD_DRIFT_THRESHOLD
    }
}

struct Acc {
    last_success_at: Option<u64>,
    consecutive_failures: u32,
    last_error: Option<String>,
    resolved: bool,
    ever_yielded: bool,
    consecutive_zero_yield: u32,
    zero_yield_streak_open: bool,
    newest_event_at: u64,
}

#[must_use]
pub fn aggregate_source_health(events_newest_first: &[Event]) -> Vec<SourceHealth> {
    let mut by_module: HashMap<&str, Acc> = HashMap::new();
    for event in events_newest_first {
        let (module, success, error, found) = match &event.kind {
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
            newest_event_at: event.ts,
        });
        if let Some(found) = found {
            if found > 0 {
                acc.ever_yielded = true;
                acc.zero_yield_streak_open = false;
            } else if acc.zero_yield_streak_open {
                acc.consecutive_zero_yield = acc.consecutive_zero_yield.saturating_add(1);
            }
        }
        if acc.resolved {
            continue;
        }
        if success {
            acc.last_success_at = Some(event.ts);
            acc.resolved = true;
        } else {
            acc.consecutive_failures = acc.consecutive_failures.saturating_add(1);
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
            newest_event_at: acc.newest_event_at,
        })
        .collect();
    out.sort_by(|left, right| left.module.cmp(&right.module));
    out
}

#[must_use]
pub fn quarantined_modules_at(health: &[SourceHealth], now: u64) -> HashSet<String> {
    health
        .iter()
        .filter(|source| {
            (source.is_drifted() || source.is_yield_drifted()) && !source.quarantine_expired(now)
        })
        .map(|source| source.module.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventKind;

    fn done(scan: &str, ts: u64, module: &str, found: usize) -> Event {
        Event::new(
            scan,
            ts,
            EventKind::ModuleDone {
                module: module.to_string(),
                found,
            },
        )
    }

    fn err(scan: &str, ts: u64, module: &str, error: &str) -> Event {
        Event::new(
            scan,
            ts,
            EventKind::ModuleError {
                module: module.to_string(),
                error: error.to_string(),
            },
        )
    }

    #[test]
    fn aggregates_failure_streaks_until_latest_success() {
        let health = aggregate_source_health(&[
            err("scan-3", 300, "crtsh", "timeout"),
            err("scan-2", 200, "crtsh", "timeout"),
            done("scan-1", 100, "crtsh", 1),
        ]);
        assert_eq!(health.len(), 1);
        assert_eq!(health[0].consecutive_failures, 2);
        assert_eq!(health[0].last_success_at, Some(100));
        assert_eq!(health[0].last_error.as_deref(), Some("timeout"));
        assert!(!health[0].is_drifted());
    }

    #[test]
    fn zero_yield_drift_requires_prior_yield() {
        let health = aggregate_source_health(&[
            done("scan-4", 400, "wayback", 0),
            done("scan-3", 300, "wayback", 0),
            done("scan-2", 200, "wayback", 0),
            done("scan-1", 100, "wayback", 2),
        ]);
        assert!(health[0].ever_yielded);
        assert_eq!(health[0].consecutive_zero_yield, 3);
        assert!(health[0].is_yield_drifted());

        let cold = aggregate_source_health(&[
            done("scan-3", 300, "cold", 0),
            done("scan-2", 200, "cold", 0),
            done("scan-1", 100, "cold", 0),
        ]);
        assert!(!cold[0].ever_yielded);
        assert!(!cold[0].is_yield_drifted());
    }

    #[test]
    fn quarantine_ttl_allows_retry() {
        let health = SourceHealth {
            module: "netlas".to_string(),
            last_success_at: None,
            consecutive_failures: 5,
            last_error: Some("401 Unauthorized".to_string()),
            ever_yielded: false,
            consecutive_zero_yield: 0,
            newest_event_at: 1_000,
        };
        let active = quarantined_modules_at(std::slice::from_ref(&health), 1_100);
        assert!(active.contains("netlas"));
        let expired =
            quarantined_modules_at(std::slice::from_ref(&health), 1_000 + DRIFT_RETRY_TTL_SECS);
        assert!(!expired.contains("netlas"));
    }
}
