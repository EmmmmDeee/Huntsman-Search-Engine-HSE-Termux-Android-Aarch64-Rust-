//! Operational telemetry — process-lifetime event counters for the running
//! `hse` process, incremented at the single event-emit chokepoint.
//!
//! # The observability split
//! This is the **operational** half of the observability surface. It is
//! deliberately distinct from the other two views, which answer different
//! questions:
//!
//! * [`crate::core::metrics`] — the **developer-diagnostic** half: a *per-scan*,
//!   pure, read-only quality synthesis ("how good was *this* scan?").
//! * `GET /api/v1/stats` — the **historical** view: a persisted, DB-backed
//!   aggregate over *all scans ever* ("what has this platform produced?").
//! * This module — the **operational** view: cross-scan, real-time counters for
//!   *this process since it started* ("what is this process doing right now,
//!   without touching the database?"). It is the signal an operator watches on a
//!   long-lived `serve` / `live` / `radar` process.
//!
//! # Cost & discipline
//! Each emitted event costs exactly one relaxed atomic increment — no
//! allocation, no lock, no I/O — so wiring it into the hot emit path is free.
//! Counters are monotonic for the process lifetime and never reset (a restart is
//! the reset); a snapshot delta over a wall-clock interval is therefore a rate.
//! `Relaxed` ordering is sufficient: the counters are independent, and a
//! snapshot is only ever read as an eventually-consistent operational gauge —
//! never used to order other memory.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::core::event::EventKind;

/// Process-lifetime operational counters. One global instance lives behind
/// [`global`]; the type is also constructible standalone (`const fn` [`new`])
/// so its recording logic is unit-tested in isolation from the process global.
///
/// [`new`]: Telemetry::new
#[derive(Debug)]
pub struct Telemetry {
    events_emitted: AtomicU64,
    scans_started: AtomicU64,
    scans_completed: AtomicU64,
    entities_found: AtomicU64,
    modules_completed: AtomicU64,
    module_errors: AtomicU64,
    correlations_found: AtomicU64,
}

impl Telemetry {
    pub const fn new() -> Self {
        Self {
            events_emitted: AtomicU64::new(0),
            scans_started: AtomicU64::new(0),
            scans_completed: AtomicU64::new(0),
            entities_found: AtomicU64::new(0),
            modules_completed: AtomicU64::new(0),
            module_errors: AtomicU64::new(0),
            correlations_found: AtomicU64::new(0),
        }
    }

    /// Fold one emitted event into the counters. Called once per event at the
    /// emit chokepoint. Every event increments `events_emitted`; specific
    /// counters increment on their matching kind. Unmatched kinds (the arm's
    /// `_`) are counted only in `events_emitted`, so the taxonomy can grow new
    /// variants without silently miscounting here.
    #[inline]
    pub fn record(&self, kind: &EventKind) {
        self.events_emitted.fetch_add(1, Ordering::Relaxed);
        let counter = match kind {
            EventKind::ScanStart { .. } => &self.scans_started,
            EventKind::ScanComplete { .. } => &self.scans_completed,
            EventKind::EntityFound { .. } => &self.entities_found,
            EventKind::ModuleDone { .. } => &self.modules_completed,
            EventKind::ModuleError { .. } => &self.module_errors,
            EventKind::CorrelationFound { .. } => &self.correlations_found,
            _ => return,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Consistent-enough point-in-time read of every counter. Loads are
    /// independent (not a single atomic transaction) — acceptable for an
    /// operational gauge, where a one-event skew across fields never matters.
    pub fn snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            events_emitted: self.events_emitted.load(Ordering::Relaxed),
            scans_started: self.scans_started.load(Ordering::Relaxed),
            scans_completed: self.scans_completed.load(Ordering::Relaxed),
            entities_found: self.entities_found.load(Ordering::Relaxed),
            modules_completed: self.modules_completed.load(Ordering::Relaxed),
            module_errors: self.module_errors.load(Ordering::Relaxed),
            correlations_found: self.correlations_found.load(Ordering::Relaxed),
        }
    }
}

impl Default for Telemetry {
    fn default() -> Self {
        Self::new()
    }
}

/// A serialisable point-in-time read of [`Telemetry`], for the API surface.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetrySnapshot {
    /// Total events emitted (every event kind).
    pub events_emitted: u64,
    pub scans_started: u64,
    pub scans_completed: u64,
    /// `EntityFound` events — an entity *emission*, not a distinct entity (the
    /// same UID can be emitted by several modules; dedup happens downstream).
    pub entities_found: u64,
    pub modules_completed: u64,
    pub module_errors: u64,
    pub correlations_found: u64,
}

/// The process-global operational telemetry, incremented at the emit chokepoint.
static GLOBAL: Telemetry = Telemetry::new();

/// The process-global [`Telemetry`]. The engine records into it; the API reads
/// its [`snapshot`](Telemetry::snapshot).
pub fn global() -> &'static Telemetry {
    &GLOBAL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::entity::{Entity, EntityKind};

    fn evt_scan_start() -> EventKind {
        EventKind::ScanStart {
            target_kind: "email".into(),
            target_value: "a@b.com".into(),
        }
    }

    #[test]
    fn record_folds_each_kind_into_the_right_counter() {
        // A fresh local instance — NOT the process global — so the assertions
        // are deterministic and cannot race parallel tests emitting events.
        let t = Telemetry::new();

        t.record(&evt_scan_start());
        t.record(&EventKind::EntityFound {
            entity: Entity::new(EntityKind::Email, "a@b.com", 0.5, "s"),
        });
        t.record(&EventKind::EntityFound {
            entity: Entity::new(EntityKind::Domain, "b.com", 0.5, "s"),
        });
        t.record(&EventKind::ModuleDone {
            module: "hibp".into(),
            found: 3,
        });
        t.record(&EventKind::ModuleError {
            module: "shodan".into(),
            error: "timeout".into(),
        });
        t.record(&EventKind::ScanComplete {
            scan_id: "s".into(),
            entity_count: 2,
        });
        // A kind with no dedicated counter still counts toward events_emitted.
        t.record(&EventKind::ModuleStart {
            module: "crtsh".into(),
        });

        let s = t.snapshot();
        assert_eq!(s.events_emitted, 7, "every record increments events_emitted");
        assert_eq!(s.scans_started, 1);
        assert_eq!(s.scans_completed, 1);
        assert_eq!(s.entities_found, 2);
        assert_eq!(s.modules_completed, 1);
        assert_eq!(s.module_errors, 1);
        assert_eq!(s.correlations_found, 0);
    }

    #[test]
    fn fresh_telemetry_is_all_zero() {
        assert_eq!(Telemetry::new().snapshot(), TelemetrySnapshot::default());
    }

    #[test]
    fn snapshot_reflects_monotonic_increments() {
        let t = Telemetry::new();
        let before = t.snapshot();
        t.record(&evt_scan_start());
        let after = t.snapshot();
        assert_eq!(after.scans_started, before.scans_started + 1);
        assert_eq!(after.events_emitted, before.events_emitted + 1);
    }
}
