//! Scored self-audit of a scan's output.
//!
//! Distils a scan — from a CSV export, the live SQLite store, or a debug-log /
//! scan-event stream — into a **quality scorecard**: noise ratio, infrastructure
//! pollution, false-positive flags, truncated/fragment values, missed-PII
//! signals, and source health, each with concrete examples and an actionable
//! recommendation. It is the manifesto's "the platform should constantly evaluate
//! itself, identify weaknesses, expose blind spots … and generate actionable
//! recommendations" as a first-class, reusable capability.
//!
//! The analysis is **pure** (no IO) and reuses the *same* authoritative
//! classifiers the engine uses to make its filtering decisions
//! ([`crate::core::scan::is_noncentral_domain`],
//! [`crate::core::validation::is_cdn_edge_ip`],
//! [`crate::util::domains::is_infrastructure_email`]), so the audit flags exactly
//! the categories the engine is supposed to suppress — turning it into a living
//! regression guard. Lives at the crate root (not under `core`) so it may use
//! both `core` and `util` without violating the core→util boundary.

mod analysis;
mod events;
mod types;

#[cfg(test)]
mod tests;

pub use analysis::audit;
pub use events::fold_events;
pub use types::{AuditEntity, AuditReport, Finding, GeoSummary, LogSignals, Severity};
