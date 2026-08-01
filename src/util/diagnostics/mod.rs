//! Scan diagnostics — per-scan introspection that ranks module
//! performance, calibrates confidence per source, surfaces optimization
//! signals, and persists a cross-scan ledger for adaptive routing.
//!
//! The ledger ($HOME/.huntsman/module_stats.json) tracks rolling
//! averages of entities/sec, error rates, and yield-per-target for
//! every module. [`read_adaptive_routing`] reads it to deprioritise
//! consistently weak modules — wired via `hse scan --adaptive`
//! (`src/cli/scan/mod.rs`), which extends `exclude_modules` with the
//! ledger's `recommended_skips` before dispatch.

mod analyse;
pub mod cluster;
pub mod event_hints;
pub(super) mod ledger;
#[cfg(test)]
mod tests;
pub mod types;

pub use analyse::{analyse, read_adaptive_routing};
pub use cluster::{country_coherence_weight, filter_country_coherent};
pub use event_hints::{append_event_sourced_hints, keyed_or_paid_zero_yield_modules};
pub use types::{
    AdaptiveRouting, ConfidenceStats, CoordinateCluster, EntityCluster, EntityOverlap,
    GeoPrecisionReport, LedgerEntry, LineageNode, ModuleHistoricalScore, ModuleLedger,
    ModulePerformance, ProximityEdge, ScanDiagnostics,
};
