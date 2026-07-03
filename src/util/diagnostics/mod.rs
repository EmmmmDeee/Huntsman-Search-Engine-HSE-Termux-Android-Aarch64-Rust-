//! Scan diagnostics — per-scan introspection that ranks module
//! performance, calibrates confidence per source, surfaces optimization
//! signals, and persists a cross-scan ledger for adaptive routing.
//!
//! The ledger ($HOME/.huntsman/module_stats.json) tracks rolling averages of
//! entities/scan and zero-yield rate per module; `hse scan --adaptive` reads
//! it (`read_adaptive_routing`) to skip modules historically zero-yield ≥80%
//! of the time over ≥5 scans. [`analyse()`] persists the entity-derived half of
//! every entry (a pure `util` fn, so it only ever sees modules that emitted
//! ≥1 entity); [`record_zero_yield_dispatches`] persists the other half — a
//! module dispatched but zero-yield this scan — sourced from the caller's own
//! `ModuleDone` events (`util` has no `StoragePort` access to fetch them
//! itself), typically via [`crate::core::event::zero_yield_module_names`].

mod analyse;
pub mod cluster;
pub(super) mod ledger;
#[cfg(test)]
mod tests;
pub mod types;

pub use analyse::{NO_OPTIMIZATION_SIGNALS_HINT, analyse, read_adaptive_routing};
pub use cluster::{country_coherence_weight, filter_country_coherent};
pub use ledger::record_zero_yield_dispatches;
pub use types::{
    AdaptiveRouting, ConfidenceStats, CoordinateCluster, EntityCluster, EntityOverlap,
    GeoPrecisionReport, LedgerEntry, LineageNode, ModuleHistoricalScore, ModuleLedger,
    ModulePerformance, ProximityEdge, ScanDiagnostics,
};
