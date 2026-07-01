//! Scan diagnostics — per-scan introspection that ranks module
//! performance, calibrates confidence per source, surfaces optimization
//! signals, and persists a cross-scan ledger for adaptive routing.
//!
//! The ledger ($HOME/.huntsman/module_stats.json) tracks rolling
//! averages of entities/sec, error rates, and yield-per-target for
//! every module. Future scans can read this to deprioritise
//! consistently weak modules (not yet wired — present as data only).

mod analyse;
pub mod cluster;
mod ledger;
#[cfg(test)]
mod tests;
pub mod types;

pub use analyse::{analyse, read_adaptive_routing, zero_yield_module_names};
pub use cluster::{country_coherence_weight, filter_country_coherent};
pub use ledger::persist_ledger;
pub use types::{
    AdaptiveRouting, ConfidenceStats, CoordinateCluster, EntityCluster, EntityOverlap,
    GeoPrecisionReport, LedgerEntry, LineageNode, ModuleHistoricalScore, ModuleLedger,
    ModulePerformance, ProximityEdge, ScanDiagnostics,
};
