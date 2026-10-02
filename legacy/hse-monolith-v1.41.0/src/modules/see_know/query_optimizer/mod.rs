//! High-Value Query Optimization System — value/cost/ROI scoring for the
//! live SeekNow endpoint dispatch order.
//!
//! - `types` — [`types::EndpointRegistry`], the single source of truth for
//!   per-endpoint entity-diversity and pivot-potential metadata.
//! - `value_scorer` — score a query on entity diversity, hit rate, pivot
//!   potential, freshness, coverage.
//! - `cost_analyzer` — effective cost (credit + latency + cascade × cache ×
//!   budget_pressure).
//! - `roi_router` — value ÷ cost.
//!
//! These four are wired directly into the live scan path:
//! [`super::endpoints`]'s `order_by_roi` constructs a [`value_scorer::ValueScorer`],
//! [`cost_analyzer::CostAnalyzer`], and [`roi_router::RoiRouter`] to reorder each
//! target's SeekNow endpoint dispatch plan by ROI — highest first — with a
//! saturating boost from `data_log::yield_counts` (endpoints that have
//! historically produced data for this operator run earlier).
//!
//! An earlier revision of this module also carried a `QueryOptimizer` /
//! `QueryPlanner` facade (multi-phase `ExecutionPlan` generation, a standalone
//! `CascadeOptimizer`) intended as the integration point for the above four
//! engines. It was never wired into anything live — `order_by_roi` calls the
//! scoring engines directly instead, a simpler design that supersedes it — so
//! it was dead code (zero callers outside its own definition) and has been
//! removed. See `docs/HIGH_VALUE_QUERY_SYSTEM.md` for the scoring-dimension
//! reference; its "Architecture Integration" section describes that
//! superseded facade, not the current wiring.

pub mod cost_analyzer;
pub mod roi_router;
pub mod types;
pub mod value_scorer;
