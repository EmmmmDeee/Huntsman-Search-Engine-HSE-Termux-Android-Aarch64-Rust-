//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod attack;
pub mod benchmark;
pub mod breach_consensus;
pub mod breach_platforms;
pub mod breach_sweep;
pub mod cancel;
pub mod claim;
pub mod classifier;
pub mod classify_module;
pub mod community;
pub mod confidence;
pub mod convex;
pub mod coref;
pub mod correlator;
pub mod cross_scan;
pub mod crypto;
pub mod data_broker;
pub mod dependency;
pub mod diamond;
pub mod diff;
pub mod engine;
pub mod engine_host;
/// Re-export of the `hse-core` crate under its original module path so all
/// existing `crate::core::entity::*` call sites keep resolving unchanged.
/// Extracted to a standalone, minimal-deps crate (see hse-core/Cargo.toml)
/// so it can be shared, unmodified, with a wasm32-unknown-unknown browser
/// build of the web UI — the concrete motivation being the confidence-tier
/// math (`Entity::c_effective`/`source_count`), whose JS reimplementation in
/// `src/web/js/helpers.js` had already drifted out of sync with the real
/// grounding logic once (see `ENRICHMENT_SOURCES`/`is_non_corroborating_source`
/// history). A WASM build calling these methods directly closes that class of
/// bug permanently instead of just re-guarding against it.
pub use hse_core as entity;
pub mod error;
pub mod event;
pub mod exposure;
pub mod gap;
pub mod geo_confidence;
pub mod geo_family;
pub mod gexf;
pub mod graph;
pub mod intelligence;
pub mod leads;
pub mod live;
pub mod metrics;
pub mod module;
pub mod module_runtime;
pub mod network;
pub mod path;
pub mod pivot;
pub mod platform;
pub mod port;
pub mod profiles;
pub mod radar_live;
pub mod radar_track;
pub mod relation;
pub mod resolve;
pub mod rf;
pub mod roi;
pub mod scan;
pub mod scan_analysis;
pub mod snake_graph;
pub mod stealer_row;
/// Re-export of `hse-core`'s `tags` module (moved alongside `core::entity` —
/// see that re-export's comment above) so `crate::core::tags::*` call sites
/// keep resolving unchanged.
pub use hse_core::tags;
#[cfg(test)]
pub mod test_support;
pub mod timeline;
pub mod trust;
pub mod validation;
pub mod webhook;
pub mod xml;

pub use cancel::CancelHandle;
pub use correlator::{Correlation, Correlator, Severity};
pub use dependency::{ModuleGraph, ModuleGraphSummary};
pub use engine::ScanEngine;
pub use engine_host::{EngineHost, NoopEngineHost};
pub use entity::{Classification, Entity, EntityKind, Evidence, scan_id, unix_now};
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use live::{LiveOptions, LiveRequest, LiveScanner, LiveSession, LiveStatus};
pub use module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleInfo, ModuleResult};
pub use module_runtime::ModuleRuntime;
pub use port::StoragePort;
pub use relation::{Relation, RelationKind};
pub use scan::{ExpansionStrategy, Scan, ScanOptions, ScanRequest, ScanStatus, Target, TargetKind};
