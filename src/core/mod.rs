//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod attack;
pub mod benchmark;
pub mod breach_consensus;
pub mod breach_sweep;
pub mod cancel;
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
pub mod entity;
pub mod error;
pub mod event;
pub mod exposure;
pub mod gap;
pub mod geo_family;
pub mod gexf;
pub mod graph;
pub mod leads;
pub mod live;
pub mod metrics;
pub mod module;
pub mod module_runtime;
pub mod network;
pub mod path;
pub mod pivot;
pub mod port;
pub mod profiles;
pub mod radar_live;
pub mod radar_track;
pub mod relation;
pub mod resolve;
pub mod roi;
pub mod scan;
pub mod snake_graph;
pub mod stealer_row;
pub mod tags;
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
