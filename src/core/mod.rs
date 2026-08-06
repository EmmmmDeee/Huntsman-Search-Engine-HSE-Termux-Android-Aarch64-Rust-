//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod attack;
pub mod cancel;
pub mod convex;
pub mod correlator;
pub mod crypto;
pub mod data_broker;
pub mod dependency;
pub mod diff;
pub mod engine;
pub mod entity;
pub mod error;
pub mod event;
pub mod gexf;
pub mod live;
pub mod module;
pub mod planner;
pub mod port;
pub mod profiles;
pub mod relation;
pub mod roi;
pub mod scan;
pub mod tags;
#[cfg(test)]
pub mod test_support;
pub mod timeline;
pub mod validation;
pub mod webhook;

pub use cancel::CancelHandle;
pub use correlator::{Correlation, Correlator, Severity};
pub use dependency::{ModuleGraph, ModuleGraphSummary};
pub use engine::ScanEngine;
pub use entity::{Classification, Entity, EntityKind, Evidence, scan_id, unix_now};
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use live::{LiveOptions, LiveRequest, LiveScanner, LiveSession, LiveStatus};
pub use module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleInfo, ModuleResult};
pub use port::StoragePort;
pub use relation::{Relation, RelationKind};
pub use scan::{ExpansionStrategy, Scan, ScanOptions, ScanRequest, ScanStatus, Target, TargetKind};
