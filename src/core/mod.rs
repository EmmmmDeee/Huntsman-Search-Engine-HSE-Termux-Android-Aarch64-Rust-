//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod cancel;
pub mod correlator;
pub mod engine;
pub mod entity;
pub mod error;
pub mod event;
pub mod live;
pub mod module;
pub mod port;
pub mod scan;
pub mod tags;

pub use cancel::CancelHandle;
pub use correlator::{Correlation, Correlator, Severity};
pub use engine::ScanEngine;
pub use entity::{Classification, Entity, EntityKind, Evidence, scan_id, unix_now};
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use live::{LiveOptions, LiveRequest, LiveScanner, LiveSession, LiveStatus};
pub use module::{Module, ModuleContext, ModuleCost, ModuleInfo, ModuleResult};
pub use port::StoragePort;
pub use scan::{Scan, ScanOptions, ScanRequest, ScanStatus, Target, TargetKind};
