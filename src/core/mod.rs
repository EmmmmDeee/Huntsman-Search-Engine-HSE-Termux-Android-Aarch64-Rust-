//! Core types: entity, scan, event, module trait, engine.
//!
//! Nothing in `core` imports from `modules/` — modules depend on core, never
//! the other way around. This keeps the engine module-agnostic.

pub mod engine;
pub mod entity;
pub mod error;
pub mod event;
pub mod module;
pub mod scan;

pub use engine::ScanEngine;
pub use entity::{Classification, Entity, EntityKind, Evidence};
pub use error::{Error, Result};
pub use event::{Event, EventBus, EventKind};
pub use module::{Module, ModuleContext, ModuleCost, ModuleInfo, ModuleResult};
pub use scan::{Scan, ScanOptions, ScanRequest, ScanStatus, Target, TargetKind};
