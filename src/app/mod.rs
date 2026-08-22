//! Application composition and process-wide services.
//!
//! This layer is the composition root shared by the CLI and HTTP adapters. It
//! owns construction of concrete infrastructure and application lifecycle
//! services; presentation layers must not construct the engine or store.

pub mod audit;
pub mod benchmark;
pub mod cells;
pub mod convert;
pub mod diff;
pub mod doctor;
pub mod export;
pub mod gap;
pub mod import;
pub mod persist;
pub mod runtime;
pub mod signal;
pub mod tidy;
pub mod update;
