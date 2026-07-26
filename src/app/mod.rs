//! Application composition and process-wide services.
//!
//! This layer is the composition root shared by the CLI and HTTP adapters. It
//! owns construction of concrete infrastructure and application lifecycle
//! services; presentation layers must not construct the engine or store.

pub mod cells;
pub mod export;
pub mod import;
pub mod runtime;
pub mod update;
