//! Stage 2 directory shim for the `web` home (see `docs/ARCHITECTURE.md`).
//!
//! Re-exports only. Every module still lives at its current `crate::<module>` path;
//! later stages move files here one at a time without changing those paths.

pub use crate::{scan_api, serve_events, serve_probe, web_server};
