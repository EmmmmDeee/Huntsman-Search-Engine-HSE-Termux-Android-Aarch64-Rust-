//! Stage 2 directory shim for the `evidence` home (see `docs/ARCHITECTURE.md`).
//!
//! Re-exports only. Every module still lives at its current `crate::<module>` path;
//! later stages move files here one at a time without changing those paths.

pub use crate::{confidence, evidence_ancestry, identity_resolution, resolve, retrieval_artifact};
