//! Stage 2 directory shim for the `infrastructure` home (see `docs/ARCHITECTURE.md`).
//!
//! Re-exports only. Every module still lives at its current `crate::<module>` path;
//! later stages move files here one at a time without changing those paths.

pub use crate::{
    api_leg, classify, credential_origin, deadline, egress, fetch, http, keys, module_selection,
    source_outcome,
};
