//! AU correlation rules — handle, platform, key, tracking and data-broker family.
//!
//! Formerly one ~1.9k-line `account.rs`; split into cohesive per-family submodules
//! (the note in `identity/mod.rs` had already flagged this list as overgrown). Every
//! rule remains `pub(in crate::core::correlator)` and is re-exported here via glob, so
//! `identity::*` / `rules::*` — and every existing call site — resolve exactly as before.

mod broker;
mod handle;
mod key;
mod platform;
mod tracking;

pub(in crate::core::correlator) use broker::*;
pub(in crate::core::correlator) use handle::*;
pub(in crate::core::correlator) use key::*;
pub(in crate::core::correlator) use platform::*;
pub(in crate::core::correlator) use tracking::*;
