//! Huntsman Storage: pure-Rust embedded graph persistence for unprivileged AArch64 runtimes.
//!
//! A single background writer batches commits into an append-only [`redb`] database to bound
//! flash wear and eliminate write-lock contention. `put` enqueues under bounded backpressure;
//! `sync` awaits durability; `get` and `observations` read committed state through MVCC read
//! transactions.
//!
//! What the store guarantees:
//!
//! * **Append-only provenance.** The first [`Entity`](huntsman_core::Entity) observed under an
//!   id owns its `entities` row forever; every distinct provenance envelope put for that id is
//!   appended to the `observations` ledger exactly once, and nothing is ever updated or deleted.
//! * **Durability truth.** `sync` returns `Ok` only if every operation enqueued before it was
//!   committed. The first failed commit is latched: later `sync`, `put` and `shutdown` calls
//!   all report it, and the store must be reopened.
//! * **Bounded memory.** The database is opened through `redb`'s builder with an explicit page
//!   cache (32 MiB by default, 64 MiB at most via [`StoreConfig`]), never its 1 GiB default.
//! * **Deterministic release.** Dropping a store drains its queue and joins the writer before
//!   the file lock is released; `shutdown` does the same and returns the drain result.
//!
//! Lint levels live in `Cargo.toml` `[lints]`, per workspace policy.

mod error;
mod store;

pub use error::StorageError;
pub use store::{GraphStore, StoreConfig};
