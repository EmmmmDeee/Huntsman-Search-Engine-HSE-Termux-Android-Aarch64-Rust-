//! Huntsman Storage: pure-Rust embedded graph persistence for unprivileged AArch64 runtimes.
//!
//! A single background writer batches commits into an append-only [`redb`] database to bound
//! flash wear and eliminate write-lock contention. `put` enqueues under bounded backpressure;
//! `sync` awaits durability; `get` reads committed state through an MVCC read transaction.
//!
//! Lint levels live in `Cargo.toml` `[lints]`, per workspace policy.

mod error;
mod store;

pub use error::StorageError;
pub use store::GraphStore;
