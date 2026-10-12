//! Huntsman Core: high-throughput, memory-bounded OSINT engine for unprivileged AArch64 runtimes.
//!
//! Lint levels (unsafe forbidden, `unwrap`/`expect` denied, docs required) are declared in
//! `Cargo.toml` `[lints]`, keeping the policy in the manifest as the workspace requires.

pub mod dag;
pub mod error;
pub mod governor;
pub mod model;
pub mod transport;

pub use dag::{Collector, DagEngine, ExecutionReport, ModuleRegistration};
pub use error::HuntsmanError;
pub use governor::{GovernorConfig, NetworkGovernor};
pub use model::{Entity, EntityId, EntityKind, EpistemicLevel, ProvenanceEnvelope};
pub use transport::{MockTransport, Transport, UnprivilegedPosixTransport};
