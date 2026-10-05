//! Stable identifiers for retrieval artifacts.
//!
//! The full retrieval-artifact record is introduced in the next epistemic-core
//! phase. This module intentionally establishes only the durable identifier
//! contract needed by provenance/independence evidence.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(pub String);

impl From<&str> for ArtifactId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}
