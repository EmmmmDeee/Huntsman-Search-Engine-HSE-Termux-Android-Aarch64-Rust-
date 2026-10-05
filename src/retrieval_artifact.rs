//! Stable identifiers for retrieval artifacts.
//!
//! Phase 1 needs only the identifier so independence evidence can reference
//! auditable supporting artifacts without introducing the full retrieval-artifact
//! record ahead of its own acceptance tests.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ArtifactId(pub String);

impl From<&str> for ArtifactId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_id_round_trips_as_transparent_string() {
        let id = ArtifactId::from("sha256:abc");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"sha256:abc\"");
        assert_eq!(serde_json::from_str::<ArtifactId>(&json).unwrap(), id);
    }
}
