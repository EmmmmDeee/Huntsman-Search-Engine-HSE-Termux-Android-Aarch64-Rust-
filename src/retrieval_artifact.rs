//! Stable identifier for a retrieved or observed artifact.
//!
//! Phase 1 only. The record that this id points at is intentionally not defined
//! here; independence evidence may cite the id without inventing a second
//! artifact authority.

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
    use super::ArtifactId;

    #[test]
    fn artifact_id_round_trips_as_transparent_string() {
        let id = ArtifactId::from("sha256:abc");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"sha256:abc\"");
        assert_eq!(serde_json::from_str::<ArtifactId>(&json).unwrap(), id);
    }
}
