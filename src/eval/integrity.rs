use serde::Serialize;

use crate::sha256::{hex32, sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDigest(pub String);

/// Stable digest for a serializable artifact. Callers that need byte-stable
/// cross-version artifacts must ensure their serialized maps use deterministic
/// ordering (the evaluation model uses `BTree*` containers for that reason).
///
/// # Errors
/// Propagates `serde_json` serialisation failure.
pub fn digest_json<T: Serialize>(value: &T) -> Result<ArtifactDigest, serde_json::Error> {
    let bytes = serde_json::to_vec(value)?;
    Ok(ArtifactDigest(hex32(&sha256(&bytes))))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn deterministic_map_digest_repeats() {
        let value = BTreeMap::from([("a", 1_u64), ("b", 2_u64)]);
        assert_eq!(digest_json(&value).unwrap(), digest_json(&value).unwrap());
    }
}
