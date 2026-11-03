//! Embedded static OSINT ownership matrix, with no I/O, provider calls or new dependencies.
/// Canonical read-only discipline catalogue for UI and API.
#[must_use]
pub fn json_catalog() -> &'static str {
    include_str!("../docs/OSINT_DISCIPLINE_MATRIX.json")
}
#[cfg(test)]
mod tests {
    use super::json_catalog;
    use std::collections::BTreeSet;
    #[test]
    fn catalog_is_valid_unique_and_explicitly_unverified() {
        let data: serde_json::Value = serde_json::from_str(json_catalog()).unwrap();
        assert_eq!(data["schema"], "huntsman.osint.disciplines");
        assert_eq!(data["collection"], "none");
        let entries = data["disciplines"].as_array().unwrap();
        assert_eq!(entries.len(), 15);
        let mut ids = BTreeSet::new();
        for entry in entries {
            let id = entry["id"].as_str().unwrap();
            assert!(ids.insert(id), "duplicate discipline: {id}");
            assert_eq!(entry["status"], "mapped_not_runtime_verified");
            assert!(!entry["files"].as_array().unwrap().is_empty());
        }
        for id in ["GEOINT", "HUMINT", "NETINT", "EVIDENCE", "ORTHOGONAL"] {
            assert!(ids.contains(id));
        }
    }
    #[test]
    fn small_embedded_catalog_for_termux() {
        assert!(json_catalog().len() < 32 * 1024);
    }
}
