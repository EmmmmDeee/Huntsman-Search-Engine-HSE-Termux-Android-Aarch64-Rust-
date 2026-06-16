use super::*;

#[test]
fn is_feature_key_accepts_registered_and_rejects_others() {
    assert!(is_feature_key("feature.regional"));
    assert!(is_feature_key("feature.recall"));
    assert!(!is_feature_key("feature.nonexistent"));
    assert!(!is_feature_key("shodan")); // engine key, not a feature toggle
    assert!(!is_feature_key(""));
}

#[test]
fn default_for_non_feature_key_is_true() {
    // Engine/module keys default to enabled (true) — they must not be
    // silently disabled by being absent from FEATURE_TOGGLES.
    assert!(default_for("shodan"));
    assert!(default_for("virustotal"));
    assert!(default_for("unknown_engine"));
}

#[test]
fn default_for_feature_keys_matches_registration() {
    // feature.regional defaults OFF; feature.recall defaults ON.
    assert!(!default_for("feature.regional"));
    assert!(default_for("feature.recall"));
}

#[test]
fn resolve_uses_map_value_over_default() {
    let mut map = BTreeMap::new();
    map.insert("k".to_string(), false);
    assert!(!resolve(&map, "k", true), "map value must win over default");
    assert!(resolve(&map, "missing", true), "absent key returns default");
}

#[test]
fn feature_toggles_length_matches_registration() {
    assert_eq!(feature_toggles().len(), FEATURE_TOGGLES.len());
    for (key, _) in feature_toggles() {
        assert!(is_feature_key(&key), "{key} missing from FEATURE_TOGGLES");
    }
}
