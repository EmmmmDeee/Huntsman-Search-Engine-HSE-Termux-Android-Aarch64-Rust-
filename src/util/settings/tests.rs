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
fn live_radar_is_registered_and_armed_by_default_with_killswitch() {
    // The live-sensor radar is a known feature toggle that defaults ON — the
    // radar is the operator's own deliberate action, so it needs no prior opt-in
    // (a single button press runs it). The key constant and helper must agree.
    assert_eq!(LIVE_RADAR_FEATURE, "feature.live_radar");
    assert!(is_feature_key(LIVE_RADAR_FEATURE), "must be in FEATURE_TOGGLES");
    assert!(
        default_for(LIVE_RADAR_FEATURE),
        "live radar must be armed (ON) by default — zero-input activation"
    );
    // Kill-switch: an explicit OFF override still wins over the default, so an
    // operator can refuse the radar entirely. Pure `resolve`, no global mutation.
    let mut off = BTreeMap::new();
    off.insert(LIVE_RADAR_FEATURE.to_string(), false);
    assert!(
        !resolve(&off, LIVE_RADAR_FEATURE, true),
        "an explicit OFF must disable the radar (kill-switch)"
    );
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
