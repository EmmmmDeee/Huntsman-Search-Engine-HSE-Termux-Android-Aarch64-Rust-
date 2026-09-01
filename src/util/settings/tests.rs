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
    // feature.regional and feature.recall both default OFF (recall off = every
    // scan is a fresh start; no archaic prior-scan data injected).
    assert!(!default_for("feature.regional"));
    assert!(!default_for("feature.recall"));
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

#[test]
fn set_bool_persists_and_get_bool_reads_it_back() {
    // `set_bool` is the ONE write path both `hse config` and
    // `PUT /api/v1/settings/toggles` funnel through; every other test in this
    // file exercises only the pure, non-mutating helpers (`resolve`,
    // `default_for`, `is_feature_key`) — nothing had ever proven the cache
    // mutation or the atomic on-disk persist actually work. Uses a scratch
    // key private to this test (not a registered `FEATURE_TOGGLES` entry) so
    // it can't collide with any other test's toggle assertions despite `CACHE`
    // and the settings file being process-global.
    let key = "test.set_bool_round_trip_marker";
    assert!(
        !get_bool(key, false),
        "an unset key must resolve to the caller's default"
    );
    set_bool(key, true).expect("set_bool persists");
    assert!(
        get_bool(key, false),
        "set_bool must flip the in-process cache immediately \
         (default false here so a cache that stayed unset can't pass by \
         coincidentally falling back to the same value)"
    );
    // Read the file back independently of the CACHE static, proving the
    // write landed on disk and isn't just an in-memory mutation.
    let on_disk = read_map(&settings_path());
    assert_eq!(
        on_disk.get(key),
        Some(&true),
        "set_bool must persist to disk, not just the in-process cache"
    );
    // Restore, so this test leaves no state behind for any other test sharing
    // the same process-global CACHE / settings file.
    set_bool(key, false).expect("restore");
}
