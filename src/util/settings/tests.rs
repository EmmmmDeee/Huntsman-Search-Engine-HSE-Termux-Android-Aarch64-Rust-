use super::*;

/// REQ-SETTINGS-001: a settings file that exists and does not parse is an
/// error that names the file, never an empty map. Read as empty, one trailing
/// comma turned every switch the operator had turned off back on.
#[test]
fn a_settings_file_that_does_not_parse_is_an_error_not_an_empty_map() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.json");
    assert!(
        load_map(&path).expect("no file is no overrides").is_empty(),
        "a missing file is a fresh start"
    );

    std::fs::write(
        &path,
        r#"{"feature.auto_update":false,"feature.map_tiles":false,}"#,
    )
    .expect("write");
    let err = load_map(&path).expect_err("a trailing comma is not a settings file");
    assert!(matches!(err, SettingsError::Parse { .. }), "{err:?}");
    let said = err.to_string();
    assert!(
        said.contains(&path.display().to_string()) && said.contains("move it aside"),
        "{said}"
    );

    std::fs::write(&path, r#"{"feature.auto_update":false}"#).expect("write");
    assert_eq!(
        load_map(&path).expect("parses").get("feature.auto_update"),
        Some(&false)
    );

    // A file that is there and cannot be read is an error too, not a fresh
    // start: here the name is taken by a directory.
    let taken = dir.path().join("taken.json");
    std::fs::create_dir(&taken).expect("dir");
    assert!(
        matches!(load_map(&taken), Err(SettingsError::Read { .. })),
        "an unreadable settings file is not an empty one"
    );
}

/// A scratch cache holding `map`, as [`set_bool_in`] and [`load_into`] take.
fn cache_of(map: Map) -> OnceLock<RwLock<Map>> {
    OnceLock::from(RwLock::new(map))
}

/// What a scratch cache holds; `None` when nothing has filled it.
fn held(cache: &OnceLock<RwLock<Map>>) -> Option<Map> {
    cache.get().map(|lock| lock.read().expect("lock").clone())
}

/// REQ-SETTINGS-001: a write never replaces a settings file it cannot read,
/// and a refused write changes nothing in this process either. The next
/// `hse config` used to replace the file with the one switch it set, and
/// `hse serve` put the refused switch in effect while saying it had failed.
#[test]
fn a_write_never_replaces_a_settings_file_that_does_not_parse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.json");
    let broken = r#"{"feature.auto_update":false,"feature.map_tiles":false,}"#;
    std::fs::write(&path, broken).expect("write");
    let before = Map::from([("feature.regional".to_string(), false)]);
    let cache = cache_of(before.clone());

    let err = set_bool_in(&cache, &path, "feature.regional", true)
        .expect_err("must not replace the operator's file");
    assert!(matches!(err, SettingsError::Parse { .. }), "{err:?}");
    assert!(err.to_string().contains("cannot be used"), "{err}");
    assert_eq!(std::fs::read_to_string(&path).expect("still there"), broken);
    assert_eq!(held(&cache), Some(before), "a refused write is not in effect");

    // Nothing filled yet: a refused write leaves it so.
    let empty = OnceLock::new();
    assert!(set_bool_in(&empty, &path, "feature.regional", true).is_err());
    assert_eq!(held(&empty), None);

    // Repaired by hand with a switch this process never saw: a write keeps
    // it, and the cache becomes what was written.
    std::fs::write(&path, r#"{"feature.map_tiles":false}"#).expect("repaired");
    set_bool_in(&cache, &path, "feature.regional", true).expect("the file parses");
    let written = load_map(&path).expect("parses");
    assert_eq!(
        written,
        Map::from([
            ("feature.map_tiles".to_string(), false),
            ("feature.regional".to_string(), true),
        ])
    );
    assert_eq!(held(&cache), Some(written.clone()));
    set_bool_in(&empty, &path, "feature.regional", true).expect("parses");
    assert_eq!(held(&empty), Some(written), "a first write fills the cache");

    // No file is a fresh start: written with the one switch.
    std::fs::remove_file(&path).expect("remove");
    set_bool_in(&cache, &path, "feature.recall", true).expect("no file: written");
    assert_eq!(
        load_map(&path).expect("parses"),
        Map::from([("feature.recall".to_string(), true)])
    );

    // A write that fails changes nothing in this process either: here the
    // file's directory is gone, so there is no file to keep and nowhere to
    // write one.
    let before = held(&cache);
    let nowhere = dir.path().join("gone").join("settings.json");
    let err = set_bool_in(&cache, &nowhere, "feature.regional", false)
        .expect_err("no directory to write in");
    assert!(matches!(err, SettingsError::Write { .. }), "{err:?}");
    assert_eq!(held(&cache), before);
}

/// REQ-SETTINGS-001: loading puts the file as it is now into the cache, and
/// a file that cannot be used leaves the cache as it was: holding its map,
/// or empty if nothing filled it.
#[test]
fn load_reads_the_file_into_the_cache_or_leaves_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.json");
    let before = Map::from([("feature.auto_update".to_string(), true)]);
    let cache = cache_of(before.clone());
    let empty = OnceLock::new();

    std::fs::write(&path, r#"{"feature.auto_update":false,}"#).expect("write");
    let err = load_into(&cache, &path).expect_err("does not parse");
    assert!(matches!(err, SettingsError::Parse { .. }), "{err:?}");
    assert_eq!(held(&cache), Some(before), "a file that cannot be used changes nothing");
    assert!(load_into(&empty, &path).is_err());
    assert_eq!(held(&empty), None);

    let valid = Map::from([("feature.auto_update".to_string(), false)]);
    std::fs::write(&path, r#"{"feature.auto_update":false}"#).expect("write");
    load_into(&cache, &path).expect("parses");
    assert_eq!(held(&cache), Some(valid.clone()));
    load_into(&empty, &path).expect("parses");
    assert_eq!(held(&empty), Some(valid));

    std::fs::remove_file(&path).expect("remove");
    load_into(&cache, &path).expect("no file is no overrides");
    assert_eq!(held(&cache), Some(Map::new()));
}

/// An empty settings file, or one an editor began with a byte-order mark,
/// holds no switch the operator could lose, so neither stops `hse`.
#[test]
fn an_empty_file_and_a_byte_order_mark_are_no_reason_to_stop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("settings.json");
    for empty in ["", "  \n", "\u{feff}", "\u{feff}\n"] {
        std::fs::write(&path, empty).expect("write");
        assert_eq!(load_map(&path).expect("no switches"), Map::new(), "{empty:?}");
    }
    std::fs::write(&path, "\u{feff}{\"feature.recall\":true}").expect("write");
    assert_eq!(
        load_map(&path).expect("parses"),
        Map::from([("feature.recall".to_string(), true)])
    );
    // A mark before a broken file is still a broken file.
    std::fs::write(&path, "\u{feff}{\"feature.recall\":true,}").expect("write");
    assert!(matches!(load_map(&path), Err(SettingsError::Parse { .. })));
}

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
fn map_tiles_is_registered_and_on_by_default_with_killswitch() {
    // The tile fetch is a known feature toggle, ON by default (a tile is only
    // ever fetched when the operator opens the map) with an explicit OFF as the
    // kill-switch for the outbound request. Key constant and helper must agree.
    assert_eq!(MAP_TILES_FEATURE, "feature.map_tiles");
    assert!(is_feature_key(MAP_TILES_FEATURE), "must be in FEATURE_TOGGLES");
    assert!(default_for(MAP_TILES_FEATURE), "tiles fetch by default");
    let mut off = BTreeMap::new();
    off.insert(MAP_TILES_FEATURE.to_string(), false);
    assert!(
        !resolve(&off, MAP_TILES_FEATURE, true),
        "an explicit OFF must stop the fetch (kill-switch)"
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
    let on_disk = load_map(&settings_path()).expect("the settings file parses");
    assert_eq!(
        on_disk.get(key),
        Some(&true),
        "set_bool must persist to disk, not just the in-process cache"
    );
    // Restore, so this test leaves no state behind for any other test sharing
    // the same process-global CACHE / settings file.
    set_bool(key, false).expect("restore");
}
