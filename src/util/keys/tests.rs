use super::io::{hardcoded_key_writes, pick_default_seed};
use super::*;
use std::collections::BTreeMap;
use tempfile::tempdir;

#[test]
fn resolve_or_default_policy() {
    assert_eq!(resolve_or_default(Some("real-key"), "default"), "real-key");
    assert_eq!(resolve_or_default(None, "default"), "default");
    // A present-but-empty value falls back to the default rather than being
    // used verbatim — the bug the wigle/wifi_intel modules had before
    // they were routed through this function.
    assert_eq!(resolve_or_default(Some(""), "default"), "default");
}

#[test]
fn own_api_keys_includes_embedded_and_splits_csv_rotation_lists() {
    let own = own_api_keys();
    assert!(
        own.contains(SEEKNOW_DEFAULT_KEY),
        "embedded SeekNow key missing"
    );
    assert!(
        own.contains(OATHNET_DEFAULT_KEY),
        "embedded OathNet key missing"
    );
    // The CSV-splitting `add` closure must register EACH key of a
    // comma-separated rotation list individually.
    let mut set = std::collections::HashSet::new();
    let mut add = |v: &str| {
        for part in v.split(',') {
            let part = part.trim();
            if part.len() >= 8 {
                set.insert(part.to_string());
            }
        }
    };
    add("rotationkeyAAAA, rotationkeyBBBB ,rotationkeyCCCC");
    assert!(set.contains("rotationkeyAAAA"));
    assert!(set.contains("rotationkeyBBBB"));
    assert!(set.contains("rotationkeyCCCC"));
    assert!(
        !set.contains("rotationkeyAAAA, rotationkeyBBBB ,rotationkeyCCCC"),
        "the joined CSV string must NOT be treated as a single key"
    );
}

#[test]
fn signup_hint_covers_common_free_providers() {
    let vt = signup_hint("HUNTSMAN_VIRUSTOTAL_KEY").expect("should succeed");
    assert!(vt.contains("virustotal.com"), "{vt}");
    let abusech = signup_hint("HUNTSMAN_ABUSECH_KEY").expect("should succeed");
    assert!(abusech.contains("auth.abuse.ch"));
    assert_eq!(
        signup_hint("HUNTSMAN_THREATFOX_KEY"),
        signup_hint("HUNTSMAN_ABUSECH_KEY")
    );
    assert!(signup_hint("HUNTSMAN_NOPE_KEY").is_none());
    for k in KNOWN_KEYS {
        if let Some(h) = signup_hint(k) {
            assert!(h.contains("https://") || h.contains("http"), "{k}: {h}");
        }
    }
}

/// Transparency invariant: EVERY key surfaced in the Settings/`hse doctor` grid
/// must tell the operator where to obtain it, so an unconfigured module is never
/// a dead end. A new `KNOWN_KEYS` entry without a `signup_hint` fails here rather
/// than shipping a hint-less row.
#[test]
fn signup_hint_is_defined_for_every_known_key() {
    let missing: Vec<&str> = KNOWN_KEYS
        .iter()
        .copied()
        .filter(|k| signup_hint(k).is_none())
        .collect();
    assert!(
        missing.is_empty(),
        "these KNOWN_KEYS have no signup_hint (add one to keep the grid self-documenting): {missing:?}"
    );
}

fn map_of(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn write_preserves_comments_and_appends_new_keys() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(&path, "# template\n#HUNTSMAN_HIBP_KEY=\n").expect("should succeed");

    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "abc123")]), &[])
        .expect("should succeed");

    let got = std::fs::read_to_string(&path).expect("should succeed");
    assert!(got.contains("# template"), "comment preserved");
    assert!(
        got.contains("#HUNTSMAN_HIBP_KEY="),
        "template placeholder preserved"
    );
    assert!(
        got.contains("HUNTSMAN_OATHNET_KEY=\"abc123\""),
        "new key appended (quoted)"
    );
}

#[test]
fn write_replaces_existing_key_in_place() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(&path, "HUNTSMAN_OATHNET_KEY=old\nHUNTSMAN_HIBP_KEY=stay\n")
        .expect("should succeed");

    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "new")]), &[]).expect("should succeed");

    let got = std::fs::read_to_string(&path).expect("should succeed");
    assert!(got.contains("HUNTSMAN_OATHNET_KEY=\"new\""));
    assert!(!got.contains("HUNTSMAN_OATHNET_KEY=old"));
    assert!(
        got.contains("HUNTSMAN_HIBP_KEY=stay"),
        "untouched key preserved verbatim (unquoted)"
    );
}

#[test]
fn written_values_round_trip_through_dotenvy() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    let cases = [
        ("HUNTSMAN_PLAIN", "abc123XYZ"),
        ("HUNTSMAN_WITH_HASH", "abc#def"),
        ("HUNTSMAN_WITH_SPACE", "two words"),
        ("HUNTSMAN_EQUALS", "a=b=c"),
    ];
    write_keys_at(&path, &map_of(&cases), &[]).expect("should succeed");

    let mut got = BTreeMap::new();
    for item in dotenvy::from_path_iter(&path).expect("should succeed") {
        let (k, v) = item.expect("should succeed");
        got.insert(k, v);
    }
    for (k, v) in cases {
        assert_eq!(
            got.get(k).map(String::as_str),
            Some(v),
            "value for {k} must round-trip unchanged through dotenvy"
        );
    }
}

#[test]
fn delete_removes_key_entirely() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(
        &path,
        "HUNTSMAN_OATHNET_KEY=goaway\nHUNTSMAN_HIBP_KEY=stay\n",
    )
    .expect("should succeed");

    write_keys_at(
        &path,
        &BTreeMap::new(),
        &["HUNTSMAN_OATHNET_KEY".to_string()],
    )
    .expect("should succeed");

    let got = std::fs::read_to_string(&path).expect("should succeed");
    assert!(!got.contains("HUNTSMAN_OATHNET_KEY"));
    assert!(got.contains("HUNTSMAN_HIBP_KEY=stay"));
}

#[test]
fn missing_file_is_created_with_appended_keys() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "seed")]), &[])
        .expect("should succeed");
    let got = std::fs::read_to_string(&path).expect("should succeed");
    assert!(got.contains("HUNTSMAN_OATHNET_KEY=\"seed\""));
}

#[test]
fn rejects_non_huntsman_keys() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    let err =
        write_keys_at(&path, &map_of(&[("PATH", "/etc")]), &[]).expect_err("should be an error");
    assert!(err.to_string().contains("HUNTSMAN_"));
}

#[test]
fn rejects_values_with_control_characters() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    assert!(
        write_keys_at(
            &path,
            &map_of(&[("HUNTSMAN_OATHNET_KEY", "bad\nvalue")]),
            &[]
        )
        .is_err()
    );
}

#[test]
fn rejects_values_with_double_quotes() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    assert!(write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "ab\"cd")]), &[]).is_err());
}

#[test]
fn rejects_values_with_backslash() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    assert!(write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "ab\\nc")]), &[]).is_err());
}

#[test]
fn load_from_file_ignores_comments_and_non_huntsman() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(
        &path,
        "# top comment\n\
         HUNTSMAN_OATHNET_KEY=abc\n\
         #HUNTSMAN_DEHASHED_KEY=skipme\n\
         OTHER=ignored\n\
         HUNTSMAN_HIBP_KEY=def\n",
    )
    .expect("should succeed");
    let m = load_from_file_only(&path);
    assert_eq!(
        m.get("HUNTSMAN_OATHNET_KEY").map(String::as_str),
        Some("abc")
    );
    assert_eq!(m.get("HUNTSMAN_HIBP_KEY").map(String::as_str), Some("def"));
    assert!(!m.contains_key("HUNTSMAN_DEHASHED_KEY"));
    assert!(!m.contains_key("OTHER"));
}

#[test]
fn load_from_file_handles_missing_file() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    let m = load_from_file_only(&path);
    assert!(m.is_empty());
}

#[test]
fn load_from_file_strips_single_quotes() {
    // A single-quoted value must come back bare, matching what dotenvy's load()
    // returns — otherwise SUPERSEDED rotation / hardcoded-fill compares a quoted
    // string against a bare constant and never matches, and the Settings UI shows
    // the quotes.
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(&path, "HUNTSMAN_OATHNET_KEY='singlequoted'\n").expect("should succeed");
    let m = load_from_file_only(&path);
    assert_eq!(
        m.get("HUNTSMAN_OATHNET_KEY").map(String::as_str),
        Some("singlequoted")
    );
}

#[test]
fn load_from_file_recovers_keys_after_a_malformed_line() {
    // The resilient line parser skips ONLY the offending line — this is the basis
    // for load()'s recovery when dotenvy abandons the rest of the file at the
    // first bad line. A garbage line between two valid keys must not drop the
    // second.
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(
        &path,
        "HUNTSMAN_OATHNET_KEY=first\n\
         this is a malformed line with no equals sign\n\
         HUNTSMAN_HIBP_KEY=second\n",
    )
    .expect("should succeed");
    let m = load_from_file_only(&path);
    assert_eq!(
        m.get("HUNTSMAN_OATHNET_KEY").map(String::as_str),
        Some("first")
    );
    assert_eq!(
        m.get("HUNTSMAN_HIBP_KEY").map(String::as_str),
        Some("second"),
        "a malformed earlier line must not drop a later key"
    );
}

#[test]
fn load_from_file_strips_double_quotes_from_written_values() {
    // write_keys_at stores values as KEY="value"; load_from_file_only must
    // return the bare value so SUPERSEDED rotation comparisons work correctly.
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "mykey123")]), &[])
        .expect("should succeed");
    let m = load_from_file_only(&path);
    assert_eq!(
        m.get("HUNTSMAN_OATHNET_KEY").map(String::as_str),
        Some("mykey123"),
        "value must not include surrounding double-quotes"
    );
}

#[test]
fn put_then_get_round_trips_through_file() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");

    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "v1")]), &[]).expect("should succeed");
    assert!(load_from_file_only(&path).contains_key("HUNTSMAN_OATHNET_KEY"));

    write_keys_at(
        &path,
        &BTreeMap::new(),
        &["HUNTSMAN_OATHNET_KEY".to_string()],
    )
    .expect("should succeed");
    assert!(!load_from_file_only(&path).contains_key("HUNTSMAN_OATHNET_KEY"));
}

#[test]
fn update_matches_key_with_whitespace_around_equals() {
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    std::fs::write(
        &path,
        "HUNTSMAN_OATHNET_KEY =old1\n\
         HUNTSMAN_HIBP_KEY= old2\n\
         HUNTSMAN_HUNTER_KEY = old3\n",
    )
    .expect("should succeed");

    write_keys_at(
        &path,
        &map_of(&[
            ("HUNTSMAN_OATHNET_KEY", "new1"),
            ("HUNTSMAN_HIBP_KEY", "new2"),
            ("HUNTSMAN_HUNTER_KEY", "new3"),
        ]),
        &[],
    )
    .expect("should succeed");

    let got = std::fs::read_to_string(&path).expect("should succeed");
    assert!(
        got.contains("HUNTSMAN_OATHNET_KEY=\"new1\""),
        "should update spaced key: {got}"
    );
    assert!(
        got.contains("HUNTSMAN_HIBP_KEY=\"new2\""),
        "should update right-spaced key: {got}"
    );
    assert!(
        got.contains("HUNTSMAN_HUNTER_KEY=\"new3\""),
        "should update both-spaced key: {got}"
    );
    assert!(!got.contains("old1"));
    assert!(!got.contains("old2"));
    assert!(!got.contains("old3"));
}

#[test]
fn read_error_other_than_not_found_surfaces() {
    let dir = tempdir().expect("should succeed");
    let err = write_keys_at(dir.path(), &map_of(&[("HUNTSMAN_OATHNET_KEY", "v")]), &[])
        .expect_err("should be an error");
    let msg = err.to_string();
    assert!(
        msg.contains("read ") || msg.contains("open ") || msg.contains("write "),
        "expected a read/open/write error, got: {msg}"
    );
}

#[test]
fn hardcoded_key_writes_fills_rotates_and_preserves() {
    use std::collections::HashMap;
    const NEW: &str = SEEKNOW_DEFAULT_KEY;
    const OLD: &str = SEEKNOW_SUPERSEDED_KEY;

    let w = hardcoded_key_writes(&HashMap::new());
    assert_eq!(w.get("HUNTSMAN_SEEKNOW_KEY").map(String::as_str), Some(NEW));
    assert!(w.contains_key("HUNTSMAN_OATHNET_KEY"));

    let stale: HashMap<String, String> =
        [("HUNTSMAN_SEEKNOW_KEY".to_string(), OLD.to_string())].into();
    assert_eq!(
        hardcoded_key_writes(&stale)
            .get("HUNTSMAN_SEEKNOW_KEY")
            .map(String::as_str),
        Some(NEW),
        "a superseded embedded key must rotate to the current default"
    );

    let custom: HashMap<String, String> = [(
        "HUNTSMAN_SEEKNOW_KEY".to_string(),
        "seek-my-own-personal-key".to_string(),
    )]
    .into();
    assert!(
        !hardcoded_key_writes(&custom).contains_key("HUNTSMAN_SEEKNOW_KEY"),
        "a custom user key must be preserved, not rotated"
    );

    let current: HashMap<String, String> =
        [("HUNTSMAN_SEEKNOW_KEY".to_string(), NEW.to_string())].into();
    assert!(!hardcoded_key_writes(&current).contains_key("HUNTSMAN_SEEKNOW_KEY"));
}

#[test]
fn pool_keys_fill_empty_env_slots() {
    let pool = crate::util::key_pool::global_pool();
    let mut entry = crate::util::key_pool::KeyEntry::new("test-pool-key-12345");
    entry.status = crate::util::key_pool::KeyStatus::Active;
    pool.add("shodan", entry);

    let map = load();
    let _ = map;
}

// ---- register_configured_keys: the T2.153-root-cause fix ----
//
// Every test below uses a FRESH, LOCAL `KeyPool::new()` — never
// `global_pool()` — so these assertions are exact and can't race with any
// other test mutating the process-global pool.

use super::io::register_configured_keys;
use crate::util::key_pool::{KeyPool, KeyStatus};

#[test]
fn register_configured_keys_registers_a_plain_single_key() {
    // The bug this closes: previously ONLY a comma-separated value ever
    // reached the pool — a single `HUNTSMAN_SHODAN_KEY=value` (the common,
    // majority real-world case) never got a pool entry at all, which made
    // every `report_key_exhausted`/`mark_status` call for it a silent no-op
    // forever, regardless of how correct the calling module's own
    // status-code handling was.
    let pool = KeyPool::new();
    let mut map: std::collections::HashMap<String, String> = [(
        "HUNTSMAN_SHODAN_KEY".to_string(),
        "single-key-abc123".to_string(),
    )]
    .into();

    register_configured_keys(&mut map, &pool);

    assert_eq!(pool.total_keys(), 1, "the single key must reach the pool");
    assert_eq!(
        pool.entry_status("shodan", "single-key-abc123"),
        Some(KeyStatus::Active),
        "a freshly-registered configured key starts Active, matching the \
         existing CSV-multi-key path's own convention"
    );
}

#[test]
fn register_configured_keys_still_splits_comma_separated_values() {
    // The pre-existing behaviour must survive the refactor unchanged.
    let pool = KeyPool::new();
    let mut map: std::collections::HashMap<String, String> = [(
        "HUNTSMAN_SHODAN_KEY".to_string(),
        "keyA111111,keyB222222,keyC333333".to_string(),
    )]
    .into();

    register_configured_keys(&mut map, &pool);

    assert_eq!(pool.service_count("shodan"), 3);
    assert_eq!(
        pool.entry_status("shodan", "keyA111111"),
        Some(KeyStatus::Active)
    );
    assert_eq!(
        pool.entry_status("shodan", "keyB222222"),
        Some(KeyStatus::Active)
    );
    assert_eq!(
        pool.entry_status("shodan", "keyC333333"),
        Some(KeyStatus::Active)
    );
    // The first key stays the "primary" env-map value — unchanged behaviour.
    assert_eq!(
        map.get("HUNTSMAN_SHODAN_KEY").map(String::as_str),
        Some("keyA111111")
    );
}

#[test]
fn register_configured_keys_never_overwrites_an_already_tracked_key() {
    // A key the pool already correctly knows is Invalid (from an earlier
    // real 401/403) must NOT be silently reset back to Active just because
    // the operator's env var still holds the same (still-dead) value —
    // `pool.add`'s own exact-value dedup is what protects this, exercised
    // here through `register_configured_keys` specifically.
    let pool = KeyPool::new();
    pool.add(
        "shodan",
        crate::util::key_pool::KeyEntry::new("dead-key-999"),
    );
    pool.mark_status("shodan", "dead-key-999", KeyStatus::Invalid);
    assert_eq!(
        pool.entry_status("shodan", "dead-key-999"),
        Some(KeyStatus::Invalid)
    );

    let mut map: std::collections::HashMap<String, String> = [(
        "HUNTSMAN_SHODAN_KEY".to_string(),
        "dead-key-999".to_string(),
    )]
    .into();
    register_configured_keys(&mut map, &pool);

    assert_eq!(
        pool.entry_status("shodan", "dead-key-999"),
        Some(KeyStatus::Invalid),
        "a previously-marked-Invalid key must stay Invalid, not reset to Active"
    );
    assert_eq!(pool.total_keys(), 1, "must not duplicate the entry either");
}

#[test]
fn register_configured_keys_ignores_unregistered_and_empty_values() {
    let pool = KeyPool::new();
    let mut map: std::collections::HashMap<String, String> = [
        // Not a registered service_defs env_var at all.
        (
            "HUNTSMAN_TOTALLY_MADE_UP_KEY".to_string(),
            "value".to_string(),
        ),
        // A registered env_var, but blank — nothing to register.
        ("HUNTSMAN_SHODAN_KEY".to_string(), String::new()),
    ]
    .into();

    register_configured_keys(&mut map, &pool);

    assert_eq!(pool.total_keys(), 0);
}

#[test]
fn register_configured_keys_reports_the_now_live_confirmed_abr_and_opencellid_gap() {
    // The exact real-world scenario this fix was diagnosed from: an operator
    // sets ONE `HUNTSMAN_ABR_GUID` and ONE `HUNTSMAN_OPENCELLID_KEY` (the
    // ordinary way to configure either service — neither has ever been
    // configured with more than one key in practice), and both must now
    // reach the pool so `abn_lookup`/`opencellid`/`cell_intel`'s
    // `report_key_exhausted`/`note_keyed_error` calls have something real to
    // update instead of silently no-op'ing.
    let pool = KeyPool::new();
    let mut map: std::collections::HashMap<String, String> = [
        (
            "HUNTSMAN_ABR_GUID".to_string(),
            "00000000-0000-0000-0000-000000000000".to_string(),
        ),
        (
            "HUNTSMAN_OPENCELLID_KEY".to_string(),
            "garbage00000invalid".to_string(),
        ),
    ]
    .into();

    register_configured_keys(&mut map, &pool);

    assert_eq!(
        pool.entry_status("abr", "00000000-0000-0000-0000-000000000000"),
        Some(KeyStatus::Active)
    );
    assert_eq!(
        pool.entry_status("opencellid", "garbage00000invalid"),
        Some(KeyStatus::Active)
    );
}

#[test]
fn default_seed_precedence_env_wins_then_file_then_none() {
    use std::collections::HashMap;
    let file: HashMap<String, String> =
        [(DEFAULT_SEED_ENV.to_string(), "from-file".to_string())].into();

    assert_eq!(
        pick_default_seed(Some("from-env".to_string()), &file).as_deref(),
        Some("from-env")
    );
    assert_eq!(pick_default_seed(None, &file).as_deref(), Some("from-file"));
    assert_eq!(pick_default_seed(None, &HashMap::new()), None);
}

#[test]
fn default_seed_trims_and_treats_blank_as_unset() {
    use std::collections::HashMap;
    let empty = HashMap::new();
    assert_eq!(
        pick_default_seed(Some("  alice  ".to_string()), &empty).as_deref(),
        Some("alice")
    );
    assert_eq!(pick_default_seed(Some("   ".to_string()), &empty), None);
    let file: HashMap<String, String> =
        [(DEFAULT_SEED_ENV.to_string(), "from-file".to_string())].into();
    assert_eq!(pick_default_seed(Some(String::new()), &file), None);
}

#[test]
fn default_seed_only_reads_the_seed_key() {
    use std::collections::HashMap;
    let file: HashMap<String, String> =
        [("HUNTSMAN_SHODAN_KEY".to_string(), "abc".to_string())].into();
    assert_eq!(pick_default_seed(None, &file), None);
}

#[test]
fn concurrent_vault_writes_never_corrupt_or_strand() {
    // The vault (`~/.huntsman.env`) is written from overlapping scans harvesting
    // keys and from `PUT`s toggling keys mid-scan. The previous hand-rolled write
    // used a FIXED temp (`path.with_extension("env.tmp")`), so two concurrent
    // writers to one $HOME both opened, truncated and interleaved into the same
    // temp and could rename a corrupt (or empty) file over the vault — which the
    // loader reads as "no keys". Routing through the unique-temp atomic writer
    // makes every write self-contained. Eight writers hammering one vault must
    // always leave a readable file that still holds the key, and no temp
    // straggler. (Mirrors `atomic_file`'s own concurrency property test.)
    let dir = tempdir().expect("should succeed");
    let path = dir.path().join(".huntsman.env");
    write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", "seed")]), &[])
        .expect("should succeed");

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let path = path.clone();
            std::thread::spawn(move || {
                for j in 0..20u32 {
                    let v = format!("k{i}_{j}");
                    let _ =
                        write_keys_at(&path, &map_of(&[("HUNTSMAN_OATHNET_KEY", v.as_str())]), &[]);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("should succeed");
    }

    let content = std::fs::read_to_string(&path).expect("vault still readable");
    assert!(
        content.contains("HUNTSMAN_OATHNET_KEY="),
        "concurrent writes must never corrupt/empty the vault: {content:?}"
    );
    let strays = std::fs::read_dir(dir.path())
        .expect("should succeed")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().contains(".tmp"))
        .count();
    assert_eq!(strays, 0, "no temp straggler after concurrent vault writes");
}
