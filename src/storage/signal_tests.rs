// Tests for RF sighting persistence and the rollup views. Addresses invented.
//
// Plain `//` rather than `//!`: `include!`d into a `mod tests` block.

use super::super::Store;
use super::*;
use crate::core::rf::{RadioKind, RfSighting, RfSource};

/// A sighting with the fields these tests vary; the rest stay absent, which is
/// how a real capture arrives.
fn sighting(
    id: &str,
    radio: RadioKind,
    name: Option<&str>,
    signal: f64,
    pos: Option<(f64, f64)>,
    epoch: i64,
) -> RfSighting {
    let mut s = RfSighting::new(id, radio, RfSource::WigleKml);
    s.name = name.map(str::to_string);
    s.signal_dbm = Some(signal);
    s.observed_epoch = Some(epoch);
    s.observed_at = Some(format!("epoch:{epoch}"));
    if let Some((lat, lon)) = pos {
        s.latitude = Some(lat);
        s.longitude = Some(lon);
    }
    s
}

#[test]
fn insert_and_roll_up_a_device_from_its_sightings() {
    let store = Store::open(":memory:").expect("in-memory store");
    // One access point heard three times as the operator moved past it.
    let rows = vec![
        sighting("00:1A:2B:3C:4D:5E", RadioKind::Wifi, Some("Cafe"), -88.0, Some((-26.81, 153.08)), 100),
        sighting("00:1A:2B:3C:4D:5E", RadioKind::Wifi, Some("Cafe"), -61.0, Some((-26.82, 153.09)), 200),
        sighting("00:1A:2B:3C:4D:5E", RadioKind::Wifi, Some("Cafe"), -75.0, Some((-26.83, 153.10)), 300),
    ];
    assert_eq!(store.insert_rf_sightings_batch("s1", &rows).expect("insert"), 3);

    let devices = store.rf_devices_for_scan("s1").expect("read back");
    assert_eq!(devices.len(), 1, "three sightings of one radio is one device");
    let d = &devices[0];
    assert_eq!(d.network_id, "00:1a:2b:3c:4d:5e", "stored canonically lowercased");
    assert_eq!(d.sightings, 3);
    assert_eq!(d.first_epoch, Some(100));
    assert_eq!(d.last_epoch, Some(300));
    assert_eq!(d.best_signal_dbm, Some(-61.0));
    assert_eq!(d.worst_signal_dbm, Some(-88.0));
    assert_eq!(d.distinct_fixes, 3, "heard from three separate positions");

    // The reported position is the STRONGEST sighting — the closest pass — not
    // the first or last. Taking either of those puts the device wherever the
    // operator happened to start or stop.
    assert_eq!(d.best_latitude, Some(-26.82));
    assert_eq!(d.best_longitude, Some(153.09));
}

#[test]
fn the_sighting_track_is_preserved_not_collapsed() {
    // The whole reason this table exists: the entity graph keeps the device,
    // this keeps every time it was heard, with where and how loudly.
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                sighting("00:1a:2b:3c:4d:5e", RadioKind::Wifi, None, -88.0, Some((-26.81, 153.08)), 300),
                sighting("00:1a:2b:3c:4d:5e", RadioKind::Wifi, None, -61.0, Some((-26.82, 153.09)), 100),
            ],
        )
        .expect("insert");

    let track = store
        .rf_sightings_for_device("s1", "00:1A:2B:3C:4D:5E")
        .expect("read back");
    assert_eq!(track.len(), 2);
    // Oldest first, and the lookup accepts either case for the address.
    assert_eq!(track[0].observed_epoch, Some(100));
    assert_eq!(track[1].observed_epoch, Some(300));
    assert_eq!(track[0].signal_dbm, Some(-61.0));
}

#[test]
fn address_kind_is_derived_on_write_from_the_bits() {
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                // `00:` universally administered — real hardware.
                sighting("00:1a:2b:3c:4d:5e", RadioKind::Wifi, None, -60.0, None, 1),
                // `02:` locally administered — a rotating privacy address.
                sighting("02:aa:bb:cc:dd:ee", RadioKind::Ble, None, -70.0, None, 2),
                // A cellular identifier is not an address at all.
                sighting("50501_28693_147572482", RadioKind::Cellular, None, -100.0, None, 3),
            ],
        )
        .expect("insert");

    let by = |id: &str| {
        store
            .rf_devices_for_scan("s1")
            .expect("read")
            .into_iter()
            .find(|d| d.network_id == id)
            .expect("present")
    };
    assert_eq!(by("00:1a:2b:3c:4d:5e").locally_administered, Some(false));
    assert_eq!(by("02:aa:bb:cc:dd:ee").locally_administered, Some(true));
    assert_eq!(
        by("50501_28693_147572482").locally_administered,
        None,
        "a cell tuple has no U/L bit and must not be given one"
    );

    // Only the fixed address is followable; this is the AU-122 filter.
    let track = store.rf_trackable_devices("s1").expect("trackable");
    assert_eq!(track.len(), 1);
    assert_eq!(track[0].network_id, "00:1a:2b:3c:4d:5e");
}

#[test]
fn the_oui_is_stored_even_with_no_vendor_known() {
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[sighting("00:1A:2B:3C:4D:5E", RadioKind::Wifi, None, -60.0, None, 1)],
        )
        .expect("insert");
    assert_eq!(
        store.rf_devices_for_scan("s1").expect("read")[0].oui.as_deref(),
        Some("001A2B"),
        "a later IEEE table must be joinable without re-reading captures"
    );
}

#[test]
fn a_null_island_position_is_stored_as_absent() {
    // 0,0 is what a receiver with no fix reports. Storing it would pin every
    // GPS-less sighting off the coast of Africa and inflate `with_position`.
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[sighting("00:1a:2b:3c:4d:5e", RadioKind::Wifi, None, -60.0, Some((0.0, 0.0)), 1)],
        )
        .expect("insert");
    let d = &store.rf_devices_for_scan("s1").expect("read")[0];
    assert_eq!(d.best_latitude, None);
    assert_eq!(d.distinct_fixes, 0);
    assert_eq!(store.rf_summary("s1").expect("summary").with_position, 0);
}

#[test]
fn shared_names_expose_multi_radio_installations() {
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                // One name on three radios — a mesh, not three networks.
                sighting("00:1a:2b:00:00:01", RadioKind::Wifi, Some("TAVERN"), -60.0, None, 1),
                sighting("00:1a:2b:00:00:02", RadioKind::Wifi, Some("TAVERN"), -61.0, None, 2),
                sighting("00:1a:2b:00:00:03", RadioKind::Wifi, Some("TAVERN"), -62.0, None, 3),
                // A name on one radio is not shared.
                sighting("00:1a:2b:00:00:04", RadioKind::Wifi, Some("Solo"), -63.0, None, 4),
                // The same radio seen twice must not count as two radios.
                sighting("00:1a:2b:00:00:05", RadioKind::Wifi, Some("Twice"), -64.0, None, 5),
                sighting("00:1a:2b:00:00:05", RadioKind::Wifi, Some("Twice"), -65.0, None, 6),
            ],
        )
        .expect("insert");

    let shared = store.rf_shared_names("s1").expect("shared names");
    assert_eq!(shared, vec![("TAVERN".to_string(), 3)]);
}

#[test]
fn summary_counts_devices_once_however_often_they_were_heard() {
    // Mixing the sighting grain with the device grain is the classic way a
    // survey summary lies, so pin both numbers against the same data.
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                sighting("00:1a:2b:00:00:01", RadioKind::Wifi, Some("A"), -60.0, Some((-26.8, 153.0)), 10),
                sighting("00:1a:2b:00:00:01", RadioKind::Wifi, Some("A"), -70.0, Some((-26.8, 153.0)), 20),
                sighting("02:aa:bb:00:00:02", RadioKind::Ble, None, -80.0, None, 30),
                sighting("00:1a:2b:00:00:03", RadioKind::BtClassic, Some("C"), -19.0, None, 40),
                sighting("50501_1_2", RadioKind::Cellular, None, -100.0, None, 50),
            ],
        )
        .expect("insert");

    let s = store.rf_summary("s1").expect("summary");
    assert_eq!(s.sightings, 5, "every observation");
    assert_eq!(s.devices, 4, "one Wi-Fi AP heard twice is one device");
    assert_eq!((s.wifi, s.ble, s.bt, s.cellular), (1, 1, 1, 1));
    assert_eq!(s.fixed_address, 2);
    assert_eq!(s.randomised_address, 1);
    assert_eq!(s.named, 2);
    assert_eq!(s.with_position, 1);
    assert_eq!(s.first_epoch, Some(10));
    assert_eq!(s.last_epoch, Some(50));
}

#[test]
fn both_radios_share_one_table_and_stay_distinguishable() {
    // A WiGLE capture and a live sweep observe the same physical thing, so they
    // share a record; `source` is what keeps a third party's observation from
    // being read as the operator's own.
    let store = Store::open(":memory:").expect("in-memory store");
    let mut sweep = RfSighting::new("00:1a:2b:3c:4d:5e", RadioKind::Ble, RfSource::BluetoothRadar);
    sweep.observed_epoch = Some(2);
    let mut capture = RfSighting::new("00:99:88:77:66:55", RadioKind::Wifi, RfSource::WigleKml);
    capture.observed_epoch = Some(1);
    store
        .insert_rf_sightings_batch("s1", &[sweep, capture])
        .expect("insert");

    let ble = store
        .rf_sightings_for_device("s1", "00:1a:2b:3c:4d:5e")
        .expect("read");
    assert_eq!(ble[0].source, RfSource::BluetoothRadar);
    assert!(ble[0].source.is_local_sensor());
    let wifi = store
        .rf_sightings_for_device("s1", "00:99:88:77:66:55")
        .expect("read");
    assert_eq!(wifi[0].source, RfSource::WigleKml);
    assert!(!wifi[0].source.is_local_sensor());
    assert_eq!(store.rf_summary("s1").expect("summary").devices, 2);
}

#[test]
fn sightings_are_scoped_to_their_own_scan() {
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "scan-a",
            &[sighting("00:1a:2b:00:00:01", RadioKind::Wifi, None, -60.0, None, 1)],
        )
        .expect("insert");
    store
        .insert_rf_sightings_batch(
            "scan-b",
            &[sighting("00:1a:2b:00:00:02", RadioKind::Wifi, None, -60.0, None, 2)],
        )
        .expect("insert");
    assert_eq!(store.rf_devices_for_scan("scan-a").expect("a").len(), 1);
    assert_eq!(store.rf_devices_for_scan("scan-b").expect("b").len(), 1);
    assert_eq!(
        store.rf_devices_for_scan("scan-a").expect("a")[0].network_id,
        "00:1a:2b:00:00:01"
    );
}

#[test]
fn an_empty_batch_is_a_no_op_not_an_error() {
    let store = Store::open(":memory:").expect("in-memory store");
    assert_eq!(
        store.insert_rf_sightings_batch("s1", &[]).expect("no-op"),
        0
    );
    assert!(store.rf_devices_for_scan("s1").expect("read").is_empty());
    assert_eq!(store.rf_summary("s1").expect("summary"), RfSummary::default());
}

#[test]
fn device_ordering_is_deterministic_and_puts_unmeasured_last() {
    let store = Store::open(":memory:").expect("in-memory store");
    let mut quiet = RfSighting::new("00:1a:2b:00:00:09", RadioKind::Wifi, RfSource::WigleKml);
    quiet.observed_epoch = Some(9); // no signal reading at all
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                sighting("00:1a:2b:00:00:02", RadioKind::Wifi, None, -70.0, None, 2),
                quiet,
                sighting("00:1a:2b:00:00:01", RadioKind::Wifi, None, -50.0, None, 1),
            ],
        )
        .expect("insert");

    let ids: Vec<String> = store
        .rf_devices_for_scan("s1")
        .expect("read")
        .into_iter()
        .map(|d| d.network_id)
        .collect();
    assert_eq!(
        ids,
        vec![
            "00:1a:2b:00:00:01".to_string(), // -50, strongest
            "00:1a:2b:00:00:02".to_string(), // -70
            "00:1a:2b:00:00:09".to_string(), // no reading — last, not first
        ]
    );
    // Repeating the query must give the same order.
    let again: Vec<String> = store
        .rf_devices_for_scan("s1")
        .expect("read")
        .into_iter()
        .map(|d| d.network_id)
        .collect();
    assert_eq!(ids, again);
}

/// A device whose LOUDEST pass had no GPS fix is still located by a weaker pass
/// that did. Ordering the rollup by signal alone picks the strongest sighting
/// and then reads whatever latitude it happens to carry, so this device
/// reported no position at all — while `distinct_fixes` counted the fix, a row
/// that contradicts itself.
#[test]
fn the_strongest_pass_lacking_a_fix_does_not_hide_a_weaker_located_one() {
    let store = Store::open(":memory:").expect("in-memory store");
    store
        .insert_rf_sightings_batch(
            "s1",
            &[
                // Loudest, but the receiver had no fix at that moment.
                sighting("00:1a:2b:00:00:01", RadioKind::Wifi, None, -40.0, None, 1),
                // Quieter, and located.
                sighting(
                    "00:1a:2b:00:00:01",
                    RadioKind::Wifi,
                    None,
                    -70.0,
                    Some((-26.81, 153.08)),
                    2,
                ),
            ],
        )
        .expect("insert");

    let d = &store.rf_devices_for_scan("s1").expect("read")[0];
    assert_eq!(d.distinct_fixes, 1, "the capture did locate this device");
    assert_eq!(
        (d.best_latitude, d.best_longitude),
        (Some(-26.81), Some(153.08)),
        "the position must come from the best sighting that HAS one"
    );
    assert_eq!(
        d.best_signal_dbm,
        Some(-40.0),
        "the strongest level is still the strongest level — only the POSITION \
         is read from a located sighting"
    );
    assert_eq!(
        store.rf_summary("s1").expect("summary").with_position,
        1,
        "a located device must count toward `with_position`"
    );
}

/// A source that reports a position but no signal level — a Bluetooth sweep
/// with no RSSI, a capture whose `Signal` field is absent or unparseable — is
/// still locatable. Excluding NULL-signal sightings from the position rollup
/// (rather than merely ranking them last) made every such device report no
/// position, and `with_position` undercounted by exactly those devices.
#[test]
fn a_device_located_without_any_signal_reading_still_reports_its_position() {
    let store = Store::open(":memory:").expect("in-memory store");
    let mut a = sighting(
        "00:1a:2b:00:00:02",
        RadioKind::Ble,
        Some("Watch"),
        0.0,
        Some((-26.81, 153.08)),
        1,
    );
    a.signal_dbm = None;
    let mut b = sighting(
        "00:1a:2b:00:00:02",
        RadioKind::Ble,
        Some("Watch"),
        0.0,
        Some((-26.90, 153.20)),
        2,
    );
    b.signal_dbm = None;
    store
        .insert_rf_sightings_batch("s1", &[a, b])
        .expect("insert");

    let d = &store.rf_devices_for_scan("s1").expect("read")[0];
    assert_eq!(d.best_signal_dbm, None, "no level was ever reported");
    assert_eq!(d.distinct_fixes, 2);
    assert_eq!(
        (d.best_latitude, d.best_longitude),
        (Some(-26.81), Some(153.08)),
        "with no level to rank by, the earliest located sighting wins — a \
         deterministic answer, not no answer"
    );
    assert_eq!(
        store.rf_summary("s1").expect("summary").with_position,
        1,
        "`Located: N with a usable fix` must count fixes the receiver had"
    );
}

/// A view carries no data of its own, so a corrected definition must reach a
/// database that already exists. Under `CREATE VIEW IF NOT EXISTS` the first
/// binary to create it owned it forever and every later fix silently applied to
/// fresh installs only — invisible to a test suite that builds `:memory:`
/// stores. Opening over a stale definition must replace it.
#[test]
fn reopening_replaces_a_stale_view_definition() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("drift.db");
    let path = path.to_str().expect("utf-8 path");

    {
        let store = Store::open(path).expect("first open");
        store
            .insert_rf_sightings_batch(
                "s1",
                &[sighting(
                    "00:1a:2b:00:00:03",
                    RadioKind::Wifi,
                    None,
                    -50.0,
                    Some((-26.81, 153.08)),
                    1,
                )],
            )
            .expect("insert");
    }

    // Stand in for a database created by an older binary: a view of the same
    // name whose definition answers differently.
    {
        let conn = rusqlite::Connection::open(path).expect("raw open");
        conn.execute_batch(
            "DROP VIEW rf_devices;
             CREATE VIEW rf_devices AS
             SELECT scan_id, network_id, radio, locally_admin, oui, device_class,
                    0 AS sightings, NULL AS first_epoch, NULL AS last_epoch,
                    NULL AS best_signal_dbm, NULL AS worst_signal_dbm,
                    NULL AS best_accuracy_m, 0 AS distinct_names, NULL AS name,
                    NULL AS best_latitude, NULL AS best_longitude,
                    0 AS distinct_fixes
               FROM rf_sightings;
             CREATE VIEW rf_trackable AS
             SELECT * FROM rf_devices WHERE locally_admin = 0;",
        )
        .expect("install a stale view");
    }

    let store = Store::open(path).expect("reopen");
    let d = &store.rf_devices_for_scan("s1").expect("read")[0];
    assert_eq!(
        d.sightings, 1,
        "the reopen must have replaced the stale definition, not kept it"
    );
    assert_eq!((d.best_latitude, d.best_longitude), (Some(-26.81), Some(153.08)));
    // The retired `rf_trackable` view an older binary created is gone too.
    let stale_views: i64 = store
        .conn
        .lock()
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'view' AND name = 'rf_trackable'",
            [],
            |r| r.get(0),
        )
        .expect("sqlite_master");
    assert_eq!(stale_views, 0, "a retired view must be dropped on open, not carried forever");
}

// ─── ble_radar continuity: interruption / partial-persistence recovery ───────
//
// A radar sweep is persisted as ONE transaction (`insert_rf_sightings_batch`),
// so the recovery property for an interrupted sweep is atomicity: the sweep
// commits whole or leaves nothing. These two tests prove the ble_radar
// continuity objective — that an interruption never leaves a half-written,
// misleading device list, that every sweep committed before the fault survives
// (RPO = the last committed sweep), and that the sightings persist across a
// restart. They are cited by `core::assurance::continuity`'s ble_radar objective.

/// FAULT: a sweep is interrupted mid-write because the device ran out of storage
/// partway through persisting it — the Termux low-storage reality the
/// `HSE_SQLITE_MAX_PAGES` cap models, injected exactly as SQLite reports it
/// (SQLITE_FULL). EXPECTED: the failing sweep returns Err (never a silent
/// partial device list); every sweep committed before it stays readable; the
/// store is not corrupted; and freeing the space lets the sweep persist.
#[test]
fn an_interrupted_radar_sweep_is_atomic_and_earlier_sweeps_survive() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("radar.db");
    let path = path.to_str().expect("utf-8 path");
    let store = Store::open(path).expect("open");

    // A completed earlier sweep — committed, must survive the later fault.
    store
        .insert_rf_sightings_batch(
            "sweep-1",
            &[
                sighting("00:1a:2b:00:00:01", RadioKind::Ble, Some("Watch"), -60.0, Some((-26.81, 153.08)), 1),
                sighting("00:1a:2b:00:00:02", RadioKind::Wifi, Some("AP"), -70.0, None, 2),
            ],
        )
        .expect("the earlier sweep commits");

    // Cap the database one page above its current size — the disk is now "full".
    {
        let conn = store.conn.lock();
        let pages: i64 = conn
            .query_row("PRAGMA page_count", [], |r| r.get(0))
            .expect("page_count");
        Store::apply_page_cap(&conn, pages + 1).expect("cap just above current size");
    }

    // A large second sweep cannot fit. It is one transaction, so it must fail
    // WHOLE — never persist the rows that fit and silently drop the rest.
    let big: Vec<RfSighting> = (0..3000u32)
        .map(|i| {
            sighting(
                &format!("00:1a:2b:{:02x}:{:02x}:{:02x}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff),
                RadioKind::Ble,
                Some("Sweep"),
                -50.0,
                Some((-26.8, 153.0)),
                i64::from(i),
            )
        })
        .collect();
    let err = store
        .insert_rf_sightings_batch("sweep-2", &big)
        .expect_err("OBSERVED: an out-of-space sweep must fail loudly, never half-persist");
    assert!(
        err.to_string().to_lowercase().contains("full"),
        "the error must name the fault (database/disk full), got: {err}"
    );

    // ATOMICITY: the interrupted sweep left nothing behind.
    assert!(
        store.rf_devices_for_scan("sweep-2").expect("read").is_empty(),
        "an interrupted sweep must leave NO partial device list"
    );
    assert_eq!(
        store.rf_summary("sweep-2").expect("summary").sightings,
        0,
        "not one sighting from the failed sweep may persist"
    );
    // RPO: the earlier committed sweep is intact, and the store is healthy.
    assert_eq!(store.rf_summary("sweep-1").expect("summary").sightings, 2);
    assert_eq!(store.rf_devices_for_scan("sweep-1").expect("read").len(), 2);
    assert_eq!(
        store.integrity_check().expect("integrity"),
        vec!["ok".to_string()],
        "a full disk mid-sweep must not corrupt the sighting store"
    );

    // RECOVERY: free the space → the sweep persists on the next attempt.
    {
        let conn = store.conn.lock();
        Store::apply_page_cap(&conn, 1_000_000).expect("raise the cap");
    }
    assert_eq!(
        store
            .insert_rf_sightings_batch(
                "sweep-2",
                &[sighting("00:1a:2b:00:00:03", RadioKind::Ble, Some("Retry"), -55.0, None, 9)],
            )
            .expect("the sweep resumes once space is freed"),
        1
    );
    assert_eq!(store.rf_summary("sweep-2").expect("summary").sightings, 1);
}

/// A radar sweep persisted to disk must survive the app being killed and
/// relaunched — the Termux "swipe it away" case. A fresh process reopening the
/// store must read back every committed sighting unchanged (RPO across restart).
#[test]
fn committed_sightings_survive_a_store_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("restart.db");
    let path = path.to_str().expect("utf-8 path");
    {
        let store = Store::open(path).expect("first open");
        store
            .insert_rf_sightings_batch(
                "sweep",
                &[
                    sighting("00:1a:2b:00:00:07", RadioKind::Ble, Some("Watch"), -60.0, Some((-26.81, 153.08)), 100),
                    sighting("00:1a:2b:00:00:07", RadioKind::Ble, Some("Watch"), -50.0, Some((-26.82, 153.09)), 200),
                ],
            )
            .expect("the sweep commits");
    } // the process "exits": the store is dropped and its connection closed.

    // A fresh process reopens the same database file.
    let store = Store::open(path).expect("reopen after restart");
    let devices = store.rf_devices_for_scan("sweep").expect("read");
    assert_eq!(devices.len(), 1, "the committed device survives the restart");
    let d = &devices[0];
    assert_eq!(d.network_id, "00:1a:2b:00:00:07");
    assert_eq!(d.sightings, 2, "both committed sightings survive the restart");
    assert_eq!(d.first_epoch, Some(100));
    assert_eq!(d.last_epoch, Some(200));
    assert_eq!(
        store.rf_latest_scan_id().expect("latest").as_deref(),
        Some("sweep"),
        "the persisted sweep is still the latest after a restart"
    );
}
