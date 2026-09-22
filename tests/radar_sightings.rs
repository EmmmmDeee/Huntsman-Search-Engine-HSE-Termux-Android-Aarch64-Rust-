//! REQ-RADAR-001 — the end-to-end lock: a live radar sweep, through the real
//! router and the real engine, records every reading as a positioned sighting
//! in `rf_sightings`. Before this, the sweep produced entities only, and the
//! table — with its geo index and every analytic on it — was reachable solely
//! through file import.
//!
//! The four Termux tools are scripted (the same shape `tests/reconciler_device.rs`
//! uses) and read through `util::termux::tool_dir_for_tests`, the crate's
//! no-`unsafe` alternative to prepending `PATH`. Only `signal_radar` is
//! registered, so nothing here touches the network.

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use huntsman_search_engine::core::module::Module;
use huntsman_search_engine::core::rf::RadioKind;
use huntsman_search_engine::modules::signal_radar::SignalRadar;
use tower::ServiceExt as _;

fn stub(dir: &Path, name: &str, body: &str) {
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/usr/bin/env bash\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The four Termux tools, scripted once per test binary: `tool_dir_for_tests`
/// pins the directory exactly once per process, so every test in this file
/// shares one set of shims (and the `no-fresh-fix` flag one test writes is
/// visible to the others — which is why the second test asserts nothing that
/// depends on a fix).
fn shims() -> &'static Path {
    static SHIMS: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    let dir = SHIMS.get_or_init(|| {
        let shims = tempfile::tempdir().expect("temp dir");
        stub(
            shims.path(),
            "termux-wifi-scaninfo",
            r#"echo '[{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"LabNet","rssi":-45,"frequency":2437},{"bssid":"11:22:33:44:55:66","rssi":-80,"frequency":5180}]'"#,
        );
        stub(
            shims.path(),
            "termux-bluetooth-scaninfo",
            r#"echo '[{"address":"AA:BB:CC:DD:EE:01","name":"Headphones","type":"classic","bondState":"none"},{"address":"AA:BB:CC:DD:EE:02","name":"Speaker","type":"le","bondState":"none"}]'"#,
        );
        // `-p <provider> -r <request>`: with the `no-fresh-fix` flag present the
        // fresh-lock stages exit 1 and only the `last` (cached-position) stages
        // answer.
        stub(
            shims.path(),
            "termux-location",
            r#"if [ -f "$(dirname "$0")/no-fresh-fix" ] && [ "$4" = "once" ]; then exit 1; fi
echo '{"latitude":-27.4705,"longitude":153.0260,"accuracy":8.0,"provider":"gps"}'"#,
        );
        // The device's own link (`device_sensors`): on LabNet until the
        // `link-down` flag appears, then Android's "no network" answer.
        stub(
            shims.path(),
            "termux-wifi-connectioninfo",
            r#"if [ -f "$(dirname "$0")/link-down" ]; then echo '{"bssid":"02:00:00:00:00:00","ssid":"<unknown ssid>","supplicant_state":"DISCONNECTED"}'; else echo '{"bssid":"AA:BB:CC:DD:EE:FF","ssid":"LabNet","rssi":-45,"ip":"192.168.1.20","link_speed_mbps":433,"supplicant_state":"COMPLETED","frequency_mhz":2437}'; fi"#,
        );
        stub(
            shims.path(),
            "termux-telephony-cellinfo",
            r#"echo '[{"type":"LTE","registered":true,"dbm":-80,"cid":12345,"tac":678,"mcc":"505","mnc":"01"}]'"#,
        );
        assert!(
            huntsman_search_engine::util::termux::tool_dir_for_tests(shims.path().to_path_buf()),
            "this binary pins the tool directory exactly once"
        );
        shims
    });
    dir.path()
}

async fn json_of(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).expect("json body")
}

/// One radar sweep through the real router: `POST /api/v1/radar`, then the
/// scan's terminal status. Returns the scan id.
async fn sweep(app: &axum::Router) -> String {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/radar")
                .header("x-hse-csrf", "1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 202, "the sweep is queued");
    let sid = json_of(resp).await["scan_id"]
        .as_str()
        .expect("scan_id")
        .to_string();
    let mut status = String::new();
    for _ in 0..600 {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/scans/{sid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        status = json_of(resp).await["status"]
            .as_str()
            .unwrap_or("")
            .to_string();
        if !matches!(status.as_str(), "pending" | "running") {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(status, "complete", "the scripted sweep completes");
    sid
}

#[tokio::test]
async fn a_live_radar_sweep_records_every_reading_as_a_positioned_sighting() {
    let shims = shims();

    let (app, store, _state) = common::test_app_with_modules_and_state(
        vec![Arc::new(SignalRadar) as Arc<dyn Module>],
        "radar-sightings",
    );

    // The radar button: no body, no target, the CSRF header every mutating
    // request carries.
    let sid = sweep(&app).await;

    // Every reading became a sighting, positioned by the sweep's own fix.
    let summary = store.rf_summary(&sid).expect("rf_summary");
    assert_eq!(
        summary.sightings, 5,
        "2 APs + 2 Bluetooth + 1 tower: {summary:?}"
    );
    assert_eq!(
        (summary.wifi, summary.ble, summary.bt, summary.cellular),
        (2, 1, 1, 1),
        "{summary:?}"
    );
    assert_eq!(
        summary.with_position, 5,
        "the sweep's fix positions every reading, the tower included: {summary:?}"
    );
    assert_eq!(summary.named, 3, "LabNet, Headphones, Speaker: {summary:?}");

    let devices = store
        .rf_devices_for_scan(&sid)
        .expect("rf_devices_for_scan");
    let ap = devices
        .iter()
        .find(|d| d.network_id == "aa:bb:cc:dd:ee:ff")
        .expect("the named AP is a device row");
    assert_eq!(ap.radio, RadioKind::Wifi);
    assert_eq!(ap.name.as_deref(), Some("LabNet"));
    assert_eq!(ap.best_signal_dbm, Some(-45.0));
    assert_eq!(
        (ap.best_latitude, ap.best_longitude, ap.best_accuracy_m),
        (Some(-27.4705), Some(153.026), Some(8.0))
    );
    let le = devices
        .iter()
        .find(|d| d.network_id == "aa:bb:cc:dd:ee:02")
        .expect("the LE speaker");
    assert_eq!(le.radio, RadioKind::Ble);
    assert!(
        devices.iter().all(|d| d.first_epoch.is_some()),
        "every sighting carries its read time: {devices:?}"
    );

    // The web reader on the same sweep (REQ-RADAR-002): with no id it defaults
    // to the survey just run and reports the store's own totals through the
    // real router; the AP's track carries the level and the sweep's fix.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/radar/signals")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_of(resp).await;
    assert_eq!(body["scan_id"], sid.as_str());
    assert_eq!(body["summary"]["sightings"], 5, "{body}");
    assert_eq!(body["summary"]["with_position"], 5, "{body}");
    assert_eq!(body["count"], 5, "{body}");
    let ap_row = body["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .find(|d| d["network_id"] == "aa:bb:cc:dd:ee:ff")
        .expect("the AP row on the web");
    assert_eq!(ap_row["name"], "LabNet");
    assert_eq!(ap_row["best_signal_dbm"], -45.0);
    // 0xAA carries the U/L bit, so the fixture AP is a locally-administered
    // address and the reader must say so rather than name a vendor for it.
    assert_eq!(ap_row["address"], "random");
    assert!(ap_row["vendor"].is_null(), "{ap_row}");
    assert_eq!(ap_row["radio"], "wifi");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/radar/signals/aa:bb:cc:dd:ee:ff?scan_id={sid}"
                ))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let track = json_of(resp).await;
    assert_eq!(track["count"], 1, "{track}");
    assert_eq!(
        (
            track["sightings"][0]["latitude"].as_f64(),
            track["sightings"][0]["longitude"].as_f64(),
            track["sightings"][0]["signal_dbm"].as_f64(),
        ),
        (Some(-27.4705), Some(153.026), Some(-45.0)),
        "{track}"
    );

    // Second sweep: no fresh lock, only the OS's cached position. The fix
    // entity still exists (tagged last-known); no sighting is positioned by
    // it, because a cached position is not where the devices were heard from.
    std::fs::write(shims.join("no-fresh-fix"), "").unwrap();
    let sid2 = sweep(&app).await;
    let summary = store.rf_summary(&sid2).expect("rf_summary");
    assert_eq!(
        summary.sightings, 5,
        "every reading is still a sighting: {summary:?}"
    );
    assert_eq!(
        summary.with_position, 0,
        "a last-known position never positions a sighting: {summary:?}"
    );
    // And the web reader now follows the newer sweep by default.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/radar/signals")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = json_of(resp).await;
    assert_eq!(body["scan_id"], sid2.as_str(), "{body}");
    assert_eq!(body["summary"]["with_position"], 0, "{body}");
    let entities = store.entities_for_scan(&sid2).expect("entities");
    let fix = entities
        .iter()
        .find(|e| e.kind == huntsman_search_engine::core::entity::EntityKind::Coordinates)
        .expect("the cached fix still yields the Coordinates entity");
    assert!(
        fix.has_tag("fix-age:last-known"),
        "and it says what it is: {:?}",
        fix.tags
    );
}

/// REQ-RADAR-004 — real-time tracking. A continuous radar (one scan per
/// iteration) announces each sweep on the bus and over its SSE stream, and
/// the readings are persisted before the completion event is emitted — the
/// property the Radar view's refresh rests on; across its sweeps the one
/// fixed-address device recurs, with its level, and has a trail.
#[tokio::test]
async fn a_continuous_radar_announces_each_sweep_and_recurrence_builds_across_them() {
    use huntsman_search_engine::core::event::EventKind;
    use huntsman_search_engine::core::live::LiveOptions;
    use huntsman_search_engine::core::scan::{
        RADAR_SENTINEL_COORD_RAW, ScanOptions, Target, TargetKind,
    };

    let _shims = shims();
    let (app, _store, state) = common::test_app_with_modules_and_state(
        vec![Arc::new(SignalRadar) as Arc<dyn Module>],
        "radar-continuous",
    );

    // Subscribe BEFORE the session starts: a broadcast channel does not replay.
    let mut rx = state.bus.subscribe();
    let options: ScanOptions = serde_json::from_value(serde_json::json!({
        "modules": ["signal_radar"], "passive_only": true, "depth": 0, "allow_live_sensors": true
    }))
    .expect("the radar's own scan options");
    let live_id = state.live.start(
        Target::new(TargetKind::Coordinates, RADAR_SENTINEL_COORD_RAW),
        options,
        LiveOptions {
            interval_secs: 1,
            iterations: Some(2),
            radar: true,
        },
    );

    // Two iterations: each a `live_tick` naming its scan, then that scan's
    // `scan_complete` — and at the moment it arrives, the scan's readings are
    // already readable through the web reader.
    let mut ticked: Vec<String> = Vec::new();
    let mut completed: Vec<String> = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(60);
    while completed.len() < 2 {
        let ev = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .expect("two iterations complete within the deadline")
            .expect("the bus stays open");
        match ev.kind {
            EventKind::LiveTick {
                live_id: lid,
                scan_id,
                ..
            } if lid == live_id => ticked.push(scan_id),
            EventKind::ScanComplete { scan_id, .. }
                if state.live.session_owns_scan(&live_id, &scan_id) =>
            {
                let resp = app
                    .clone()
                    .oneshot(
                        Request::builder()
                            .uri(format!("/api/v1/radar/signals?scan_id={scan_id}"))
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    resp.status(),
                    200,
                    "readings are persisted before the event"
                );
                let body = json_of(resp).await;
                assert_eq!(body["summary"]["sightings"], 5, "{body}");
                completed.push(scan_id);
            }
            _ => {}
        }
    }
    assert_eq!(
        ticked, completed,
        "each tick's scan is the one that completed, in order"
    );
    assert_ne!(completed[0], completed[1]);

    // The recurrence review over those sweeps: the one universally-administered
    // address (0x11) recurs with the level it was heard at; the `aa:…` fixtures
    // carry the U/L bit and cannot recur, whatever their names.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/radar/recurring?min=2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let review = json_of(resp).await;
    let macs: Vec<&str> = review["devices"]
        .as_array()
        .expect("devices")
        .iter()
        .map(|d| d["mac"].as_str().unwrap())
        .collect();
    assert_eq!(macs, ["11:22:33:44:55:66"], "{review}");
    assert_eq!(review["devices"][0]["sweeps_seen"], 2);
    assert_eq!(review["devices"][0]["best_signal_dbm"], -80.0);
    assert_eq!(review["legacy_sweeps"], 0, "{review}");

    // Its trail: one point per sweep, oldest first, each naming its sweep.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/radar/devices/11:22:33:44:55:66/track")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let track = json_of(resp).await;
    assert_eq!(
        (track["count"].as_u64(), track["sweeps"].as_u64()),
        (Some(2), Some(2)),
        "{track}"
    );
    let scans: Vec<&str> = track["points"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["scan_id"].as_str().unwrap())
        .collect();
    assert_eq!(
        scans, completed,
        "the trail runs through both sweeps in order"
    );
}

/// REQ-RESILIENCE-002 — the device's own link is a record per sweep, "not
/// connected" included, and the review over two sweeps sees a forced
/// disconnection: off the network while the access point it was on is still
/// heard. `device_sensors` runs beside `signal_radar` here, as in the radar
/// spec; the access points heard come from the sighting table.
#[tokio::test]
async fn a_forced_disconnection_is_seen_across_two_sweeps() {
    use huntsman_search_engine::modules::device_sensors::DeviceSensors;
    let shims = shims();
    let (app, store, _state) = common::test_app_with_modules_and_state(
        vec![
            Arc::new(SignalRadar) as Arc<dyn Module>,
            Arc::new(DeviceSensors) as Arc<dyn Module>,
        ],
        "radar-link",
    );

    // Sweep 1: on LabNet. The record is typed, canonical, and persisted.
    let sid1 = sweep(&app).await;
    let link = store
        .wifi_link_for_scan(&sid1)
        .expect("read")
        .expect("the sweep recorded its link");
    assert!(link.connected, "{link:?}");
    assert_eq!(link.bssid.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    assert_eq!(link.ssid.as_deref(), Some("LabNet"));
    assert_eq!(link.signal_dbm, Some(-45.0));

    // Sweep 2: thrown off, LabNet still heard at −45 by the radar.
    std::fs::write(shims.join("link-down"), "").unwrap();
    let sid2 = sweep(&app).await;
    let link = store
        .wifi_link_for_scan(&sid2)
        .expect("read")
        .expect("off the network is a record too");
    assert!(!link.connected, "{link:?}");

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/radar/disruptions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body = json_of(resp).await;
    assert_eq!(
        (
            body["sweeps"].as_u64(),
            body["connected_sweeps"].as_u64(),
            body["disconnected_sweeps"].as_u64(),
            body["unrecorded_sweeps"].as_u64()
        ),
        (Some(2), Some(1), Some(1), Some(0)),
        "{body}"
    );
    let kinds: Vec<&str> = body["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["forced_disconnect", "outage"], "{body}");
    let forced = &body["findings"][0];
    assert_eq!(forced["bssid"], "aa:bb:cc:dd:ee:ff");
    assert_eq!(forced["ssid"], "LabNet");
    assert_eq!(forced["heard_dbm"], -45.0, "the radar still heard it");
    assert_eq!(forced["scan_id"], sid2.as_str());
    assert!(forced["advice"].as_str().is_some_and(|a| !a.is_empty()));
}
