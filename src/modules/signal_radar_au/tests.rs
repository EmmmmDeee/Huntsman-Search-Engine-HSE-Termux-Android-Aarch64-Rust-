use super::*;
use crate::core::scan::{Target, TargetKind};

#[test]
fn parse_error_returns_empty() {
    // A non-coordinate target value should not panic and should produce no
    // entities. We exercise the parse_coords helper directly to confirm.
    assert!(parse_coords("not-a-coordinate").is_none());
    assert!(parse_coords("abc,def").is_none());
    assert!(parse_coords("").is_none());
    assert!(parse_coords(",").is_none());
}

#[test]
fn accepts_only_coordinates() {
    let m = SignalRadarAu;
    assert!(m.accepts(&Target::new(TargetKind::Coordinates, "-33.8688,151.2093")));
    assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.1.1.1")));
    assert!(!m.accepts(&Target::new(TargetKind::MacAddress, "aa:bb:cc:dd:ee:ff")));
    assert!(!m.accepts(&Target::new(TargetKind::Address, "Sydney")));
}

#[test]
fn empty_db_returns_empty_result() {
    // Open an in-memory SQLite DB (no tables) and confirm the helpers return
    // nothing rather than panicking.
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    let mut result = ModuleResult::new();

    // Neither table exists — both helpers should be silent.
    query_wigle_au(&conn, -33.8688, 151.2093, "test-scan", &mut result);
    query_opencellid_au(&conn, -33.8688, 151.2093, "test-scan", &mut result);

    assert!(result.entities.is_empty());
}

#[test]
fn wigle_au_wifi_row_emits_mac_address_entity() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE wigle_au (
            netid TEXT, kind TEXT, ssid TEXT, lat REAL, lon REAL,
            accuracy TEXT, last_seen TEXT, encryption TEXT, channel TEXT
        );
        INSERT INTO wigle_au VALUES
            ('AA:BB:CC:DD:EE:FF','wifi','TestNet',-33.8688,151.2093,'10','2024-01-01','WPA2','6');",
    )
    .unwrap();

    let mut result = ModuleResult::new();
    query_wigle_au(&conn, -33.8688, 151.2093, "s", &mut result);

    assert_eq!(result.entities.len(), 1);
    let e = &result.entities[0];
    assert_eq!(e.kind, EntityKind::MacAddress);
    assert_eq!(e.value, "AA:BB:CC:DD:EE:FF");
    assert!(e.has_tag("wifi-ap"));
    assert!(e.has_tag("corpus-hit"));
    assert!(e.has_tag("au-corpus"));
}

#[test]
fn opencellid_au_row_emits_device_id_entity() {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE opencellid_au (
            radio TEXT, mcc INTEGER, mnc INTEGER, lac INTEGER, cid INTEGER,
            lat REAL, lon REAL, range_m INTEGER
        );
        INSERT INTO opencellid_au VALUES
            ('LTE',505,1,1234,56789,-33.8688,151.2093,500);",
    )
    .unwrap();

    let mut result = ModuleResult::new();
    query_opencellid_au(&conn, -33.8688, 151.2093, "s", &mut result);

    assert_eq!(result.entities.len(), 1);
    let e = &result.entities[0];
    assert_eq!(e.kind, EntityKind::DeviceId);
    assert_eq!(e.value, "505-1-1234-56789");
    assert!(e.has_tag("cell-tower"));
    assert!(e.has_tag("opencellid"));
    assert!(e.has_tag("radio:lte"));
}

#[test]
fn module_metadata() {
    let m = SignalRadarAu;
    assert_eq!(m.name(), "signal_radar_au");
    assert_eq!(m.priority(), 72);
    assert!(m.is_passive());
    assert_eq!(m.max_timeout_ms(), 5_000);
    assert_eq!(m.attack_techniques(), &["T1591.001", "T1592"]);
}

#[test]
fn parse_coords_valid() {
    let (lat, lon) = parse_coords("-33.8688,151.2093").unwrap();
    assert!((lat - -33.8688f64).abs() < 1e-6);
    assert!((lon - 151.2093f64).abs() < 1e-6);
}
