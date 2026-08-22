// Tests for the RF sighting model. Addresses here are invented.
//
// Plain `//` rather than `//!`: this file is `include!`d into a `mod tests`
// block (the repo convention that keeps `tests/architecture.rs`'s orphan-file
// check able to see it), where an inner doc comment is not valid.

use super::*;

// ── WiGLE `Type:` classification ─────────────────────────────────────────────

#[test]
fn wigle_type_splits_family_from_device_class() {
    // Every distinct spelling observed in real captures off the device.
    assert_eq!(classify_wigle_type("WIFI"), (RadioKind::Wifi, None));
    assert_eq!(classify_wigle_type("LTE"), (RadioKind::Cellular, None));
    assert_eq!(
        classify_wigle_type("BLEAttributes: Watch;10"),
        (RadioKind::Ble, Some("Watch".to_string()))
    );
    assert_eq!(
        classify_wigle_type("BTAttributes: Display/Speaker;10"),
        (RadioKind::BtClassic, Some("Display/Speaker".to_string()))
    );
    assert_eq!(
        classify_wigle_type("BLEAttributes: Keyboard"),
        (RadioKind::Ble, Some("Keyboard".to_string()))
    );
    assert_eq!(
        classify_wigle_type("BLEAttributes: Misc"),
        (RadioKind::Ble, Some("Misc".to_string()))
    );
}

#[test]
fn a_declined_classification_is_one_value_not_three_spellings() {
    // `Uncategorized` and `null` are the source refusing to classify. Carrying
    // them as classes would make "unclassified" look like three device types.
    assert_eq!(
        classify_wigle_type("BLEAttributes: Uncategorized;10"),
        (RadioKind::Ble, None)
    );
    assert_eq!(
        classify_wigle_type("BLEAttributes: Uncategorized"),
        (RadioKind::Ble, None)
    );
    assert_eq!(
        classify_wigle_type("BTAttributes: null;10"),
        (RadioKind::BtClassic, None)
    );
}

#[test]
fn the_family_is_matched_by_prefix_not_equality() {
    // The app writes `BLEAttributes`, never a bare `BLE`; an equality test
    // classified every Bluetooth record as cellular and dropped its class.
    assert_eq!(classify_wigle_type("BLEAttributes: Misc").0, RadioKind::Ble);
    assert_eq!(classify_wigle_type("bleattributes: misc").0, RadioKind::Ble);
    assert_eq!(classify_wigle_type("wifi").0, RadioKind::Wifi);
}

#[test]
fn a_device_class_is_never_attributed_to_wifi_or_cellular() {
    // Only Bluetooth reports one. A colon in a Wi-Fi or cell type must not be
    // mined into a class.
    assert_eq!(classify_wigle_type("WIFI: something").1, None);
    assert_eq!(classify_wigle_type("GSM: 505").1, None);
}

// ── Address handling ─────────────────────────────────────────────────────────

#[test]
fn is_mac_accepts_only_six_hex_octets() {
    assert!(is_mac("00:1a:2b:3c:4d:5e"));
    assert!(is_mac("00:1A:2B:3C:4D:5E"));
    assert!(!is_mac("00:1a:2b:3c:4d"), "five octets");
    assert!(!is_mac("00:1a:2b:3c:4d:5e:6f"), "seven octets");
    assert!(!is_mac("zz:1a:2b:3c:4d:5e"), "non-hex");
    assert!(!is_mac("501_28693_147572482"), "a cell tuple is not a MAC");
    assert!(!is_mac(""));
}

#[test]
fn canonicalisation_folds_case_for_macs_only() {
    // WiGLE writes BSSIDs uppercase, the local radio lowercase. Without folding
    // one access point becomes two devices.
    assert_eq!(canonical_network_id("00:1A:2B:3C:4D:5E"), "00:1a:2b:3c:4d:5e");
    assert_eq!(canonical_network_id("  00:1A:2B:3C:4D:5E  "), "00:1a:2b:3c:4d:5e");
    // A cell tuple's case is not known to be insignificant, so it is untouched.
    assert_eq!(canonical_network_id("50501_28693_ABC"), "50501_28693_ABC");
}

#[test]
fn address_kind_reads_the_ul_bit_not_a_vendor_table() {
    // `02:` has the locally-administered bit set; `00:` does not. This is the
    // AU-122 distinction, and it works on every MAC — unlike a vendor lookup.
    let fixed = RfSighting::new("00:1a:2b:3c:4d:5e", RadioKind::Wifi, RfSource::WigleKml);
    let rand = RfSighting::new("02:aa:bb:cc:dd:ee", RadioKind::Wifi, RfSource::WigleKml);
    assert_eq!(fixed.address_kind(), AddressKind::Fixed);
    assert_eq!(rand.address_kind(), AddressKind::Randomised);

    // A cellular identifier is not an address and must never be classified as
    // followable hardware.
    let cell = RfSighting::new("50501_28693_147572482", RadioKind::Cellular, RfSource::WigleKml);
    assert_eq!(cell.address_kind(), AddressKind::NotAnAddress);
}

#[test]
fn oui_is_extracted_even_when_no_vendor_is_known_for_it() {
    // Storing the OUI regardless is what lets a larger IEEE table be joined in
    // later without re-reading a capture.
    let s = RfSighting::new("00:1A:2B:3C:4D:5E", RadioKind::Wifi, RfSource::WigleKml);
    assert_eq!(s.oui().as_deref(), Some("001A2B"));
    let cell = RfSighting::new("50501_28693_1", RadioKind::Cellular, RfSource::WigleKml);
    assert_eq!(cell.oui(), None);
}

// ── Position ────────────────────────────────────────────────────────────────

#[test]
fn the_null_island_and_out_of_range_positions_are_not_usable() {
    let mut s = RfSighting::new("00:1a:2b:3c:4d:5e", RadioKind::Wifi, RfSource::WigleKml);
    assert!(!s.has_usable_position(), "no position at all");

    s.latitude = Some(0.0);
    s.longitude = Some(0.0);
    assert!(!s.has_usable_position(), "0,0 is a receiver with no fix");

    s.latitude = Some(91.0);
    s.longitude = Some(10.0);
    assert!(!s.has_usable_position());

    s.latitude = Some(-26.814_468);
    s.longitude = Some(153.086_472);
    assert!(s.has_usable_position());
}

// ── Timestamps ──────────────────────────────────────────────────────────────

#[test]
fn iso8601_parses_utc_and_offsets() {
    assert_eq!(parse_iso8601_epoch("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_iso8601_epoch("2000-01-01T00:00:00Z"), Some(946_684_800));
    // No offset is read as UTC.
    assert_eq!(parse_iso8601_epoch("2000-01-01T00:00:00"), Some(946_684_800));
    // A negative offset is BEHIND UTC, so the instant is LATER than the wall
    // clock reads; getting this sign backwards silently shifts a whole capture.
    assert_eq!(
        parse_iso8601_epoch("2000-01-01T00:00:00-07:00"),
        Some(946_684_800 + 7 * 3600)
    );
    assert_eq!(
        parse_iso8601_epoch("2000-01-01T00:00:00+05:30"),
        Some(946_684_800 - (5 * 3600 + 1800))
    );
    // Fractional seconds are accepted and ignored; the offset still parses.
    assert_eq!(
        parse_iso8601_epoch("2000-01-01T00:00:00.000-07:00"),
        Some(946_684_800 + 7 * 3600)
    );
    // Compact offset spelling.
    assert_eq!(
        parse_iso8601_epoch("2000-01-01T00:00:00-0700"),
        Some(946_684_800 + 7 * 3600)
    );
}

#[test]
fn epoch_ordering_beats_lexicographic_ordering_across_offsets() {
    // The reason the epoch column exists. As text, the -07:00 stamp sorts
    // first; as instants, it is later. A MIN() over the text would report the
    // wrong first-seen for a capture that crossed a timezone.
    let a = "2026-08-21T16:00:00-07:00"; // 23:00Z
    let b = "2026-08-21T20:00:00+00:00"; // 20:00Z
    assert!(a < b, "precondition: lexicographically a sorts first");
    let (ea, eb) = (
        parse_iso8601_epoch(a).expect("parses"),
        parse_iso8601_epoch(b).expect("parses"),
    );
    assert!(eb < ea, "as instants b is genuinely earlier");
}

#[test]
fn a_leap_day_and_a_century_boundary_land_correctly() {
    // 2000 is a leap year (divisible by 400); 1900 was not. The civil-days
    // algorithm has no special case for either, so pin both.
    assert_eq!(parse_iso8601_epoch("2000-02-29T00:00:00Z"), Some(951_782_400));
    assert_eq!(parse_iso8601_epoch("2024-02-29T12:00:00Z"), Some(1_709_208_000));
}

#[test]
fn a_malformed_stamp_is_none_rather_than_a_guess() {
    // A wrong epoch silently reorders a device's history; an absent one does not.
    for bad in [
        "",
        "not a date",
        "2026-08-21",
        "2026/08/21T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-08-32T00:00:00Z",
        "2026-08-21T24:00:00Z",
        "2026-08-21T00:60:00Z",
        "2026-08-21T00:00:00~07:00",
        "2026-08-21T00:00:00-7:00",
        "2026-08-21T00:00:00-25:00",
    ] {
        assert_eq!(parse_iso8601_epoch(bad), None, "{bad:?} must not parse");
    }
}

#[test]
fn round_trips_through_the_db_string_forms() {
    for r in [
        RadioKind::Wifi,
        RadioKind::Ble,
        RadioKind::BtClassic,
        RadioKind::Cellular,
    ] {
        assert_eq!(RadioKind::from_db_str(r.as_db_str()), r);
    }
    for s in [
        RfSource::WigleKml,
        RfSource::WigleApi,
        RfSource::BluetoothRadar,
        RfSource::WifiRadar,
    ] {
        assert_eq!(RfSource::from_db_str(s.as_db_str()), s);
    }
    assert!(RfSource::BluetoothRadar.is_local_sensor());
    assert!(!RfSource::WigleApi.is_local_sensor());
    assert!(RadioKind::Wifi.has_hardware_address());
    assert!(!RadioKind::Cellular.has_hardware_address());
}
