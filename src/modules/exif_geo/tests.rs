use exif::Value;

use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCategory};
use crate::core::scan::{Target, TargetKind};

use super::ExifGeo;
use super::extract::{
    altitude_classification, bearing_compass_label, clean_owner, derive_utc_offset,
    device_fingerprint, dop_confidence, looks_like_image_url, speed_motion_tag, utc_offset_label,
};
use super::parse::{
    dms_to_decimal, extract_dop, extract_gps, extract_gps_altitude, extract_gps_bearing,
    extract_gps_speed_kmh, extract_gps_utc_secs, read_str,
};

// ── accepts() URL classifier ────────────────────────────────

#[test]
fn accepts_only_image_urls() {
    let m = ExifGeo;
    let yes = [
        "https://example.com/photo.jpg",
        "https://x.com/img.JPEG",
        "https://cdn.x.com/path/to/file.heic",
        "https://example.com/a/b/c.tiff?w=1024",
        "https://example.com/x.webp#frag",
    ];
    for u in yes {
        assert!(
            m.accepts(&Target::new(TargetKind::Url, u)),
            "expected to accept {u}"
        );
    }
    let no = [
        "https://example.com/page.html",
        "https://example.com/doc.pdf",
        "https://example.com/video.mp4",
        "https://example.com/no-extension",
        "https://example.com/img.png", // PNGs rarely carry EXIF
        "",
    ];
    for u in no {
        assert!(
            !m.accepts(&Target::new(TargetKind::Url, u)),
            "expected to reject {u}"
        );
    }
}

#[test]
fn rejects_non_url_kinds_even_with_image_extension() {
    let m = ExifGeo;
    // Email values shaped like an image URL must NOT route here.
    assert!(!m.accepts(&Target::new(TargetKind::Email, "a@b.jpg")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.jpg")));
}

// ── looks_like_image_url helper ────────────────────────────

#[test]
fn looks_like_image_url_strips_query_and_fragment() {
    assert!(looks_like_image_url("https://a.b/c.jpg?x=1&y=2"));
    assert!(looks_like_image_url("https://a.b/c.jpg#abc"));
    assert!(looks_like_image_url("https://a.b/c.JPG?abc"));
    assert!(!looks_like_image_url("https://a.b/c.html?img=x.jpg"));
}

#[test]
fn looks_like_image_url_case_insensitive() {
    assert!(looks_like_image_url("https://x.com/A.JPG"));
    assert!(looks_like_image_url("https://x.com/A.HeIc"));
}

// ── module metadata ────────────────────────────────────────

#[test]
fn category_is_geo() {
    assert_eq!(ExifGeo.category(), ModuleCategory::Geo);
}

#[test]
fn produces_coordinates_device_and_person() {
    assert_eq!(
        ExifGeo.produces(),
        &[
            EntityKind::Coordinates,
            EntityKind::DeviceId,
            EntityKind::Person
        ]
    );
}

// ── device_fingerprint ─────────────────────────────────────

#[test]
fn fingerprint_requires_a_serial() {
    // No serial → no anchor (make+model alone matches millions of devices).
    assert_eq!(
        device_fingerprint(Some("Apple"), Some("iPhone 13"), None),
        None
    );
    assert_eq!(
        device_fingerprint(Some("Apple"), Some("iPhone 13"), Some("  ")),
        None
    );
    // With a serial, include the human-readable label, else fall back.
    assert_eq!(
        device_fingerprint(Some("Canon"), Some("EOS R5"), Some("123456")).as_deref(),
        Some("Canon EOS R5 s/n 123456")
    );
    assert_eq!(
        device_fingerprint(None, None, Some("SN-XYZ")).as_deref(),
        Some("camera s/n SN-XYZ")
    );
    // Same serial, same anchor → two images of one camera correlate.
    assert_eq!(
        device_fingerprint(Some("Canon"), Some("EOS R5"), Some("123456")),
        device_fingerprint(Some("Canon"), Some("EOS R5"), Some("123456"))
    );
}

// ── clean_owner ────────────────────────────────────────────

#[test]
fn clean_owner_accepts_names_rejects_boilerplate() {
    assert_eq!(
        clean_owner(Some("Jordan Meyers")).as_deref(),
        Some("Jordan Meyers")
    );
    assert_eq!(
        clean_owner(Some("  Erik Lindqvist  ")).as_deref(),
        Some("Erik Lindqvist")
    );
    // Boilerplate / non-identity.
    assert_eq!(clean_owner(None), None);
    assert_eq!(clean_owner(Some("")), None);
    assert_eq!(clean_owner(Some("© 2021 Getty Images")), None);
    assert_eq!(clean_owner(Some("Copyright Acme")), None);
    assert_eq!(clean_owner(Some("shutterstock")), None);
    assert_eq!(clean_owner(Some("unknown")), None);
    assert_eq!(clean_owner(Some("12345")), None); // no letters
}

#[test]
fn priority_places_above_ip_geo_bench() {
    // ip_geo et al sit in the 10–20 range; exif_geo at 28 ranks
    // above so the EXIF lead wins the merge on the same entity.
    assert!(ExifGeo.priority() >= 25);
}

// ── dms_to_decimal ─────────────────────────────────────────

fn rat(num: u32, den: u32) -> exif::Rational {
    exif::Rational { num, denom: den }
}

#[test]
fn dms_zero_zero_zero_is_zero_decimal() {
    let v = Value::Rational(vec![rat(0, 1), rat(0, 1), rat(0, 1)]);
    assert_eq!(dms_to_decimal(&v), Some(0.0));
}

#[test]
fn dms_one_degree_thirty_minutes_is_one_point_five() {
    let v = Value::Rational(vec![rat(1, 1), rat(30, 1), rat(0, 1)]);
    let d = dms_to_decimal(&v).unwrap();
    assert!((d - 1.5).abs() < 1e-9);
}

#[test]
fn dms_with_fractional_seconds() {
    // 27° 28' 35.76" → 27.476600
    let v = Value::Rational(vec![rat(27, 1), rat(28, 1), rat(3576, 100)]);
    let d = dms_to_decimal(&v).unwrap();
    assert!((d - 27.476600).abs() < 1e-4, "got {d}");
}

#[test]
fn dms_rejects_non_rational_values() {
    let v = Value::Byte(vec![1, 2, 3]);
    assert!(dms_to_decimal(&v).is_none());
}

#[test]
fn dms_rejects_truncated_input() {
    let v = Value::Rational(vec![rat(1, 1), rat(0, 1)]); // only D, M
    assert!(dms_to_decimal(&v).is_none());
}

#[test]
fn dms_rejects_division_by_zero() {
    // 1/0 D should produce non-finite — dms_to_decimal returns None.
    let v = Value::Rational(vec![rat(1, 0), rat(0, 1), rat(0, 1)]);
    assert!(dms_to_decimal(&v).is_none());
}

#[test]
fn shared_validator_rejects_exif_null_island() {
    // Regression: a sensor-zeroed / metadata-stripped image encodes GPS as
    // the 0/1,0/1,0/1 DMS triple → decodes to 0.0,0.0. dms_to_decimal still
    // converts each axis to 0.0 (it's just arithmetic), but extract_gps now
    // rejects the resulting Null-Island pair via the shared validator, so
    // no false Coordinates entity is emitted.
    assert_eq!(
        dms_to_decimal(&Value::Rational(vec![rat(0, 1), rat(0, 1), rat(0, 1)])),
        Some(0.0)
    );
    assert!(!crate::util::geo::is_valid_coords(0.0, 0.0));
    // A real fix still passes.
    assert!(crate::util::geo::is_valid_coords(-27.4766, 153.0166));
}

// ── Real EXIF container: extract_gps + read_str end-to-end ──────────────────
// `dms_to_decimal` is unit-tested above on raw `Value::Rational`s, but
// `extract_gps` (N/S/E/W sign handling, GPS-IFD field access) and `read_str`
// (ASCII field, null-trim) only run against a parsed `exif::Exif`. Build the
// smallest container that yields one — a little-endian TIFF (EXIF *is* TIFF) with
// an ImageDescription and a GPS sub-IFD — and drive both helpers through the real
// `exif::Reader`, so a regression in our glue (not kamadak-exif's) fails here.

/// Assemble a minimal little-endian TIFF carrying ImageDescription + a GPS IFD
/// at Brisbane (S 27°28'35.76", E 153°0'59.76" → −27.4766, 153.0166). Offsets are
/// fixed by the layout below; each value >4 bytes lives in the trailing data area.
fn build_gps_tiff() -> Vec<u8> {
    // Layout (byte offsets): header 0..8 · IFD0 8..38 · GPS IFD 38..92 ·
    // data area 92.. (ImageDescription string, then the two 3-rational arrays).
    const IFD0: u32 = 8;
    const GPS_IFD: u32 = 38;
    const DESC_OFF: u32 = 92; // "HSE GPS fixture\0" (16 bytes) → 92..108
    const LAT_OFF: u32 = 108; // 3 rationals (24 bytes) → 108..132
    const LON_OFF: u32 = 132; // 3 rationals (24 bytes) → 132..156

    let mut b: Vec<u8> = Vec::new();
    // TIFF header: "II", 42, offset of IFD0.
    b.extend_from_slice(b"II");
    b.extend_from_slice(&42u16.to_le_bytes());
    b.extend_from_slice(&IFD0.to_le_bytes());

    // One 12-byte IFD entry. `inline` is the raw 4-byte value-or-offset field.
    let entry = |tag: u16, typ: u16, count: u32, inline: [u8; 4]| {
        let mut e = Vec::with_capacity(12);
        e.extend_from_slice(&tag.to_le_bytes());
        e.extend_from_slice(&typ.to_le_bytes());
        e.extend_from_slice(&count.to_le_bytes());
        e.extend_from_slice(&inline);
        e
    };
    let off = |o: u32| o.to_le_bytes();

    // IFD0: ImageDescription (ASCII) + GPSInfoIFDPointer (LONG).
    b.extend_from_slice(&2u16.to_le_bytes()); // entry count
    b.extend_from_slice(&entry(0x010E, 2, 16, off(DESC_OFF))); // ImageDescription
    b.extend_from_slice(&entry(0x8825, 4, 1, off(GPS_IFD))); // GPSInfoIFDPointer
    b.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = none
    debug_assert_eq!(b.len() as u32, GPS_IFD);

    // GPS IFD: refs are ASCII(2) and fit inline; lat/lon are RATIONAL(5) arrays.
    b.extend_from_slice(&4u16.to_le_bytes()); // entry count
    b.extend_from_slice(&entry(0x0001, 2, 2, *b"S\0\0\0")); // GPSLatitudeRef
    b.extend_from_slice(&entry(0x0002, 5, 3, off(LAT_OFF))); // GPSLatitude
    b.extend_from_slice(&entry(0x0003, 2, 2, *b"E\0\0\0")); // GPSLongitudeRef
    b.extend_from_slice(&entry(0x0004, 5, 3, off(LON_OFF))); // GPSLongitude
    b.extend_from_slice(&0u32.to_le_bytes()); // next-IFD = none
    debug_assert_eq!(b.len() as u32, DESC_OFF);

    // Data area. ImageDescription (16 bytes incl. trailing NUL).
    b.extend_from_slice(b"HSE GPS fixture\0");
    debug_assert_eq!(b.len() as u32, LAT_OFF);
    // GPSLatitude  = 27/1, 28/1, 3576/100   (→ 27.4766)
    for (num, den) in [(27u32, 1u32), (28, 1), (3576, 100)] {
        b.extend_from_slice(&num.to_le_bytes());
        b.extend_from_slice(&den.to_le_bytes());
    }
    debug_assert_eq!(b.len() as u32, LON_OFF);
    // GPSLongitude = 153/1, 0/1, 5976/100   (→ 153.0166)
    for (num, den) in [(153u32, 1u32), (0, 1), (5976, 100)] {
        b.extend_from_slice(&num.to_le_bytes());
        b.extend_from_slice(&den.to_le_bytes());
    }
    b
}

fn read_fixture_exif() -> exif::Exif {
    let bytes = build_gps_tiff();
    exif::Reader::new()
        .read_from_container(&mut std::io::Cursor::new(&bytes))
        .expect("hand-built TIFF must parse as an EXIF container")
}

#[test]
fn extract_gps_decodes_southern_western_refs() {
    let exif = read_fixture_exif();
    let (lat, lon) = extract_gps(&exif).expect("GPS IFD must yield a coordinate");
    // S ref negates latitude; E ref leaves longitude positive.
    assert!((lat - -27.4766).abs() < 1e-3, "lat = {lat}");
    assert!((lon - 153.0166).abs() < 1e-3, "lon = {lon}");
    // Sanity: it passes the shared validator (real fix, not Null Island).
    assert!(crate::util::geo::is_valid_coords(lat, lon));
}

#[test]
fn read_str_reads_and_trims_ascii_field() {
    let exif = read_fixture_exif();
    assert_eq!(
        read_str(&exif, exif::Tag::ImageDescription).as_deref(),
        Some("HSE GPS fixture"),
        "ImageDescription ASCII field, trailing NUL trimmed"
    );
    // A tag absent from the fixture yields None, not an empty string.
    assert_eq!(read_str(&exif, exif::Tag::Make), None);
}

// ── dop_confidence ─────────────────────────────────────────────────────────────

#[test]
fn dop_confidence_boundary_values() {
    // At and below the ideal knot → 0.95.
    let c = dop_confidence(1.0).unwrap();
    assert!((c - 0.95).abs() < 1e-9, "DOP 1.0 → {c}");
    let c = dop_confidence(0.5).unwrap();
    assert!((c - 0.95).abs() < 1e-9, "DOP 0.5 → {c}");
    // At the poor knot → 0.65.
    let c = dop_confidence(15.0).unwrap();
    assert!((c - 0.65).abs() < 1e-9, "DOP 15.0 → {c}");
    let c = dop_confidence(99.0).unwrap();
    assert!((c - 0.65).abs() < 1e-9, "DOP 99.0 → {c}");
}

#[test]
fn dop_confidence_interpolates() {
    // DOP 2.0 → exactly 0.90.
    let c = dop_confidence(2.0).unwrap();
    assert!((c - 0.90).abs() < 1e-9, "DOP 2.0 → {c}");
    // DOP 3.0 midpoint between knots (2→0.90, 4→0.82) → 0.86.
    let c = dop_confidence(3.0).unwrap();
    assert!((c - 0.86).abs() < 1e-6, "DOP 3.0 → {c}");
}

#[test]
fn dop_confidence_rejects_non_finite() {
    assert!(dop_confidence(f64::NAN).is_none());
    assert!(dop_confidence(f64::INFINITY).is_none());
}

// ── altitude_classification ────────────────────────────────────────────────────

#[test]
fn altitude_classification_labels() {
    assert_eq!(altitude_classification(0.0), ("ground-level", false));
    assert_eq!(altitude_classification(-10.0), ("ground-level", false));
    assert_eq!(altitude_classification(4.9), ("ground-level", false));
    assert_eq!(altitude_classification(5.0), ("low-elevated", false));
    assert_eq!(altitude_classification(29.9), ("low-elevated", false));
    assert_eq!(altitude_classification(30.0), ("elevated", true));
    assert_eq!(altitude_classification(149.9), ("elevated", true));
    assert_eq!(altitude_classification(150.0), ("airborne", true));
    assert_eq!(altitude_classification(10_000.0), ("airborne", true));
}

// ── speed_motion_tag ───────────────────────────────────────────────────────────

#[test]
fn speed_motion_tag_buckets() {
    assert_eq!(speed_motion_tag(0.0), "stationary");
    assert_eq!(speed_motion_tag(1.9), "stationary");
    assert_eq!(speed_motion_tag(2.0), "walking-pace");
    assert_eq!(speed_motion_tag(14.9), "walking-pace");
    assert_eq!(speed_motion_tag(15.0), "vehicle-slow");
    assert_eq!(speed_motion_tag(59.9), "vehicle-slow");
    assert_eq!(speed_motion_tag(60.0), "vehicle-fast");
    assert_eq!(speed_motion_tag(299.9), "vehicle-fast");
    assert_eq!(speed_motion_tag(300.0), "airborne-speed");
    assert_eq!(speed_motion_tag(900.0), "airborne-speed");
}

// ── bearing_compass_label ──────────────────────────────────────────────────────

#[test]
fn bearing_compass_label_cardinals() {
    assert_eq!(bearing_compass_label(0.0), "N");
    assert_eq!(bearing_compass_label(90.0), "E");
    assert_eq!(bearing_compass_label(180.0), "S");
    assert_eq!(bearing_compass_label(270.0), "W");
}

#[test]
fn bearing_compass_label_intercardinals() {
    assert_eq!(bearing_compass_label(45.0), "NE");
    assert_eq!(bearing_compass_label(135.0), "SE");
    assert_eq!(bearing_compass_label(225.0), "SW");
    assert_eq!(bearing_compass_label(315.0), "NW");
}

#[test]
fn bearing_compass_label_sector_boundaries() {
    // 22.5° is exactly the N/NE boundary; >= 22.5 → NE.
    assert_eq!(bearing_compass_label(22.4), "N");
    assert_eq!(bearing_compass_label(22.5), "NE");
    // 337.5° → N (wraps back).
    assert_eq!(bearing_compass_label(337.5), "N");
    assert_eq!(bearing_compass_label(337.4), "NW");
}

// ── derive_utc_offset ──────────────────────────────────────────────────────────

#[test]
fn derive_utc_offset_aest() {
    // GPS UTC = 00:00:00 (midnight UTC), camera shows 10:00:00 → UTC+10 (AEST).
    let offset = derive_utc_offset(0.0, "2024:03:15 10:00:00").unwrap();
    assert_eq!(offset, 36_000, "expected +10h = 36000s, got {offset}");
}

#[test]
fn derive_utc_offset_negative_west() {
    // GPS UTC = 20:00:00, camera shows 15:00:00 → UTC−5 (EST/PET).
    let gps = 20.0 * 3600.0;
    let offset = derive_utc_offset(gps, "2024:01:01 15:00:00").unwrap();
    assert_eq!(offset, -18_000, "expected −5h = −18000s, got {offset}");
}

#[test]
fn derive_utc_offset_midnight_wrap() {
    // GPS UTC = 23:30:00, camera shows 09:00:00 next day.
    // Raw delta = 9*3600 - 23.5*3600 = -52200 → after wrap: +33 600 → UTC+9:20?
    // Actually 09:30 - 23:30 = -50400 + 86400 = 36000 → UTC+10.
    let gps = 23.5 * 3600.0;
    let offset = derive_utc_offset(gps, "2024:01:02 09:30:00").unwrap();
    assert_eq!(offset, 36_000);
}

#[test]
fn derive_utc_offset_rounds_to_15min() {
    // GPS UTC = 00:00:00, camera shows 05:31:00 — real offset is 5h31m.
    // Nearest 15-min boundary = 5h30m = 19800s.
    let offset = derive_utc_offset(0.0, "2024:06:01 05:31:00").unwrap();
    assert_eq!(offset, 19_800);
}

#[test]
fn derive_utc_offset_rejects_malformed_timestamp() {
    assert!(derive_utc_offset(0.0, "not a date").is_none());
    assert!(derive_utc_offset(0.0, "2024:01:01").is_none()); // no time part
}

// ── utc_offset_label ───────────────────────────────────────────────────────────

#[test]
fn utc_offset_label_known_zones() {
    assert!(utc_offset_label(36_000).contains("AEST"), "AEST offset");
    assert!(utc_offset_label(0).contains("UTC/GMT"), "UTC offset");
    assert!(utc_offset_label(-18_000).contains("EST"), "EST offset");
}

#[test]
fn utc_offset_label_unknown_zone_formats_cleanly() {
    // UTC+05:45 (Nepal is +5:45, but our mapping uses NPT only at +5:30).
    let label = utc_offset_label(20_700); // NPT
    assert!(label.starts_with("UTC+"), "label = {label}");
    // An offset with no known abbreviation.
    let label = utc_offset_label(1_800); // UTC+00:30 — uncommon
    assert_eq!(label, "UTC+00:30");
}

// ── Extended TIFF fixture with DOP, altitude, bearing, speed, timestamp ────────

/// Build a TIFF that adds GPS DOP, Altitude, AltitudeRef, ImgDirection,
/// ImgDirectionRef, Speed, SpeedRef, TimeStamp to the basic GPS fixture.
///
/// All offsets are recomputed for the extended layout.
fn build_extended_gps_tiff() -> Vec<u8> {
    // Layout:
    //   0..8    TIFF header
    //   8..26   IFD0: count(2) + 1 entry(12) + next(4) = 18 bytes
    //  26..152  GPS IFD: count(2) + 10 entries(120) + next(4) = 126 bytes
    // 152..     data area
    const IFD0_OFF: u32 = 8;
    const GPS_IFD_OFF: u32 = 26; // 8 + 18
    const DATA_OFF: u32 = 152; // 26 + 126

    // Data layout inside the data area:
    //   DATA_OFF+0  : GPSLatitude  3 rationals (24 bytes)
    //   DATA_OFF+24 : GPSLongitude 3 rationals (24 bytes)
    //   DATA_OFF+48 : GPSTimeStamp 3 rationals (24 bytes)
    //   DATA_OFF+72 : GPSAltitude  1 rational  (8 bytes)
    //   DATA_OFF+80 : GPSDOP       1 rational  (8 bytes)
    //   DATA_OFF+88 : GPSImgDir    1 rational  (8 bytes)
    //   DATA_OFF+96 : GPSSpeed     1 rational  (8 bytes)
    const LAT_OFF: u32 = DATA_OFF;
    const LON_OFF: u32 = DATA_OFF + 24;
    const TS_OFF: u32 = DATA_OFF + 48;
    const ALT_OFF: u32 = DATA_OFF + 72;
    const DOP_OFF: u32 = DATA_OFF + 80;
    const DIR_OFF: u32 = DATA_OFF + 88;
    // SPD_OFF not used — extended fixture omits GPSSpeed to test None path.

    let mut b: Vec<u8> = Vec::new();
    // TIFF header.
    b.extend_from_slice(b"II");
    b.extend_from_slice(&42u16.to_le_bytes());
    b.extend_from_slice(&IFD0_OFF.to_le_bytes());

    let entry = |tag: u16, typ: u16, count: u32, inline: [u8; 4]| {
        let mut e = Vec::with_capacity(12);
        e.extend_from_slice(&tag.to_le_bytes());
        e.extend_from_slice(&typ.to_le_bytes());
        e.extend_from_slice(&count.to_le_bytes());
        e.extend_from_slice(&inline);
        e
    };
    let off = |o: u32| o.to_le_bytes();
    let rat1 = |o: u32| o.to_le_bytes(); // same as off, for clarity at call sites

    // IFD0: 1 entry (GPSInfoIFDPointer).
    b.extend_from_slice(&1u16.to_le_bytes());
    b.extend_from_slice(&entry(0x8825, 4, 1, off(GPS_IFD_OFF)));
    b.extend_from_slice(&0u32.to_le_bytes()); // next IFD = none
    debug_assert_eq!(b.len() as u32, GPS_IFD_OFF);

    // GPS IFD: 10 entries (sorted by tag per TIFF spec).
    b.extend_from_slice(&10u16.to_le_bytes());
    // 0x0001 GPSLatitudeRef  ASCII 2  "S\0" inline
    b.extend_from_slice(&entry(0x0001, 2, 2, *b"S\0\0\0"));
    // 0x0002 GPSLatitude     RATIONAL 3  → LAT_OFF
    b.extend_from_slice(&entry(0x0002, 5, 3, rat1(LAT_OFF)));
    // 0x0003 GPSLongitudeRef ASCII 2  "E\0" inline
    b.extend_from_slice(&entry(0x0003, 2, 2, *b"E\0\0\0"));
    // 0x0004 GPSLongitude    RATIONAL 3  → LON_OFF
    b.extend_from_slice(&entry(0x0004, 5, 3, rat1(LON_OFF)));
    // 0x0005 GPSAltitudeRef  BYTE 1  0=above inline
    b.extend_from_slice(&entry(0x0005, 1, 1, [0, 0, 0, 0]));
    // 0x0006 GPSAltitude     RATIONAL 1  → ALT_OFF (50 m)
    b.extend_from_slice(&entry(0x0006, 5, 1, rat1(ALT_OFF)));
    // 0x0007 GPSTimeStamp    RATIONAL 3  → TS_OFF (14:30:00 UTC)
    b.extend_from_slice(&entry(0x0007, 5, 3, rat1(TS_OFF)));
    // 0x000b GPSDOP          RATIONAL 1  → DOP_OFF (2.0)
    b.extend_from_slice(&entry(0x000b, 5, 1, rat1(DOP_OFF)));
    // 0x0010 GPSImgDirectionRef ASCII 2 "T\0" inline (True North)
    b.extend_from_slice(&entry(0x0010, 2, 2, *b"T\0\0\0"));
    // 0x0011 GPSImgDirection RATIONAL 1  → DIR_OFF (90.0 = East)
    b.extend_from_slice(&entry(0x0011, 5, 1, rat1(DIR_OFF)));
    b.extend_from_slice(&0u32.to_le_bytes()); // next IFD = none
    debug_assert_eq!(b.len() as u32, DATA_OFF);

    // Data area.
    // GPSLatitude: 27/1, 28/1, 3576/100
    for (n, d) in [(27u32, 1u32), (28, 1), (3576, 100)] {
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
    }
    // GPSLongitude: 153/1, 0/1, 5976/100
    for (n, d) in [(153u32, 1u32), (0, 1), (5976, 100)] {
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
    }
    // GPSTimeStamp: 14/1, 30/1, 0/1 (14:30:00 UTC)
    for (n, d) in [(14u32, 1u32), (30, 1), (0, 1)] {
        b.extend_from_slice(&n.to_le_bytes());
        b.extend_from_slice(&d.to_le_bytes());
    }
    // GPSAltitude: 50/1 (50 m)
    b.extend_from_slice(&50u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    // GPSDOP: 2/1 (DOP=2.0)
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    // GPSImgDirection: 90/1 (East)
    b.extend_from_slice(&90u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b
}

fn read_extended_exif() -> exif::Exif {
    let bytes = build_extended_gps_tiff();
    exif::Reader::new()
        .read_from_container(&mut std::io::Cursor::new(&bytes))
        .expect("extended TIFF must parse")
}

#[test]
fn extended_fixture_parses_altitude() {
    let exif = read_extended_exif();
    let alt = extract_gps_altitude(&exif).expect("altitude must be present");
    assert!((alt - 50.0).abs() < 0.01, "altitude = {alt}");
    assert_eq!(altitude_classification(alt), ("elevated", true));
}

#[test]
fn extended_fixture_parses_dop_and_yields_dop_confidence() {
    let exif = read_extended_exif();
    let dop = extract_dop(&exif).expect("DOP must be present");
    assert!((dop - 2.0).abs() < 0.01, "dop = {dop}");
    let conf = dop_confidence(dop).unwrap();
    assert!((conf - 0.90).abs() < 1e-9, "conf for DOP=2 = {conf}");
}

#[test]
fn extended_fixture_parses_bearing() {
    let exif = read_extended_exif();
    let (deg, is_true) = extract_gps_bearing(&exif).expect("bearing must be present");
    assert!((deg - 90.0).abs() < 0.01, "bearing = {deg}");
    assert!(is_true, "ImgDirectionRef T → true north");
    assert_eq!(bearing_compass_label(deg), "E");
}

#[test]
fn extended_fixture_parses_gps_utc_timestamp() {
    let exif = read_extended_exif();
    let secs = extract_gps_utc_secs(&exif).expect("GPS UTC timestamp must be present");
    // 14*3600 + 30*60 + 0 = 52200
    assert!((secs - 52_200.0).abs() < 0.01, "secs = {secs}");
}

#[test]
fn extended_fixture_gps_speed_absent_returns_none() {
    // The extended fixture deliberately omits GPSSpeed/GPSSpeedRef.
    let exif = read_extended_exif();
    assert!(extract_gps_speed_kmh(&exif).is_none());
}

#[test]
fn timezone_derivation_from_fixture_timestamp() {
    // GPS UTC = 14:30:00. If camera shows "2024:06:15 00:30:00",
    // delta = 0:30 - 14:30 = -14:00 → after wrap +24h = +10h → UTC+10 (AEST).
    let gps_secs = 14.0 * 3600.0 + 30.0 * 60.0;
    let offset = derive_utc_offset(gps_secs, "2024:06:15 00:30:00").unwrap();
    assert_eq!(offset, 36_000, "expected UTC+10, got {offset}");
    let label = utc_offset_label(offset);
    assert!(label.contains("AEST"), "label = {label}");
}
