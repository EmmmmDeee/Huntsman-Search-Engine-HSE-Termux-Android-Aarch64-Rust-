use exif::Value;

use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCategory};
use crate::core::scan::{Target, TargetKind};

use super::ExifGeo;
use super::extract::{clean_owner, device_fingerprint, looks_like_image_url};
use super::parse::{dms_to_decimal, extract_gps, read_str};

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
