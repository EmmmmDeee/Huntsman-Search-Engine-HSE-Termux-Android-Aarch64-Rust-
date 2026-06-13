use exif::Value;

use crate::core::scan::{Target, TargetKind};
use crate::core::entity::EntityKind;
use crate::core::module::{Module, ModuleCategory};

use super::ExifGeo;
use super::extract::{clean_owner, device_fingerprint, looks_like_image_url};
use super::parse::dms_to_decimal;

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
