//! Parser and command tests over hand-built EXIF byte streams, so no binary fixture is committed
//! and the whole JPEG -> TIFF -> GPS path is exercised deterministically.

use super::{EntityKind, ExifArgs, ExifRun, parse, run};

fn le16(value: u16) -> [u8; 2] {
    value.to_le_bytes()
}

fn le32(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// A 4-byte inline value field: the bytes left-justified and zero-padded.
fn inline(bytes: &[u8]) -> [u8; 4] {
    let mut field = [0u8; 4];
    for (slot, byte) in field.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    field
}

fn push_entry(out: &mut Vec<u8>, tag: u16, typ: u16, count: u32, value: [u8; 4]) {
    out.extend_from_slice(&le16(tag));
    out.extend_from_slice(&le16(typ));
    out.extend_from_slice(&le32(count));
    out.extend_from_slice(&value);
}

fn push_rationals(out: &mut Vec<u8>, parts: &[(u32, u32)]) {
    for (num, den) in parts {
        out.extend_from_slice(&le32(*num));
        out.extend_from_slice(&le32(*den));
    }
}

/// A little-endian TIFF with IFD0 (`Make = "ACME"`) and a GPS IFD at 48.85N, 2.3333E.
fn exif_tiff() -> Vec<u8> {
    let ifd0 = 8u32;
    let gps_ifd = 38u32; // header 8 + IFD0 (2 + 2*12 + 4 = 30)
    let heap = 92u32; // + GPS IFD (2 + 4*12 + 4 = 54)
    let make_at = heap; // "ACME\0" (5)
    let lat_at = make_at + 5; // 3 rationals (24)
    let lon_at = lat_at + 24;

    let mut t = Vec::new();
    t.extend_from_slice(b"II");
    t.extend_from_slice(&le16(42));
    t.extend_from_slice(&le32(ifd0));

    // IFD0
    t.extend_from_slice(&le16(2));
    push_entry(&mut t, 0x010F, 2, 5, le32(make_at)); // Make
    push_entry(&mut t, 0x8825, 4, 1, le32(gps_ifd)); // GPS IFD pointer
    t.extend_from_slice(&le32(0));

    // GPS IFD
    t.extend_from_slice(&le16(4));
    push_entry(&mut t, 0x0001, 2, 2, inline(b"N\0")); // GPSLatitudeRef
    push_entry(&mut t, 0x0002, 5, 3, le32(lat_at)); // GPSLatitude
    push_entry(&mut t, 0x0003, 2, 2, inline(b"E\0")); // GPSLongitudeRef
    push_entry(&mut t, 0x0004, 5, 3, le32(lon_at)); // GPSLongitude
    t.extend_from_slice(&le32(0));

    // heap
    t.extend_from_slice(b"ACME\0");
    push_rationals(&mut t, &[(48, 1), (51, 1), (0, 1)]); // 48 + 51/60 = 48.85
    push_rationals(&mut t, &[(2, 1), (20, 1), (0, 1)]); // 2 + 20/60 = 2.3333

    t
}

/// The same TIFF wrapped in a minimal JPEG `APP1 Exif` segment.
fn exif_jpeg() -> Vec<u8> {
    let tiff = exif_tiff();
    let segment_len = u16::try_from(2 + 6 + tiff.len()).unwrap();
    let mut jpeg = vec![0xFF, 0xD8, 0xFF, 0xE1];
    jpeg.extend_from_slice(&segment_len.to_be_bytes());
    jpeg.extend_from_slice(b"Exif\x00\x00");
    jpeg.extend_from_slice(&tiff);
    jpeg.extend_from_slice(&[0xFF, 0xD9]);
    jpeg
}

#[test]
fn reads_gps_and_make_from_a_tiff() {
    let parsed = parse(&exif_tiff()).expect("valid TIFF");
    assert_eq!(parsed.format, "TIFF");
    let gps = parsed.gps.expect("a GPS fix");
    assert!((gps.lat - 48.85).abs() < 1e-6, "lat {}", gps.lat);
    assert!((gps.lon - 2.333_333).abs() < 1e-5, "lon {}", gps.lon);
    assert!(
        parsed
            .fields
            .iter()
            .any(|(k, v)| k == "Make" && v == "ACME"),
        "{:?}",
        parsed.fields
    );
    assert!(parsed.fields.iter().any(|(k, _)| k == "GPSLatitude"));
}

#[test]
fn finds_exif_inside_a_jpeg_wrapper() {
    let parsed = parse(&exif_jpeg()).expect("valid JPEG");
    assert_eq!(parsed.format, "JPEG");
    let gps = parsed.gps.expect("a GPS fix");
    assert!((gps.lat - 48.85).abs() < 1e-6);
}

#[test]
fn a_southern_western_point_is_negative() {
    // Flip the hemisphere refs to S and W in a fresh TIFF.
    let mut tiff = exif_tiff();
    // GPSLatitudeRef inline value starts at the GPS IFD's first entry value field.
    // Entry layout inside GPS IFD (offset 38): count(2) then entries of 12 bytes; the
    // value field of entry 0 is at 38 + 2 + 8 = 48, entry 2 (LonRef) at 38 + 2 + 24 + 8 = 72.
    tiff[48] = b'S';
    tiff[72] = b'W';
    let gps = parse(&tiff).expect("valid TIFF").gps.expect("a GPS fix");
    assert!(gps.lat < 0.0, "lat {}", gps.lat);
    assert!(gps.lon < 0.0, "lon {}", gps.lon);
}

#[test]
fn a_jpeg_without_exif_is_a_clean_empty_result() {
    let jpeg = [0xFF, 0xD8, 0xFF, 0xD9];
    let parsed = parse(&jpeg).expect("a JPEG with no APP1");
    assert_eq!(parsed.format, "JPEG");
    assert!(parsed.fields.is_empty());
    assert!(parsed.gps.is_none());
}

#[test]
fn a_non_image_is_rejected() {
    assert!(parse(b"not an image at all").is_err());
    assert!(parse(&[]).is_err());
}

#[test]
fn run_emits_a_coordinates_entity_and_a_success_report() {
    match run(&exif_jpeg(), "photo.jpg", 1) {
        ExifRun::Printed { text, report } => {
            assert!(text.contains("exif\tsuccess"), "{text}");
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Coordinates),
                "no coordinates entity in {:?}",
                report.entities
            );
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Document),
                "no document entity"
            );
        }
        ExifRun::Network(why) | ExifRun::Failed(why) => panic!("{why}"),
    }
}

#[test]
fn run_on_a_non_image_fails() {
    match run(b"garbage", "x.bin", 1) {
        ExifRun::Failed(_) => {}
        _ => panic!("expected a failure"),
    }
}

#[test]
fn args_parse_one_path_and_reject_the_rest() {
    assert_eq!(
        ExifArgs::parse(&["photo.jpg".into()]).unwrap().label,
        "photo.jpg"
    );
    assert!(ExifArgs::parse(&[]).is_err());
    assert!(ExifArgs::parse(&["a".into(), "b".into()]).is_err());
    assert!(ExifArgs::parse(&["   ".into()]).is_err());
}

fn exif_webp(prefixed: bool) -> Vec<u8> {
    let mut payload = exif_tiff();
    if prefixed {
        let mut wrapped = b"Exif\x00\x00".to_vec();
        wrapped.extend_from_slice(&payload);
        payload = wrapped;
    }
    let padding = payload.len() % 2;
    let riff_size = u32::try_from(4 + 8 + payload.len() + padding).unwrap();
    let mut webp = b"RIFF".to_vec();
    webp.extend_from_slice(&riff_size.to_le_bytes());
    webp.extend_from_slice(b"WEBP");
    webp.extend_from_slice(b"EXIF");
    webp.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    webp.extend_from_slice(&payload);
    if padding != 0 {
        webp.push(0);
    }
    webp
}

#[test]
fn reads_exif_and_gps_from_webp_riff_chunk() {
    for prefixed in [false, true] {
        let parsed = parse(&exif_webp(prefixed)).expect("valid WebP EXIF");
        assert_eq!(parsed.format, "WebP");
        let gps = parsed.gps.expect("WebP GPS fix");
        assert!((gps.lat - 48.85).abs() < 1e-6);
        assert!((gps.lon - 2.333_333).abs() < 1e-5);
    }
}

#[test]
fn webp_without_exif_is_clean_and_truncation_is_rejected() {
    let clean = b"RIFF\x04\x00\x00\x00WEBP";
    let parsed = parse(clean).expect("WebP with no EXIF chunk");
    assert_eq!(parsed.format, "WebP");
    assert!(parsed.fields.is_empty());
    assert!(parsed.gps.is_none());

    let mut broken = exif_webp(false);
    broken.pop();
    assert!(parse(&broken).is_err());
    let mut broken_chunk = exif_webp(false);
    broken_chunk[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse(&broken_chunk).is_err());
}

#[test]
fn webp_gps_becomes_a_coordinates_entity_not_just_metadata_text() {
    match run(&exif_webp(false), "sample.webp", 1) {
        ExifRun::Printed { report, .. } => {
            assert!(
                report
                    .entities
                    .iter()
                    .any(|entity| entity.kind == EntityKind::Coordinates)
            );
        }
        ExifRun::Network(error) | ExifRun::Failed(error) => panic!("{error}"),
    }
}
