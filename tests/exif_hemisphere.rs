//! An unsigned EXIF coordinate is not a located point without its own valid hemisphere.
use huntsman_recon::entity::EntityKind;
use huntsman_recon::exif::{self, ExifRun};

fn entry(out: &mut Vec<u8>, tag: u16, typ: u16, count: u32, value: [u8; 4]) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&typ.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&value);
}
fn reference(out: &mut Vec<u8>, tag: u16, bytes: &[u8]) {
    let mut value = [0; 4];
    value[..bytes.len()].copy_from_slice(bytes);
    entry(
        out,
        tag,
        2,
        u32::try_from(bytes.len()).expect("small reference"),
        value,
    );
}
fn fixture(lat_ref: Option<&[u8]>, lon_ref: Option<&[u8]>) -> Vec<u8> {
    let count = 2 + u16::from(lat_ref.is_some()) + u16::from(lon_ref.is_some());
    let gps = 26_u32;
    let heap = gps + 2 + u32::from(count) * 12 + 4;
    let mut out = b"II".to_vec();
    out.extend_from_slice(&42_u16.to_le_bytes());
    out.extend_from_slice(&8_u32.to_le_bytes());
    out.extend_from_slice(&1_u16.to_le_bytes());
    entry(&mut out, 0x8825, 4, 1, gps.to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    if let Some(bytes) = lat_ref {
        reference(&mut out, 1, bytes);
    }
    entry(&mut out, 2, 5, 3, heap.to_le_bytes());
    if let Some(bytes) = lon_ref {
        reference(&mut out, 3, bytes);
    }
    entry(&mut out, 4, 5, 3, (heap + 24).to_le_bytes());
    out.extend_from_slice(&0_u32.to_le_bytes());
    for numerator in [12_u32, 30, 0, 45, 15, 0] {
        out.extend_from_slice(&numerator.to_le_bytes());
        out.extend_from_slice(&1_u32.to_le_bytes());
    }
    out
}
fn assert_unlocated(lat_ref: Option<&[u8]>, lon_ref: Option<&[u8]>) {
    let parsed = exif::parse(&fixture(lat_ref, lon_ref)).expect("valid TIFF envelope");
    assert!(parsed.fields.iter().any(|(key, _)| key == "GPSLatitude"));
    assert!(parsed.fields.iter().any(|(key, _)| key == "GPSLongitude"));
    assert!(
        parsed.gps.is_none(),
        "unsigned coordinate magnitudes cannot imply north or east"
    );
}
#[test]
fn missing_hemispheres_do_not_default_to_north_and_east() {
    assert_unlocated(None, Some(b"E\0"));
    assert_unlocated(Some(b"N\0"), None);
    assert_unlocated(None, None);
}
#[test]
fn unknown_blank_and_wrong_axis_hemispheres_are_not_positions() {
    for bad in [
        b"?\0".as_slice(),
        b"\0".as_slice(),
        b" \0".as_slice(),
        b"s\0".as_slice(),
    ] {
        assert_unlocated(Some(bad), Some(b"E\0"));
        assert_unlocated(Some(b"N\0"), Some(bad));
    }
    assert_unlocated(Some(b"E\0"), Some(b"N\0"));
    assert_unlocated(Some(b"W\0"), Some(b"S\0"));
}
#[test]
fn ambiguous_metadata_is_kept_on_the_document_without_a_coordinates_entity() {
    let bytes = fixture(Some(b"?\0"), Some(b"E\0"));
    let parsed = exif::parse(&bytes).expect("valid TIFF");
    let ExifRun::Printed { report, .. } = exif::run(&bytes, "fixture.tif", 1_000) else {
        panic!("ambiguous GPS must not discard the document");
    };
    let document = report
        .entities
        .iter()
        .find(|e| e.kind == EntityKind::Document)
        .expect("document retained");
    for (key, value) in parsed.fields {
        assert!(
            document.evidence.iter().any(|e| e
                .attributes
                .get(&format!("exif_{key}"))
                .is_some_and(|v| v == &value)),
            "every decoded GPS tag remains evidence"
        );
    }
    assert!(
        !report
            .entities
            .iter()
            .any(|e| e.kind == EntityKind::Coordinates),
        "no position may be invented"
    );
}
#[test]
fn all_four_valid_hemisphere_pairs_keep_their_positions_and_signs() {
    for lat in [b"N\0".as_slice(), b"S\0".as_slice()] {
        for lon in [b"E\0".as_slice(), b"W\0".as_slice()] {
            let parsed = exif::parse(&fixture(Some(lat), Some(lon))).expect("valid TIFF");
            let gps = parsed.gps.expect("a fully specified position");
            assert!((gps.lat.abs() - 12.5).abs() < 1e-9);
            assert!((gps.lon.abs() - 45.25).abs() < 1e-9);
            if lat[0] == b'S' {
                assert!(gps.lat < 0.0);
            } else {
                assert!(gps.lat > 0.0);
            }
            if lon[0] == b'W' {
                assert!(gps.lon < 0.0);
            } else {
                assert!(gps.lon > 0.0);
            }
        }
    }
}
