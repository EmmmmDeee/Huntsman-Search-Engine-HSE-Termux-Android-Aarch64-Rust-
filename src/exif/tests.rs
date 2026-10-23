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

/// One PNG chunk: big-endian length, type, body and a CRC this parser does not check.
fn png_chunk(png: &mut Vec<u8>, kind: [u8; 4], body: &[u8]) {
    png.extend_from_slice(&u32::try_from(body.len()).unwrap().to_be_bytes());
    png.extend_from_slice(&kind);
    png.extend_from_slice(body);
    png.extend_from_slice(&[0; 4]);
}

/// A PNG whose `eXIf` chunk carries [`exif_tiff`], optionally after the `Exif\0\0` signature some
/// writers add.
fn exif_png(prefixed: bool) -> Vec<u8> {
    let mut payload = if prefixed {
        b"Exif\x00\x00".to_vec()
    } else {
        Vec::new()
    };
    payload.extend_from_slice(&exif_tiff());
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png_chunk(&mut png, *b"IHDR", &[0; 13]);
    png_chunk(&mut png, *b"tEXt", b"Comment\0hello");
    png_chunk(&mut png, *b"eXIf", &payload);
    png_chunk(&mut png, *b"IEND", &[]);
    png
}

#[test]
fn reads_exif_and_gps_from_a_png_exif_chunk() {
    for prefixed in [false, true] {
        let parsed = parse(&exif_png(prefixed)).expect("valid PNG eXIf");
        assert_eq!(parsed.format, "PNG");
        let gps = parsed.gps.expect("PNG GPS fix");
        assert!((gps.lat - 48.85).abs() < 1e-6);
        assert!((gps.lon - 2.333_333).abs() < 1e-5);
    }
    match run(&exif_png(false), "shot.png", 1) {
        ExifRun::Printed { report, .. } => assert!(
            report
                .entities
                .iter()
                .any(|entity| entity.kind == EntityKind::Coordinates)
        ),
        ExifRun::Network(error) | ExifRun::Failed(error) => panic!("{error}"),
    }
}

#[test]
fn a_png_without_exif_is_clean_and_truncation_is_rejected() {
    let mut clean = b"\x89PNG\r\n\x1a\n".to_vec();
    png_chunk(&mut clean, *b"IHDR", &[0; 13]);
    png_chunk(&mut clean, *b"IEND", &[]);
    let parsed = parse(&clean).expect("PNG with no eXIf chunk");
    assert_eq!(parsed.format, "PNG");
    assert!(parsed.fields.is_empty() && parsed.gps.is_none());
    // A chunk that claims more bytes than the file holds is malformed, not a clean absence.
    let mut broken = exif_png(false);
    broken.truncate(broken.len() - 30);
    assert!(parse(&broken).is_err());
}

#[test]
fn a_png_exif_chunk_is_found_however_many_chunks_come_first() {
    // libpng writes 8 KiB IDAT chunks, so a large PNG has thousands of chunks, and an eXIf may
    // follow them; private chunks may come before it too. The walk is bounded by the file.
    let mut after_idat = b"\x89PNG\r\n\x1a\n".to_vec();
    png_chunk(&mut after_idat, *b"IHDR", &[0; 13]);
    for _ in 0..5000 {
        png_chunk(&mut after_idat, *b"IDAT", &[0; 8]);
    }
    png_chunk(&mut after_idat, *b"eXIf", &exif_tiff());
    png_chunk(&mut after_idat, *b"IEND", &[]);
    let gps = parse(&after_idat)
        .expect("valid PNG")
        .gps
        .expect("GPS after 5000 IDATs");
    assert!((gps.lat - 48.85).abs() < 1e-6);
}

#[test]
fn a_small_hostile_tiff_cannot_render_into_a_huge_report() {
    // 4096 directory entries, each a 4096-number SHORT array, all pointing at the same 8 KiB: a
    // 57 KB file that rendered every array in full came to some 235 MB of text.
    let n: u16 = 4096;
    let data = 8 + 2 + u32::from(n) * 12 + 4;
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&8_u32.to_le_bytes());
    tiff.extend_from_slice(&n.to_le_bytes());
    for tag in 0..n {
        tiff.extend_from_slice(&(0x1000 + tag).to_le_bytes());
        tiff.extend_from_slice(&3_u16.to_le_bytes());
        tiff.extend_from_slice(&4096_u32.to_le_bytes());
        tiff.extend_from_slice(&data.to_le_bytes());
    }
    tiff.extend_from_slice(&0_u32.to_le_bytes());
    tiff.extend(std::iter::repeat_n(0xFF_u8, 8192));
    let parsed = parse(&tiff).expect("a readable TIFF");
    assert!(parsed.fields.len() <= crate::exif::MAX_METADATA_FIELDS);
    let rendered: usize = parsed.fields.iter().map(|(k, v)| k.len() + v.len()).sum();
    assert!(rendered <= 5 * 1024 * 1024, "{rendered} bytes of fields");
    assert!(
        parsed
            .fields
            .iter()
            .all(|(_, v)| v.len() <= crate::exif::MAX_METADATA_VALUE_BYTES)
    );
}

/// A little-endian TIFF whose IFD0 holds `junk` private SHORT tags, then a pointer to an Exif IFD
/// (a capture time) and to the GPS IFD of [`exif_tiff`] at 48.85N, 2.3333E.
fn crowded_tiff(junk: u16) -> Vec<u8> {
    let ifd0 = 8u32;
    let ifd0_len = 2 + (u32::from(junk) + 2) * 12 + 4;
    let exif_ifd = ifd0 + ifd0_len;
    let gps_ifd = exif_ifd + 2 + 12 + 4;
    let heap = gps_ifd + 2 + 4 * 12 + 4;
    let (when_at, lat_at) = (heap, heap + 20);
    let lon_at = lat_at + 24;
    let mut t = b"II".to_vec();
    t.extend_from_slice(&le16(42));
    t.extend_from_slice(&le32(ifd0));
    t.extend_from_slice(&le16(junk + 2));
    for tag in 0..junk {
        push_entry(&mut t, 0xC000 + tag, 3, 1, inline(&le16(7)));
    }
    push_entry(&mut t, 0x8769, 4, 1, le32(exif_ifd));
    push_entry(&mut t, 0x8825, 4, 1, le32(gps_ifd));
    t.extend_from_slice(&le32(0));
    t.extend_from_slice(&le16(1));
    push_entry(&mut t, 0x9003, 2, 20, le32(when_at)); // DateTimeOriginal
    t.extend_from_slice(&le32(0));
    t.extend_from_slice(&le16(4));
    push_entry(&mut t, 0x0001, 2, 2, inline(b"N\0"));
    push_entry(&mut t, 0x0002, 5, 3, le32(lat_at));
    push_entry(&mut t, 0x0003, 2, 2, inline(b"E\0"));
    push_entry(&mut t, 0x0004, 5, 3, le32(lon_at));
    t.extend_from_slice(&le32(0));
    t.extend_from_slice(b"2026:10:01 12:34:56\0");
    push_rationals(&mut t, &[(48, 1), (51, 1), (0, 1)]);
    push_rationals(&mut t, &[(2, 1), (20, 1), (0, 1)]);
    t
}

#[test]
fn a_crowded_first_directory_never_hides_the_camera_and_gps_fields() {
    let parsed = parse(&crowded_tiff(1000)).expect("a readable TIFF");
    assert!(parsed.fields.len() <= crate::exif::MAX_METADATA_FIELDS);
    let names: Vec<&str> = parsed
        .fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert!(
        names.iter().any(|name| name.contains("DateTimeOriginal")),
        "{names:?}"
    );
    assert!(
        names.iter().any(|name| name.starts_with("GPSLatitude")),
        "{names:?}"
    );
    // What was not kept is counted, and said.
    assert_eq!(parsed.fields.len() + parsed.omitted, 1000 + 1 + 4);
    match run(&crowded_tiff(1000), "crowded.tif", 1) {
        ExifRun::Printed { report, .. } => {
            let document = &report.entities[0].evidence[0];
            assert!(
                document.summary.contains("not kept"),
                "{}",
                document.summary
            );
            assert!(document.attributes.contains_key("exif_fields_omitted"));
        }
        ExifRun::Network(error) | ExifRun::Failed(error) => panic!("{error}"),
    }
    // A file within the bound keeps everything and says nothing about omissions.
    let small = parse(&crowded_tiff(10)).expect("a readable TIFF");
    assert_eq!((small.fields.len(), small.omitted), (15, 0));
}

#[test]
fn a_value_of_control_bytes_renders_within_the_bound() {
    // 512 ASCII tags all pointing at the same 8 KiB of 0x01: each byte renders as `\u{1}`, so a
    // bound on raw bytes let a 14 KB file render some 21 MB.
    let n: u16 = 512;
    let data = 8 + 2 + u32::from(n) * 12 + 4;
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&8_u32.to_le_bytes());
    tiff.extend_from_slice(&n.to_le_bytes());
    for tag in 0..n {
        push_entry(&mut tiff, 0x1000 + tag, 2, 8192, le32(data));
    }
    tiff.extend_from_slice(&0_u32.to_le_bytes());
    tiff.extend(std::iter::repeat_n(0x01_u8, 8192));
    match run(&tiff, "controls.tif", 1) {
        ExifRun::Printed { text, .. } => {
            assert!(
                text.len() <= 6 * 1024 * 1024,
                "{} bytes rendered",
                text.len()
            );
        }
        ExifRun::Network(error) | ExifRun::Failed(error) => panic!("{error}"),
    }
}

#[test]
fn a_long_number_array_shows_whole_numbers_and_how_many_there_are() {
    // A 4096-value SHORT array renders past the value bound: only whole numbers are shown, then
    // the count, never a number cut part way through.
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&8_u32.to_le_bytes());
    tiff.extend_from_slice(&1_u16.to_le_bytes());
    push_entry(&mut tiff, 0x0111, 3, 4096, le32(8 + 2 + 12 + 4)); // StripOffsets
    tiff.extend_from_slice(&0_u32.to_le_bytes());
    for _ in 0..4096 {
        tiff.extend_from_slice(&le16(12345));
    }
    let parsed = parse(&tiff).expect("a readable TIFF");
    let (_, value) = &parsed.fields[0];
    assert!(value.len() <= crate::exif::MAX_METADATA_VALUE_BYTES);
    let (shown, count) = value.rsplit_once(" \u{2026} ").expect("a cut list says so");
    assert_eq!(count, "(4096 values)");
    assert!(shown.split(", ").all(|number| number == "12345"), "{shown}");
}

#[test]
fn png_chunks_require_the_complete_crc_field() {
    // CRC presence is structural; checksum verification is a separate concern.
    for kind in [b"IHDR", b"IEND", b"eXIf"] {
        let mut full = b"\x89PNG\r\n\x1a\n".to_vec();
        full.extend_from_slice(&0_u32.to_be_bytes());
        full.extend_from_slice(kind);
        full.extend_from_slice(&[0_u8; 4]);
        let complete = super::png_chunks(&full)
            .next()
            .expect("one chunk")
            .expect("complete CRC");
        assert_eq!(complete.0, kind);
        for missing in 1..=4 {
            let truncated = &full[..full.len() - missing];
            assert!(
                super::png_chunks(truncated)
                    .next()
                    .expect("truncated chunk")
                    .is_err(),
                "{kind:?}: missing {missing} CRC bytes must be rejected"
            );
        }
    }
}

/// A coordinate past the poles or the antimeridian, or with 60 or more minutes or seconds, names
/// no place, and gives no fix rather than an impossible one.
#[test]
fn an_impossible_gps_coordinate_gives_no_fix() {
    // In `exif_tiff`'s heap the latitude's rationals start at 97 and the longitude's at 121,
    // each degrees, minutes, seconds as numerator then denominator.
    let with = |patches: &[(usize, u32)]| {
        let mut tiff = exif_tiff();
        for &(at, value) in patches {
            tiff[at..at + 4].copy_from_slice(&le32(value));
        }
        parse(&tiff).expect("valid TIFF").gps
    };
    assert!(with(&[(97, 200)]).is_none(), "latitude 200");
    assert!(with(&[(97, 90)]).is_none(), "latitude 90 and 51 minutes");
    assert!(with(&[(105, 60)]).is_none(), "60 minutes");
    assert!(with(&[(113, 60)]).is_none(), "60 seconds");
    assert!(with(&[(121, 181), (129, 0)]).is_none(), "longitude 181");
    let edge = with(&[(97, 90), (105, 0), (121, 180), (129, 0)]).expect("the poles and 180");
    assert!((edge.lat - 90.0).abs() < 1e-9 && (edge.lon - 180.0).abs() < 1e-9);
}

/// Every corruption of a well-formed JPEG, TIFF, WebP and PNG (a byte, an extreme count or
/// offset, a cut, a repeated stretch) is read or refused: none panics.
#[test]
fn a_corrupted_image_is_read_or_refused_never_a_panic() {
    for (name, image) in [
        ("jpeg", exif_jpeg()),
        ("tiff", exif_tiff()),
        ("webp", exif_webp(true)),
        ("png", exif_png(true)),
    ] {
        for (case, bytes) in crate::test_support::mutations(&image, 0x5EED_0E1F, 3_000)
            .into_iter()
            .enumerate()
        {
            let outcome = std::panic::catch_unwind(|| parse(&bytes));
            assert!(outcome.is_ok(), "{name} case {case} panicked");
        }
    }
}
