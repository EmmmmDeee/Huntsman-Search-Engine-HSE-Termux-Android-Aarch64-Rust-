//! The stripper over hand-built images that carry what cameras and editors embed. Each test first
//! shows the `exif` or `docmeta` reader finds the metadata in the original, then that the
//! stripped image keeps its picture and holds none of it.

use super::super::test_images::{
    GPS, gps_tiff, jpeg_picture, jpeg_with_metadata, plain_jpeg, png_chunk, png_picture,
    png_with_metadata, segment, vp8, vp8x, webp, webp_chunk, webp_with_metadata,
};
use super::{Format, strip};

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The `exif` reader's fields and GPS position, and the `docmeta` reader's fields.
fn metadata(image: &[u8]) -> (usize, bool, usize) {
    let exif = crate::exif::parse(image).expect("a readable image");
    (
        exif.fields.len(),
        exif.gps.is_some(),
        crate::docmeta::parse(image).fields.len(),
    )
}

#[test]
fn a_jpeg_loses_exif_gps_xmp_iptc_comments_and_its_appended_preview_and_keeps_its_picture() {
    let original = jpeg_with_metadata();
    let gps = crate::exif::parse(&original).unwrap().gps.expect("GPS");
    assert!((gps.lat - GPS.0).abs() < 1e-9 && (gps.lon - GPS.1).abs() < 1e-9);
    let (_, _, docmeta) = metadata(&original);
    assert!(docmeta > 0, "the fixture's XMP and IPTC are found");

    let stripped = strip(&original, Format::Jpeg).unwrap();
    let out = &stripped.bytes;
    assert!(out.starts_with(&[0xFF, 0xD8]), "starts with SOI");
    assert!(out.ends_with(&[0xFF, 0xD9]), "ends with EOI");
    assert_eq!(metadata(out), (0, false, 0));
    for marker in [
        &b"Exif\0\0"[..],
        b"http://ns.adobe.com/xap/1.0/",
        b"<x:xmpmeta",
    ] {
        assert!(!holds(out, marker), "{}", String::from_utf8_lossy(marker));
    }
    for gone in [
        &b"Photoshop 3.0"[..],
        b"taken at home",
        b"JFIF",
        b"Ada Lovelace",
    ] {
        assert!(!holds(out, gone), "{}", String::from_utf8_lossy(gone));
    }
    // The picture's segments, scan data included, are kept byte for byte, with the Adobe
    // colour transform before them, and nothing follows the first end of image.
    let mut expected = vec![0xFF, 0xD8];
    expected.extend(segment(0xEE, b"Adobe\0\x64\0\0\0\0\x01"));
    expected.extend(jpeg_picture());
    expected.extend_from_slice(&[0xFF, 0xD9]);
    assert_eq!(out, &expected);
    assert_eq!(
        stripped.removed,
        ["APP0", "APP1", "APP13", "COM", "trailing data"]
    );
}

#[test]
fn a_jpeg_loses_metadata_between_progressive_scans_and_keeps_both_scans() {
    let mut original = vec![0xFF, 0xD8];
    original.extend(segment(0xDB, &[0x00; 65]));
    original.extend(segment(
        0xC2,
        &[0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00],
    )); // SOF2
    let first_scan = [
        segment(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x00, 0x01]),
        vec![0x11, 0xFF, 0x00],
    ];
    let second_scan = [
        segment(0xDA, &[0x01, 0x01, 0x00, 0x01, 0x3F, 0x10]),
        vec![0x22, 0x33],
    ];
    original.extend(segment(0xC4, &[0x00; 17]));
    original.extend(first_scan.concat());
    original.extend(segment(0xFE, b"between scans"));
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend(gps_tiff());
    original.extend(segment(0xE1, &exif));
    original.extend(segment(0xC4, &[0x10; 17]));
    original.extend(second_scan.concat());
    original.extend_from_slice(&[0xFF, 0xFF, 0xD9]); // a fill byte before EOI

    let stripped = strip(&original, Format::Jpeg).unwrap();
    assert!(!holds(&stripped.bytes, b"between scans"));
    assert!(!holds(&stripped.bytes, b"Exif\0\0"));
    assert!(holds(&stripped.bytes, &first_scan.concat()));
    assert!(holds(&stripped.bytes, &second_scan.concat()));
    assert!(stripped.bytes.ends_with(&[0xFF, 0xD9]));
    assert_eq!(stripped.removed, ["COM", "APP1"]);
}

#[test]
fn a_jpeg_without_metadata_comes_out_unchanged() {
    let original = plain_jpeg();
    let stripped = strip(&original, Format::Jpeg).unwrap();
    assert_eq!(stripped.bytes, original);
    assert!(stripped.removed.is_empty());
}

#[test]
fn a_png_loses_exif_and_text_chunks_and_keeps_its_picture() {
    let original = png_with_metadata();
    let gps = crate::exif::parse(&original).unwrap().gps.expect("GPS");
    assert!((gps.lat - GPS.0).abs() < 1e-9);
    assert!(
        metadata(&original).2 > 0,
        "the fixture's text chunks are found"
    );

    let stripped = strip(&original, Format::Png).unwrap();
    let mut expected = crate::exif::PNG_SIGNATURE.to_vec();
    expected.extend(png_picture().concat());
    assert_eq!(stripped.bytes, expected);
    assert_eq!(metadata(&stripped.bytes), (0, false, 0));
    assert_eq!(
        stripped.removed,
        ["eXIf", "tEXt", "zTXt", "iTXt", "tIME", "trailing data"]
    );
}

#[test]
fn a_png_keeps_its_palette_and_transparency_and_refuses_what_it_cannot_decode_safely() {
    let [header, data, end] = png_picture();
    let palette = png_chunk(*b"PLTE", &[0, 0, 0]);
    let alpha = png_chunk(*b"tRNS", &[0]);
    let gamma = png_chunk(*b"gAMA", &[0, 0, 0xB1, 0x8F]);
    let mut kept = crate::exif::PNG_SIGNATURE.to_vec();
    kept.extend(
        [
            header.clone(),
            palette.clone(),
            alpha.clone(),
            data.clone(),
            end.clone(),
        ]
        .concat(),
    );
    let mut original = crate::exif::PNG_SIGNATURE.to_vec();
    original.extend(
        [
            header.clone(),
            gamma,
            palette,
            alpha,
            data.clone(),
            end.clone(),
        ]
        .concat(),
    );
    let stripped = strip(&original, Format::Png).unwrap();
    assert_eq!(stripped.bytes, kept);
    assert_eq!(stripped.removed, ["gAMA"]);

    let refused = |chunks: &[Vec<u8>]| {
        let mut file = crate::exif::PNG_SIGNATURE.to_vec();
        file.extend(chunks.concat());
        strip(&file, Format::Png).is_err()
    };
    let critical = png_chunk(*b"ABCD", b"needed to decode");
    assert!(refused(&[
        header.clone(),
        critical,
        data.clone(),
        end.clone()
    ]));
    assert!(refused(&[header.clone(), data.clone()]), "no IEND");
    assert!(refused(&[header.clone(), end.clone()]), "no image data");
    assert!(
        refused(&[data.clone(), header.clone(), end.clone()]),
        "IHDR not first"
    );
    let mut cut = crate::exif::PNG_SIGNATURE.to_vec();
    cut.extend([header, data].concat());
    cut.truncate(cut.len() - 3);
    assert!(strip(&cut, Format::Png).is_err(), "a truncated chunk");
}

#[test]
fn a_webp_loses_exif_xmp_and_its_profile_and_its_flags_say_so() {
    let original = webp_with_metadata();
    let gps = crate::exif::parse(&original).unwrap().gps.expect("GPS");
    assert!((gps.lon - GPS.1).abs() < 1e-9);
    assert!(metadata(&original).2 > 0, "the fixture's XMP is found");

    let stripped = strip(&original, Format::WebP).unwrap();
    let out = &stripped.bytes;
    assert_eq!(out, &webp(&[vp8x(0x00), vp8()]));
    let size = u32::from_le_bytes(out[4..8].try_into().unwrap());
    assert_eq!(usize::try_from(size).unwrap(), out.len() - 8);
    assert_eq!(
        out[20] & (0x20 | 0x08 | 0x04),
        0,
        "ICC, Exif and XMP flags clear"
    );
    assert_eq!(metadata(out), (0, false, 0));
    assert!(!holds(out, b"EXIF") && !holds(out, b"XMP ") && !holds(out, b"ICCP"));
    assert_eq!(stripped.removed, ["ICCP", "EXIF", "XMP", "trailing data"]);
}

#[test]
fn a_webp_keeps_its_alpha_and_refuses_animation_and_extra_pictures() {
    let alpha = webp_chunk(*b"ALPH", b"\0alpha");
    let original = webp(&[vp8x(0x10), alpha.clone(), vp8()]);
    let stripped = strip(&original, Format::WebP).unwrap();
    assert_eq!(stripped.bytes, original);
    assert!(stripped.removed.is_empty());

    for refused in [
        webp(&[vp8x(0x02), webp_chunk(*b"ANIM", &[0; 6]), vp8()]),
        webp(&[vp8x(0x00), webp_chunk(*b"ANMF", &[0; 16])]),
        webp(&[vp8(), vp8()]),
        webp(&[vp8x(0x00)]),
        webp(&[vp8(), vp8x(0x00)]),
        webp(&[webp_chunk(*b"VP8X", &[0; 4]), vp8()]),
    ] {
        assert!(strip(&refused, Format::WebP).is_err());
    }
    let mut cut = webp(&[vp8x(0x00), vp8()]);
    cut.truncate(cut.len() - 1);
    assert!(strip(&cut, Format::WebP).is_err(), "a truncated container");
}

#[test]
fn a_gif_and_a_malformed_jpeg_are_refused() {
    assert!(strip(b"GIF89a\x01\x00\x01\x00", Format::Gif).is_err());
    let mut cut = plain_jpeg();
    cut.truncate(cut.len() - 2);
    assert!(strip(&cut, Format::Jpeg).is_err(), "no end of image");
    let mut scan_first = vec![0xFF, 0xD8];
    scan_first.extend(segment(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]));
    scan_first.extend_from_slice(&[0x00, 0xFF, 0xD9]);
    assert!(
        strip(&scan_first, Format::Jpeg).is_err(),
        "a scan before the frame"
    );
    let mut hierarchical = vec![0xFF, 0xD8];
    hierarchical.extend(segment(0xDE, &[0; 5])); // DHP
    hierarchical.extend(jpeg_picture());
    hierarchical.extend_from_slice(&[0xFF, 0xD9]);
    assert!(
        strip(&hierarchical, Format::Jpeg).is_err(),
        "an unsupported marker"
    );
    let mut garbage = plain_jpeg();
    garbage.insert(2, 0x00);
    assert!(
        strip(&garbage, Format::Jpeg).is_err(),
        "bytes between segments"
    );
}

#[test]
fn the_removed_kinds_are_bounded_and_say_when_more_were_removed() {
    let [header, data, end] = png_picture();
    let mut file = crate::exif::PNG_SIGNATURE.to_vec();
    file.extend(header);
    for n in 0..40u8 {
        let kind = [b'p', b'r', b'v', b'A' + (n % 26)];
        let kind = if n >= 26 {
            [b'q', b'r', b'v', b'A' + (n - 26)]
        } else {
            kind
        };
        file.extend(png_chunk(kind, b"private"));
    }
    file.extend([data, end].concat());
    let stripped = strip(&file, Format::Png).unwrap();
    assert_eq!(stripped.removed.len(), super::MAX_REMOVED_KINDS);
    assert_eq!(
        stripped.removed.last().map(String::as_str),
        Some(super::MORE)
    );
}
