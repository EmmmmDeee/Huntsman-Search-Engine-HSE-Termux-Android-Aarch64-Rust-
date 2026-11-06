//! Hand-built images for the tests that read embedded metadata (reverse-image, the embedded
//! metadata reader), so no binary fixture is committed. Each carries
//! the metadata a camera, a phone or an editor embeds, beside the data a decoder needs.

/// The picture's place in every fixture's GPS block: 48°51'N 2°21'E.
pub const GPS: (f64, f64) = (48.85, 2.35);

/// A little-endian TIFF block whose GPS IFD puts the camera at [`GPS`], as an Exif segment or
/// chunk holds it.
pub fn gps_tiff() -> Vec<u8> {
    fn entry(out: &mut Vec<u8>, tag: u16, kind: u16, count: u32, value: [u8; 4]) {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&value);
    }
    // Header (8), IFD0 at 8 (2 + 12 + 4), the GPS IFD at 26 (2 + 4 * 12 + 4), rationals at 80.
    let mut tiff = b"II*\0".to_vec();
    tiff.extend_from_slice(&8u32.to_le_bytes());
    tiff.extend_from_slice(&1u16.to_le_bytes());
    entry(&mut tiff, 0x8825, 4, 1, 26u32.to_le_bytes()); // GPS IFD pointer
    tiff.extend_from_slice(&0u32.to_le_bytes());
    tiff.extend_from_slice(&4u16.to_le_bytes());
    entry(&mut tiff, 0x0001, 2, 2, *b"N\0\0\0"); // GPSLatitudeRef
    entry(&mut tiff, 0x0002, 5, 3, 80u32.to_le_bytes()); // GPSLatitude
    entry(&mut tiff, 0x0003, 2, 2, *b"E\0\0\0"); // GPSLongitudeRef
    entry(&mut tiff, 0x0004, 5, 3, 104u32.to_le_bytes()); // GPSLongitude
    tiff.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(tiff.len(), 80);
    for (numerator, denominator) in [(48u32, 1u32), (51, 1), (0, 1), (2, 1), (21, 1), (0, 1)] {
        tiff.extend_from_slice(&numerator.to_le_bytes());
        tiff.extend_from_slice(&denominator.to_le_bytes());
    }
    tiff
}

/// An XMP packet naming its creator and a GPS position, as an editor writes one.
pub const XMP_PACKET: &[u8] = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:exif="http://ns.adobe.com/exif/1.0/" exif:GPSLatitude="48,51.0N" exif:GPSLongitude="2,21.0E"><dc:creator><rdf:Seq><rdf:li>Ada Lovelace</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>"#;

/// One JPEG marker segment: the marker, its two-byte length and its payload.
pub fn segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let length = u16::try_from(payload.len() + 2).expect("a segment fits its length field");
    let mut out = vec![0xFF, marker];
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The segments a decoder needs for a one-pixel greyscale baseline JPEG: a quantisation table, the
/// frame, a Huffman table and one scan, whose data holds a stuffed `0xFF` and a restart marker.
pub fn jpeg_picture() -> Vec<u8> {
    let mut out = segment(0xDB, &[0x00; 65]); // DQT: table 0, 64 entries
    out.extend(segment(
        0xC0,
        &[0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00],
    )); // SOF0
    out.extend(segment(0xC4, &[0x00; 17])); // DHT: class 0, table 0, 16 counts
    out.extend(segment(0xDA, &[0x01, 0x01, 0x00, 0x00, 0x3F, 0x00])); // SOS
    out.extend_from_slice(&[0x2B, 0xFF, 0x00, 0x7F, 0xFF, 0xD0, 0x15]); // scan data
    out
}

/// A JPEG whose application segments and comment carry Exif with a GPS position, XMP, IPTC and a
/// comment beside the JFIF header and the Adobe colour transform, followed after its end by a
/// second picture with its own Exif, as a multi-picture file holds a preview.
pub fn jpeg_with_metadata() -> Vec<u8> {
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend(gps_tiff());
    let mut xmp = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    xmp.extend_from_slice(XMP_PACKET);
    // A Photoshop image-resource block 0x0404 holding the IPTC by-line 2:80.
    let byline = b"Ada Lovelace";
    let mut iptc = vec![0x1C, 0x02, 0x50, 0x00, u8::try_from(byline.len()).unwrap()];
    iptc.extend_from_slice(byline);
    let mut irb = b"Photoshop 3.0\08BIM\x04\x04\0\0".to_vec();
    irb.extend_from_slice(&u32::try_from(iptc.len()).unwrap().to_be_bytes());
    irb.extend(&iptc);
    if iptc.len() % 2 == 1 {
        irb.push(0);
    }
    let mut out = vec![0xFF, 0xD8];
    out.extend(segment(0xE0, b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0"));
    out.extend(segment(0xE1, &exif));
    out.extend(segment(0xE1, &xmp));
    out.extend(segment(0xED, &irb));
    out.extend(segment(0xFE, b"taken at home by Ada"));
    out.extend(segment(0xEE, b"Adobe\0\x64\0\0\0\0\x01"));
    out.extend(jpeg_picture());
    out.extend_from_slice(&[0xFF, 0xD9]);
    // The appended preview, with its own Exif.
    out.extend_from_slice(&[0xFF, 0xD8]);
    out.extend(segment(0xE1, &exif));
    out.extend(jpeg_picture());
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

/// A JPEG with no metadata at all: SOI, [`jpeg_picture`] and EOI.
pub fn plain_jpeg() -> Vec<u8> {
    let mut out = vec![0xFF, 0xD8];
    out.extend(jpeg_picture());
    out.extend_from_slice(&[0xFF, 0xD9]);
    out
}

/// One directory entry for [`exif_tiff`]: the tag, its TIFF type and its value bytes, already in
/// the block's byte order.
pub type TiffEntry<'a> = (u16, u16, &'a [u8]);

/// A TIFF block, big-endian (`MM`) or little-endian (`II`), whose IFD0 holds `image` and, when
/// `camera` is not empty, points to an Exif sub-IFD holding `camera`, as a camera writes one: each
/// directory sorted by tag, and every value longer than four bytes stored after the directories.
pub fn exif_tiff(big_endian: bool, image: &[TiffEntry], camera: &[TiffEntry]) -> Vec<u8> {
    let u16_bytes = |value: u16| {
        if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    };
    let u32_bytes = |value: usize| {
        let value = u32::try_from(value).expect("a test block fits in 32 bits");
        if big_endian {
            value.to_be_bytes()
        } else {
            value.to_le_bytes()
        }
    };
    let directory_len = |count: usize| 2 + 12 * count + 4;
    let points_to_camera = !camera.is_empty();
    let camera_at = 8 + directory_len(image.len() + usize::from(points_to_camera));
    let values_at = camera_at
        + if points_to_camera {
            directory_len(camera.len())
        } else {
            0
        };
    let mut out = if big_endian {
        b"MM\0*".to_vec()
    } else {
        b"II*\0".to_vec()
    };
    out.extend_from_slice(&u32_bytes(8));
    let mut values = Vec::new();
    for (entries, pointer) in [(image, points_to_camera), (camera, false)] {
        if entries.is_empty() && !pointer {
            continue;
        }
        let mut all: Vec<(u16, u16, Vec<u8>)> = entries
            .iter()
            .map(|&(tag, kind, value)| (tag, kind, value.to_vec()))
            .collect();
        if pointer {
            all.push((0x8769, 4, u32_bytes(camera_at).to_vec()));
        }
        all.sort_by_key(|&(tag, ..)| tag);
        out.extend_from_slice(&u16_bytes(u16::try_from(all.len()).unwrap()));
        for (tag, kind, value) in all {
            let unit = match kind {
                3 => 2,
                4 => 4,
                5 => 8,
                _ => 1,
            };
            out.extend_from_slice(&u16_bytes(tag));
            out.extend_from_slice(&u16_bytes(kind));
            out.extend_from_slice(&u32_bytes(value.len() / unit));
            if value.len() <= 4 {
                let mut inline = value;
                inline.resize(4, 0);
                out.extend(inline);
            } else {
                out.extend_from_slice(&u32_bytes(values_at + values.len()));
                values.extend(value);
            }
        }
        out.extend_from_slice(&u32_bytes(0));
    }
    assert_eq!(out.len(), values_at);
    out.extend(values);
    out
}

/// [`plain_jpeg`] with `tiff` as its Exif segment and, when given, `xmp` as its XMP packet.
pub fn jpeg_with(tiff: &[u8], xmp: Option<&[u8]>) -> Vec<u8> {
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend_from_slice(tiff);
    let picture = plain_jpeg();
    let mut out = picture[..2].to_vec();
    out.extend(segment(0xE1, &exif));
    if let Some(packet) = xmp {
        let mut payload = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
        payload.extend_from_slice(packet);
        out.extend(segment(0xE1, &payload));
    }
    out.extend_from_slice(&picture[2..]);
    out
}

/// `text` as a NUL-terminated ASCII value.
pub fn ascii_value(text: &str) -> Vec<u8> {
    let mut value = text.as_bytes().to_vec();
    value.push(0);
    value
}

/// The CRC-32 a PNG chunk ends with, over its type and body.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// One PNG chunk: length, type, body and CRC.
pub fn png_chunk(kind: [u8; 4], body: &[u8]) -> Vec<u8> {
    let mut out = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
    out.extend_from_slice(&kind);
    out.extend_from_slice(body);
    out.extend_from_slice(&crc32(&out[4..]).to_be_bytes());
    out
}

/// A one-pixel greyscale PNG's header, image data and end.
pub fn png_picture() -> [Vec<u8>; 3] {
    [
        png_chunk(*b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0]),
        png_chunk(*b"IDAT", &[120, 156, 99, 104, 0, 0, 0, 130, 0, 129]),
        png_chunk(*b"IEND", &[]),
    ]
}

/// A PNG carrying an `eXIf` chunk with a GPS position, `tEXt`, `zTXt`, an XMP `iTXt` and a `tIME`,
/// with bytes appended after its end.
pub fn png_with_metadata() -> Vec<u8> {
    let [header, data, end] = png_picture();
    let mut xmp = b"XML:com.adobe.xmp\0\0\0\0\0".to_vec();
    xmp.extend_from_slice(XMP_PACKET);
    let mut out = crate::exif::PNG_SIGNATURE.to_vec();
    out.extend(header);
    out.extend(png_chunk(*b"eXIf", &gps_tiff()));
    out.extend(png_chunk(*b"tEXt", b"Author\0Ada Lovelace"));
    out.extend(png_chunk(*b"zTXt", b"Comment\0\0x\x9c\x03\0\0\0\0\x01"));
    out.extend(png_chunk(*b"iTXt", &xmp));
    out.extend(png_chunk(*b"tIME", &[0x07, 0xEA, 11, 5, 9, 30, 0]));
    out.extend(data);
    out.extend(end);
    out.extend_from_slice(b"appended after IEND");
    out
}

/// One WebP chunk: its code, its size, its payload and the pad byte an odd size takes.
pub fn webp_chunk(fourcc: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut out = fourcc.to_vec();
    out.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_le_bytes());
    out.extend_from_slice(payload);
    if payload.len() % 2 == 1 {
        out.push(0);
    }
    out
}

/// A WebP file of `chunks`, with the RIFF size they make.
pub fn webp(chunks: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = chunks.concat();
    let mut out = b"RIFF".to_vec();
    out.extend_from_slice(&u32::try_from(body.len() + 4).unwrap().to_le_bytes());
    out.extend_from_slice(b"WEBP");
    out.extend(body);
    out
}

/// A `VP8X` chunk with `flags` and a one-by-one canvas.
pub fn vp8x(flags: u8) -> Vec<u8> {
    webp_chunk(*b"VP8X", &[flags, 0, 0, 0, 0, 0, 0, 0, 0, 0])
}

/// A lossy image chunk (its frame bytes are not decoded here).
pub fn vp8() -> Vec<u8> {
    webp_chunk(
        *b"VP8 ",
        b"\x30\x01\x00\x9d\x01\x2a\x01\x00\x01\x00\x02\x00",
    )
}

/// An extended WebP whose `VP8X` flags an ICC profile, Exif and XMP, holding all three beside its
/// image, with bytes appended after the RIFF container.
pub fn webp_with_metadata() -> Vec<u8> {
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend(gps_tiff());
    let mut out = webp(&[
        vp8x(0x20 | 0x08 | 0x04),
        webp_chunk(*b"ICCP", b"profile of a phone camera"),
        vp8(),
        webp_chunk(*b"EXIF", &exif),
        webp_chunk(*b"XMP ", XMP_PACKET),
    ]);
    out.extend_from_slice(b"appended");
    out
}
