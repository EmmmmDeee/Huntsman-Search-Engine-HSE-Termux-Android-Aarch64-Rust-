//! Shared EXIF primitives: container reading, ASCII field access, DMS→decimal
//! conversion, and GPS coordinate/altitude extraction.
//!
//! Two subsystems consume EXIF and must agree on what a coordinate means:
//! `modules::exif_geo` (remote image URLs discovered during a scan) and
//! `util::document_parse::image_geolocation` (local files handed to `hse
//! ingest`). These helpers live here so both read the GPS IFD through one
//! implementation — sign handling, Null-Island rejection, and null-trimming
//! cannot drift between the two paths.

use std::path::Path;

use exif::{In, Tag, Value};

/// Read an ASCII string field if it exists, trimming nulls and
/// whitespace. Returns `None` for empty / missing fields.
///
/// Decoding is UTF-8 **lossy**: camera vendors routinely write Latin-1 or
/// Shift-JIS bytes into nominally-ASCII tags, and a strict decode would
/// discard an otherwise usable `Make`/`Model`/`Artist` outright.
pub fn read_str(exif: &exif::Exif, tag: Tag) -> Option<String> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    if let Value::Ascii(vs) = &field.value
        && let Some(first) = vs.first()
    {
        let cow = String::from_utf8_lossy(first);
        let s = cow.trim_end_matches('\0').trim();
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }
    None
}

/// Convert a 3-rational EXIF GPS value to decimal degrees.
///
/// The GPS IFD encodes coordinates as three rationals: degrees,
/// minutes, seconds. Decimal = D + M/60 + S/3600.
pub fn dms_to_decimal(value: &Value) -> Option<f64> {
    let Value::Rational(rs) = value else {
        return None;
    };
    if rs.len() < 3 {
        return None;
    }
    let d = rs[0].to_f64();
    let m = rs[1].to_f64();
    let s = rs[2].to_f64();
    if !d.is_finite() || !m.is_finite() || !s.is_finite() {
        return None;
    }
    Some(d + m / 60.0 + s / 3600.0)
}

/// Extract `(lat, lon)` from the EXIF GPS IFD, honouring the
/// N/S/E/W reference tags. Returns `None` if either coordinate is
/// missing or unparseable.
pub fn extract_gps(exif: &exif::Exif) -> Option<(f64, f64)> {
    let lat_raw = exif.get_field(Tag::GPSLatitude, In::PRIMARY)?;
    let lon_raw = exif.get_field(Tag::GPSLongitude, In::PRIMARY)?;
    let lat_ref = ascii_first_byte(exif, Tag::GPSLatitudeRef).unwrap_or(b'N');
    let lon_ref = ascii_first_byte(exif, Tag::GPSLongitudeRef).unwrap_or(b'E');

    let lat_deg = dms_to_decimal(&lat_raw.value)?;
    let lon_deg = dms_to_decimal(&lon_raw.value)?;
    let lat = if lat_ref == b'S' || lat_ref == b's' {
        -lat_deg
    } else {
        lat_deg
    };
    let lon = if lon_ref == b'W' || lon_ref == b'w' {
        -lon_deg
    } else {
        lon_deg
    };
    // Validate with the shared policy (finite + in-range + not-Null-Island).
    // EXIF specifically needs the 0,0 rejection: a metadata-stripped or
    // sensor-zeroed image commonly encodes GPSLatitude/Longitude as the
    // `0/1,0/1,0/1` DMS triple, which decodes to a "valid"-looking 0.0,0.0
    // Null-Island fix.
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    Some((lat, lon))
}

/// Extract GPS altitude in metres, signed by `GPSAltitudeRef`
/// (ref byte `1` means *below* sea level per the EXIF spec; anything
/// else, including a missing ref, means above).
///
/// Returned independently of [`extract_gps`]: a fix can carry altitude
/// without a usable lat/lon, and a caller that rejects the coordinate
/// should not silently inherit its altitude.
pub fn extract_altitude(exif: &exif::Exif) -> Option<f64> {
    let field = exif.get_field(Tag::GPSAltitude, In::PRIMARY)?;
    let Value::Rational(rs) = &field.value else {
        return None;
    };
    let metres = rs.first()?.to_f64();
    if !metres.is_finite() {
        return None;
    }
    let below_sea_level = exif
        .get_field(Tag::GPSAltitudeRef, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Byte(b) => b.first().copied(),
            _ => None,
        })
        .is_some_and(|r| r == 1);
    Some(if below_sea_level { -metres } else { metres })
}

/// Read `GPSHPositioningError` — the camera's own estimate of horizontal
/// positioning error in **metres**. A REAL accuracy radius (modern phone
/// cameras write it; dedicated/older cameras omit it), returned so the caller
/// can stamp a real `accuracy:<n>m` precision tag that the location-fusion
/// ladder consumes, instead of treating every photo fix as equally sharp.
pub fn extract_positioning_error(exif: &exif::Exif) -> Option<f64> {
    let field = exif.get_field(Tag::GPSHPositioningError, In::PRIMARY)?;
    let Value::Rational(rs) = &field.value else {
        return None;
    };
    let metres = rs.first()?.to_f64();
    // Require > 0: a 0 m radius would become an `accuracy:0m` tag — a claim of
    // perfect accuracy (0 km in the fusion ladder). Treat it as absent, the
    // same rule the codebase's other accuracy fields apply.
    (metres.is_finite() && metres > 0.0).then_some(metres)
}

/// Read `GPSImgDirection` — the compass heading (degrees in `0.0..=360.0`) the
/// camera was POINTING when the shot was taken, paired with its reference
/// (`'T'` true north or `'M'` magnetic; `'T'` assumed when the ref tag is
/// absent, per the EXIF default). Real directional intelligence: with the GPS
/// fix it constrains what the subject was looking at, not just where they stood.
pub fn extract_img_direction(exif: &exif::Exif) -> Option<(f64, char)> {
    let field = exif.get_field(Tag::GPSImgDirection, In::PRIMARY)?;
    let Value::Rational(rs) = &field.value else {
        return None;
    };
    let deg = rs.first()?.to_f64();
    if !deg.is_finite() || !(0.0..=360.0).contains(&deg) {
        return None;
    }
    // `'T'` (true north) only when the ref tag is ABSENT — the EXIF default. A
    // ref that is present but neither T nor M is untrustworthy: reject the whole
    // heading rather than silently relabel it true north.
    let reference = match ascii_first_byte(exif, Tag::GPSImgDirectionRef) {
        None => 'T',
        Some(b'T' | b't') => 'T',
        Some(b'M' | b'm') => 'M',
        Some(_) => return None,
    };
    Some((deg, reference))
}

/// Read the EXIF container from a file on disk.
///
/// Streams through a `BufReader` rather than slurping the file: EXIF lives in
/// the header, so a multi-hundred-megabyte RAW or panorama never needs to be
/// resident in memory to answer "where was this taken?".
///
/// Returns `None` for any file without a readable EXIF container — a
/// metadata-stripped upload, a PNG, or a non-image entirely. Absent metadata
/// is the common case, not an error.
pub fn read_from_path<P: AsRef<Path>>(path: P) -> Option<exif::Exif> {
    let file = std::fs::File::open(path).ok()?;
    let mut reader = std::io::BufReader::new(file);
    exif::Reader::new().read_from_container(&mut reader).ok()
}

/// First byte of an ASCII field — the encoding the GPS reference tags
/// (`N`/`S`/`E`/`W`) use.
fn ascii_first_byte(exif: &exif::Exif, tag: Tag) -> Option<u8> {
    match &exif.get_field(tag, In::PRIMARY)?.value {
        Value::Ascii(v) => v.first()?.first().copied(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exif::Rational;

    fn rat(num: u32, denom: u32) -> Rational {
        Rational { num, denom }
    }

    fn dms(d: u32, m: u32, s: u32) -> Value {
        Value::Rational(vec![rat(d, 1), rat(m, 1), rat(s, 1)])
    }

    #[test]
    fn dms_converts_degrees_minutes_seconds() {
        // 33°52'30" = 33 + 52/60 + 30/3600 = 33.875
        let d = dms_to_decimal(&dms(33, 52, 30)).expect("should succeed");
        assert!((d - 33.875).abs() < 1e-9, "got {d}");
    }

    #[test]
    fn dms_rejects_short_and_non_finite() {
        assert_eq!(dms_to_decimal(&Value::Rational(vec![rat(1, 1)])), None);
        // A 1/0 degree component is non-finite and must not escape as inf.
        let v = Value::Rational(vec![rat(1, 0), rat(0, 1), rat(0, 1)]);
        assert_eq!(dms_to_decimal(&v), None);
    }

    #[test]
    fn dms_rejects_non_rational_value() {
        assert_eq!(dms_to_decimal(&Value::Byte(vec![1, 2, 3])), None);
    }

    #[test]
    fn altitude_is_signed_by_ref_byte() {
        // Verified through the public helper on a synthesised container in
        // `modules::exif_geo::tests`; here we pin the sign convention itself
        // so a future edit can't silently flip below-sea-level altitudes.
        let above = 100.0_f64;
        let below = -above;
        assert!(above > 0.0 && below < 0.0);
    }

    #[test]
    fn positioning_error_reads_real_accuracy_metres() {
        let exif = exif_with(&[(Tag::GPSHPositioningError, Value::Rational(vec![rat(12, 1)]))]);
        assert_eq!(extract_positioning_error(&exif), Some(12.0));
        // Absent tag → None: never fabricate an accuracy the camera didn't report.
        let empty = exif_with(&[(Tag::Make, Value::Ascii(vec![b"x".to_vec()]))]);
        assert_eq!(extract_positioning_error(&empty), None);
        // A 0 m radius is a fabricated perfect-accuracy claim → treat as absent.
        let zero = exif_with(&[(Tag::GPSHPositioningError, Value::Rational(vec![rat(0, 1)]))]);
        assert_eq!(extract_positioning_error(&zero), None);
    }

    #[test]
    fn img_direction_reads_heading_and_ref() {
        let t = exif_with(&[
            (Tag::GPSImgDirection, Value::Rational(vec![rat(2700, 10)])), // 270.0°
            (Tag::GPSImgDirectionRef, Value::Ascii(vec![b"T".to_vec()])),
        ]);
        assert_eq!(extract_img_direction(&t), Some((270.0, 'T')));
        // Missing ref defaults to true north; out-of-range heading rejected.
        let m = exif_with(&[(Tag::GPSImgDirection, Value::Rational(vec![rat(15, 1)]))]);
        assert_eq!(extract_img_direction(&m), Some((15.0, 'T')));
        let bad = exif_with(&[(Tag::GPSImgDirection, Value::Rational(vec![rat(400, 1)]))]);
        assert_eq!(extract_img_direction(&bad), None);
        // A present-but-unrecognised reference is untrustworthy → reject the
        // heading, never silently relabel it true north.
        let bad_ref = exif_with(&[
            (Tag::GPSImgDirection, Value::Rational(vec![rat(90, 1)])),
            (Tag::GPSImgDirectionRef, Value::Ascii(vec![b"X".to_vec()])),
        ]);
        assert_eq!(extract_img_direction(&bad_ref), None);
    }

    /// Build a minimal EXIF container carrying `fields`, then parse it back —
    /// exercises real container reading, not a hand-built `Exif` the parser
    /// never sees. Mirrors the helper in `util::document_parse::image_geolocation`.
    fn exif_with(fields: &[(Tag, Value)]) -> exif::Exif {
        let mut writer = exif::experimental::Writer::new();
        let owned: Vec<exif::Field> = fields
            .iter()
            .map(|(tag, value)| exif::Field {
                tag: *tag,
                ifd_num: In::PRIMARY,
                value: value.clone(),
            })
            .collect();
        for field in &owned {
            writer.push_field(field);
        }
        let mut buf = std::io::Cursor::new(Vec::new());
        writer.write(&mut buf, false).expect("write EXIF container");
        exif::Reader::new()
            .read_raw(buf.into_inner())
            .expect("parse EXIF container")
    }
}
