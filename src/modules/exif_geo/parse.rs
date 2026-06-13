//! EXIF parsing helpers: raw field reading, DMS-to-decimal conversion, and
//! GPS coordinate extraction from an [`exif::Exif`] object.

use exif::{In, Tag, Value};

/// Read an ASCII string field if it exists, trimming nulls and
/// whitespace. Returns `None` for empty / missing fields.
pub(super) fn read_str(exif: &exif::Exif, tag: Tag) -> Option<String> {
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
pub(super) fn dms_to_decimal(value: &Value) -> Option<f64> {
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
pub(super) fn extract_gps(exif: &exif::Exif) -> Option<(f64, f64)> {
    let lat_raw = exif.get_field(Tag::GPSLatitude, In::PRIMARY)?;
    let lon_raw = exif.get_field(Tag::GPSLongitude, In::PRIMARY)?;
    let lat_ref = exif
        .get_field(Tag::GPSLatitudeRef, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Ascii(v) if !v.is_empty() && !v[0].is_empty() => Some(v[0][0]),
            _ => None,
        })
        .unwrap_or(b'N');
    let lon_ref = exif
        .get_field(Tag::GPSLongitudeRef, In::PRIMARY)
        .and_then(|f| match &f.value {
            Value::Ascii(v) if !v.is_empty() && !v[0].is_empty() => Some(v[0][0]),
            _ => None,
        })
        .unwrap_or(b'E');

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
    // Null-Island fix. The prior inline range check let that through.
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    Some((lat, lon))
}
