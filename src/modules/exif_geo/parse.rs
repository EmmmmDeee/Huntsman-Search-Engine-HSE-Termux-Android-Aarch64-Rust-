//! EXIF parsing helpers: raw field reading, DMS-to-decimal conversion,
//! and full GPS IFD extraction (coordinates, altitude, DOP, bearing,
//! speed, UTC timestamp).

use exif::{In, Tag, Value};

// ── Generic field readers ──────────────────────────────────────────────────

/// Read an ASCII string field if it exists, trimming nulls and whitespace.
/// Returns `None` for empty or missing fields.
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

/// Read a single `RATIONAL` GPS tag as `f64`. Many GPS fields store exactly
/// one rational (DOP, Altitude, Speed, Track, ImgDirection). Returns `None`
/// if the tag is absent, the value is a different type, or the result is
/// non-finite (e.g. division by zero in the rational denominator).
pub(super) fn read_rational_gps(exif: &exif::Exif, tag: Tag) -> Option<f64> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    match &field.value {
        Value::Rational(rs) if !rs.is_empty() => {
            let v = rs[0].to_f64();
            v.is_finite().then_some(v)
        }
        _ => None,
    }
}

/// Read a single `BYTE` GPS tag as `u8`. Used for `GPSAltitudeRef`
/// (0 = above sea level, 1 = below).
pub(super) fn read_byte_val(exif: &exif::Exif, tag: Tag) -> Option<u8> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    match &field.value {
        Value::Byte(bs) if !bs.is_empty() => Some(bs[0]),
        _ => None,
    }
}

// ── DMS coordinate conversion ──────────────────────────────────────────────

/// Convert a 3-rational EXIF GPS value (degrees, minutes, seconds) to
/// decimal degrees. Returns `None` for non-Rational values or fewer than
/// three components.
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

// ── GPS IFD extraction ─────────────────────────────────────────────────────

/// Extract `(lat, lon)` from the GPS IFD, honouring N/S/E/W reference tags
/// and rejecting Null Island (0.0, 0.0 from sensor-zeroed / stripped images).
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
    if !crate::util::geo::is_valid_coords(lat, lon) {
        return None;
    }
    Some((lat, lon))
}

/// Extract GPS altitude in **signed metres**: positive = above sea level,
/// negative = below (e.g. Dead Sea). Returns `None` if `GPSAltitude` is
/// absent or non-finite.
pub(super) fn extract_gps_altitude(exif: &exif::Exif) -> Option<f64> {
    let meters = read_rational_gps(exif, Tag::GPSAltitude)?;
    // GPSAltitudeRef: 0 = above (default), 1 = below.
    let below = read_byte_val(exif, Tag::GPSAltitudeRef).unwrap_or(0) != 0;
    Some(if below { -meters } else { meters })
}

/// Extract the image-direction bearing as `(degrees_0_359, is_true_north)`.
/// `GPSImgDirectionRef` defaults to True North when absent.
/// Returns `None` if the tag is missing or the bearing is outside `[0, 360)`.
pub(super) fn extract_gps_bearing(exif: &exif::Exif) -> Option<(f64, bool)> {
    let deg = read_rational_gps(exif, Tag::GPSImgDirection)?;
    if !deg.is_finite() || !(0.0..360.0).contains(&deg) {
        return None;
    }
    let is_true = read_str(exif, Tag::GPSImgDirectionRef)
        .is_none_or(|s| !s.to_ascii_uppercase().starts_with('M'));
    Some((deg, is_true))
}

/// Extract GPS speed in **km/h**, converting from the unit declared in
/// `GPSSpeedRef` (K = km/h, M = mph, N = knots). Returns `None` if
/// `GPSSpeed` is absent or negative.
pub(super) fn extract_gps_speed_kmh(exif: &exif::Exif) -> Option<f64> {
    let raw = read_rational_gps(exif, Tag::GPSSpeed)?;
    if !raw.is_finite() || raw < 0.0 {
        return None;
    }
    let kmh = match read_str(exif, Tag::GPSSpeedRef)
        .as_deref()
        .map(str::to_ascii_uppercase)
        .as_deref()
    {
        Some("M") => raw * 1.609_344,
        Some("N") => raw * 1.852,
        _ => raw, // "K" or absent → already km/h
    };
    Some(kmh)
}

/// Extract the GPS dilution of precision (DOP). A lower value indicates
/// better GPS geometry; 1.0 is ideal, >10 is poor. Returns `None` if the
/// `GPSDOP` tag is absent.
pub(super) fn extract_dop(exif: &exif::Exif) -> Option<f64> {
    read_rational_gps(exif, Tag::GPSDOP)
}

/// Extract the GPS UTC timestamp as **seconds since midnight** (0.0–86399.x).
///
/// `GPSTimeStamp` encodes hour, minute, second as three rationals (UTC).
/// Returns `None` if the tag is absent, malformed, or out of range.
pub(super) fn extract_gps_utc_secs(exif: &exif::Exif) -> Option<f64> {
    let field = exif.get_field(Tag::GPSTimeStamp, In::PRIMARY)?;
    let Value::Rational(rs) = &field.value else {
        return None;
    };
    if rs.len() < 3 {
        return None;
    }
    let h = rs[0].to_f64();
    let m = rs[1].to_f64();
    let s = rs[2].to_f64();
    if !h.is_finite() || !m.is_finite() || !s.is_finite() {
        return None;
    }
    let total = h * 3600.0 + m * 60.0 + s;
    (0.0..86400.0).contains(&total).then_some(total)
}
