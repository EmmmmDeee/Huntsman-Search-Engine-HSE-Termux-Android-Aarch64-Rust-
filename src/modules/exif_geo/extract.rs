//! High-level extraction helpers: URL classification, camera device
//! fingerprinting, and owner-name sanitisation.

use super::IMAGE_EXTS;

/// True if the URL ends (case-insensitive) with one of the
/// image extensions we extract EXIF from. Query strings and
/// fragments are stripped before the check so
/// `https://x.com/a.jpg?w=1024` still matches.
pub(super) fn looks_like_image_url(url: &str) -> bool {
    let trimmed = url.trim();
    // Strip query string and fragment in one pass. `split(['?', '#'])`
    // splits at either delimiter; the first segment is the URL path,
    // which is what we want to extension-check.
    let path = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let lower = path.to_lowercase();
    IMAGE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Build a stable cross-image correlation anchor for a physical camera — used
/// **only** when a serial number is present. A serial uniquely identifies one
/// device, so the same serial recovered from two images links them to the same
/// camera. Make+model alone is deliberately *not* an anchor: millions of devices
/// share `Apple iPhone 13`, so clustering on it would fuse unrelated people.
/// Returns `None` without a (non-blank) serial.
pub(super) fn device_fingerprint(
    make: Option<&str>,
    model: Option<&str>,
    serial: Option<&str>,
) -> Option<String> {
    let serial = serial.map(str::trim).filter(|s| !s.is_empty())?;
    let label = [make, model]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    Some(if label.is_empty() {
        format!("camera s/n {serial}")
    } else {
        format!("{label} s/n {serial}")
    })
}

/// DOP (dilution of precision) → GPS confidence scalar.
///
/// Piecewise-linear interpolation over the standard DOP quality ladder:
/// ≤1 (ideal) → 0.95 · 2 → 0.90 · 4 → 0.82 · 8 → 0.74 · ≥15 (poor) → 0.65.
/// Values between knots are linearly interpolated; below 1 clamps to 0.95,
/// above 15 clamps to 0.65. `NaN`/infinite input → `None`.
pub(super) fn dop_confidence(dop: f64) -> Option<f64> {
    if !dop.is_finite() {
        return None;
    }
    const KNOTS: &[(f64, f64)] = &[
        (1.0, 0.95),
        (2.0, 0.90),
        (4.0, 0.82),
        (8.0, 0.74),
        (15.0, 0.65),
    ];
    if dop <= KNOTS[0].0 {
        return Some(KNOTS[0].1);
    }
    if dop >= KNOTS[KNOTS.len() - 1].0 {
        return Some(KNOTS[KNOTS.len() - 1].1);
    }
    for w in KNOTS.windows(2) {
        let (x0, y0) = w[0];
        let (x1, y1) = w[1];
        if dop <= x1 {
            let t = (dop - x0) / (x1 - x0);
            return Some(y0 + t * (y1 - y0));
        }
    }
    Some(KNOTS[KNOTS.len() - 1].1)
}

/// Classify a signed altitude (metres above/below sea level) into an
/// operational label and an "is elevated" flag used for OSINT tagging.
///
/// Returns `(label, is_elevated)` where:
/// * `"ground-level"` < 5 m   (elevated = false)
/// * `"low-elevated"` 5–30 m  (elevated = false)
/// * `"elevated"`     30–150 m (elevated = true)
/// * `"airborne"`     ≥ 150 m  (elevated = true)
///
/// Negative (below-sea-level) altitudes classify as ground-level.
pub(super) fn altitude_classification(alt_m: f64) -> (&'static str, bool) {
    match alt_m {
        a if a < 5.0 => ("ground-level", false),
        a if a < 30.0 => ("low-elevated", false),
        a if a < 150.0 => ("elevated", true),
        _ => ("airborne", true),
    }
}

/// Map a GPS speed (km/h, already converted) to an OSINT motion label.
///
/// * < 2     → `"stationary"`
/// * 2–15    → `"walking-pace"`
/// * 15–60   → `"vehicle-slow"`
/// * 60–300  → `"vehicle-fast"`
/// * ≥ 300   → `"airborne-speed"`
pub(super) fn speed_motion_tag(speed_kmh: f64) -> &'static str {
    match speed_kmh {
        s if s < 2.0 => "stationary",
        s if s < 15.0 => "walking-pace",
        s if s < 60.0 => "vehicle-slow",
        s if s < 300.0 => "vehicle-fast",
        _ => "airborne-speed",
    }
}

/// Convert a bearing in degrees [0, 360) to an 8-point compass label.
///
/// Sectors are 45° wide, centred on each cardinal/intercardinal point:
/// N (337.5–22.5), NE, E, SE, S, SW, W, NW.
pub(super) fn bearing_compass_label(deg: f64) -> &'static str {
    const LABELS: &[&str] = &["N", "NE", "E", "SE", "S", "SW", "W", "NW"];
    let idx = ((deg + 22.5) / 45.0) as usize % 8;
    LABELS[idx]
}

/// Derive the photographer's UTC offset from GPS UTC time and the camera's
/// local `DateTimeOriginal` string (`"YYYY:MM:DD HH:MM:SS"`).
///
/// Returns the offset in **whole seconds**, rounded to the nearest 15-minute
/// boundary (900 s). Range check: ±14 h (±50 400 s).
/// Returns `None` if the camera timestamp is malformed or the delta is
/// implausible.
pub(super) fn derive_utc_offset(gps_utc_secs: f64, camera_local: &str) -> Option<i32> {
    // Parse HH:MM:SS from the trailing portion of "YYYY:MM:DD HH:MM:SS".
    let time_part = camera_local.trim().get(11..)?;
    let mut parts = time_part.splitn(3, ':');
    let h: f64 = parts.next()?.trim().parse().ok()?;
    let m: f64 = parts.next()?.trim().parse().ok()?;
    let s: f64 = parts.next()?.trim().parse().ok()?;
    if !(0.0..24.0).contains(&h) || !(0.0..60.0).contains(&m) || !(0.0..60.0).contains(&s) {
        return None;
    }
    let local_secs = h * 3600.0 + m * 60.0 + s;
    // Raw delta can be negative (west of UTC) or positive (east).
    let raw_delta = local_secs - gps_utc_secs;
    // Handle midnight wrap-around: if |delta| > 12h, shift by ±24h.
    let delta = if raw_delta > 43200.0 {
        raw_delta - 86400.0
    } else if raw_delta < -43200.0 {
        raw_delta + 86400.0
    } else {
        raw_delta
    };
    // Round to nearest 15-minute boundary.
    let rounded = ((delta / 900.0).round() as i32) * 900;
    // Reject implausible offsets (|offset| > 14 h).
    if rounded.abs() > 50_400 {
        return None;
    }
    Some(rounded)
}

/// Format a UTC offset in seconds as a human-readable label, appending
/// well-known timezone abbreviations where the offset is unambiguous.
///
/// Examples: `"UTC+10:00 (AEST)"`, `"UTC-05:00 (EST)"`, `"UTC+00:00"`.
pub(super) fn utc_offset_label(offset_secs: i32) -> String {
    let sign = if offset_secs < 0 { '-' } else { '+' };
    let abs = offset_secs.unsigned_abs();
    let hh = abs / 3600;
    let mm = (abs % 3600) / 60;
    let base = format!("UTC{sign}{hh:02}:{mm:02}");
    let abbr = match offset_secs {
        0 => Some("UTC/GMT"),
        3_600 => Some("CET"),
        7_200 => Some("EET/CEST"),
        10_800 => Some("MSK/EAT"),
        19_800 => Some("IST"),
        20_700 => Some("NPT"),
        21_600 => Some("BST/OMST"),
        23_400 => Some("MMT"),
        25_200 => Some("ICT/WIB"),
        28_800 => Some("CST/AWST/HKT"),
        32_400 => Some("JST/KST"),
        34_200 => Some("ACST"),
        36_000 => Some("AEST"),
        37_800 => Some("ACDT"),
        39_600 => Some("AEDT/NZST"),
        43_200 => Some("NZDT"),
        -18_000 => Some("EST/PET"),
        -21_600 => Some("CST/MDT"),
        -25_200 => Some("MST/PDT"),
        -28_800 => Some("PST/AKDT"),
        -32_400 => Some("AKST/HDT"),
        -36_000 => Some("HST"),
        _ => None,
    };
    match abbr {
        Some(a) => format!("{base} ({a})"),
        None => base,
    }
}

/// Sanitise an EXIF owner/artist string into a usable Person name, or `None` if
/// it is empty or obvious non-identity boilerplate (a copyright notice, a stock
/// agency, a software string). Conservative — a metadata name is a real lead, so
/// only clear junk is rejected.
pub(super) fn clean_owner(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.len() < 2 || s.chars().count() > 80 || !s.chars().any(char::is_alphabetic) {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    const NOISE: &[&str] = &[
        "copyright",
        "all rights",
        "getty",
        "shutterstock",
        "istock",
        "adobe",
        "unknown",
        "n/a",
        "camera owner",
    ];
    if lower.starts_with('©') || lower.starts_with("(c)") || NOISE.iter().any(|n| lower.contains(n))
    {
        return None;
    }
    Some(s.to_string())
}
