/// Coarse timezone inference from coordinates via 15° longitude bands.
/// Returns IANA-style "Etc/GMT±N" identifier — accurate to within
/// 1-2 hours for any inland location. Refines for Australia (UTC+8/9.5/10),
/// US (Pacific/Mountain/Central/Eastern), and Europe (CET/EET).
///
/// # Guarantees
/// - Always returns a non-empty `&'static str` (the 15°-band fallback covers
///   every longitude); never panics, even for out-of-range inputs.
/// - Refined regions (AU/US/EU) take precedence over the generic band.
///
/// ```
/// use huntsman_search_engine::util::geohash::timezone_for;
///
/// assert_eq!(timezone_for(-27.47, 153.02), "Australia/Sydney"); // Brisbane
/// assert_eq!(timezone_for(51.5074, -0.1278), "Europe/London");
/// ```
pub fn timezone_for(lat: f64, lon: f64) -> &'static str {
    // Australia tight bands (more precise than longitude/15)
    if (-44.0..=-10.0).contains(&lat) {
        if lon > 140.0 {
            return "Australia/Sydney"; // UTC+10/+11 (Eastern: NSW, VIC, QLD, TAS)
        }
        if lon > 130.0 {
            return "Australia/Adelaide"; // UTC+9:30/+10:30 (SA, NT central)
        }
        if lon > 110.0 {
            return "Australia/Perth"; // UTC+8 (WA)
        }
    }
    // CONUS
    if (24.0..=49.0).contains(&lat) && (-125.0..=-66.0).contains(&lon) {
        if lon < -114.0 {
            return "America/Los_Angeles";
        }
        if lon < -102.0 {
            return "America/Denver";
        }
        if lon < -87.0 {
            return "America/Chicago";
        }
        return "America/New_York";
    }
    // UK + Western Europe
    if (35.0..=60.0).contains(&lat) {
        if (-12.0..=2.0).contains(&lon) {
            return "Europe/London";
        }
        if (2.0..=20.0).contains(&lon) {
            return "Europe/Paris"; // CET
        }
        if (20.0..=30.0).contains(&lon) {
            return "Europe/Helsinki"; // EET
        }
    }
    // Generic fallback: 15° bands
    let offset = (lon / 15.0).round() as i32;
    match offset {
        -12 => "Etc/GMT+12",
        -11 => "Etc/GMT+11",
        -10 => "Pacific/Honolulu",
        -9 => "Etc/GMT+9",
        -8 => "America/Los_Angeles",
        -7 => "America/Denver",
        -6 => "America/Chicago",
        -5 => "America/New_York",
        -4 => "Atlantic/Bermuda",
        -3 => "America/Argentina/Buenos_Aires",
        -2 => "Etc/GMT+2",
        -1 => "Atlantic/Azores",
        0 => "Etc/UTC",
        1 => "Europe/Paris",
        2 => "Europe/Helsinki",
        3 => "Europe/Moscow",
        4 => "Asia/Dubai",
        5 => "Asia/Karachi",
        6 => "Asia/Dhaka",
        7 => "Asia/Bangkok",
        8 => "Asia/Singapore",
        9 => "Asia/Tokyo",
        10 => "Australia/Sydney",
        11 => "Pacific/Noumea",
        12 => "Pacific/Auckland",
        _ => "Etc/UTC",
    }
}
