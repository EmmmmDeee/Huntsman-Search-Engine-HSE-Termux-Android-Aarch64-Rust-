//! Geospatial enrichment helpers — geohash, address normalisation,
//! timezone inference, all offline (no API calls, no deps).
//!
//! These functions feed the geo-precision pipeline: every Coordinates
//! entity gets a geohash and timezone attached as evidence; every
//! Address entity gets parsed into structured components so downstream
//! geocode/overpass can resolve it more reliably.

/// Standard geohash base-32 alphabet (no a/i/l/o to avoid confusion).
const BASE32: &[u8; 32] = b"0123456789bcdefghjkmnpqrstuvwxyz";

/// Compute the geohash for a (lat, lon) pair at the given precision.
///
/// Precision 7 = ±76m on the equator (suburb-level). 8 = ±19m (block).
/// 9 = ±2.4m (building). The default 7 matches HSE's coordinate
/// confidence — anything tighter is false precision.
///
/// # Guarantees
/// - On valid coordinates, returns a string of exactly `precision.clamp(1, 12)`
///   base-32 characters (the standard `0-9 b-z` minus `a i l o` alphabet).
/// - Out-of-range `lat`/`lon` yield an empty string — never a panic.
///
/// ```
/// use huntsman_search_engine::util::geohash::geohash;
///
/// // Canonical reference point (Wikipedia) → its known geohash.
/// assert_eq!(geohash(57.64911, 10.40744, 11), "u4pruydqqvj");
/// assert_eq!(geohash(57.64911, 10.40744, 5), "u4pru"); // shorter precision = prefix
/// // Out-of-range latitude → empty, no panic.
/// assert_eq!(geohash(91.0, 0.0, 7), "");
/// ```
pub fn geohash(lat: f64, lon: f64, precision: u8) -> String {
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return String::new();
    }
    let precision = precision.clamp(1, 12) as usize;
    let mut out = String::with_capacity(precision);
    let mut lat_range = (-90.0_f64, 90.0_f64);
    let mut lon_range = (-180.0_f64, 180.0_f64);
    let mut even = true;
    let mut bit: u8 = 0;
    let mut idx: u8 = 0;
    while out.len() < precision {
        let mid = if even {
            (lon_range.0 + lon_range.1) / 2.0
        } else {
            (lat_range.0 + lat_range.1) / 2.0
        };
        let val = if even { lon } else { lat };
        if val >= mid {
            idx = (idx << 1) | 1;
            if even {
                lon_range.0 = mid;
            } else {
                lat_range.0 = mid;
            }
        } else {
            idx <<= 1;
            if even {
                lon_range.1 = mid;
            } else {
                lat_range.1 = mid;
            }
        }
        even = !even;
        bit += 1;
        if bit == 5 {
            out.push(BASE32[idx as usize] as char);
            bit = 0;
            idx = 0;
        }
    }
    out
}

/// Parse a `"lat,lon"` string (as produced by HSE `Coordinates` entities) into a
/// `(f64, f64)` pair.
///
/// # Guarantees
/// - Returns `Some((lat, lon))` only when `s` is two comma-separated numbers with
///   `lat ∈ [-90, 90]` and `lon ∈ [-180, 180]`; surrounding whitespace on each
///   component is trimmed.
/// - Returns `None` for any other shape, a non-numeric component, or an
///   out-of-range value — never panics.
///
/// ```
/// use huntsman_search_engine::util::geohash::parse_coords;
///
/// assert_eq!(parse_coords(" -27.47 , 153.02 "), Some((-27.47, 153.02)));
/// assert_eq!(parse_coords("91.0,0.0"), None); // latitude out of range
/// assert_eq!(parse_coords("153.02"), None);   // not a pair
/// assert_eq!(parse_coords("a,b"), None);      // not numeric
/// ```
pub fn parse_coords(s: &str) -> Option<(f64, f64)> {
    let (lat_s, lon_s) = s.split_once(',')?;
    let lat: f64 = lat_s.trim().parse().ok()?;
    let lon: f64 = lon_s.trim().parse().ok()?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return None;
    }
    Some((lat, lon))
}

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

/// Reverse-geocode to an ISO country code via bounding-box lookup.
///
/// Coarse but offline — covers the 60 countries most likely to appear
/// in OSINT breach data. Falls back to None for ambiguous regions
/// (oceans, border zones). Caller can then trigger an HTTP-based
/// reverse geocode (Nominatim) only when this returns None.
///
/// # Guarantees
/// - Returns `Some(iso)` when the point falls in a known country box, else
///   `None` (ocean / uncovered region) — a coarse first pass, never a panic.
/// - Bounding boxes overlap at borders; the first match in declaration order
///   wins, so this is a hint, not an authority.
///
/// ```
/// use huntsman_search_engine::util::geohash::reverse_country_iso;
///
/// assert_eq!(reverse_country_iso(-27.47, 153.02), Some("AU")); // Brisbane
/// assert_eq!(reverse_country_iso(51.5074, -0.1278), Some("GB")); // London
/// assert_eq!(reverse_country_iso(0.0, -140.0), None); // mid-Pacific → no box
/// ```
pub fn reverse_country_iso(lat: f64, lon: f64) -> Option<&'static str> {
    // (iso, lat_min, lat_max, lon_min, lon_max)
    const BOXES: &[(&str, f64, f64, f64, f64)] = &[
        // Anglosphere
        ("US", 24.0, 49.5, -125.0, -66.5),
        ("AK", 51.0, 71.5, -180.0, -130.0), // US Alaska
        ("HI", 18.5, 22.5, -161.0, -154.0), // US Hawaii
        ("CA", 41.5, 84.0, -141.0, -52.0),
        ("MX", 14.5, 32.7, -118.0, -86.7),
        ("AU", -44.0, -10.0, 113.0, 154.0),
        ("NZ", -47.5, -34.0, 166.0, 179.0),
        ("GB", 49.5, 60.9, -8.7, 1.8),
        ("IE", 51.4, 55.5, -10.5, -5.4),
        // EU west
        ("FR", 41.3, 51.1, -5.2, 9.6),
        ("ES", 35.2, 43.8, -9.4, 4.4),
        ("PT", 36.9, 42.2, -9.6, -6.2),
        ("DE", 47.3, 55.1, 5.9, 15.0),
        ("NL", 50.7, 53.6, 3.3, 7.3),
        ("BE", 49.5, 51.6, 2.5, 6.4),
        ("LU", 49.4, 50.2, 5.7, 6.6),
        ("CH", 45.8, 47.9, 5.9, 10.5),
        ("AT", 46.4, 49.1, 9.5, 17.2),
        ("IT", 35.5, 47.1, 6.6, 18.6),
        // Nordics
        ("NO", 57.9, 71.2, 4.0, 31.5),
        ("SE", 55.3, 69.1, 10.9, 24.2),
        ("FI", 59.7, 70.1, 20.5, 31.6),
        ("DK", 54.5, 57.8, 8.0, 12.7),
        ("IS", 63.3, 66.6, -24.5, -13.4),
        // EU central / east
        ("PL", 49.0, 54.9, 14.1, 24.2),
        ("CZ", 48.5, 51.1, 12.0, 18.9),
        ("SK", 47.7, 49.7, 16.8, 22.6),
        ("HU", 45.7, 48.6, 16.1, 22.9),
        ("RO", 43.6, 48.3, 20.2, 29.7),
        ("GR", 34.8, 41.7, 19.4, 28.3),
        // Russia (vast but the box catches it)
        ("RU", 41.2, 81.9, 19.6, 180.0),
        ("UA", 44.4, 52.4, 22.1, 40.2),
        // Asia
        ("JP", 30.0, 45.6, 128.0, 146.0),
        ("KR", 33.1, 38.6, 124.6, 131.9),
        ("CN", 18.2, 53.6, 73.5, 134.8),
        ("IN", 6.7, 35.7, 68.1, 97.4),
        ("ID", -11.0, 6.1, 95.0, 141.0),
        ("PH", 4.6, 21.1, 116.9, 126.6),
        ("VN", 8.5, 23.4, 102.1, 109.5),
        ("TH", 5.6, 20.5, 97.3, 105.6),
        ("MY", 0.9, 7.4, 99.6, 119.3),
        ("SG", 1.2, 1.5, 103.6, 104.0),
        ("HK", 22.2, 22.6, 113.8, 114.4),
        ("TW", 21.9, 25.3, 119.5, 122.0),
        ("AE", 22.6, 26.1, 51.6, 56.4),
        ("SA", 16.4, 32.2, 34.5, 55.7),
        ("IL", 29.5, 33.3, 34.3, 35.9),
        ("TR", 35.8, 42.1, 25.7, 44.8),
        // South America
        ("BR", -33.8, 5.3, -73.9, -34.8),
        ("AR", -55.1, -21.8, -73.6, -53.6),
        ("CL", -55.9, -17.5, -75.7, -66.4),
        ("CO", -4.2, 13.4, -79.0, -66.8),
        ("PE", -18.3, 0.0, -81.3, -68.7),
        // Africa
        ("ZA", -34.8, -22.1, 16.5, 32.9),
        ("EG", 22.0, 31.7, 24.7, 36.9),
        ("NG", 4.3, 13.9, 2.7, 14.7),
        ("KE", -4.7, 5.0, 33.9, 41.9),
        ("MA", 27.7, 35.9, -13.2, -1.0),
    ];
    for (iso, la_min, la_max, lo_min, lo_max) in BOXES {
        if lat >= *la_min && lat <= *la_max && lon >= *lo_min && lon <= *lo_max {
            // Special case: US sub-boxes alias to "US".
            return Some(match *iso {
                "AK" | "HI" => "US",
                other => other,
            });
        }
    }
    None
}

/// Country-name lookup for an ISO code (rough but offline). Used to
/// surface a human-readable country alongside the ISO code in evidence.
pub fn country_name_for_iso(iso: &str) -> Option<&'static str> {
    Some(match iso {
        "US" => "United States",
        "CA" => "Canada",
        "MX" => "Mexico",
        "AU" => "Australia",
        "NZ" => "New Zealand",
        "GB" => "United Kingdom",
        "IE" => "Ireland",
        "FR" => "France",
        "ES" => "Spain",
        "PT" => "Portugal",
        "DE" => "Germany",
        "NL" => "Netherlands",
        "BE" => "Belgium",
        "LU" => "Luxembourg",
        "CH" => "Switzerland",
        "AT" => "Austria",
        "IT" => "Italy",
        "NO" => "Norway",
        "SE" => "Sweden",
        "FI" => "Finland",
        "DK" => "Denmark",
        "IS" => "Iceland",
        "PL" => "Poland",
        "CZ" => "Czechia",
        "SK" => "Slovakia",
        "HU" => "Hungary",
        "RO" => "Romania",
        "GR" => "Greece",
        "RU" => "Russia",
        "UA" => "Ukraine",
        "JP" => "Japan",
        "KR" => "South Korea",
        "CN" => "China",
        "IN" => "India",
        "ID" => "Indonesia",
        "PH" => "Philippines",
        "VN" => "Vietnam",
        "TH" => "Thailand",
        "MY" => "Malaysia",
        "SG" => "Singapore",
        "HK" => "Hong Kong",
        "TW" => "Taiwan",
        "AE" => "United Arab Emirates",
        "SA" => "Saudi Arabia",
        "IL" => "Israel",
        "TR" => "Turkey",
        "BR" => "Brazil",
        "AR" => "Argentina",
        "CL" => "Chile",
        "CO" => "Colombia",
        "PE" => "Peru",
        "ZA" => "South Africa",
        "EG" => "Egypt",
        "NG" => "Nigeria",
        "KE" => "Kenya",
        "MA" => "Morocco",
        _ => return None,
    })
}

/// Great-circle distance between two coordinates in kilometres
/// (Haversine formula). For proximity scoring.
///
/// # Guarantees
/// - A proper metric for finite inputs: non-negative, symmetric, zero iff the
///   points coincide, and bounded by half the Earth's circumference (≈20 015 km).
///   Uses the numerically-stable `atan2` form, so identical/antipodal points do
///   not produce `NaN`. (Invariants proved over a randomised sample in
///   `haversine_is_a_bounded_symmetric_metric`.)
///
/// ```
/// use huntsman_search_engine::util::geohash::haversine_km;
///
/// // Sydney → Melbourne is ~714 km great-circle.
/// assert!((haversine_km(-33.87, 151.21, -37.81, 144.96) - 714.0).abs() < 15.0);
/// assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0); // identical → 0, no NaN
/// ```
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0; // Earth radius in km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    2.0 * R * a.sqrt().atan2((1.0 - a).sqrt())
}

/// The convex geographic footprint of a set of observed coordinates: the hull
/// polygon that bounds every point, the area's centroid (the single best
/// point-estimate of the subject's base), and its diameter (the greatest
/// great-circle span across the points, in km).
#[derive(Debug, Clone, PartialEq)]
pub struct GeoFootprint {
    /// Convex-hull vertices in counter-clockwise order as `(lat, lon)`. For one
    /// or two distinct points the "hull" is just those points.
    pub hull: Vec<(f64, f64)>,
    /// Mean of the hull vertices, `(lat, lon)` — the area's centre of mass.
    pub centroid: (f64, f64),
    /// Greatest great-circle distance between any two input points, in km.
    pub diameter_km: f64,
}

impl GeoFootprint {
    /// A footprint is *tight* when every point lies within a single metropolitan
    /// span (diameter ≤ 25 km). A tight cluster of independent geo sources is a
    /// strong fix on a residence/base; a wide one describes a travel pattern.
    pub fn is_tight(&self) -> bool {
        self.diameter_km <= 25.0
    }
}

/// Compute the [`GeoFootprint`] of a set of `(lat, lon)` points: the convex hull
/// (via Andrew's monotone-chain algorithm), the centroid of the hull, and the
/// great-circle diameter. Returns `None` for fewer than three *distinct* points
/// (a hull needs three non-collinear vertices to bound an area; with one or two
/// distinct points there is no polygon to report).
///
/// The hull is computed in planar (lon, lat) degree space. At the city/region
/// scales OSINT geolocation operates over, the planar hull and the spherical
/// hull share the same vertex set, so this stays dependency-free and exact for
/// the bounding question; the *diameter* is measured with the spherical
/// [`haversine_km`] so the reported span is true great-circle kilometres.
///
/// ```
/// use huntsman_search_engine::util::geohash::geo_footprint;
///
/// // A tight cluster of three independent sightings around one suburb.
/// let pts = [(-33.870, 151.210), (-33.872, 151.215), (-33.868, 151.208)];
/// let fp = geo_footprint(&pts).expect("three points bound an area");
/// assert!(fp.is_tight(), "a few-hundred-metre spread is a tight fix");
/// ```
pub fn geo_footprint(points: &[(f64, f64)]) -> Option<GeoFootprint> {
    // Deduplicate identical coordinates first; the hull and the distinct-count
    // guard must both see unique points.
    let mut pts: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for &p in points {
        if !pts.contains(&p) {
            pts.push(p);
        }
    }
    if pts.len() < 3 {
        return None;
    }
    let hull = convex_hull_latlon(&pts);
    if hull.len() < 3 {
        // All points collinear — no bounded area.
        return None;
    }
    let n = hull.len() as f64;
    let centroid = (
        hull.iter().map(|p| p.0).sum::<f64>() / n,
        hull.iter().map(|p| p.1).sum::<f64>() / n,
    );
    // Diameter: greatest pairwise great-circle distance. The point count is
    // bounded (a scan holds tens of coordinates), so the O(n²) scan is trivial.
    let mut diameter_km = 0.0_f64;
    for i in 0..pts.len() {
        for j in (i + 1)..pts.len() {
            let d = haversine_km(pts[i].0, pts[i].1, pts[j].0, pts[j].1);
            if d > diameter_km {
                diameter_km = d;
            }
        }
    }
    Some(GeoFootprint {
        hull,
        centroid,
        diameter_km,
    })
}

/// Andrew's monotone-chain convex hull over `(lat, lon)` points, returned
/// counter-clockwise. Treats `lon` as x and `lat` as y. Collinear points on a
/// hull edge are excluded (strict turns only), so a degenerate all-collinear
/// input yields fewer than three vertices and the caller reports "no area".
fn convex_hull_latlon(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let mut pts: Vec<(f64, f64)> = points.to_vec();
    // Sort by lon (x) then lat (y). Total order via partial_cmp is safe: scan
    // coordinates are finite (parse_coords range-validates, no NaN).
    pts.sort_by(|a, b| {
        a.1.partial_cmp(&b.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal))
    });

    // 2D cross product of OA×OB for points O, A, B. >0 ⇒ counter-clockwise turn.
    let cross = |o: (f64, f64), a: (f64, f64), b: (f64, f64)| -> f64 {
        (a.1 - o.1) * (b.0 - o.0) - (a.0 - o.0) * (b.1 - o.1)
    };

    let mut lower: Vec<(f64, f64)> = Vec::new();
    for &p in &pts {
        while lower.len() >= 2 && cross(lower[lower.len() - 2], lower[lower.len() - 1], p) <= 0.0 {
            lower.pop();
        }
        lower.push(p);
    }
    let mut upper: Vec<(f64, f64)> = Vec::new();
    for &p in pts.iter().rev() {
        while upper.len() >= 2 && cross(upper[upper.len() - 2], upper[upper.len() - 1], p) <= 0.0 {
            upper.pop();
        }
        upper.push(p);
    }
    // Concatenate, dropping each chain's last point (it's the first of the other).
    lower.pop();
    upper.pop();
    lower.extend(upper);
    lower
}

/// The smallest circle enclosing a set of observed coordinates: its centre — the
/// **Chebyshev centre**, the point that minimises the *worst-case* distance to
/// any sighting — and the radius (km) to the farthest one.
///
/// This is a more robust single-point location estimate than a hull centroid:
/// the centroid is the mean of hull *vertices* and drifts toward whichever side
/// has more vertices, whereas the min-enclosing-circle centre is fixed by the
/// extreme points alone and answers "the one place that is never far from any
/// sighting" — exactly the location an investigator wants, with `radius_km` as
/// the honest uncertainty around it.
#[derive(Debug, Clone, PartialEq)]
pub struct EnclosingCircle {
    /// Circle centre as `(lat, lon)`.
    pub center: (f64, f64),
    /// Great-circle distance from the centre to the farthest input point, km.
    pub radius_km: f64,
}

/// Compute the [`EnclosingCircle`] of a set of `(lat, lon)` points via Welzl's
/// algorithm (the incremental, move-to-front formulation). Returns `None` for an
/// empty input.
///
/// Deterministic: unlike the textbook randomised Welzl, points are processed in
/// their given order. The minimum enclosing circle is *unique*, so the result is
/// order-independent regardless; with the bounded coordinate counts a scan holds
/// (tens), the non-randomised worst case is irrelevant. The circle is fitted in
/// planar (lon, lat) degree space — at city/region scale that shares the optimum
/// with the spherical problem — while `radius_km` is measured with the spherical
/// [`haversine_km`] so the reported uncertainty is true kilometres.
///
/// ```
/// use huntsman_search_engine::util::geohash::min_enclosing_circle;
///
/// // Three points spanning a small triangle; the centre sits between them.
/// let c = min_enclosing_circle(&[(0.0, 0.0), (0.0, 0.2), (0.2, 0.1)]).unwrap();
/// assert!(c.radius_km > 0.0 && c.radius_km < 30.0);
/// ```
pub fn min_enclosing_circle(points: &[(f64, f64)]) -> Option<EnclosingCircle> {
    // Planar disk in (x=lon, y=lat) degree space.
    #[derive(Clone, Copy)]
    struct Disk {
        x: f64,
        y: f64,
        r: f64,
    }
    // Numerical slack so a point exactly on the boundary counts as inside.
    const EPS: f64 = 1e-12;
    let dist = |ax: f64, ay: f64, bx: f64, by: f64| ((ax - bx).powi(2) + (ay - by).powi(2)).sqrt();
    let in_disk = |d: &Disk, x: f64, y: f64| dist(d.x, d.y, x, y) <= d.r + EPS;
    // Circle through two points: the diameter circle.
    let from2 = |a: (f64, f64), b: (f64, f64)| Disk {
        x: (a.0 + b.0) / 2.0,
        y: (a.1 + b.1) / 2.0,
        r: dist(a.0, a.1, b.0, b.1) / 2.0,
    };
    // Circumscribed circle of three points; `None` if (near-)collinear.
    let from3 = |a: (f64, f64), b: (f64, f64), c: (f64, f64)| -> Option<Disk> {
        let d = 2.0 * (a.0 * (b.1 - c.1) + b.0 * (c.1 - a.1) + c.0 * (a.1 - b.1));
        if d.abs() < 1e-15 {
            return None;
        }
        let (a2, b2, c2) = (
            a.0 * a.0 + a.1 * a.1,
            b.0 * b.0 + b.1 * b.1,
            c.0 * c.0 + c.1 * c.1,
        );
        let ux = (a2 * (b.1 - c.1) + b2 * (c.1 - a.1) + c2 * (a.1 - b.1)) / d;
        let uy = (a2 * (c.0 - b.0) + b2 * (a.0 - c.0) + c2 * (b.0 - a.0)) / d;
        Some(Disk {
            x: ux,
            y: uy,
            r: dist(ux, uy, a.0, a.1),
        })
    };

    // Points in (x=lon, y=lat) order. Deduplicate so collinear/coincident inputs
    // don't stall the incremental passes.
    let mut p: Vec<(f64, f64)> = Vec::with_capacity(points.len());
    for &(lat, lon) in points {
        let q = (lon, lat);
        if !p.contains(&q) {
            p.push(q);
        }
    }
    let first = *p.first()?;
    // Incremental Welzl: maintain the MEC of p[0..=i], rebuilding when p[i] falls
    // outside, using one then two boundary points.
    let mut d = Disk {
        x: first.0,
        y: first.1,
        r: 0.0,
    };
    for i in 1..p.len() {
        if in_disk(&d, p[i].0, p[i].1) {
            continue;
        }
        d = Disk {
            x: p[i].0,
            y: p[i].1,
            r: 0.0,
        };
        for j in 0..i {
            if in_disk(&d, p[j].0, p[j].1) {
                continue;
            }
            d = from2(p[i], p[j]);
            for k in 0..j {
                if in_disk(&d, p[k].0, p[k].1) {
                    continue;
                }
                if let Some(d3) = from3(p[i], p[j], p[k]) {
                    d = d3;
                }
            }
        }
    }
    // Report the centre as (lat, lon) and the radius as the true great-circle
    // distance to the farthest original point.
    let center = (d.y, d.x);
    let radius_km = points
        .iter()
        .map(|&(lat, lon)| haversine_km(center.0, center.1, lat, lon))
        .fold(0.0_f64, f64::max);
    Some(EnclosingCircle { center, radius_km })
}

/// The **geometric median** (Weber point) of observed coordinates — the location
/// that minimises the *sum* of great-circle distances to every sighting (the L1
/// facility-location optimum), found with **Weiszfeld's algorithm**.
///
/// This is the most outlier-robust single-point location estimate available: a
/// plain centroid (L2) or a Chebyshev centre (L∞, the min-enclosing-circle
/// centre) is dragged toward a lone faraway sighting — a trip, a VPN exit, a
/// planted address — whereas the geometric median has a breakdown point of 0.5
/// (up to half the points can be arbitrarily corrupted before it moves far). For
/// "where does this person actually live", it is the estimator to trust.
///
/// Deterministic: initialised at the centroid and iterated a fixed bounded number
/// of times (no randomness); when an iterate lands on a data point — Weiszfeld's
/// singularity — it snaps to that point, which is the median in that case. Fitted
/// in planar (lon, lat) degree space, consistent with the other geometry helpers.
///
/// ```
/// use huntsman_search_engine::util::geohash::geometric_median;
///
/// // Three tight points plus a far outlier: the median stays with the cluster.
/// let pts = [(0.0, 0.0), (0.0, 0.01), (0.01, 0.0), (10.0, 10.0)];
/// let m = geometric_median(&pts).unwrap();
/// assert!(m.0.abs() < 1.0 && m.1.abs() < 1.0, "robust to the outlier: {m:?}");
/// ```
pub fn geometric_median(points: &[(f64, f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    if points.len() == 1 {
        return Some(points[0]);
    }
    // Work in (x = lon, y = lat).
    let pts: Vec<(f64, f64)> = points.iter().map(|&(lat, lon)| (lon, lat)).collect();
    let n = pts.len() as f64;
    let mut x = pts.iter().fold((0.0, 0.0), |a, p| (a.0 + p.0, a.1 + p.1));
    x = (x.0 / n, x.1 / n);

    const MAX_ITERS: usize = 128;
    const CONVERGED: f64 = 1e-10; // degrees
    const ON_POINT: f64 = 1e-12;
    for _ in 0..MAX_ITERS {
        let mut num = (0.0_f64, 0.0_f64);
        let mut den = 0.0_f64;
        let mut snapped: Option<(f64, f64)> = None;
        for &p in &pts {
            let d = ((x.0 - p.0).powi(2) + (x.1 - p.1).powi(2)).sqrt();
            if d < ON_POINT {
                snapped = Some(p);
                break;
            }
            let w = 1.0 / d;
            num.0 += p.0 * w;
            num.1 += p.1 * w;
            den += w;
        }
        if let Some(p) = snapped {
            x = p;
            break;
        }
        let next = (num.0 / den, num.1 / den);
        let moved = ((next.0 - x.0).powi(2) + (next.1 - x.1).powi(2)).sqrt();
        x = next;
        if moved < CONVERGED {
            break;
        }
    }
    Some((x.1, x.0)) // back to (lat, lon)
}

/// Confidence-weighted centroid of observed coordinates — the **convex
/// combination** `Σ wᵢ·pᵢ / Σ wᵢ` of the points `pᵢ` by non-negative weights
/// `wᵢ` (each sighting's `c_effective`). Because the weights are non-negative and
/// normalised, the result provably lies inside the convex hull of the points (a
/// convex combination never escapes the hull), so it is always a valid interior
/// location estimate — but, unlike the plain hull centroid, it is pulled toward
/// the *high-confidence* sightings rather than treating a shaky IP-geo guess and
/// a GPS-exact photo as equals.
///
/// Returns `None` for an empty input. If every weight is zero (or negative,
/// which is clamped away), it degrades to the unweighted mean so a degenerate
/// confidence set still yields a centre rather than a divide-by-zero.
///
/// ```
/// use huntsman_search_engine::util::geohash::weighted_centroid;
///
/// // A high-confidence point and a low-confidence one: the centre sits much
/// // closer to the trusted sighting than a plain average (0.5) would.
/// let c = weighted_centroid(&[((0.0, 0.0), 0.9), ((0.0, 1.0), 0.1)]).unwrap();
/// assert!(c.1 < 0.2, "weighted toward the high-confidence point");
/// ```
pub fn weighted_centroid(points: &[((f64, f64), f64)]) -> Option<(f64, f64)> {
    if points.is_empty() {
        return None;
    }
    let mut sw = 0.0_f64;
    let mut slat = 0.0_f64;
    let mut slon = 0.0_f64;
    for &((lat, lon), w) in points {
        let w = w.max(0.0);
        sw += w;
        slat += w * lat;
        slon += w * lon;
    }
    if sw <= 0.0 {
        // All weights zero → fall back to the unweighted mean.
        let n = points.len() as f64;
        let lat = points.iter().map(|&((la, _), _)| la).sum::<f64>() / n;
        let lon = points.iter().map(|&((_, lo), _)| lo).sum::<f64>() / n;
        return Some((lat, lon));
    }
    Some((slat / sw, slon / sw))
}

/// Test whether point `p = (lat, lon)` lies inside (or on the boundary of) the
/// convex polygon `hull`, whose vertices are in counter-clockwise order — the
/// form [`geo_footprint`] returns. The check is whether `p` is left-of-or-on
/// every directed edge (all cross products ≥ 0 in (lon, lat) space). A hull of
/// fewer than three vertices bounds no area, so the result is `false`.
///
/// Use: decide whether a *candidate* location — a geocoded breach address, a
/// claimed home — is consistent with a subject's established area of operation,
/// without any distance threshold to tune; the polygon itself is the boundary.
///
/// ```
/// use huntsman_search_engine::util::geohash::point_in_convex_hull;
///
/// let square = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0)];
/// assert!(point_in_convex_hull(&square, (0.5, 0.5)));   // interior
/// assert!(point_in_convex_hull(&square, (0.0, 0.5)));   // on an edge
/// assert!(!point_in_convex_hull(&square, (2.0, 0.5)));  // outside
/// ```
pub fn point_in_convex_hull(hull: &[(f64, f64)], p: (f64, f64)) -> bool {
    if hull.len() < 3 {
        return false;
    }
    // Cross product of edge a→b with a→p, in (x=lon, y=lat) space — same
    // orientation as `convex_hull_latlon` (CCW ⇒ ≥ 0 on the interior side).
    let cross = |a: (f64, f64), b: (f64, f64)| -> f64 {
        (b.1 - a.1) * (p.0 - a.0) - (b.0 - a.0) * (p.1 - a.1)
    };
    // Tiny negative slack so a point numerically on an edge counts as inside.
    const EPS: f64 = -1e-12;
    let n = hull.len();
    (0..n).all(|i| cross(hull[i], hull[(i + 1) % n]) >= EPS)
}

/// Parsed components of a free-form address string.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AddressComponents {
    pub street: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub iso_country: Option<String>,
}

/// Two-letter ISO country code lookup by name. Covers the ~30
/// countries most likely to appear in OSINT breach data.
fn iso_for(country: &str) -> Option<&'static str> {
    let l = country.trim().to_lowercase();
    Some(match l.as_str() {
        "united states" | "usa" | "us" | "united states of america" => "US",
        "australia" | "au" => "AU",
        "united kingdom" | "uk" | "great britain" | "england" | "gb" => "GB",
        "canada" | "ca" => "CA",
        "germany" | "de" | "deutschland" => "DE",
        "france" | "fr" => "FR",
        "netherlands" | "nl" | "holland" => "NL",
        "spain" | "es" => "ES",
        "italy" | "it" => "IT",
        "japan" | "jp" => "JP",
        "china" | "cn" => "CN",
        "india" | "in" => "IN",
        "brazil" | "br" => "BR",
        "russia" | "ru" => "RU",
        "ireland" | "ie" => "IE",
        "new zealand" | "nz" => "NZ",
        "singapore" | "sg" => "SG",
        "south africa" | "za" => "ZA",
        "mexico" | "mx" => "MX",
        "south korea" | "kr" | "korea" => "KR",
        "switzerland" | "ch" => "CH",
        "sweden" | "se" => "SE",
        "norway" | "no" => "NO",
        "denmark" | "dk" => "DK",
        "finland" | "fi" => "FI",
        "poland" | "pl" => "PL",
        "belgium" | "be" => "BE",
        "austria" | "at" => "AT",
        "portugal" | "pt" => "PT",
        _ => return None,
    })
}

/// Australian state-name normaliser.
fn au_state_norm(s: &str) -> Option<&'static str> {
    let l = s.trim().to_lowercase();
    Some(match l.as_str() {
        "nsw" | "new south wales" => "NSW",
        "vic" | "victoria" => "VIC",
        "qld" | "queensland" => "QLD",
        "wa" | "western australia" => "WA",
        "sa" | "south australia" => "SA",
        "tas" | "tasmania" => "TAS",
        "act" | "australian capital territory" => "ACT",
        "nt" | "northern territory" => "NT",
        _ => return None,
    })
}

/// Parse a comma-separated address into structured components.
///
/// Handles common formats:
///   "Sydney, NSW, Australia"      → city=Sydney, state=NSW, country=Australia
///   "10 Smith St, Melbourne, VIC" → street=..., city=..., state=...
///   "SA, VIC"                     → state list (no city/country)
///   "Brisbane, QLD 4000"          → city + state + postal
pub fn parse_address(input: &str) -> AddressComponents {
    let mut out = AddressComponents::default();
    let parts: Vec<&str> = input
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if parts.is_empty() {
        return out;
    }

    // Country: last part if it matches a known ISO name.
    if let Some(last) = parts.last()
        && let Some(iso) = iso_for(last)
    {
        out.country = Some((*last).to_string());
        out.iso_country = Some(iso.to_string());
    }

    // Scan every part for state codes and postal patterns. A part like
    // "QLD 4000" carries both — split on space and try each token.
    for part in &parts {
        for token in part.split_whitespace() {
            // Australian state code
            if out.state.is_none()
                && let Some(s) = au_state_norm(token)
            {
                out.state = Some(s.to_string());
                if out.iso_country.is_none() {
                    out.iso_country = Some("AU".to_string());
                    out.country = Some("Australia".to_string());
                }
            }
        }
        // Postal code (bare digits, 4-10 chars). Only the LAST token of a part
        // is a candidate: a real postcode trails its part ("QLD 4000", "4000"),
        // whereas a leading digit run like the street number in "1234 Smith St"
        // is followed by the street name and must NOT be captured as a postcode.
        if out.postal_code.is_none()
            && let Some(tok) = part.split_whitespace().last()
            && tok.chars().all(|c| c.is_ascii_digit())
            && (4..=10).contains(&tok.len())
        {
            out.postal_code = Some(tok.to_string());
        }
    }

    // Street detection BEFORE city: if parts.len() ≥ 3 and the first
    // part starts with a digit, it's a street address.
    let mut city_skip = 0usize;
    if parts.len() >= 3 && parts[0].chars().next().map(|c| c.is_ascii_digit()) == Some(true) {
        out.street = Some(parts[0].to_string());
        city_skip = 1;
    }

    // City: first non-classified part after any street.
    for part in parts.iter().skip(city_skip) {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if out.country.as_deref() == Some(p) {
            continue;
        }
        // "QLD 4000"-style parts: skip if the entire part is a state token,
        // a postal, or "state postal" combination.
        let first_token = p.split_whitespace().next().unwrap_or("");
        if au_state_norm(first_token).is_some() {
            continue;
        }
        if iso_for(p).is_some() {
            continue;
        }
        if p.chars().all(|c| c.is_ascii_digit() || c.is_whitespace()) {
            continue;
        }
        // First valid candidate wins.
        out.city = Some(p.to_string());
        break;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geohash_sydney_opera_house() {
        // Famous coords: -33.8568° S, 151.2153° E → r3gx2f7 prefix
        let h = geohash(-33.8568, 151.2153, 7);
        assert!(h.starts_with("r3gx2"), "got {h}");
        assert_eq!(h.len(), 7);
    }

    #[test]
    fn geohash_invalid_coords_returns_empty() {
        assert!(geohash(91.0, 0.0, 7).is_empty());
        assert!(geohash(0.0, 200.0, 7).is_empty());
    }

    #[test]
    fn parse_coords_handles_typical_format() {
        assert_eq!(
            parse_coords("-33.8568,151.2153"),
            Some((-33.8568, 151.2153))
        );
        assert_eq!(parse_coords("38.83, -104.82"), Some((38.83, -104.82)));
    }

    #[test]
    fn parse_coords_rejects_invalid() {
        assert!(parse_coords("not-coords").is_none());
        assert!(parse_coords("91,0").is_none());
        assert!(parse_coords("0,181").is_none());
    }

    #[test]
    fn timezone_australia_specific() {
        assert_eq!(timezone_for(-33.86, 151.21), "Australia/Sydney");
        assert_eq!(timezone_for(-31.95, 115.86), "Australia/Perth");
        assert_eq!(timezone_for(-34.93, 138.60), "Australia/Adelaide");
    }

    #[test]
    fn timezone_us_specific() {
        assert_eq!(timezone_for(40.71, -74.00), "America/New_York");
        assert_eq!(timezone_for(37.77, -122.41), "America/Los_Angeles");
    }

    #[test]
    fn parse_address_aus_full() {
        let a = parse_address("Sydney, NSW, Australia");
        assert_eq!(a.city.as_deref(), Some("Sydney"));
        assert_eq!(a.state.as_deref(), Some("NSW"));
        assert_eq!(a.country.as_deref(), Some("Australia"));
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_with_street() {
        let a = parse_address("10 Smith St, Melbourne, VIC, Australia");
        assert_eq!(a.street.as_deref(), Some("10 Smith St"));
        assert_eq!(a.city.as_deref(), Some("Melbourne"));
        assert_eq!(a.state.as_deref(), Some("VIC"));
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_state_only() {
        let a = parse_address("SA, VIC");
        // First-classified-state wins
        assert_eq!(a.state.as_deref(), Some("SA"));
        // Country inferred from AU state code
        assert_eq!(a.iso_country.as_deref(), Some("AU"));
    }

    #[test]
    fn parse_address_postal_code() {
        let a = parse_address("Brisbane, QLD 4000");
        assert_eq!(a.city.as_deref(), Some("Brisbane"));
        assert_eq!(a.state.as_deref(), Some("QLD"));
        assert_eq!(a.postal_code.as_deref(), Some("4000"));
    }

    #[test]
    fn parse_address_does_not_mistake_street_number_for_postal() {
        // Regression: a multi-digit street number is the LEADING token of a
        // street part, not a postcode — it must not be captured as postal_code.
        let a = parse_address("1234 Smith St, Sydney, NSW");
        assert_eq!(a.street.as_deref(), Some("1234 Smith St"));
        assert_eq!(a.postal_code, None);
        assert_eq!(a.state.as_deref(), Some("NSW"));

        // A trailing postcode is still captured even alongside a long street no.
        let b = parse_address("4000 George St, Brisbane, QLD 4000");
        assert_eq!(b.street.as_deref(), Some("4000 George St"));
        assert_eq!(b.postal_code.as_deref(), Some("4000")); // from "QLD 4000", not the street
        assert_eq!(b.state.as_deref(), Some("QLD"));
    }

    #[test]
    fn haversine_known_distance_sydney_to_melbourne() {
        // SYD (-33.87,151.21) → MEL (-37.81,144.96) is ~714 km great-circle.
        let d = haversine_km(-33.87, 151.21, -37.81, 144.96);
        assert!((d - 714.0).abs() < 15.0, "got {d} km");
        // Identical points → zero distance, no NaN.
        assert_eq!(haversine_km(10.0, 20.0, 10.0, 20.0), 0.0);
    }

    /// Metric invariants of `haversine_km`, proved over a randomised sample of
    /// valid coordinates (seeded LCG — deterministic, no `rand` dependency). The
    /// geo-cluster correlators treat this as a distance, so it must stay a proper
    /// metric: finite, non-negative, symmetric, identity-zero, and bounded by
    /// half the Earth's circumference. Guards against a future edit (e.g. swapping
    /// back to the `acos` form, or transposing a term) silently breaking it.
    #[test]
    fn haversine_is_a_bounded_symmetric_metric() {
        // Half-circumference upper bound: π·R, plus a hair for float slack.
        let max_km = std::f64::consts::PI * 6371.0 + 1e-6;
        let mut state: u64 = 0x5DEECE66D;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            // Top 53 bits → [0, 1).
            (state >> 11) as f64 / (1u64 << 53) as f64
        };
        for _ in 0..50_000 {
            let lat1 = next() * 180.0 - 90.0;
            let lon1 = next() * 360.0 - 180.0;
            let lat2 = next() * 180.0 - 90.0;
            let lon2 = next() * 360.0 - 180.0;
            let d = haversine_km(lat1, lon1, lat2, lon2);
            assert!(d.is_finite() && d >= 0.0, "non-metric distance {d}");
            assert!(d <= max_km, "distance {d} exceeds half-circumference");
            // Symmetric: swapping the endpoints is byte-identical (the formula is
            // symmetric, so this is exact, not approximate).
            assert_eq!(d, haversine_km(lat2, lon2, lat1, lon1), "asymmetric");
            // Identity: a point is zero distance from itself.
            assert_eq!(haversine_km(lat1, lon1, lat1, lon1), 0.0);
        }
    }

    #[test]
    fn footprint_needs_three_distinct_noncollinear_points() {
        // Fewer than three distinct points: no bounded area.
        assert!(geo_footprint(&[]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0)]).is_none());
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0)]).is_none());
        // Duplicates collapse — three records of two places is still two points.
        assert!(geo_footprint(&[(0.0, 0.0), (0.0, 0.0), (1.0, 1.0)]).is_none());
        // Three collinear points bound no area.
        assert!(geo_footprint(&[(0.0, 0.0), (1.0, 1.0), (2.0, 2.0)]).is_none());
    }

    #[test]
    fn footprint_hull_centroid_and_diameter() {
        // A unit square (plus an interior point that must NOT become a vertex).
        let pts = [
            (0.0, 0.0),
            (0.0, 1.0),
            (1.0, 1.0),
            (1.0, 0.0),
            (0.5, 0.5), // interior — excluded from the hull
        ];
        let fp = geo_footprint(&pts).expect("square has an area");
        assert_eq!(fp.hull.len(), 4, "interior point must not be a hull vertex");
        // Centroid of the four corners is the square's centre.
        assert!((fp.centroid.0 - 0.5).abs() < 1e-9 && (fp.centroid.1 - 0.5).abs() < 1e-9);
        // Diameter is a diagonal of the square (~157 km at the equator), strictly
        // greater than a side (~111 km).
        assert!(
            fp.diameter_km > 111.0 && fp.diameter_km < 160.0,
            "{}",
            fp.diameter_km
        );
        assert!(!fp.is_tight(), "a ~1° square is not a single-metro fix");
    }

    #[test]
    fn footprint_tight_cluster_is_a_location_fix() {
        // Three sightings within a few hundred metres of one suburb.
        let pts = [
            (-33.8700, 151.2100),
            (-33.8720, 151.2150),
            (-33.8680, 151.2080),
        ];
        let fp = geo_footprint(&pts).expect("three points bound an area");
        assert!(
            fp.is_tight(),
            "diameter {} should be <=25km",
            fp.diameter_km
        );
    }

    #[test]
    fn min_enclosing_circle_basics() {
        // Empty → None.
        assert!(min_enclosing_circle(&[]).is_none());
        // Single point → zero-radius circle centred on it.
        let c = min_enclosing_circle(&[(10.0, 20.0)]).unwrap();
        assert_eq!(c.center, (10.0, 20.0));
        assert_eq!(c.radius_km, 0.0);
    }

    #[test]
    fn min_enclosing_circle_covers_every_point_and_is_order_independent() {
        let pts = [
            (-33.8700, 151.2100),
            (-33.8800, 151.2300),
            (-33.8600, 151.2000),
            (-33.8750, 151.2200), // interior-ish
        ];
        let c = min_enclosing_circle(&pts).expect("non-empty");
        // Every input point lies within the circle (radius is the max distance,
        // so all are ≤ radius by construction — assert with a small slack).
        for &(lat, lon) in &pts {
            let d = haversine_km(c.center.0, c.center.1, lat, lon);
            assert!(
                d <= c.radius_km + 1e-6,
                "point {d}km outside r={}",
                c.radius_km
            );
        }
        // The minimum circle is unique → permuting the input gives the same
        // centre and radius (determinism the correlator relies on).
        let mut rev = pts;
        rev.reverse();
        let c2 = min_enclosing_circle(&rev).unwrap();
        assert!((c.center.0 - c2.center.0).abs() < 1e-9);
        assert!((c.center.1 - c2.center.1).abs() < 1e-9);
        assert!((c.radius_km - c2.radius_km).abs() < 1e-6);
    }

    #[test]
    fn min_enclosing_circle_chebyshev_beats_centroid_for_worst_case() {
        // Three points clustered tightly plus one outlier. The Chebyshev centre
        // minimises the worst-case distance, so its radius must be no larger than
        // the worst-case distance from the hull centroid.
        let pts = [
            (0.0, 0.0),
            (0.0, 0.01),
            (0.01, 0.0),
            (0.0, 0.5), // outlier
        ];
        let mec = min_enclosing_circle(&pts).unwrap();
        let fp = geo_footprint(&pts).unwrap();
        let centroid_worst = pts
            .iter()
            .map(|&(lat, lon)| haversine_km(fp.centroid.0, fp.centroid.1, lat, lon))
            .fold(0.0_f64, f64::max);
        assert!(
            mec.radius_km <= centroid_worst + 1e-6,
            "MEC radius {} must minimise worst-case vs centroid {}",
            mec.radius_km,
            centroid_worst
        );
    }

    #[test]
    fn geometric_median_basics_and_robustness() {
        // Empty → None; single → itself.
        assert!(geometric_median(&[]).is_none());
        assert_eq!(geometric_median(&[(12.0, 34.0)]), Some((12.0, 34.0)));

        // The defining property: robust to an outlier. Three tight points near
        // the origin plus one far outlier. The geometric median must stay with
        // the cluster, while the plain mean is dragged a quarter of the way to
        // the outlier.
        let pts = [(0.0, 0.0), (0.0, 0.02), (0.02, 0.0), (10.0, 10.0)];
        let med = geometric_median(&pts).unwrap();
        let mean = (
            pts.iter().map(|p| p.0).sum::<f64>() / 4.0,
            pts.iter().map(|p| p.1).sum::<f64>() / 4.0,
        );
        let dist0 = |q: (f64, f64)| haversine_km(0.0, 0.0, q.0, q.1);
        assert!(dist0(med) < 5.0, "median stays with the cluster: {med:?}");
        assert!(
            dist0(med) < dist0(mean),
            "median ({:.1}km) must beat the mean ({:.1}km) on outlier robustness",
            dist0(med),
            dist0(mean)
        );
    }

    #[test]
    fn geometric_median_minimises_total_distance() {
        // Against a small random sample, the Weiszfeld solution's summed distance
        // must be ≤ that of any input point (the optimum beats every vertex).
        let pts = [
            (-33.87, 151.21),
            (-33.80, 151.10),
            (-33.95, 151.20),
            (-33.70, 151.30),
            (-33.88, 151.00),
        ];
        let med = geometric_median(&pts).unwrap();
        let total = |q: (f64, f64)| {
            pts.iter()
                .map(|&p| haversine_km(q.0, q.1, p.0, p.1))
                .sum::<f64>()
        };
        let med_total = total(med);
        for &p in &pts {
            assert!(
                med_total <= total(p) + 1e-6,
                "median total {med_total} must be ≤ vertex total {}",
                total(p)
            );
        }
    }

    #[test]
    fn weighted_centroid_pulls_toward_confidence_and_stays_in_hull() {
        // Empty → None.
        assert!(weighted_centroid(&[]).is_none());
        // All-zero weights → unweighted mean (no divide-by-zero).
        let mean = weighted_centroid(&[((0.0, 0.0), 0.0), ((0.0, 2.0), 0.0)]).unwrap();
        assert!((mean.1 - 1.0).abs() < 1e-9);
        // A trusted point and a shaky one: the centre is pulled toward the
        // high-confidence sighting and remains a convex combination (inside the
        // segment, i.e. between the two longitudes).
        let c = weighted_centroid(&[((0.0, 0.0), 0.95), ((0.0, 1.0), 0.30)]).unwrap();
        assert!(c.1 > 0.0 && c.1 < 0.5, "pulled toward 0.0: {}", c.1);
    }

    #[test]
    fn point_in_convex_hull_uses_real_hull_orientation() {
        // Build the hull the same way the footprint does, then test membership —
        // proves the in-hull test agrees with the hull builder's CCW order.
        let pts = [(0.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 0.0), (0.5, 0.5)];
        let fp = geo_footprint(&pts).unwrap();
        assert!(point_in_convex_hull(&fp.hull, (0.5, 0.5)), "interior point");
        assert!(
            point_in_convex_hull(&fp.hull, (0.0, 0.5)),
            "edge point counts inside"
        );
        assert!(
            !point_in_convex_hull(&fp.hull, (1.5, 0.5)),
            "point outside the square"
        );
        assert!(
            !point_in_convex_hull(&fp.hull, (-0.1, -0.1)),
            "point below-left"
        );
        // Degenerate hulls bound no area.
        assert!(!point_in_convex_hull(&[(0.0, 0.0), (1.0, 1.0)], (0.5, 0.5)));
    }

    #[test]
    fn reverse_country_iso_aliases_us_subregions() {
        assert_eq!(reverse_country_iso(-33.87, 151.21), Some("AU")); // Sydney
        assert_eq!(reverse_country_iso(61.0, -150.0), Some("US")); // Alaska → US
        assert_eq!(reverse_country_iso(21.3, -157.8), Some("US")); // Hawaii → US
        assert_eq!(reverse_country_iso(0.0, -30.0), None); // mid-Atlantic
    }
}
