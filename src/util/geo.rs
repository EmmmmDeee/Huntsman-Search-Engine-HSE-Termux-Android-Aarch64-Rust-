use crate::core::error::{Error, Result};

/// Parse a `"lat,lon"` seed into a finite, in-range coordinate pair.
///
/// Every forward-geo module (`geocode`/`photon`/`overpass`/`wigle`/
/// `sunrise_sunset`) feeds the result straight into an external API query via
/// `?`, so an out-of-range or non-finite value here would issue a nonsense
/// request (lat = 200, NaN, …). Rejecting at the parse boundary means no
/// caller can forget to validate, and matches the range gate that
/// [`crate::util::geohash::parse_coords`] applies on the classifier side — the
/// two stay byte-for-byte consistent about what a coordinate is. The
/// null-island (`0,0`) sentinel is intentionally *not* rejected here: that is
/// an output-filtering policy for provider responses ([`is_valid_coords`]),
/// not an input-parsing concern for a seed the operator typed deliberately.
pub fn parse_coords(value: &str) -> Result<(f64, f64)> {
    let (a, b) = value
        .split_once(',')
        .ok_or_else(|| Error::module("geo", "coordinates must be 'lat,lon'"))?;
    let lat: f64 = a
        .trim()
        .parse()
        .map_err(|_| Error::module("geo", "invalid latitude"))?;
    let lon: f64 = b
        .trim()
        .parse()
        .map_err(|_| Error::module("geo", "invalid longitude"))?;
    if !lat.is_finite() || !(-90.0..=90.0).contains(&lat) {
        return Err(Error::module("geo", "latitude out of range (-90..=90)"));
    }
    if !lon.is_finite() || !(-180.0..=180.0).contains(&lon) {
        return Err(Error::module("geo", "longitude out of range (-180..=180)"));
    }
    Ok((lat, lon))
}

/// Canonical validity check for a geographic coordinate, shared by every
/// module that turns an external lat/lon into a `Coordinates` entity (the
/// forward geocoders `geocode`/`photon`/`overpass`, the precise-fix sources
/// `geo_intel`/`exif_geo`/`wifi_intel`/`cell_intel`/`mls`, …). Modules
/// previously hand-rolled some subset of these guards — most only rejected
/// `0,0` and let out-of-range/NaN values through, which then became
/// high-confidence false fixes that poison the geo-cluster correlator. One
/// definition keeps the policy consistent.
///
/// Rejects:
///   - non-finite values (NaN, ±inf) from malformed JSON,
///   - out-of-range values (`|lat| > 90`, `|lon| > 180`), and
///   - the `0.0, 0.0` "Null Island" sentinel that geo APIs and the Android
///     location stack emit when they have no real fix.
///
/// Coarse IP/WiFi-geo providers (`ip_geo`, `ipinfo`, `ipapi`, `ip2location`,
/// `ipquery`, `wigle`) want [`is_plausible_provider_coord`] instead: it
/// builds on this but additionally drops the near-null-island placeholder
/// band those APIs emit. Precise sources stay here so a real equatorial fix
/// isn't discarded.
///
/// ```
/// use huntsman_search_engine::util::geo::is_valid_coords;
///
/// assert!(is_valid_coords(-27.4766, 153.0166)); // Brisbane
/// assert!(is_valid_coords(0.0, 153.0));          // a real equatorial fix is kept
/// assert!(!is_valid_coords(0.0, 0.0));           // Null Island sentinel
/// assert!(!is_valid_coords(91.0, 0.0));          // out of range
/// assert!(!is_valid_coords(f64::NAN, 0.0));      // non-finite
/// ```
#[must_use]
pub fn is_valid_coords(lat: f64, lon: f64) -> bool {
    lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
        && !(lat == 0.0 && lon == 0.0)
}

/// True if a coordinate falls within the bounding box of the Australian
/// mainland plus Tasmania. A coarse, **offline** AU-relevance gate: it lets a
/// raw `Coordinates` seed be classified as on-region before (or without) a
/// network reverse-geocode, so an AU-focused scan can keep AU fixes as strong
/// anchors and down-weight everything else.
///
/// The box (lat −44.0..=−10.0, lon 112.0..=154.0) covers the continent and
/// Tasmania. It deliberately excludes the far external territories (Christmas
/// Island, Cocos, Norfolk, Macquarie) — including them would stretch the box
/// far enough to swallow large tracts of ocean and neighbouring countries,
/// trading a tiny recall gain for real false positives. A point still must be
/// [`is_valid_coords`]; null island and out-of-range values are never "in AU".
///
/// ```
/// use huntsman_search_engine::util::geo::is_in_australia;
///
/// assert!(is_in_australia(-27.4766, 153.0166)); // Brisbane
/// assert!(is_in_australia(-42.8821, 147.3272));  // Hobart, Tasmania
/// assert!(!is_in_australia(40.7128, -74.0060));  // New York
/// assert!(!is_in_australia(-36.8485, 174.7633)); // Auckland, NZ
/// assert!(!is_in_australia(0.0, 0.0));           // null island
/// ```
#[must_use]
pub fn is_in_australia(lat: f64, lon: f64) -> bool {
    is_valid_coords(lat, lon) && (-44.0..=-10.0).contains(&lat) && (112.0..=154.0).contains(&lon)
}

/// Resolve a coordinate to the Australian state/territory whose bounding box
/// contains it, returning the canonical abbreviation (`QLD`, `NSW`, `VIC`,
/// `SA`, `WA`, `TAS`, `NT`, `ACT`) or `None` when the point is outside
/// Australia. A coarse, **offline** companion to [`is_in_australia`]: it lets a
/// raw coordinate seed be attributed to a state with no network call, so an
/// AU-focused scan can sharpen "somewhere in Australia" to a jurisdiction and
/// cross-check it against state-derived signals (postcodes, addresses).
///
/// These are rectangular approximations, not polygons, so points near a shared
/// border can be misattributed and the boxes overlap. The ACT (a small enclave
/// inside NSW) is therefore tested first so it isn't swallowed by the NSW box;
/// the remaining states are mostly disjoint in longitude/latitude. This is a
/// hint to prioritise on-region leads, never proof of jurisdiction.
///
/// ```
/// use huntsman_search_engine::util::geo::au_state_for_coords;
///
/// assert_eq!(au_state_for_coords(-27.4766, 153.0166), Some("QLD")); // Brisbane
/// assert_eq!(au_state_for_coords(-31.9523, 115.8613), Some("WA"));  // Perth
/// assert_eq!(au_state_for_coords(-35.2809, 149.1300), Some("ACT")); // Canberra
/// assert_eq!(au_state_for_coords(40.7128, -74.0060), None);         // New York
/// ```
#[must_use]
pub fn au_state_for_coords(lat: f64, lon: f64) -> Option<&'static str> {
    if !is_in_australia(lat, lon) {
        return None;
    }
    // (state, lat_min, lat_max, lon_min, lon_max). ACT first: it sits inside the
    // NSW box, so a NSW-first scan would never reach it.
    const BOXES: &[(&str, f64, f64, f64, f64)] = &[
        ("ACT", -35.92, -35.12, 148.76, 149.40),
        ("QLD", -29.18, -10.0, 138.0, 153.55),
        ("NSW", -37.51, -28.16, 140.99, 153.64),
        ("VIC", -39.20, -33.98, 140.96, 150.04),
        ("TAS", -43.65, -39.20, 143.82, 148.50),
        ("SA", -38.07, -26.0, 129.0, 141.0),
        ("NT", -26.0, -10.96, 129.0, 138.0),
        ("WA", -35.14, -13.69, 112.92, 129.0),
    ];
    for &(state, lat_min, lat_max, lon_min, lon_max) in BOXES {
        if (lat_min..=lat_max).contains(&lat) && (lon_min..=lon_max).contains(&lon) {
            return Some(state);
        }
    }
    None
}

/// Magnitude (in degrees) below which a *coarse* geolocation provider's
/// coordinate component is treated as that provider's "no fix" placeholder
/// rather than a real position. Several IP/WiFi-geo APIs return `0.0000` or a
/// sub-degree jitter around null island when they have no location.
pub const NULL_ISLAND_BAND: f64 = 0.01;

/// Validity check for coordinates coming from a *coarse* IP/WiFi-geolocation
/// provider (`ipinfo`, `ipapi`, `ip2location`, `ipquery`, `wigle`, …):
/// [`is_valid_coords`] **and** clear of the near-null-island
/// [`NULL_ISLAND_BAND`] those providers emit as an "unknown" placeholder (a
/// `loc` like `0.0000,0.0000` or `0.001,0.001`). Both components must exceed
/// the band.
///
/// Prefer this over a bare `lat.abs() > 0.01 && lon.abs() > 0.01`: that idiom
/// (which had been copied across the five providers above) dropped null
/// island but *silently accepted out-of-range and non-finite values*, which
/// then became high-confidence false fixes — precisely what
/// [`is_valid_coords`] exists to reject. Folding the validity check in keeps
/// the band heuristic while closing that gap in one place.
///
/// ```
/// use huntsman_search_engine::util::geo::is_plausible_provider_coord;
///
/// assert!(is_plausible_provider_coord(-27.47, 153.02)); // real fix
/// assert!(!is_plausible_provider_coord(0.001, 0.001));  // null-island jitter
/// assert!(!is_plausible_provider_coord(0.0, 153.0));    // a component in the band
/// assert!(!is_plausible_provider_coord(91.0, 0.0));     // also fails validity
/// ```
#[must_use]
pub fn is_plausible_provider_coord(lat: f64, lon: f64) -> bool {
    is_valid_coords(lat, lon) && lat.abs() > NULL_ISLAND_BAND && lon.abs() > NULL_ISLAND_BAND
}

/// Build the coarse IP-geolocation `geoint` Coordinates entity shared by the
/// IP-geo provider modules (`ipinfo` / `ipapi` / `ip2location` / `ipquery`):
/// the plausibility gate ([`is_plausible_provider_coord`]), the 4-decimal
/// (~11 m — honest for city-level IP geo, not GPS precision) formatting, and
/// the `geoint` tag. Born identically whichever provider returned the fix, so
/// the formatting and tag can't drift between four near-identical modules.
///
/// Returns `None` for an implausible fix (null-island band / out-of-range /
/// non-finite), letting the caller gate its whole emit block with
/// `if let Some(mut ce) = coarse_provider_coords(..) { ce.tag(provider); .. }`.
/// The caller adds its own provider tag and evidence.
///
/// Every fix is additionally tagged for AU relevance via the offline
/// [`is_in_australia`] bounding box — `au-relevant` inside the box, `off-region`
/// outside it — so an Australia-focused scan can prefer on-region fixes and
/// flag the rest without any extra network call. Confidence stays the caller's
/// (provider-specific) decision; only the explanatory tag is added here.
#[must_use]
pub fn coarse_provider_coords(
    lat: f64,
    lon: f64,
    confidence: f64,
    scan_id: &str,
) -> Option<crate::core::entity::Entity> {
    if !is_plausible_provider_coord(lat, lon) {
        return None;
    }
    let mut e = crate::core::entity::Entity::new(
        crate::core::entity::EntityKind::Coordinates,
        format!("{lat:.4},{lon:.4}"),
        confidence,
        scan_id,
    );
    e.tag(crate::core::tags::GEOINT);
    if let Some(state) = au_state_for_coords(lat, lon) {
        e.tag("au-relevant");
        e.tag(format!("au-state:{state}"));
    } else {
        e.tag("off-region");
    }
    Some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_coords_accepts_well_formed_pairs() {
        assert_eq!(
            parse_coords("-27.4766,153.0166").unwrap(),
            (-27.4766, 153.0166)
        );
        assert_eq!(
            parse_coords(" 51.5074 , -0.1278 ").unwrap(),
            (51.5074, -0.1278)
        );
        // Null Island parses: it's a deliberately-typed seed, not a provider
        // sentinel — output filtering (is_valid_coords) is a separate concern.
        assert_eq!(parse_coords("0,0").unwrap(), (0.0, 0.0));
    }

    #[test]
    fn parse_coords_rejects_invalid_before_any_api_call() {
        assert!(parse_coords("not,coords").is_err()); // non-numeric
        assert!(parse_coords("153.02").is_err()); // not a pair
        assert!(parse_coords("200,300").is_err()); // out of range
        assert!(parse_coords("10,181").is_err()); // lon out of range
        assert!(parse_coords("nan,10").is_err()); // non-finite latitude
        assert!(parse_coords("10,inf").is_err()); // non-finite longitude
    }

    #[test]
    fn valid_coords_accepts_real_positions() {
        assert!(is_valid_coords(-27.4766, 153.0166)); // Brisbane
        assert!(is_valid_coords(51.5074, -0.1278)); // London
        assert!(is_valid_coords(90.0, 180.0)); // boundaries
        assert!(is_valid_coords(-90.0, -180.0));
    }

    #[test]
    fn valid_coords_rejects_bad_fixes() {
        assert!(!is_valid_coords(0.0, 0.0)); // Null Island
        assert!(!is_valid_coords(91.0, 10.0)); // lat out of range
        assert!(!is_valid_coords(10.0, 181.0)); // lon out of range
        assert!(!is_valid_coords(f64::NAN, 10.0)); // non-finite
        assert!(!is_valid_coords(10.0, f64::INFINITY));
    }

    #[test]
    fn in_australia_box_covers_continent_and_tasmania_only() {
        assert!(is_in_australia(-27.4766, 153.0166)); // Brisbane
        assert!(is_in_australia(-33.8688, 151.2093)); // Sydney
        assert!(is_in_australia(-31.9523, 115.8613)); // Perth
        assert!(is_in_australia(-42.8821, 147.3272)); // Hobart
        // Outside: neighbours, distant cities, and bad fixes are never in-box.
        assert!(!is_in_australia(-36.8485, 174.7633)); // Auckland, NZ
        assert!(!is_in_australia(-6.2088, 106.8456)); // Jakarta
        assert!(!is_in_australia(40.7128, -74.0060)); // New York
        assert!(!is_in_australia(0.0, 0.0)); // null island
        assert!(!is_in_australia(91.0, 130.0)); // out of range
    }

    #[test]
    fn au_state_for_coords_attributes_capitals_and_rejects_foreign() {
        assert_eq!(au_state_for_coords(-27.4766, 153.0166), Some("QLD")); // Brisbane
        assert_eq!(au_state_for_coords(-33.8688, 151.2093), Some("NSW")); // Sydney
        assert_eq!(au_state_for_coords(-37.8136, 144.9631), Some("VIC")); // Melbourne
        assert_eq!(au_state_for_coords(-34.9285, 138.6007), Some("SA")); // Adelaide
        assert_eq!(au_state_for_coords(-31.9523, 115.8613), Some("WA")); // Perth
        assert_eq!(au_state_for_coords(-42.8821, 147.3272), Some("TAS")); // Hobart
        assert_eq!(au_state_for_coords(-12.4634, 130.8456), Some("NT")); // Darwin
        // Canberra: inside the NSW box, but the ACT box is tested first.
        assert_eq!(au_state_for_coords(-35.2809, 149.1300), Some("ACT"));
        // Outside Australia → no state.
        assert_eq!(au_state_for_coords(-36.8485, 174.7633), None); // Auckland
        assert_eq!(au_state_for_coords(0.0, 0.0), None); // null island
    }

    #[test]
    fn plausible_provider_coord_keeps_real_fixes() {
        assert!(is_plausible_provider_coord(-27.4766, 153.0166)); // Brisbane
        assert!(is_plausible_provider_coord(51.5074, -0.1278)); // London
    }

    #[test]
    fn coarse_provider_coords_builds_a_gated_geoint_entity() {
        use crate::core::entity::EntityKind;
        // A real fix: 4-decimal value, Coordinates kind, geoint tag, the given
        // confidence. This is the identical birth the four IP-geo modules share.
        let e = coarse_provider_coords(-27.476600, 153.016601, 0.58, "scan-x")
            .expect("a plausible fix yields an entity");
        assert_eq!(e.kind, EntityKind::Coordinates);
        assert_eq!(e.raw_value, "-27.4766,153.0166"); // 4-decimal coarse format
        assert!(e.has_tag(crate::core::tags::GEOINT));
        // The Brisbane fix is inside the AU box → tagged on-region + state.
        assert!(e.has_tag("au-relevant"));
        assert!(e.has_tag("au-state:QLD"));
        assert!(!e.has_tag("off-region"));
        assert!((e.confidence - 0.58).abs() < 1e-9);
        // A plausible but foreign fix (London) is flagged off-region.
        let foreign = coarse_provider_coords(51.5074, -0.1278, 0.58, "scan-x")
            .expect("a plausible foreign fix still yields an entity");
        assert!(foreign.has_tag("off-region"));
        assert!(!foreign.has_tag("au-relevant"));
        // An implausible fix (null-island band / out-of-range) gates the whole
        // emit block to None.
        assert!(coarse_provider_coords(0.001, 0.001, 0.58, "scan-x").is_none());
        assert!(coarse_provider_coords(200.0, 10.0, 0.58, "scan-x").is_none());
    }

    #[test]
    fn plausible_provider_coord_drops_null_island_band() {
        // The band the IP/WiFi providers emit as "no fix".
        assert!(!is_plausible_provider_coord(0.0, 0.0));
        assert!(!is_plausible_provider_coord(0.001, 0.001));
        // Either component inside the band is enough to drop it.
        assert!(!is_plausible_provider_coord(0.005, 120.0));
        assert!(!is_plausible_provider_coord(45.0, -0.004));
    }

    #[test]
    fn plausible_provider_coord_rejects_out_of_range_and_nonfinite() {
        // The gap the bare `abs() > 0.01` idiom left open: these used to pass
        // straight through into a high-confidence Coordinates entity.
        assert!(!is_plausible_provider_coord(500.0, 999.0));
        assert!(!is_plausible_provider_coord(91.0, 10.0));
        assert!(!is_plausible_provider_coord(10.0, 181.0));
        assert!(!is_plausible_provider_coord(f64::INFINITY, f64::INFINITY));
        assert!(!is_plausible_provider_coord(f64::NAN, 10.0));
    }
}
