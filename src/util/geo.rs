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
        assert!((e.confidence - 0.58).abs() < 1e-9);
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
