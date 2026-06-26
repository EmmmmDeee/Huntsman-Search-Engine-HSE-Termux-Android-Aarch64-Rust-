use crate::core::error::{Error, Result};

pub mod coords;

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
/// Coarse IP/WiFi-geo providers (`ip_geo`, `ipinfo`, `ip_whois_geo`,
/// `ip2location`, `ipquery`, `wigle`) want [`is_plausible_provider_coord`]
/// instead: it
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

/// Compose a `"City, Region, Country"` address line from a geolocation record,
/// dropping an empty middle component (region / state / province) so a record
/// with only a city and country reads `"City, Country"` — never the
/// `"City, , Country"` an empty join would leave. Several IP-geo providers
/// expose the same three-tier shape under different field names, so this join
/// lives here once rather than re-inlined per module.
///
/// The caller keeps its own presence guard: some sources emit an Address only
/// when both city and country are present, others on a non-empty city alone.
///
/// ```
/// use huntsman_search_engine::util::geo::compose_address;
///
/// assert_eq!(compose_address("Brisbane", "QLD", "AU"), "Brisbane, QLD, AU");
/// assert_eq!(compose_address("Singapore", "", "SG"), "Singapore, SG");
/// ```
#[must_use]
pub fn compose_address(city: &str, region: &str, country: &str) -> String {
    if region.is_empty() {
        format!("{city}, {country}")
    } else {
        format!("{city}, {region}, {country}")
    }
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

/// Curated reverse-geocoding anchors: the Australian capitals and major regional
/// centres, `(locality, state, lat, lon)`. Together they cover the overwhelming
/// majority of the AU population, so the nearest anchor to a coordinate is a
/// genuine, human-readable place label — `(-26.73, 152.76)` → "near Maleny" is
/// what an investigator wants from a bare GPS fix, not just "QLD". Coordinates
/// are well-known city centroids; an outback fix simply resolves to its nearest
/// regional centre (the distance, reported alongside, keeps that honest).
const AU_LOCALITY_ANCHORS: &[(&str, &str, f64, f64)] = &[
    // NSW + ACT
    ("Sydney", "NSW", -33.8688, 151.2093),
    ("Newcastle", "NSW", -32.9283, 151.7817),
    ("Wollongong", "NSW", -34.4248, 150.8931),
    ("Central Coast (Gosford)", "NSW", -33.4269, 151.3431),
    ("Wagga Wagga", "NSW", -35.1082, 147.3598),
    ("Albury", "NSW", -36.0737, 146.9135),
    ("Port Macquarie", "NSW", -31.4333, 152.9000),
    ("Tamworth", "NSW", -31.0927, 150.9290),
    ("Orange", "NSW", -33.2839, 149.1000),
    ("Dubbo", "NSW", -32.2569, 148.6011),
    ("Coffs Harbour", "NSW", -30.2963, 153.1135),
    ("Bathurst", "NSW", -33.4193, 149.5780),
    ("Lismore", "NSW", -28.8136, 153.2773),
    ("Broken Hill", "NSW", -31.9560, 141.4675),
    ("Canberra", "ACT", -35.2809, 149.1300),
    // VIC
    ("Melbourne", "VIC", -37.8136, 144.9631),
    ("Geelong", "VIC", -38.1499, 144.3617),
    ("Ballarat", "VIC", -37.5622, 143.8503),
    ("Bendigo", "VIC", -36.7570, 144.2794),
    ("Shepparton", "VIC", -36.3805, 145.3989),
    ("Mildura", "VIC", -34.1855, 142.1625),
    ("Warrnambool", "VIC", -38.3818, 142.4880),
    ("Traralgon", "VIC", -38.1957, 146.5407),
    ("Wodonga", "VIC", -36.1214, 146.8880),
    // QLD
    ("Brisbane", "QLD", -27.4698, 153.0251),
    ("Gold Coast", "QLD", -28.0167, 153.4000),
    ("Sunshine Coast (Maroochydore)", "QLD", -26.6500, 153.0667),
    ("Townsville", "QLD", -19.2590, 146.8169),
    ("Cairns", "QLD", -16.9203, 145.7710),
    ("Toowoomba", "QLD", -27.5598, 151.9507),
    ("Mackay", "QLD", -21.1413, 149.1860),
    ("Rockhampton", "QLD", -23.3781, 150.5100),
    ("Bundaberg", "QLD", -24.8661, 152.3489),
    ("Hervey Bay", "QLD", -25.2986, 152.8535),
    ("Gladstone", "QLD", -23.8489, 151.2566),
    ("Mount Isa", "QLD", -20.7256, 139.4927),
    ("Maleny", "QLD", -26.7290, 152.7554),
    // SA
    ("Adelaide", "SA", -34.9285, 138.6007),
    ("Mount Gambier", "SA", -37.8294, 140.7828),
    ("Whyalla", "SA", -33.0333, 137.5667),
    ("Port Augusta", "SA", -32.4925, 137.7659),
    // WA
    ("Perth", "WA", -31.9505, 115.8605),
    ("Bunbury", "WA", -33.3271, 115.6414),
    ("Geraldton", "WA", -28.7744, 114.6153),
    ("Kalgoorlie", "WA", -30.7490, 121.4658),
    ("Albany", "WA", -35.0228, 117.8814),
    ("Broome", "WA", -17.9614, 122.2359),
    ("Karratha", "WA", -20.7364, 116.8460),
    ("Port Hedland", "WA", -20.3107, 118.6080),
    // TAS
    ("Hobart", "TAS", -42.8821, 147.3272),
    ("Launceston", "TAS", -41.4332, 147.1441),
    ("Devonport", "TAS", -41.1769, 146.3506),
    ("Burnie", "TAS", -41.0553, 145.9058),
    // NT
    ("Darwin", "NT", -12.4634, 130.8456),
    ("Alice Springs", "NT", -23.6980, 133.8807),
    ("Palmerston", "NT", -12.4861, 130.9833),
    ("Katherine", "NT", -14.4652, 132.2635),
    // Metro suburbs — tighter labels where most of the population lives. The
    // nearest-anchor search means each only sharpens (never coarsens) a fix that
    // would otherwise resolve to the city centroid.
    // Greater Sydney
    ("Parramatta", "NSW", -33.8150, 151.0011),
    ("Penrith", "NSW", -33.7511, 150.6942),
    ("Liverpool", "NSW", -33.9203, 150.9233),
    ("Blacktown", "NSW", -33.7715, 150.9063),
    ("Bondi", "NSW", -33.8915, 151.2767),
    ("Chatswood", "NSW", -33.7969, 151.1803),
    ("Hornsby", "NSW", -33.7048, 151.0993),
    ("Campbelltown", "NSW", -34.0650, 150.8142),
    ("Cronulla", "NSW", -34.0577, 151.1543),
    ("Bankstown", "NSW", -33.9171, 151.0349),
    // Greater Melbourne
    ("Dandenong", "VIC", -37.9810, 145.2150),
    ("Frankston", "VIC", -38.1413, 145.1226),
    ("Box Hill", "VIC", -37.8197, 145.1242),
    ("Footscray", "VIC", -37.8000, 144.9000),
    ("Werribee", "VIC", -37.9000, 144.6614),
    ("Ringwood", "VIC", -37.8140, 145.2300),
    ("Sunshine", "VIC", -37.7880, 144.8330),
    // Greater Brisbane
    ("Ipswich", "QLD", -27.6171, 152.7600),
    ("Logan Central", "QLD", -27.6390, 153.1090),
    ("Redcliffe", "QLD", -27.2300, 153.1100),
    ("Chermside", "QLD", -27.3850, 153.0330),
    ("Mount Gravatt", "QLD", -27.5400, 153.0800),
    // Greater Perth
    ("Joondalup", "WA", -31.7448, 115.7661),
    ("Rockingham", "WA", -32.2769, 115.7297),
    ("Fremantle", "WA", -32.0569, 115.7439),
    ("Mandurah", "WA", -32.5269, 115.7217),
    // Greater Adelaide
    ("Elizabeth", "SA", -34.7120, 138.6710),
    ("Noarlunga", "SA", -35.1390, 138.4960),
    ("Salisbury", "SA", -34.7590, 138.6410),
];

/// Great-circle distance between two coordinates in kilometres (haversine,
/// mean Earth radius 6371 km). Pure.
#[must_use]
pub fn haversine_km(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R: f64 = 6371.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * R * a.sqrt().asin()
}

/// Offline **reverse geocode**: the nearest Australian population centre to
/// `(lat, lon)`, as `(locality, state, distance_km)`, or `None` when the point
/// is outside Australia ([`is_in_australia`]).
///
/// This turns a bare coordinate — an EXIF fix, a GPS sensor sample, a geocoded
/// address — into a human place label with **no network**, the companion to the
/// forward postcode gazetteer. The distance is returned so the caller can be
/// honest about precision: `~2 km` is "in Maleny", `~140 km` is "nearest centre
/// is Alice Springs". Anchors cover the capitals and major regional centres
/// (most of the AU population); pair with [`au_state_for_coords`] for the
/// authoritative state of a remote point between anchors.
///
/// ```
/// use huntsman_search_engine::util::geo::nearest_au_locality;
///
/// let (name, state, km) = nearest_au_locality(-27.47, 153.02).unwrap(); // Brisbane CBD
/// assert_eq!((name, state), ("Brisbane", "QLD"));
/// assert!(km < 5.0);
/// assert!(nearest_au_locality(40.71, -74.0).is_none()); // New York → not AU
/// ```
#[must_use]
pub fn nearest_au_locality(lat: f64, lon: f64) -> Option<(&'static str, &'static str, f64)> {
    if !is_in_australia(lat, lon) {
        return None;
    }
    AU_LOCALITY_ANCHORS
        .iter()
        .map(|&(name, state, alat, alon)| (name, state, haversine_km(lat, lon, alat, alon)))
        .min_by(|a, b| a.2.total_cmp(&b.2))
}

/// Tag `entity` with its Australian state and `country:AU` when `(lat, lon)`
/// falls inside an AU state/territory; a no-op otherwise. Coordinate-emitting
/// modules apply this exact AU-relevance pair (`au-state:{STATE}` + `country:AU`)
/// to a fresh fix, so the lookup-and-tag lives here once rather than re-inlined
/// per module. Uses [`au_state_for_coords`] for the offline classification.
pub fn tag_au_state(entity: &mut crate::core::entity::Entity, lat: f64, lon: f64) {
    if let Some(state) = au_state_for_coords(lat, lon) {
        entity.tag(format!("au-state:{state}"));
        entity.tag("country:AU");
    }
}

/// Magnitude (in degrees) below which a *coarse* geolocation provider's
/// coordinate component is treated as that provider's "no fix" placeholder
/// rather than a real position. Several IP/WiFi-geo APIs return `0.0000` or a
/// sub-degree jitter around null island when they have no location.
pub const NULL_ISLAND_BAND: f64 = 0.01;

/// Validity check for coordinates coming from a *coarse* IP/WiFi-geolocation
/// provider (`ipinfo`, `ip_whois_geo`, `ip2location`, `ipquery`, `wigle`, …):
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
/// IP-geo provider modules (`ipinfo` / `ip2location` / `ipquery`):
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

/// Build the `Asn` entity shared verbatim by every IP-geo provider module
/// (`ip_geo` / `ipinfo` / `ip2location` / `ipquery` / `ip_whois_geo`).
///
/// Each of those modules emitted exactly
/// `Entity::new(EntityKind::Asn, asn, 0.80, scan_id)` carrying a single
/// `Evidence::new(src, format!("ASN for {ip}"))`, then optionally stamped one
/// provider tag on top. That birth was byte-identical across all five, so it
/// lives here once: the fixed `0.80` confidence and the `"ASN for {ip}"`
/// evidence summary can no longer drift between the modules.
///
/// The two genuine per-module differences are kept at the call site, *not*
/// pushed into the signature: the caller passes the already-formatted ASN
/// string (some providers hand back `"AS1221"`, others a bare `"1221"` that the
/// caller prefixes) and adds any provider tag (`"ipinfo"`, `"ip-whois"`, …)
/// onto the returned entity. `src` is the calling module's own evidence source
/// tag (its `SRC` constant). **Pure** (no IO).
///
/// ```
/// use huntsman_search_engine::util::geo::ip_asn_entity;
/// use huntsman_search_engine::core::entity::EntityKind;
///
/// let mut e = ip_asn_entity("AS1221", "ipinfo", "1.2.3.4", "scan-1");
/// e.tag("ipinfo"); // caller layers its provider tag after
/// assert_eq!(e.kind, EntityKind::Asn);
/// assert_eq!(e.value, "AS1221");
/// assert!((e.confidence - 0.80).abs() < 1e-9);
/// assert_eq!(e.evidence[0].summary, "ASN for 1.2.3.4");
/// assert!(e.has_tag("ipinfo"));
/// ```
#[must_use]
pub fn ip_asn_entity(asn: &str, src: &str, ip: &str, scan_id: &str) -> crate::core::entity::Entity {
    let mut e =
        crate::core::entity::Entity::new(crate::core::entity::EntityKind::Asn, asn, 0.80, scan_id);
    e.add_evidence(crate::core::entity::Evidence::new(
        src,
        format!("ASN for {ip}"),
    ));
    e
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
