#![allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]

//! Offline geographic helpers rebuilt from the monolith's `util::geo`,
//! `util::city_coords`, and the data-light parts of `core::geo_family`.

use crate::Error;
use crate::address_au;
use crate::geohash::{haversine_km, parse_coords as parse_pair};
use crate::http::Transport;
use crate::postcode_au;

/// Confidence ladder for a fix with a reported accuracy radius.
pub const VERY_HIGH_CONFIDENCE: f64 = 0.90;
pub const HIGH_CONFIDENCE: f64 = 0.75;
pub const MEDIUM_CONFIDENCE: f64 = 0.55;
pub const TENTATIVE_CONFIDENCE: f64 = 0.35;

pub const FAMILY_GEO_KM: f64 = 150.0;
pub const NAMESAKE_GEO_KM: f64 = 800.0;
pub const NULL_ISLAND_BAND: f64 = 0.01;

const AU_LOCALITIES: &[(&str, &str, f64, f64)] = &[
    ("Brisbane", "QLD", -27.4698, 153.0251),
    ("Sydney", "NSW", -33.8688, 151.2093),
    ("Melbourne", "VIC", -37.8136, 144.9631),
    ("Adelaide", "SA", -34.9285, 138.6007),
    ("Perth", "WA", -31.9505, 115.8605),
    ("Hobart", "TAS", -42.8821, 147.3272),
    ("Darwin", "NT", -12.4634, 130.8456),
    ("Canberra", "ACT", -35.2809, 149.1300),
    ("Maleny", "QLD", -26.7290, 152.7554),
    ("Parramatta", "NSW", -33.8150, 151.0011),
    ("Caboolture", "QLD", -27.0850, 152.9510),
    ("Maitland", "NSW", -32.7316, 151.5566),
];

const CITY_ROWS: &[(&str, f64, f64)] = &[
    ("adelaide", -34.9285, 138.6007),
    ("auckland", -36.8485, 174.7633),
    ("brisbane", -27.4698, 153.0251),
    ("caboolture", -27.0850, 152.9510),
    ("canberra", -35.2809, 149.1300),
    ("darwin", -12.4634, 130.8456),
    ("liverpool", 53.4084, -2.9916),
    ("london", 51.5074, -0.1278),
    ("maitland", -32.7316, 151.5566),
    ("maleny", -26.7290, 152.7554),
    ("melbourne", -37.8136, 144.9631),
    ("parramatta", -33.8150, 151.0011),
    ("perth", -31.9505, 115.8605),
    ("philadelphia", 39.9526, -75.1652),
    ("sydney", -33.8688, 151.2093),
];

const NON_AU_COUNTRY_PHRASES: &[&str] = &[
    "british columbia",
    "hong kong",
    "new hampshire",
    "new jersey",
    "new mexico",
    "new zealand",
    "north carolina",
    "north dakota",
    "papua new guinea",
    "rhode island",
    "south carolina",
    "south dakota",
    "south africa",
    "sri lanka",
    "united kingdom",
    "united states",
    "west virginia",
];

const NON_AU_COUNTRY_TOKENS: &[&str] = &[
    "alabama",
    "alaska",
    "alberta",
    "arizona",
    "arkansas",
    "bangladesh",
    "brazil",
    "california",
    "canada",
    "china",
    "colorado",
    "connecticut",
    "denmark",
    "england",
    "egypt",
    "finland",
    "florida",
    "france",
    "georgia",
    "germany",
    "greece",
    "hawaii",
    "idaho",
    "illinois",
    "india",
    "indiana",
    "indonesia",
    "ireland",
    "italy",
    "japan",
    "kansas",
    "kenya",
    "kentucky",
    "louisiana",
    "maine",
    "malaysia",
    "manitoba",
    "maryland",
    "massachusetts",
    "mexico",
    "michigan",
    "minnesota",
    "mississippi",
    "missouri",
    "montana",
    "netherlands",
    "nebraska",
    "nevada",
    "newfoundland",
    "nigeria",
    "norway",
    "nz",
    "ohio",
    "oklahoma",
    "ontario",
    "oregon",
    "pakistan",
    "pennsylvania",
    "philippines",
    "poland",
    "portugal",
    "quebec",
    "russia",
    "saskatchewan",
    "scotland",
    "singapore",
    "spain",
    "sweden",
    "switzerland",
    "texas",
    "thailand",
    "turkey",
    "uk",
    "us",
    "usa",
    "utah",
    "vermont",
    "vietnam",
    "virginia",
    "wisconsin",
    "wyoming",
];

/// # Errors
/// Returns [`Error::Invalid`] when the input is not a valid `lat,lon` pair.
/// Thin error-mapping wrapper around `crate::geohash::parse_coords`.
pub fn parse_coords(value: &str) -> Result<(f64, f64), Error> {
    parse_pair(value).ok_or_else(|| {
        Error::Invalid("coordinates must be 'lat,lon' with lat -90..=90 and lon -180..=180".into())
    })
}

#[must_use]
pub fn compose_address(city: &str, region: &str, country: &str) -> String {
    if region.is_empty() {
        format!("{city}, {country}")
    } else {
        format!("{city}, {region}, {country}")
    }
}

#[must_use]
pub fn is_valid_coords(lat: f64, lon: f64) -> bool {
    lat.is_finite()
        && lon.is_finite()
        && (-90.0..=90.0).contains(&lat)
        && (-180.0..=180.0).contains(&lon)
        && !(lat == 0.0 && lon == 0.0)
}

#[must_use]
pub fn is_in_australia(lat: f64, lon: f64) -> bool {
    is_valid_coords(lat, lon) && (-44.0..=-10.0).contains(&lat) && (112.0..=154.0).contains(&lon)
}

#[must_use]
pub fn au_state_for_coords(lat: f64, lon: f64) -> Option<&'static str> {
    if !is_in_australia(lat, lon) {
        return None;
    }
    if (-35.92..=-35.12).contains(&lat) && (148.72..=149.40).contains(&lon) {
        return Some("ACT");
    }
    if lat <= -39.6 && (143.5..=148.6).contains(&lon) {
        return Some("TAS");
    }
    if lon < 129.0 {
        return Some("WA");
    }
    if lon < 138.0 {
        return Some(if lat > -26.0 { "NT" } else { "SA" });
    }
    if lon < 141.0 {
        return Some(if lat > -26.0 { "QLD" } else { "SA" });
    }
    if lat > qld_nsw_border_lat(lon) {
        return Some("QLD");
    }
    Some(if lat < nsw_vic_border_lat(lon) {
        "VIC"
    } else {
        "NSW"
    })
}

#[must_use]
pub fn nearest_au_locality(lat: f64, lon: f64) -> Option<(&'static str, &'static str, f64)> {
    if !is_in_australia(lat, lon) {
        return None;
    }
    AU_LOCALITIES
        .iter()
        .map(|&(name, state, city_lat, city_lon)| {
            (name, state, haversine_km(lat, lon, city_lat, city_lon))
        })
        .min_by(|left, right| left.2.total_cmp(&right.2))
}

#[must_use]
pub fn confidence_for_accuracy_m(metres: Option<f64>) -> f64 {
    let metres = match metres {
        Some(value) if value.is_finite() && value >= 0.0 => value,
        _ => 5_000.0,
    };
    if metres <= 200.0 {
        VERY_HIGH_CONFIDENCE
    } else if metres <= 1_000.0 {
        HIGH_CONFIDENCE
    } else if metres <= 5_000.0 {
        MEDIUM_CONFIDENCE
    } else {
        TENTATIVE_CONFIDENCE
    }
}

#[must_use]
pub fn is_plausible_provider_coord(lat: f64, lon: f64) -> bool {
    is_valid_coords(lat, lon) && lat.abs() > NULL_ISLAND_BAND && lon.abs() > NULL_ISLAND_BAND
}

#[must_use]
pub fn postcode_coords(postcode: &str) -> Option<(f64, f64)> {
    postcode_au::offline_centroid(postcode)
}

#[must_use]
pub fn postcode_localities_with<T: Transport>(
    postcode: &str,
    transport: &T,
) -> Vec<postcode_au::Locality> {
    postcode_au::localities_with(postcode, transport)
}

#[must_use]
pub fn au_postcode_region(postcode: &str) -> Option<(f64, f64)> {
    if !postcode_au::is_shaped(postcode) {
        return None;
    }
    match address_au::state_for_postcode(postcode)? {
        "ACT" => postcode_coords("2600"),
        "NSW" => postcode_coords("2000"),
        "NT" => postcode_coords("0800"),
        "QLD" => postcode_coords("4000"),
        "SA" => Some((-34.9285, 138.6007)),
        "TAS" => postcode_coords("7000"),
        "VIC" => postcode_coords("3000"),
        "WA" => postcode_coords("6000"),
        _ => None,
    }
}

#[must_use]
pub fn extract_au_postcode(text: &str) -> Option<String> {
    let last = text
        .split(|c: char| !c.is_ascii_digit())
        .rfind(|piece| !piece.is_empty())?;
    if !(postcode_au::is_shaped(last) && postcode_au::is_in_au_range(last)) {
        return None;
    }
    if let Some(index) = text.rfind(last) {
        if index >= 6 {
            let prefix = &text[index - 6..index];
            if prefix.as_bytes()[5] == b'-' && prefix[..5].bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
    }
    Some(last.to_string())
}

#[must_use]
pub fn city_coords(addr: &str) -> Option<(f64, f64)> {
    let trimmed = addr.trim();
    let lower = trimmed.to_ascii_lowercase();
    if let Some(hit) = match_tabulated_city(&lower) {
        return Some(hit);
    }
    if postcode_au::is_shaped(trimmed) {
        return postcode_coords(trimmed).or_else(|| au_postcode_region(trimmed));
    }
    if !mentions_non_au_country(&lower) {
        if let Some(pc) = extract_au_postcode(trimmed) {
            return postcode_coords(&pc).or_else(|| au_postcode_region(&pc));
        }
    }
    None
}

#[must_use]
pub fn distance_between_postcodes(left: &str, right: &str) -> Option<f64> {
    let (lat1, lon1) = postcode_coords(left).or_else(|| au_postcode_region(left))?;
    let (lat2, lon2) = postcode_coords(right).or_else(|| au_postcode_region(right))?;
    Some(haversine_km(lat1, lon1, lat2, lon2))
}

#[must_use]
pub fn is_geo_corroborated_family(postcode: &str, subject_postcodes: &[&str]) -> bool {
    subject_postcodes.iter().any(|subject| {
        distance_between_postcodes(postcode, subject).is_some_and(|km| km <= FAMILY_GEO_KM)
    })
}

#[must_use]
pub fn is_geo_discordant_namesake(postcode: &str, subject_postcodes: &[&str]) -> bool {
    subject_postcodes.iter().any(|subject| {
        distance_between_postcodes(postcode, subject).is_some_and(|km| km > NAMESAKE_GEO_KM)
    })
}

#[must_use]
pub fn is_namesake(postcode: &str, subject_postcodes: &[&str], surname_common: bool) -> bool {
    surname_common && is_geo_discordant_namesake(postcode, subject_postcodes)
}

fn border_lat(lon: f64, anchors: &[(f64, f64)]) -> f64 {
    if lon <= anchors[0].0 {
        return anchors[0].1;
    }
    for window in anchors.windows(2) {
        let ((lon0, lat0), (lon1, lat1)) = (window[0], window[1]);
        if lon <= lon1 {
            return lat0 + (lon - lon0) / (lon1 - lon0) * (lat1 - lat0);
        }
    }
    anchors[anchors.len() - 1].1
}

fn qld_nsw_border_lat(lon: f64) -> f64 {
    const BORDER: &[(f64, f64)] = &[(141.0, -29.0), (151.5, -29.0), (153.55, -28.2)];
    border_lat(lon, BORDER)
}

fn nsw_vic_border_lat(lon: f64) -> f64 {
    const BORDER: &[(f64, f64)] = &[
        (141.0, -34.05),
        (142.2, -34.15),
        (143.55, -35.34),
        (144.75, -36.05),
        (145.65, -35.92),
        (146.0, -36.01),
        (146.92, -36.10),
        (147.9, -36.05),
        (148.2, -36.5),
        (149.97, -37.5),
        (150.1, -39.0),
    ];
    border_lat(lon, BORDER)
}

fn address_tokens(lower: &str) -> Vec<&str> {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|piece| !piece.is_empty())
        .collect()
}

fn phrase_in_tokens(tokens: &[&str], name: &str) -> bool {
    let want: Vec<&str> = name.split(' ').filter(|piece| !piece.is_empty()).collect();
    if want.is_empty() || want.len() > tokens.len() {
        return false;
    }
    tokens
        .windows(want.len())
        .any(|window| window == want.as_slice())
}

fn match_tabulated_city(lower: &str) -> Option<(f64, f64)> {
    let tokens = address_tokens(lower);
    if tokens.is_empty() {
        return None;
    }
    let names_foreign = mentions_non_au_country(lower);
    let names_au = !names_foreign && names_au_locality(lower);
    let mut best: Option<(usize, f64, f64)> = None;
    for &(city, lat, lon) in CITY_ROWS {
        if names_foreign && is_in_australia(lat, lon) {
            continue;
        }
        if names_au && !is_in_australia(lat, lon) {
            continue;
        }
        if !phrase_in_tokens(&tokens, city) {
            continue;
        }
        let specificity = city.split(' ').filter(|piece| !piece.is_empty()).count();
        match best {
            Some((best_words, _, _)) if specificity <= best_words => {}
            _ => best = Some((specificity, lat, lon)),
        }
    }
    best.map(|(_, lat, lon)| (lat, lon))
}

#[allow(clippy::too_many_lines)]
fn mentions_non_au_country(lower: &str) -> bool {
    if NON_AU_COUNTRY_PHRASES
        .iter()
        .any(|phrase| lower.contains(phrase))
    {
        return true;
    }
    address_tokens(lower)
        .iter()
        .any(|token| NON_AU_COUNTRY_TOKENS.contains(token))
}

fn names_au_locality(lower: &str) -> bool {
    if lower.contains("australia") {
        return true;
    }
    let Some(postcode) = extract_au_postcode(lower) else {
        return false;
    };
    address_au::single_state_code(lower).is_some() && postcode_au::is_in_au_range(&postcode)
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_validate_coords() {
        assert_eq!(
            parse_coords("-27.4766,153.0166").unwrap(),
            (-27.4766, 153.0166)
        );
        assert_eq!(
            parse_coords(" 51.5074 , -0.1278 ").unwrap(),
            (51.5074, -0.1278)
        );
        assert!(parse_coords("not,coords").is_err());
        assert!(parse_coords("153.02").is_err());
        assert!(parse_coords("200,300").is_err());

        assert!(is_valid_coords(-27.4766, 153.0166));
        assert!(is_valid_coords(90.0, 180.0));
        assert!(!is_valid_coords(0.0, 0.0));
        assert!(!is_valid_coords(91.0, 10.0));
    }

    #[test]
    fn australia_box_and_state_partition_cover_reference_points() {
        assert!(is_in_australia(-27.4766, 153.0166));
        assert!(is_in_australia(-42.8821, 147.3272));
        assert!(!is_in_australia(-36.8485, 174.7633));
        assert!(!is_in_australia(0.0, 0.0));

        assert_eq!(au_state_for_coords(-27.4766, 153.0166), Some("QLD"));
        assert_eq!(au_state_for_coords(-33.8688, 151.2093), Some("NSW"));
        assert_eq!(au_state_for_coords(-37.8136, 144.9631), Some("VIC"));
        assert_eq!(au_state_for_coords(-34.9285, 138.6007), Some("SA"));
        assert_eq!(au_state_for_coords(-31.9523, 115.8613), Some("WA"));
        assert_eq!(au_state_for_coords(-42.8821, 147.3272), Some("TAS"));
        assert_eq!(au_state_for_coords(-12.4634, 130.8456), Some("NT"));
        assert_eq!(au_state_for_coords(-35.2809, 149.13), Some("ACT"));
        assert_eq!(au_state_for_coords(-28.8103, 153.2830), Some("NSW"));
        assert_eq!(au_state_for_coords(-36.3805, 145.3980), Some("VIC"));
        assert_eq!(au_state_for_coords(-36.8485, 174.7633), None);
    }

    #[test]
    fn nearest_locality_uses_the_small_verified_anchor_set() {
        let (name, state, km) = nearest_au_locality(-27.47, 153.02).unwrap();
        assert_eq!((name, state), ("Brisbane", "QLD"));
        assert!(km < 5.0);
        assert_eq!(
            nearest_au_locality(-31.95, 115.86).map(|(n, s, _)| (n, s)),
            Some(("Perth", "WA"))
        );
        assert_eq!(
            nearest_au_locality(-33.8150, 151.0011).map(|(n, s, _)| (n, s)),
            Some(("Parramatta", "NSW"))
        );
        assert_eq!(
            nearest_au_locality(-27.0850, 152.9510).map(|(n, s, _)| (n, s)),
            Some(("Caboolture", "QLD"))
        );
        assert_eq!(
            nearest_au_locality(-32.7316, 151.5566).map(|(n, s, _)| (n, s)),
            Some(("Maitland", "NSW"))
        );
        assert!(nearest_au_locality(40.71, -74.0).is_none());
    }

    #[test]
    fn provider_plausibility_and_accuracy_confidence_are_defensive() {
        fn approx_eq(left: f64, right: f64) {
            assert!((left - right).abs() < 1e-12, "{left} != {right}");
        }

        assert!(is_plausible_provider_coord(-27.47, 153.02));
        assert!(!is_plausible_provider_coord(0.001, 0.001));
        assert!(!is_plausible_provider_coord(0.0, 153.0));
        assert!(!is_plausible_provider_coord(91.0, 0.0));

        approx_eq(confidence_for_accuracy_m(Some(25.0)), VERY_HIGH_CONFIDENCE);
        approx_eq(confidence_for_accuracy_m(Some(2_000.0)), MEDIUM_CONFIDENCE);
        approx_eq(
            confidence_for_accuracy_m(Some(25_000.0)),
            TENTATIVE_CONFIDENCE,
        );
        approx_eq(
            confidence_for_accuracy_m(Some(-1.0)),
            confidence_for_accuracy_m(None),
        );
        approx_eq(
            confidence_for_accuracy_m(Some(f64::NAN)),
            confidence_for_accuracy_m(None),
        );
    }

    #[test]
    fn city_lookup_uses_whole_tokens_longest_match_and_postcode_fallback() {
        assert_eq!(city_coords("Brisbane, QLD"), Some((-27.4698, 153.0251)));
        assert!(city_coords("Philadelphia").is_some());
        assert!(city_coords("Auckland").is_some());
        assert!(city_coords("London").is_some());
        assert!(city_coords("Clobberville").is_none());
        assert_eq!(city_coords("4000"), Some((-27.4698, 153.0251)));
        assert!(city_coords("0100").is_none());
        assert_eq!(
            city_coords("12 Smith St, Maleny QLD 4552"),
            Some((-26.7290, 152.7554))
        );
        assert_eq!(
            city_coords("Liverpool, NSW 2170"),
            Some((-33.9200, 150.9228))
        );
        assert!(city_coords("Perth, Scotland").is_none());
        assert!(city_coords("6509 Angels Orchard Dr, Sparks, NV, 89436-9322").is_none());
    }

    #[test]
    fn postcode_regions_and_family_distance_are_coarse_but_useful() {
        assert!(au_postcode_region("1234").is_some());
        assert!(au_postcode_region("8000").is_some());
        assert!(au_postcode_region("9000").is_some());
        assert!(au_postcode_region("0000").is_none());
        assert_eq!(
            extract_au_postcode("QLD 4518, Australia").as_deref(),
            Some("4518")
        );
        assert!(extract_au_postcode("1019 Winston Dr, Jefferson City, MO, 65101").is_none());

        assert!(is_geo_corroborated_family("4552", &["4000"]));
        assert!(is_geo_discordant_namesake("6000", &["4000"]));
        assert!(is_namesake("6000", &["4000"], true));
        assert!(!is_namesake("6000", &["4000"], false));
    }

    #[test]
    fn compose_address_and_country_name_are_simple_helpers() {
        assert_eq!(
            compose_address("Brisbane", "QLD", "AU"),
            "Brisbane, QLD, AU"
        );
        assert_eq!(compose_address("Singapore", "", "SG"), "Singapore, SG");
        let parsed = crate::geohash::parse_address("Sydney, NSW, Australia");
        assert_eq!(
            crate::geohash::country_name_for_iso(parsed.iso_country.as_deref().unwrap()),
            Some("Australia")
        );
    }
}
