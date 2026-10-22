//! AU postcode shape checks and the offline gazetteer, rebuilt from the monolith's
//! `util::postcode_au`. Pure, no I/O.

#[derive(Debug, Clone, PartialEq)]
pub struct Locality {
    pub suburb: String,
    pub lat: f64,
    pub lon: f64,
}

#[must_use]
pub fn is_shaped(value: &str) -> bool {
    value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Whether `value` is a display postcode on the ASIC and TPS register pages: four digits from
/// 2000 to 7999, the range from New South Wales to Tasmania. The register HTML is the oracle for
/// this range, which is deliberately narrower than the 0800 to 9999 AU range.
#[must_use]
pub fn is_display_postcode(value: &str) -> bool {
    is_shaped(value)
        && value
            .parse::<u32>()
            .is_ok_and(|number| (2000..=7999).contains(&number))
}

#[must_use]
pub fn offline_centroid(postcode: &str) -> Option<(f64, f64)> {
    offline_fallback(postcode)
        .first()
        .map(|locality| (locality.lat, locality.lon))
}

fn offline_fallback(postcode: &str) -> Vec<Locality> {
    let locality = |suburb: &str, lat: f64, lon: f64| Locality {
        suburb: suburb.to_string(),
        lat,
        lon,
    };
    match postcode {
        "0800" | "0801" => vec![locality("Darwin", -12.4634, 130.8456)],
        "0870" => vec![locality("Alice Springs", -23.6980, 133.8807)],
        "2000" => vec![locality("Sydney CBD", -33.8688, 151.2093)],
        "2170" => vec![locality("Liverpool", -33.9200, 150.9228)],
        "2300" => vec![locality("Newcastle", -32.9283, 151.7817)],
        "2500" => vec![locality("Wollongong", -34.4278, 150.8931)],
        "2600" | "2601" => vec![locality("Canberra City", -35.2809, 149.1300)],
        "3000" => vec![locality("Melbourne CBD", -37.8136, 144.9631)],
        "3220" => vec![locality("Geelong", -38.1499, 144.3617)],
        "4000" => vec![locality("Brisbane CBD", -27.4698, 153.0251)],
        "4217" => vec![locality("Surfers Paradise", -28.0029, 153.4300)],
        "4552" => vec![
            locality("Maleny", -26.7290, 152.7554),
            locality("Booroobin", -26.7290, 152.7554),
            locality("Conondale", -26.7333, 152.7167),
        ],
        "4700" => vec![locality("Rockhampton", -23.3791, 150.5100)],
        "5290" => vec![locality("Mount Gambier", -37.8307, 140.7828)],
        "6000" => vec![locality("Perth CBD", -31.9505, 115.8605)],
        "6210" => vec![locality("Mandurah", -32.5264, 115.7239)],
        "7000" => vec![locality("Hobart CBD", -42.8821, 147.3272)],
        "7250" => vec![locality("Launceston", -41.4388, 147.1347)],
        "7310" => vec![locality("Devonport", -41.1769, 146.3506)],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_and_centroid_helpers_work() {
        assert!(is_shaped("4552"));
        assert!(is_shaped("0800"));
        assert!(!is_shaped("455"));
        assert!(!is_shaped("45a2"));
        assert_eq!(offline_centroid("7250"), Some((-41.4388, 147.1347)));
    }

    #[test]
    fn display_postcodes_are_the_register_range_not_the_wider_au_range() {
        assert!(!is_display_postcode("1999"));
        assert!(is_display_postcode("2000"));
        assert!(is_display_postcode("7999"));
        assert!(!is_display_postcode("8000"));
        assert!(!is_display_postcode("20x0"));
    }
}
