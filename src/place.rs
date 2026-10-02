//! Place-string helpers rebuilt from the monolith's `util::geohash` helpers and
//! `util::place_grain`. Pure, offline, no I/O.

/// Coordinates farther apart than this are more likely separate localities than
/// corroborating fixes of the same place.
pub const GEO_OUTLIER_KM: f64 = 150.0;

/// Parsed components of a free-form address string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AddressComponents {
    pub street: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub iso_country: Option<String>,
}

const COUNTRY_NAMES: &[&str] = &[
    "afghanistan",
    "albania",
    "algeria",
    "andorra",
    "angola",
    "argentina",
    "armenia",
    "australia",
    "austria",
    "azerbaijan",
    "bahamas",
    "bahrain",
    "bangladesh",
    "barbados",
    "belarus",
    "belgium",
    "belize",
    "benin",
    "bhutan",
    "bolivia",
    "bosnia",
    "bosnia and herzegovina",
    "botswana",
    "brazil",
    "brunei",
    "bulgaria",
    "burkina faso",
    "burundi",
    "cambodia",
    "cameroon",
    "canada",
    "chad",
    "chile",
    "china",
    "colombia",
    "congo",
    "costa rica",
    "croatia",
    "cuba",
    "cyprus",
    "czech republic",
    "czechia",
    "denmark",
    "djibouti",
    "dominica",
    "dominican republic",
    "ecuador",
    "egypt",
    "el salvador",
    "england",
    "estonia",
    "eswatini",
    "ethiopia",
    "fiji",
    "finland",
    "france",
    "gabon",
    "gambia",
    "georgia",
    "germany",
    "ghana",
    "greece",
    "great britain",
    "grenada",
    "guatemala",
    "guinea",
    "guyana",
    "haiti",
    "holland",
    "honduras",
    "hong kong",
    "hungary",
    "iceland",
    "india",
    "indonesia",
    "iran",
    "iraq",
    "ireland",
    "israel",
    "italy",
    "ivory coast",
    "jamaica",
    "japan",
    "jordan",
    "kazakhstan",
    "kenya",
    "kiribati",
    "kosovo",
    "kuwait",
    "kyrgyzstan",
    "laos",
    "latvia",
    "lebanon",
    "lesotho",
    "liberia",
    "libya",
    "liechtenstein",
    "lithuania",
    "luxembourg",
    "macau",
    "madagascar",
    "malawi",
    "malaysia",
    "maldives",
    "mali",
    "malta",
    "mauritania",
    "mauritius",
    "mexico",
    "moldova",
    "monaco",
    "mongolia",
    "montenegro",
    "morocco",
    "mozambique",
    "myanmar",
    "namibia",
    "nauru",
    "nepal",
    "netherlands",
    "new zealand",
    "nicaragua",
    "niger",
    "nigeria",
    "north korea",
    "north macedonia",
    "norway",
    "oman",
    "pakistan",
    "palau",
    "palestine",
    "panama",
    "papua new guinea",
    "paraguay",
    "peru",
    "philippines",
    "poland",
    "portugal",
    "qatar",
    "romania",
    "russia",
    "russian federation",
    "rwanda",
    "samoa",
    "san marino",
    "saudi arabia",
    "scotland",
    "senegal",
    "serbia",
    "seychelles",
    "sierra leone",
    "singapore",
    "slovakia",
    "slovenia",
    "somalia",
    "south africa",
    "south korea",
    "south sudan",
    "spain",
    "sri lanka",
    "sudan",
    "suriname",
    "sweden",
    "switzerland",
    "syria",
    "taiwan",
    "tajikistan",
    "tanzania",
    "thailand",
    "the netherlands",
    "togo",
    "tonga",
    "trinidad and tobago",
    "tunisia",
    "turkey",
    "turkmenistan",
    "tuvalu",
    "uae",
    "uganda",
    "uk",
    "ukraine",
    "united arab emirates",
    "united kingdom",
    "united states",
    "united states of america",
    "uruguay",
    "us",
    "usa",
    "uzbekistan",
    "vanuatu",
    "vatican city",
    "venezuela",
    "vietnam",
    "wales",
    "yemen",
    "zambia",
    "zimbabwe",
];

#[must_use]
pub fn is_bare_country(s: &str) -> bool {
    if s.contains(',') {
        return false;
    }
    let mut norm = s.trim().to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    norm.retain(|c| c != '.');
    norm = norm.split_whitespace().collect::<Vec<_>>().join(" ");
    if let Some(stripped) = norm.strip_prefix("the ") {
        norm = stripped.to_string();
    }
    COUNTRY_NAMES.contains(&norm.as_str())
}

#[must_use]
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

    if let Some(last) = parts.last() {
        if let Some(iso) = iso_for(last) {
            out.country = Some((*last).to_string());
            out.iso_country = Some(iso.to_string());
        }
    }

    for part in &parts {
        if out.state.is_some() {
            continue;
        }
        let matched = if let Some(state) = au_state_norm(part) {
            Some(state)
        } else {
            part.split_whitespace().find_map(au_state_norm)
        };
        if let Some(state) = matched {
            out.state = Some(state.to_string());
            if out.iso_country.is_none() {
                out.iso_country = Some("AU".to_string());
                out.country = Some("Australia".to_string());
            }
        }
    }

    for part in parts.iter().rev() {
        if out.postal_code.is_some() {
            continue;
        }
        if let Some(tok) = part.split_whitespace().last() {
            if tok.bytes().all(|b| b.is_ascii_digit()) && (4..=10).contains(&tok.len()) {
                out.postal_code = Some(tok.to_string());
            }
        }
    }

    let mut city_skip = 0usize;
    if parts.len() >= 3 {
        if let Some(first) = parts[0].chars().next() {
            if first.is_ascii_digit() {
                out.street = Some(parts[0].to_string());
                city_skip = 1;
            }
        }
    }

    for part in parts.iter().skip(city_skip) {
        let piece = part.trim();
        if piece.is_empty() {
            continue;
        }
        if out.country.as_deref() == Some(piece) {
            continue;
        }
        let first_token = piece.split_whitespace().next().unwrap_or("");
        if au_state_norm(piece).is_some() || au_state_norm(first_token).is_some() {
            continue;
        }
        if iso_for(piece).is_some() {
            continue;
        }
        if piece
            .bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_whitespace())
        {
            continue;
        }
        out.city = Some(piece.to_string());
        break;
    }

    out
}

#[must_use]
pub fn reverse_country_iso(lat: f64, lon: f64) -> Option<&'static str> {
    const BOXES: &[(&str, f64, f64, f64, f64)] = &[
        ("US", 24.0, 49.5, -125.0, -66.5),
        ("AK", 51.0, 71.5, -180.0, -130.0),
        ("HI", 18.5, 22.5, -161.0, -154.0),
        ("CA", 41.5, 84.0, -141.0, -52.0),
        ("MX", 14.5, 32.7, -118.0, -86.7),
        ("AU", -44.0, -10.0, 113.0, 154.0),
        ("NZ", -47.5, -34.0, 166.0, 179.0),
        ("GB", 49.5, 60.9, -8.7, 1.8),
        ("IE", 51.4, 55.5, -10.5, -5.4),
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
        ("NO", 57.9, 71.2, 4.0, 31.5),
        ("SE", 55.3, 69.1, 10.9, 24.2),
        ("FI", 59.7, 70.1, 20.5, 31.6),
        ("DK", 54.5, 57.8, 8.0, 12.7),
        ("IS", 63.3, 66.6, -24.5, -13.4),
        ("PL", 49.0, 54.9, 14.1, 24.2),
        ("CZ", 48.5, 51.1, 12.0, 18.9),
        ("SK", 47.7, 49.7, 16.8, 22.6),
        ("HU", 45.7, 48.6, 16.1, 22.9),
        ("RO", 43.6, 48.3, 20.2, 29.7),
        ("GR", 34.8, 41.7, 19.4, 28.3),
        ("RU", 41.2, 81.9, 19.6, 180.0),
        ("UA", 44.4, 52.4, 22.1, 40.2),
        ("JP", 30.0, 45.6, 128.0, 146.0),
        ("KR", 33.1, 38.6, 124.6, 131.9),
        ("HK", 22.2, 22.6, 113.8, 114.4),
        ("TW", 21.9, 25.3, 119.5, 122.0),
        ("CN", 18.2, 53.6, 73.5, 134.8),
        ("IN", 6.7, 35.7, 68.1, 97.4),
        ("SG", 1.2, 1.5, 103.6, 104.0),
        ("ID", -11.0, 6.1, 95.0, 141.0),
        ("PH", 4.6, 21.1, 116.9, 126.6),
        ("VN", 8.5, 23.4, 102.1, 109.5),
        ("TH", 5.6, 20.5, 97.3, 105.6),
        ("MY", 0.9, 7.4, 99.6, 119.3),
        ("AE", 22.6, 26.1, 51.6, 56.4),
        ("SA", 16.4, 32.2, 34.5, 55.7),
        ("IL", 29.5, 33.3, 34.3, 35.9),
        ("TR", 35.8, 42.1, 25.7, 44.8),
        ("BR", -33.8, 5.3, -73.9, -34.8),
        ("AR", -55.1, -21.8, -73.6, -53.6),
        ("CL", -55.9, -17.5, -75.7, -66.4),
        ("CO", -4.2, 13.4, -79.0, -66.8),
        ("PE", -18.3, 0.0, -81.3, -68.7),
        ("ZA", -34.8, -22.1, 16.5, 32.9),
        ("EG", 22.0, 31.7, 24.7, 36.9),
        ("NG", 4.3, 13.9, 2.7, 14.7),
        ("KE", -4.7, 5.0, 33.9, 41.9),
        ("MA", 27.7, 35.9, -13.2, -1.0),
    ];
    for (iso, lat_min, lat_max, lon_min, lon_max) in BOXES {
        if lat >= *lat_min && lat <= *lat_max && lon >= *lon_min && lon <= *lon_max {
            return Some(match *iso {
                "AK" | "HI" => "US",
                other => other,
            });
        }
    }
    None
}

#[must_use]
pub fn country_name_for_iso(iso: &str) -> Option<&'static str> {
    Some(match iso {
        "AR" => "Argentina",
        "AT" => "Austria",
        "AU" => "Australia",
        "BE" => "Belgium",
        "BR" => "Brazil",
        "CA" => "Canada",
        "CH" => "Switzerland",
        "CL" => "Chile",
        "CN" => "China",
        "CO" => "Colombia",
        "CZ" => "Czechia",
        "DE" => "Germany",
        "DK" => "Denmark",
        "EG" => "Egypt",
        "ES" => "Spain",
        "FI" => "Finland",
        "FR" => "France",
        "GB" => "United Kingdom",
        "GR" => "Greece",
        "HK" => "Hong Kong",
        "HU" => "Hungary",
        "ID" => "Indonesia",
        "IE" => "Ireland",
        "IL" => "Israel",
        "IN" => "India",
        "IS" => "Iceland",
        "IT" => "Italy",
        "JP" => "Japan",
        "KE" => "Kenya",
        "KR" => "South Korea",
        "LU" => "Luxembourg",
        "MA" => "Morocco",
        "MX" => "Mexico",
        "MY" => "Malaysia",
        "NG" => "Nigeria",
        "NL" => "Netherlands",
        "NO" => "Norway",
        "NZ" => "New Zealand",
        "PE" => "Peru",
        "PH" => "Philippines",
        "PL" => "Poland",
        "PT" => "Portugal",
        "RO" => "Romania",
        "RU" => "Russia",
        "SA" => "Saudi Arabia",
        "SE" => "Sweden",
        "SG" => "Singapore",
        "SK" => "Slovakia",
        "TH" => "Thailand",
        "TR" => "Turkey",
        "TW" => "Taiwan",
        "UA" => "Ukraine",
        "US" => "United States",
        "VN" => "Vietnam",
        "ZA" => "South Africa",
        _ => return None,
    })
}

#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub fn timezone_for(lat: f64, lon: f64) -> &'static str {
    if (-44.0..=-10.0).contains(&lat) {
        if lon > 140.0 {
            return "Australia/Sydney";
        }
        if lon > 130.0 {
            return "Australia/Adelaide";
        }
        if lon > 110.0 {
            return "Australia/Perth";
        }
    }
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
    if (35.0..=60.0).contains(&lat) {
        if (-12.0..=2.0).contains(&lon) {
            return "Europe/London";
        }
        if (2.0..=20.0).contains(&lon) {
            return "Europe/Paris";
        }
        if (20.0..=30.0).contains(&lon) {
            return "Europe/Helsinki";
        }
    }
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

fn iso_for(country: &str) -> Option<&'static str> {
    let lower = country.trim().to_ascii_lowercase();
    Some(match lower.as_str() {
        "australia" | "au" => "AU",
        "austria" | "at" => "AT",
        "belgium" | "be" => "BE",
        "brazil" | "br" => "BR",
        "canada" | "ca" => "CA",
        "china" | "cn" => "CN",
        "france" | "fr" => "FR",
        "germany" | "de" | "deutschland" => "DE",
        "great britain" | "england" | "gb" | "uk" | "united kingdom" => "GB",
        "hong kong" | "hk" => "HK",
        "india" | "in" => "IN",
        "indonesia" | "id" => "ID",
        "ireland" | "ie" => "IE",
        "italy" | "it" => "IT",
        "japan" | "jp" => "JP",
        "malaysia" | "my" => "MY",
        "mexico" | "mx" => "MX",
        "netherlands" | "nl" | "holland" => "NL",
        "new zealand" | "nz" => "NZ",
        "philippines" | "ph" => "PH",
        "portugal" | "pt" => "PT",
        "singapore" | "sg" => "SG",
        "south africa" | "za" => "ZA",
        "south korea" | "kr" | "korea" => "KR",
        "spain" | "es" => "ES",
        "switzerland" | "ch" => "CH",
        "taiwan" | "tw" => "TW",
        "thailand" | "th" => "TH",
        "turkey" | "tr" => "TR",
        "united states" | "united states of america" | "us" | "usa" => "US",
        "vietnam" | "vn" => "VN",
        _ => return None,
    })
}

fn au_state_norm(s: &str) -> Option<&'static str> {
    let lower = s.trim().to_ascii_lowercase();
    Some(match lower.as_str() {
        "act" | "australian capital territory" => "ACT",
        "nsw" | "new south wales" => "NSW",
        "nt" | "northern territory" => "NT",
        "qld" | "queensland" => "QLD",
        "sa" | "south australia" => "SA",
        "tas" | "tasmania" => "TAS",
        "vic" | "victoria" => "VIC",
        "wa" | "western australia" => "WA",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_country_names_are_recognised() {
        for value in [
            "Australia",
            "  AUSTRALIA  ",
            "United Kingdom",
            "USA",
            "U.S.A.",
            "The Netherlands",
            "new  zealand",
        ] {
            assert!(is_bare_country(value), "{value}");
        }
    }

    #[test]
    fn finer_addresses_are_not_country_grain() {
        for value in [
            "12 Smith St, Perth, Australia",
            "Darwin, NT, Australia",
            "Sydney",
            "Northern Territory",
            "",
            "55 Cavenagh Street",
        ] {
            assert!(!is_bare_country(value), "{value}");
        }
    }

    #[test]
    fn parse_address_handles_common_forms() {
        let full = parse_address("Sydney, NSW, Australia");
        assert_eq!(full.city.as_deref(), Some("Sydney"));
        assert_eq!(full.state.as_deref(), Some("NSW"));
        assert_eq!(full.country.as_deref(), Some("Australia"));
        assert_eq!(full.iso_country.as_deref(), Some("AU"));

        let street = parse_address("10 Smith St, Melbourne, VIC, Australia");
        assert_eq!(street.street.as_deref(), Some("10 Smith St"));
        assert_eq!(street.city.as_deref(), Some("Melbourne"));
        assert_eq!(street.state.as_deref(), Some("VIC"));
        assert_eq!(street.iso_country.as_deref(), Some("AU"));

        let state_only = parse_address("SA, VIC");
        assert_eq!(state_only.state.as_deref(), Some("SA"));
        assert_eq!(state_only.iso_country.as_deref(), Some("AU"));

        let postcode = parse_address("Brisbane, QLD 4000");
        assert_eq!(postcode.city.as_deref(), Some("Brisbane"));
        assert_eq!(postcode.state.as_deref(), Some("QLD"));
        assert_eq!(postcode.postal_code.as_deref(), Some("4000"));
    }

    #[test]
    fn parse_address_handles_multiword_states_and_postcodes() {
        let a = parse_address("Sydney, New South Wales, Australia");
        assert_eq!(a.city.as_deref(), Some("Sydney"));
        assert_eq!(a.state.as_deref(), Some("NSW"));

        let b = parse_address("Perth, Western Australia");
        assert_eq!(b.city.as_deref(), Some("Perth"));
        assert_eq!(b.state.as_deref(), Some("WA"));
        assert_eq!(b.iso_country.as_deref(), Some("AU"));

        let c = parse_address("PO Box 4321, Sydney NSW 2000");
        assert_eq!(c.postal_code.as_deref(), Some("2000"));
        assert_eq!(c.state.as_deref(), Some("NSW"));

        let d = parse_address("1234 Smith St, Sydney, NSW");
        assert_eq!(d.street.as_deref(), Some("1234 Smith St"));
        assert_eq!(d.postal_code, None);
    }

    #[test]
    fn timezone_and_country_boxes_cover_reference_points() {
        assert_eq!(timezone_for(-33.86, 151.21), "Australia/Sydney");
        assert_eq!(timezone_for(-31.95, 115.86), "Australia/Perth");
        assert_eq!(timezone_for(40.71, -74.0), "America/New_York");
        assert_eq!(timezone_for(51.5074, -0.1278), "Europe/London");

        assert_eq!(reverse_country_iso(-33.87, 151.21), Some("AU"));
        assert_eq!(reverse_country_iso(61.0, -150.0), Some("US"));
        assert_eq!(reverse_country_iso(21.3, -157.8), Some("US"));
        assert_eq!(reverse_country_iso(1.3521, 103.8198), Some("SG"));
        assert_eq!(reverse_country_iso(22.3193, 114.1694), Some("HK"));
        assert_eq!(reverse_country_iso(25.0330, 121.5654), Some("TW"));
        assert_eq!(reverse_country_iso(0.0, -30.0), None);
        assert_eq!(country_name_for_iso("AU"), Some("Australia"));
        assert_eq!(country_name_for_iso("ZZ"), None);
    }
}
