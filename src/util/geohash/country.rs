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

/// Two-letter ISO country code lookup by name. Covers the ~30
/// countries most likely to appear in OSINT breach data.
pub(super) fn iso_for(country: &str) -> Option<&'static str> {
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
pub(super) fn au_state_norm(s: &str) -> Option<&'static str> {
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
