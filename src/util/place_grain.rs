//! Pure, offline predicate: is a place string a **bare country name**
//! (country-grain), carrying no finer locality?
//!
//! Forward-geocoding a bare country name returns the country **centroid** — the
//! geographic middle of the whole nation, ~1500 km from most of its population.
//! That is never a subject's location, yet it arrives as a precise-looking
//! `Coordinates` fix and then cascades into the geo-convergence correlations: a
//! phone number's coarse carrier-country signal (`phone_carrier_geo` emits an
//! `Address` of just `"Australia"`) becomes a CONFIDENT street-level location the
//! subject has no connection to. A live `+61…` scan reproduced exactly this —
//! geocoding the literal string `"Australia"` produced `-25.27,133.77` (dead
//! centre of the continent), which AU-030/AU-017/AU-057 then "converged" into a
//! CRITICAL fix. This predicate lets a geocoder refuse to manufacture that fix.
//!
//! Deliberately strict: it fires ONLY when the WHOLE value is a country name (or
//! a common alias). Any finer component — a comma, a street, a suburb, a
//! postcode — means the string is not country-grain and is left for normal
//! geocoding, so a real address like `"12 Smith St, Perth, Australia"` is
//! unaffected.

/// Recognised country names + the everyday aliases, all lowercase. Not the full
/// ISO-3166 set — the common nations plus every value the phone-carrier /
/// area-code geo tables can emit — extend as needed. A bare match here means the
/// string names a whole country and nothing finer.
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
    "czechia",
    "czech republic",
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
    "grenada",
    "guatemala",
    "guinea",
    "guyana",
    "haiti",
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
    "togo",
    "tonga",
    "trinidad and tobago",
    "tunisia",
    "turkey",
    "turkmenistan",
    "tuvalu",
    "uganda",
    "ukraine",
    "united arab emirates",
    "united kingdom",
    "united states",
    "united states of america",
    "uruguay",
    "uzbekistan",
    "vanuatu",
    "vatican city",
    "venezuela",
    "vietnam",
    "wales",
    "yemen",
    "zambia",
    "zimbabwe",
    // Everyday aliases / abbreviations (periods are stripped before matching, so
    // "U.S.A." / "U.K." collapse to these dotless forms).
    "uk",
    "usa",
    "us",
    "uae",
    "great britain",
    "britain",
    "holland",
];

/// True if `s`, taken whole, is nothing more than a country name (or a common
/// alias). Case-insensitive; tolerant of surrounding whitespace, a trailing dot,
/// and a leading `the `. Any value with a comma or additional locality tokens is
/// NOT country-grain and returns `false`.
#[must_use]
pub fn is_bare_country(s: &str) -> bool {
    // Any comma means there is a finer component (locality, region) → not bare.
    if s.contains(',') {
        return false;
    }
    let mut norm = s.trim().to_ascii_lowercase();
    // Strip all periods so "U.S.A." / "U.K." match their dotless forms — no
    // country name contains one.
    norm.retain(|c| c != '.');
    // Collapse internal whitespace runs to single spaces.
    if norm.contains("  ") || norm.trim() != norm {
        norm = norm.split_whitespace().collect::<Vec<_>>().join(" ");
    }
    if let Some(stripped) = norm.strip_prefix("the ") {
        norm = stripped.to_string();
    }
    COUNTRY_NAMES.contains(&norm.as_str())
}

/// Qualifiers that turn a CITY name into the region around or above it.
///
/// Each is unambiguous in the position given: no city is named "X State", and
/// "Upstate X" names the part of a state that is explicitly NOT the city.
const CITY_NEGATING_SUFFIXES: &[&str] = &[" state", " province", " prefecture"];
const CITY_NEGATING_PREFIXES: &[&str] = &["upstate ", "greater ", "metropolitan "];

/// True when `s` names a REGION around or above a city rather than the city —
/// `"New York State"`, `"Upstate New York"`, `"Greater London"`.
///
/// This is [`is_bare_country`]'s defect one grain down. A city table matches a
/// tabulated name as a consecutive run of whole tokens, so `"New York State"`
/// tokenises to `["new","york","state"]`, contains the run `new york`, and earns
/// **the city centroid** — a precise-looking fix on Manhattan for a string whose
/// whole point is that it means the rest of the state. Same for
/// `"Upstate New York"`, which names the region explicitly excluding the city.
///
/// **Pure**, offline, case-insensitive.
///
/// Deliberately narrow, because the cost of over-reach is losing a real
/// location: `"New York, NY"` and `"New York"` are the city and must still
/// resolve. The qualifier must be a WHOLE leading or trailing token — a suburb
/// legitimately called `"Statenville"` or `"Upstate Road"` is untouched
/// (REQ-SOCIALLOC-002).
#[must_use]
pub fn negates_city_grain(s: &str) -> bool {
    let norm = s.trim().to_ascii_lowercase();
    // A comma means a finer component follows ("New York, NY"), which is an
    // address naming the city — never a bare region label.
    if norm.contains(',') {
        return false;
    }
    let norm = norm.split_whitespace().collect::<Vec<_>>().join(" ");
    CITY_NEGATING_SUFFIXES
        .iter()
        .any(|q| norm.ends_with(q) && norm.len() > q.len())
        || CITY_NEGATING_PREFIXES
            .iter()
            .any(|q| norm.starts_with(q) && norm.len() > q.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_country_names_are_recognised() {
        assert!(is_bare_country("Australia"));
        assert!(is_bare_country("australia"));
        assert!(is_bare_country("  AUSTRALIA  "));
        assert!(is_bare_country("United Kingdom"));
        assert!(is_bare_country("USA"));
        assert!(is_bare_country("U.S.A."));
        assert!(is_bare_country("The Netherlands"));
        assert!(is_bare_country("new  zealand")); // collapsed whitespace
    }

    #[test]
    fn finer_addresses_are_not_country_grain() {
        assert!(!is_bare_country("12 Smith St, Perth, Australia"));
        assert!(!is_bare_country("Darwin, NT, Australia"));
        assert!(!is_bare_country("Sydney")); // a city, not a country
        assert!(!is_bare_country("Northern Territory"));
        assert!(!is_bare_country(""));
        assert!(!is_bare_country("55 Cavenagh Street"));
    }
}

#[cfg(test)]
mod city_grain_tests {
    use super::negates_city_grain;

    /// REQ-SOCIALLOC-002: a region label must not earn the city's centroid.
    #[test]
    fn a_qualifier_that_means_the_region_is_recognised() {
        for s in [
            "New York State",
            "new york state",
            "  New   York   State  ",
            "Upstate New York",
            "upstate new york",
            "Greater London",
            "Metropolitan Sydney",
            "Washington State",
        ] {
            assert!(negates_city_grain(s), "{s} names a region, not the city");
        }
    }

    /// THE OVER-CORRECTION CONTROL. Losing a real city fix is the expensive
    /// failure here — this guard exists to drop a WRONG coordinate, not a right
    /// one, and every string below is the city itself.
    #[test]
    fn the_city_itself_is_never_negated() {
        for s in [
            "New York",
            "New York, NY",
            "new york, ny",
            "New York, New York",
            "Sydney",
            "Sydney, NSW 2000",
            "London",
            "12 Smith St, Perth, Australia",
            // A comma means an address naming the city, even with a qualifier
            // word elsewhere in it.
            "Upstate Road, New York, NY",
        ] {
            assert!(
                !negates_city_grain(s),
                "{s} is the city and must still resolve"
            );
        }
    }

    /// The qualifier must be a WHOLE leading or trailing token — a place whose
    /// name merely starts or ends with those letters is not a region label.
    #[test]
    fn a_qualifier_must_be_a_whole_token_not_a_substring() {
        for s in ["Statenville", "Upstateville", "Realestate", "Greaterville"] {
            assert!(
                !negates_city_grain(s),
                "{s} is a place name, not a qualified region"
            );
        }
        // Vacuity guard: the bare qualifier alone is not a region label either
        // (there is no city to negate), and must not panic or over-match.
        assert!(!negates_city_grain("state"));
        assert!(!negates_city_grain("upstate"));
        assert!(!negates_city_grain(""));
    }
}
