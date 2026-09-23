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

/// The finest STREET-level component a place string names: a house number on a
/// street, or a street alone. See [`PlaceNaming`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreetGrain {
    /// A numbered address on a street (`"12 Smith St"`).
    House,
    /// A street with no number (`"Martin Place"`).
    Street,
}

/// The finest ADMINISTRATIVE component a place string names, finest first.
/// See [`PlaceNaming`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdminGrain {
    /// A postcode (`"… QLD 4066"`, `"4552"`).
    Postcode,
    /// A tabulated city, suburb or regional centre (`"Toowong"`, `"Sydney"`).
    Locality,
    /// A state or province and nothing finer (`"North Carolina"`, `"QLD"`).
    Region,
    /// A whole country ([`is_bare_country`]).
    Country,
}

/// What a place string NAMES, at its finest: the street part and the
/// administrative part, each `None` when the string names none.
///
/// Why a geocoder's INPUT matters to the precision of its OUTPUT: a forward
/// geocode cannot be finer than what it was asked. `"Ian Thorpe, North
/// Carolina"` names a state and two words that are not a place; Photon still
/// answers with a street ("Thorpe-Abbotts Lane") because the surname is a
/// fragment of a road name, and that street-grain hit then reads as a 40 m fix.
/// `core::place::grain` caps a forward-geocode hit at the grain its input
/// names, so the answer can never be more precise than the question
/// (REQ-GEOLABEL-001).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlaceNaming {
    /// A house number on a street, or a street alone.
    pub street: Option<StreetGrain>,
    /// The finest administrative area named.
    pub admin: Option<AdminGrain>,
}

/// Street-type words, the same vocabulary `util::address_au`'s address pattern
/// ends a street with.
const STREET_TYPES: &[&str] = &[
    "street",
    "st",
    "road",
    "rd",
    "avenue",
    "ave",
    "lane",
    "ln",
    "drive",
    "dr",
    "court",
    "ct",
    "crescent",
    "cres",
    "place",
    "pl",
    "way",
    "highway",
    "hwy",
    "parade",
    "pde",
    "terrace",
    "tce",
    "boulevard",
    "blvd",
    "circuit",
    "cct",
    "close",
    "cl",
    "esplanade",
    "esp",
    "square",
    "sq",
];

/// The US states (and DC), lowercase, matched as whole-token phrases. A US
/// state is region grain exactly as an Australian one is.
const US_STATES: &[&str] = &[
    "alabama",
    "alaska",
    "arizona",
    "arkansas",
    "california",
    "colorado",
    "connecticut",
    "delaware",
    "florida",
    "georgia",
    "hawaii",
    "idaho",
    "illinois",
    "indiana",
    "iowa",
    "kansas",
    "kentucky",
    "louisiana",
    "maine",
    "maryland",
    "massachusetts",
    "michigan",
    "minnesota",
    "mississippi",
    "missouri",
    "montana",
    "nebraska",
    "nevada",
    "new hampshire",
    "new jersey",
    "new mexico",
    "new york",
    "north carolina",
    "north dakota",
    "ohio",
    "oklahoma",
    "oregon",
    "pennsylvania",
    "rhode island",
    "south carolina",
    "south dakota",
    "tennessee",
    "texas",
    "utah",
    "vermont",
    "virginia",
    "washington",
    "west virginia",
    "wisconsin",
    "wyoming",
    "district of columbia",
];

/// `s` split into whole words, each folded to ASCII lowercase
/// (`util::str_util::fold_ascii_lower`), empties dropped — so `"Hà Nội"` and
/// `"Ha Noi"` tokenise alike and punctuation never joins or splits a word.
fn folded_tokens(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric())
        .map(crate::util::str_util::fold_ascii_lower)
        .filter(|t| !t.is_empty())
        .collect()
}

/// True when `needle` occurs in `haystack` as a consecutive run of WHOLE words,
/// compared diacritic- and case-insensitively. Whole words, so `"Sydney
/// Heads"` is not a phrase of `"Sydney, Australia"` and `"Milton"` is not one
/// of `"Hamilton"`. An empty `needle` is a phrase of nothing. Pure.
///
/// The test a geocoder's matched place name must pass to be an answer TO the
/// query rather than a fuzzy neighbour of it: Open-Meteo answered
/// `"Sydney, Australia"` with the headland "Sydney Heads", 1,400 km north in
/// Queensland.
#[must_use]
pub fn is_whole_word_phrase(needle: &str, haystack: &str) -> bool {
    let want = folded_tokens(needle);
    let have = folded_tokens(haystack);
    !want.is_empty()
        && want.len() <= have.len()
        && have.windows(want.len()).any(|w| w == want.as_slice())
}

/// What `s` names at its finest ([`PlaceNaming`]). Pure, offline, no I/O.
///
/// * **Street** — a street-type word ([`STREET_TYPES`]) that FOLLOWS a name word
///   in its comma-separated segment (so the `St` of `"St Kilda"` is a saint,
///   not a street); a **house** when a digit-bearing word precedes it in that
///   segment (`"12 Smith St"`, `"3/15 Smith St"`).
/// * **Administrative**, first match in this order:
///   a tabulated locality or postcode (`util::city_coords::city_coords_with_grain`
///   — `"city"` is [`AdminGrain::Locality`], a postcode centroid or postcode
///   region is [`AdminGrain::Postcode`] because the string named a postcode);
///   an Australian state (`util::address_au::single_state_code`) or a US state
///   ([`US_STATES`]) → [`AdminGrain::Region`]; a bare country
///   ([`is_bare_country`]) → [`AdminGrain::Country`]. Anything else names no
///   administrative area this can recognise (`None`), which a caller must read
///   as locality at best — an unrecognised word is not evidence of a street.
#[must_use]
pub fn place_naming(s: &str) -> PlaceNaming {
    let mut street = None;
    for segment in s.split(',') {
        let words: Vec<&str> = segment.split_whitespace().collect();
        for (i, w) in words.iter().enumerate() {
            let bare = w
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_ascii_lowercase();
            if i == 0 || !STREET_TYPES.contains(&bare.as_str()) {
                continue;
            }
            let numbered = words[..i]
                .iter()
                .any(|p| p.chars().any(|c| c.is_ascii_digit()));
            let found = if numbered {
                StreetGrain::House
            } else {
                StreetGrain::Street
            };
            if street != Some(StreetGrain::House) {
                street = Some(found);
            }
        }
    }
    let tokens = folded_tokens(s);
    let names_us_state = US_STATES.iter().any(|st| {
        let want: Vec<&str> = st.split(' ').collect();
        tokens
            .windows(want.len())
            .any(|w| w.iter().map(String::as_str).eq(want.iter().copied()))
    });
    let admin = match crate::util::city_coords::city_coords_with_grain(s) {
        Some((_, "city")) => Some(AdminGrain::Locality),
        Some(_) => Some(AdminGrain::Postcode),
        None if crate::util::address_au::single_state_code(s).is_some() || names_us_state => {
            Some(AdminGrain::Region)
        }
        None if is_bare_country(s) => Some(AdminGrain::Country),
        None => None,
    };
    PlaceNaming { street, admin }
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
    use super::{AdminGrain, StreetGrain, is_whole_word_phrase, negates_city_grain, place_naming};

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

    /// REQ-GEOLABEL-001: what a place string names at its finest — the input
    /// cap a forward geocode of it can never beat.
    #[test]
    fn place_naming_reads_the_finest_component() {
        let n = place_naming("12 Smith St, Toowong QLD 4066");
        assert_eq!(n.street, Some(StreetGrain::House));
        assert_eq!(
            place_naming("Martin Place, Sydney").street,
            Some(StreetGrain::Street)
        );
        // `St Kilda` is a saint, not a street.
        assert_eq!(place_naming("St Kilda, Victoria").street, None);
        assert_eq!(place_naming("Toowong").admin, Some(AdminGrain::Locality));
        assert_eq!(place_naming("4552").admin, Some(AdminGrain::Postcode));
        let nc = place_naming("Ian Thorpe, North Carolina");
        assert_eq!(nc.street, None);
        assert_eq!(nc.admin, Some(AdminGrain::Region));
        assert_eq!(place_naming("Queensland").admin, Some(AdminGrain::Region));
        assert_eq!(place_naming("Australia").admin, Some(AdminGrain::Country));
        assert_eq!(place_naming("Ian Thorpe").admin, None);
    }

    /// REQ-OPENMETEO-002: a match must be a whole-word phrase of the query.
    #[test]
    fn whole_word_phrase_matching() {
        assert!(is_whole_word_phrase("Sydney", "Sydney, Australia"));
        assert!(!is_whole_word_phrase("Sydney Heads", "Sydney, Australia"));
        assert!(!is_whole_word_phrase("Milton", "Hamilton, NZ"));
        assert!(is_whole_word_phrase("Hà Nội", "ha noi, vietnam"));
        assert!(!is_whole_word_phrase(
            "Thorpe-Abbotts Lane",
            "Ian Thorpe, North Carolina"
        ));
        assert!(!is_whole_word_phrase("", "anything"));
    }
}
