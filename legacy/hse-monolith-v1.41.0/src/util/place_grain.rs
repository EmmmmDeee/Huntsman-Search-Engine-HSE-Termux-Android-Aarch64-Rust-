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
