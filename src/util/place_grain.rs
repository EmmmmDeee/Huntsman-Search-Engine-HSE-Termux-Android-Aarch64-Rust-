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

/// Street-type words that FOLLOW the street's name (`"Smith Street"`,
/// `"Oak Grove"`, `"Main Circle"`), matched as a whole, ASCII-lowercased word.
///
/// A superset of `util::address_au`'s extraction pattern, deliberately not the
/// same list: that pattern mints an address out of free prose, so it keeps to
/// the types common enough to be worth the false positives; this one reads a
/// string a caller already holds AS a place (a geocoder's input, a register's
/// address field), where missing a street type is the expensive failure — the
/// geocode of `"12 Oak Grove, Toowong"` was capped at the suburb, stamped an
/// area and withheld from every pivot. Kept free of every word a tabulated
/// locality name ends with (`city_coords::tests` holds that invariant), so no
/// gazetteer name is ever read as a street.
const STREET_TYPES: &[&str] = &[
    "street",
    "st",
    "road",
    "rd",
    "avenue",
    "ave",
    "av",
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
    "freeway",
    "fwy",
    "motorway",
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
    "grove",
    "gr",
    "rise",
    "mews",
    "walk",
    "loop",
    "link",
    "parkway",
    "pkwy",
    "promenade",
    "row",
    "circle",
    "cir",
    "trail",
    "trl",
    "plaza",
    "alley",
    "track",
];

/// Street-type words that PRECEDE the street's name, each with whether a
/// number AFTER the name is the house number.
///
/// * **Vietnamese** — `"Đường Láng"` (street), `"Phố Huế"` (street, in the
///   old quarters), `"Ngõ 12 Láng Hạ"` / `"Ngách"` / `"Hẻm"` / `"Kiệt"`
///   (alleys and sub-alleys), `"Đại lộ Thăng Long"` (boulevard). The house
///   number comes FIRST (`"12 Đường Láng"`); a number after the type is part
///   of the street's own name (`"Đường 3 Tháng 2"`, alley `"Ngõ 12"`), so it is
///   not a house number.
/// * **Romance** — `"rue"`, `"calle"`, `"via"`, `"avenida"`, `"rua"`,
///   `"carrer"`: the number comes either first (`"12 rue de Rivoli"`) or after
///   the name (`"Calle Mayor 5"`, `"Via Roma 10"`).
///
/// Matched on the lowercased word WITH its diacritics, never on the folded
/// ASCII: `"Đường"` (street) and `"Dương"` (one of the commonest Vietnamese
/// surnames) fold to the same `duong`, and a name read as a street would lift
/// the cap on a geocode of `"Dương Văn Minh, Hà Nội"` — the Ian Thorpe defect
/// in Vietnamese. The forms are NFC, the form every provider and keyboard
/// emits.
const LEADING_STREET_TYPES: &[(&[&str], bool)] = &[
    (&["đường"], false),
    (&["phố"], false),
    (&["ngõ"], false),
    (&["ngách"], false),
    (&["hẻm"], false),
    (&["kiệt"], false),
    (&["đại", "lộ"], false),
    (&["rue"], true),
    (&["calle"], true),
    (&["via"], true),
    (&["avenida"], true),
    (&["rua"], true),
    (&["carrer"], true),
];

/// Endings that make ONE word a street name with its type fused on
/// (`"Hauptstraße"`, `"Kerkstraat"`, `"Herrengasse"`); the house number follows
/// the name. The abbreviated `"Hauptstr."` is recognised by its trailing
/// `str.`.
const COMPOUND_STREET_SUFFIXES: &[&str] = &["straße", "strasse", "straat", "gasse"];

/// A house-number word: 1–3 digits with an optional letter (`"12"`, `"45A"`),
/// or a unit/number pair (`"12/5"`, `"3/15"`). Never four digits, which is the
/// shape of an Australian postcode (`"4066 Toowong"` names a postcode area, not
/// house 4066), and never five, a European or US postcode.
fn is_house_number(w: &str) -> bool {
    let w = w.trim_matches(|c: char| !c.is_alphanumeric() && c != '/');
    let one = |part: &str| {
        let digits = part.chars().take_while(char::is_ascii_digit).count();
        let rest = &part[digits..];
        (1..=3).contains(&digits)
            && (rest.is_empty()
                || (rest.len() == 1 && rest.chars().all(|c| c.is_ascii_alphabetic())))
    };
    !w.is_empty() && w.split('/').all(one)
}

/// A street found in one comma-separated segment: its grain, and the index of
/// the first word AFTER it (the locality that shares the segment, as in
/// `"45 Sydney Road Brunswick"`).
struct SegmentStreet {
    grain: StreetGrain,
    rest_from: usize,
}

/// The street one comma-separated segment names, if any.
///
/// `street_line` is true for the FIRST segment of a multi-segment string: the
/// line an address puts its street on in Australia, the US and Vietnam alike.
/// There, a leading house number followed by a name is a numbered street even
/// with no type word (`"123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh"`) — the
/// Vietnamese convention, and the common shorthand elsewhere.
fn segment_street(words: &[&str], street_line: bool) -> Option<SegmentStreet> {
    let lower: Vec<String> = words
        .iter()
        .map(|w| {
            w.trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .collect();
    let has_digit = |w: &&str| w.chars().any(|c| c.is_ascii_digit());
    let mut best: Option<SegmentStreet> = None;
    let mut found = |grain: StreetGrain, rest_from: usize| {
        let keep = best.as_ref().is_none_or(|b| {
            (grain == StreetGrain::House && b.grain == StreetGrain::Street)
                || (grain == b.grain && rest_from > b.rest_from)
        });
        if keep {
            best = Some(SegmentStreet { grain, rest_from });
        }
    };
    let numbered = |yes: bool| {
        if yes {
            StreetGrain::House
        } else {
            StreetGrain::Street
        }
    };
    for (i, w) in lower.iter().enumerate() {
        // A trailing type FOLLOWS a name word, so the `St` of `"St Kilda"` is a
        // saint, not a street.
        if i > 0 && STREET_TYPES.contains(&w.as_str()) {
            found(numbered(words[..i].iter().any(has_digit)), i + 1);
        }
        // A leading type STARTS the street line — first, or after only the
        // house number (`"12 Đường Láng"`) — and a name must follow it, so
        // `"Brisbane via Toowoomba"` is a route, not a street.
        if words[..i].iter().all(has_digit) {
            for &(phrase, number_may_follow) in LEADING_STREET_TYPES {
                let end = i + phrase.len();
                if end < lower.len()
                    && lower[i..end]
                        .iter()
                        .map(String::as_str)
                        .eq(phrase.iter().copied())
                {
                    let before = i > 0;
                    let after = number_may_follow && words[end..].iter().any(has_digit);
                    found(numbered(before || after), words.len());
                }
            }
        }
        let compound = COMPOUND_STREET_SUFFIXES
            .iter()
            .any(|s| w.len() > s.len() && w.ends_with(s))
            || words[i].to_lowercase().ends_with("str.") && w.len() > 3;
        if compound {
            let others = words
                .iter()
                .enumerate()
                .any(|(j, o)| j != i && has_digit(o));
            found(numbered(others), words.len());
        }
    }
    if street_line
        && words.len() >= 2
        && is_house_number(words[0])
        && words[1..]
            .iter()
            .any(|w| w.chars().any(char::is_alphabetic))
    {
        found(StreetGrain::House, words.len());
    }
    best
}

/// Each comma-separated segment of `s` with the street it names, if any.
fn segments_with_streets(s: &str) -> Vec<(Vec<&str>, Option<SegmentStreet>)> {
    let segments: Vec<&str> = s.split(',').collect();
    let multi = segments.len() >= 2;
    segments
        .iter()
        .enumerate()
        .map(|(k, seg)| {
            let words: Vec<&str> = seg.split_whitespace().collect();
            let street = segment_street(&words, multi && k == 0);
            (words, street)
        })
        .collect()
}

/// `s` with its street part removed — the locality it names, for a lookup that
/// must resolve the PLACE and never a word of a street's name.
///
/// A street is named after places: `"45 Sydney Road, Brunswick VIC"` is in
/// Melbourne, `"Hobart Rd, Kings Meadows TAS"` in Launceston, and a gazetteer
/// that matches `"sydney"` anywhere in the string anchors both 700 km from the
/// address. Every segment [`place_naming`] reads as a street is dropped, except
/// the words that FOLLOW a trailing street type in the same segment (the
/// `"Brunswick"` of `"45 Sydney Road Brunswick"`). Whitespace inside a kept
/// segment is normalised; segments are rejoined with `", "`. Pure.
#[must_use]
pub fn locality_part(s: &str) -> String {
    segments_with_streets(s)
        .into_iter()
        .filter_map(|(words, street)| {
            let from = street.map_or(0, |st| st.rest_from);
            let kept = words.get(from..).unwrap_or_default().join(" ");
            (!kept.is_empty()).then_some(kept)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

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

/// Abbreviations a place name is written with either way — `"Mt Isa"` /
/// `"Mount Isa"`, `"St Kilda"` / `"Saint Kilda"`, `"Pt Lonsdale"` / `"Point
/// Lonsdale"` — read as their full word on both sides of a comparison.
const PLACE_WORD_ABBREVIATIONS: &[(&str, &str)] = &[
    ("mt", "mount"),
    ("st", "saint"),
    ("pt", "point"),
    ("ft", "fort"),
];

/// [`folded_tokens`], with each abbreviation read as its full word.
fn place_tokens(s: &str) -> Vec<String> {
    folded_tokens(s)
        .into_iter()
        .map(|t| {
            PLACE_WORD_ABBREVIATIONS
                .iter()
                .find(|(short, _)| *short == t)
                .map_or(t, |(_, full)| (*full).to_string())
        })
        .collect()
}

/// True when a geocoder's matched place `name` is the place `query` asked
/// about — its words, read as ONE name, are a consecutive run of the query's
/// words — rather than a fuzzy neighbour of it. Pure.
///
/// The test a geocoder's answer must pass to be a geocode OF the query:
/// Open-Meteo answered `"Sydney, Australia"` with the headland "Sydney Heads",
/// 1,400 km north in Queensland, and Photon answered `"Ian Thorpe, North
/// Carolina"` with "Thorpe-Abbotts Lane". Whole words, so `"Sydney Heads"` is
/// not the place of `"Sydney, Australia"` and `"Milton"` is not one of
/// `"Hamilton"`. The comparison forgives only how ONE name is written:
///
/// * diacritics and case (`"Hà Nội"` / `"ha noi"`);
/// * word boundaries — the run's words are compared joined, so `"Hanoi"` and
///   `"Ha Noi"`, `"Haiphong"` and `"Hải Phòng"` are one name;
/// * the everyday abbreviations ([`PLACE_WORD_ABBREVIATIONS`]);
/// * a trailing generic `"City"` on the matched name — GeoNames' English name
///   for Vietnam's largest city is "Ho Chi Minh City", asked as `"Ho Chi Minh,
///   Vietnam"` — unless the name without it is a state or a country ("Kansas
///   City" is not Kansas, "Mexico City" not Mexico).
///
/// An empty `name` is the place of nothing.
#[must_use]
pub fn is_name_of_queried_place(name: &str, query: &str) -> bool {
    let mut want = place_tokens(name);
    if want.len() >= 2 && want.last().is_some_and(|t| t == "city") {
        let rest = want[..want.len() - 1].join(" ");
        let names_region = matches!(
            place_naming(&rest).admin,
            Some(AdminGrain::Region | AdminGrain::Country)
        );
        if !names_region {
            want.pop();
        }
    }
    let joined = want.concat();
    if joined.is_empty() {
        return false;
    }
    let have = place_tokens(query);
    (0..have.len()).any(|i| {
        let mut run = String::new();
        for t in &have[i..] {
            run.push_str(t);
            if run.len() >= joined.len() {
                return run == joined;
            }
        }
        false
    })
}

/// What `s` names at its finest ([`PlaceNaming`]). Pure, offline, no I/O.
///
/// * **Street**, read per comma-separated segment:
///   a street-type word ([`STREET_TYPES`]) that FOLLOWS a name word (so the
///   `St` of `"St Kilda"` is a saint, not a street) — a **house** when a
///   digit-bearing word precedes it (`"12 Smith St"`, `"3/15 Smith St"`);
///   a type that PRECEDES the name ([`LEADING_STREET_TYPES`]: `"12 Đường
///   Láng"`, `"Ngõ 12 Láng Hạ"`, `"Calle Mayor 5"`); a word with its type fused
///   on ([`COMPOUND_STREET_SUFFIXES`]: `"Hauptstraße 12"`); and, on the first
///   segment of a multi-segment string, a house number followed by a name
///   (`"123 Nguyễn Huệ, Quận 1"`), the Vietnamese form with no type word.
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
    let street = segments_with_streets(s)
        .into_iter()
        .filter_map(|(_, st)| st.map(|st| st.grain))
        .max_by_key(|g| *g == StreetGrain::House);
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
    use super::{
        AdminGrain, StreetGrain, is_name_of_queried_place, locality_part, negates_city_grain,
        place_naming,
    };

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

    /// REQ-GEOLABEL-010: a street is recognised in the forms the operating
    /// jurisdiction and the common AU/US/European addresses write it — a
    /// leading Vietnamese or Romance type, a fused German/Dutch type, the
    /// Vietnamese "number + name" street line with no type word, and the
    /// AU/US types the first list lacked — without reading a surname, a
    /// route or a postcode area as one.
    #[test]
    fn place_naming_reads_streets_in_every_form_the_jurisdictions_write() {
        let house = Some(StreetGrain::House);
        let street = Some(StreetGrain::Street);
        for (s, want) in [
            ("12 Đường Láng, Phường Láng, Hà Nội", house),
            ("Đường Láng, Hà Nội", street),
            ("5 Phố Huế, Hai Bà Trưng, Hà Nội", house),
            ("Ngõ 12 Láng Hạ, Đống Đa, Hà Nội", street),
            ("Hẻm 45 Lê Lợi, Huế", street),
            ("Đường 3 Tháng 2, Quận 10", street),
            ("Đại lộ Thăng Long, Hà Nội", street),
            ("123 Nguyễn Huệ, Quận 1, TP. Hồ Chí Minh", house),
            ("12 rue de Rivoli, Paris", house),
            ("Calle Mayor 5, Madrid", house),
            ("Via Roma 10, Torino", house),
            ("Hauptstraße 12, Berlin", house),
            ("Kerkstraat 3, Amsterdam", house),
            ("Hauptstr. 7, Berlin", house),
            ("12 Oak Grove, Toowong QLD 4066", house),
            ("450 Main Circle, Springfield", house),
            ("3 Harbour Rise, Hope Island", house),
            ("7 Kings Mews, London", house),
            ("Riverside Walk, Brisbane", street),
            // Types read on their own, not through the first-line number rule.
            ("Oak Grove, Toowong QLD", street),
            ("12 Oak Grove Toowong", house),
            ("Main Circle, Springfield", street),
            ("1 Sunset Parkway, Denver", house),
        ] {
            assert_eq!(place_naming(s).street, want, "{s}");
        }
        for s in [
            // A surname is not a street: "Dương" folds to the same ASCII as
            // "Đường" but is not the street word.
            "Dương Văn Minh, Hà Nội",
            // A route, not a street line.
            "Brisbane via Toowoomba",
            // A postcode area, a lone name, a saint.
            "4066 Toowong, QLD",
            "Nguyễn Huệ",
            "St Kilda, Victoria",
            // One segment: a bare number + name is not read as a street line.
            "12 Nguyễn Huệ",
        ] {
            assert_eq!(place_naming(s).street, None, "{s}");
        }
    }

    /// REQ-GEO-018: the locality part of an address is what is left once its
    /// street is dropped — never a place name inside the street's.
    #[test]
    fn the_locality_part_drops_the_street_and_keeps_the_place() {
        assert_eq!(
            locality_part("45 Sydney Road, Brunswick VIC"),
            "Brunswick VIC"
        );
        assert_eq!(
            locality_part("45 Sydney Road Brunswick VIC 3056"),
            "Brunswick VIC 3056"
        );
        assert_eq!(
            locality_part("Hobart Rd, Kings Meadows TAS"),
            "Kings Meadows TAS"
        );
        assert_eq!(
            locality_part("12 Đường Láng, Phường Láng, Hà Nội"),
            "Phường Láng, Hà Nội"
        );
        assert_eq!(locality_part("Martin Place, Sydney"), "Sydney");
        // Nothing to drop: the string is returned whitespace-normalised.
        assert_eq!(locality_part("Toowong,  QLD"), "Toowong, QLD");
        assert_eq!(locality_part("St Kilda, Victoria"), "St Kilda, Victoria");
    }

    /// REQ-OPENMETEO-002: a match must be the queried place, not a neighbour.
    #[test]
    fn a_matched_name_must_be_the_queried_place() {
        assert!(is_name_of_queried_place("Sydney", "Sydney, Australia"));
        assert!(!is_name_of_queried_place(
            "Sydney Heads",
            "Sydney, Australia"
        ));
        assert!(!is_name_of_queried_place("Milton", "Hamilton, NZ"));
        assert!(is_name_of_queried_place("Hà Nội", "ha noi, vietnam"));
        assert!(!is_name_of_queried_place(
            "Thorpe-Abbotts Lane",
            "Ian Thorpe, North Carolina"
        ));
        assert!(!is_name_of_queried_place("", "anything"));
    }
}
